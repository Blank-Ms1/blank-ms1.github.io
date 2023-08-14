El dia de hoy vamos a estar resolviendo la maquina <code class="language-plaintext highlighter-rouge">Developer</code> de la plataforma de [vulnyx](https://vulnyx.com/) 

![](/assets/img/developer/machine.png)

## Enumeracion

Empezemos Detectando que puertos estan abiertos en la maquina victima para esto voy a estar unsando la herramienta <code class="language-plaintext highlighter-rouge">nmap</code>


<pre><code class="language-python"><span style="color: green;">❯ nmap </span> 192.168.1.12
Nmap scan report for 192.168.1.12
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
</code></pre>

Solo Tenemos 2 puertos en el puerto <code class="language-plaintext highlighter-rouge">22</code> corre <code class="language-plaintext highlighter-rouge">ssh</code> y en el <code class="language-plaintext highlighter-rouge">80</code> un servicio <code class="language-plaintext highlighter-rouge">http</code>.

Enumeremos el servidor Web.
![](/assets/img/developer/web.png)

Viendo un poco la pagina web me llamo algo la atencion en la session de contacto, atraves de un parametro llama el archivo.
![](/assets/img/developer/page.png)

El tema de usar parametros para mostar archivos es mala idea si no saben como sanitizarlo de forma correcta, en este caso se llama al archivo atraves del parametro <code class="language-plaintext highlighter-rouge">?page=</code>, Veamos si se acontese un <code class="language-plaintext highlighter-rouge">LFI</code>.
![](/assets/img/developer/path.png)

Y no funciona esto puede ser que se este implementando algun tipo de sanitizacion, Si el servidor nos esta quitando el <code class="language-plaintext highlighter-rouge">../</code> Podemos intentar bypassear esto usando <code class="language-plaintext highlighter-rouge">....//</code> Te muestro un pequeño ejemplo de esto.

Esto es algo parecido a lo que se esta aplicando en el servidor.
![](/assets/img/developer/str.png)

Esto no es muy seguro ya que podemos usar <code class="language-plaintext highlighter-rouge">....//</code> para bypassearlo.

![](/assets/img/developer/bypass.png)

Pobramos esto en la Web y funciona Tenemos <code class="language-plaintext highlighter-rouge">LFI</code>

![](/assets/img/developer/lfi.png)

Voy a crear un script simple en python para ir viendo los archivos que me interesan.
<pre class="highlight">
<code><span class="c1">#!/usr/bin/python3

</span><span class="kn">import</span> <span class="nn">requests</span>
<span class="kn">import</span> <span class="nn">sys</span>

<span class="c1"># Variables
</span><span class="n">url_lfi</span> <span class="o">=</span> <span class="s2">'http://192.168.1.12/pagecontact.php?page=....//....//....//....//....//....//....//....//....//....//....//....//....//..../'</span>

<span class="k">def</span> <span class="nf">getFile</span><span class="p">():</span>
    <span class="n">file</span> <span class="o">=</span> <span class="n">sys</span><span class="o">.</span><span class="n">argv</span><span class="p">[</span><span class="mi">1</span><span class="p">]</span>
    <span class="n">main_url</span> <span class="o">=</span> <span class="n">url_lfi</span> <span class="o">+</span> <span class="n">file</span>
    <span class="n">r</span> <span class="o">=</span> <span class="n">requests</span><span class="o">.</span><span class="n">get</span><span class="p">(</span><span class="n">main_url</span><span class="p">)</span>
    <span class="nb">print</span><span class="p">(</span><span class="n">r</span><span class="o">.</span><span class="n">text</span><span class="p">)</span>

<span class="k">if</span> <span class="nb">__name__</span> <span class="o">==</span> <span class="s2">'__main__'</span><span class="p">:</span>
    <span class="n">getFile</span><span class="p">()</span>
</code></pre>

Ejecutamos el script y como <code class="language-plaintext highlighter-rouge">argumento</code> le pasamos el <code class="language-plaintext highlighter-rouge">archivo</code> que deseamos leer.

![](/assets/img/developer/passwd.png)

Veamos que puertos esta abiertos en la maquina victima para esto vemos la ruta <code class="language-plaintext highlighter-rouge">/proc/net/tcp</code>

![](/assets/img/developer/net.png)

Estos numeros estan en hexadecimal por lo que simplemente los tenemos que pasar a decimal.

![](/assets/img/developer/port.png)

Vemos el puerto <code class="language-plaintext highlighter-rouge">873</code> que es el puerto de el servicio <code class="language-plaintext highlighter-rouge">rsync</code> sin embargo este puerto esta cerrado.

![](/assets/img/developer/1.png)

Veamos si este puerto esta abierto por <code class="language-plaintext highlighter-rouge">ipv6</code> para sacar la dirreccion ipv6 de la maquina podemos ver el archivo <code class="language-plaintext highlighter-rouge">/proc/net/if_inet6</code> 

![](/assets/img/developer/2.png)

Tenemos la siguiente dirreccion.

<code class="language-python"><span style="color: green;">❯ echo </span><span style="color: yellow;">"280000e2258004370a0027fffe35a6c4"</span>

Esta direccion hay que hacerle un tratamiento, las dirrecciones ipv6 esta confomardas por <code class="language-plaintext highlighter-rouge">128 bits</code> y se componen de <code class="language-plaintext highlighter-rouge">8 campos</code> los cuales estan conformados por <code class="language-plaintext highlighter-rouge">16 bits</code> cada uno, cada campo se une con <code class="language-plaintext highlighter-rouge">dos puntos</code>, Para que lo entiendas un poco mejor cada 4 numeros agregamos <code class="language-plaintext highlighter-rouge">dos puntos</code> la dirreccion ipv6 nos quedaria de la siguiente forma.

<code class="language-python"><span style="color: green;">❯ echo </span><span style="color: yellow;">"2800:00e2:2580:0437:0a00:27ff:fe35:a6c4"</span>

Veamos que puertos esta abiertos por ipv6.
<pre><code class="language-python"><span style="color: green;">❯ nmap </span>-6 2800:00e2:2580:0437:0a00:27ff:fe35:a6c4
Nmap scan report for developer (2800:e2:2580:437:a00:27ff:fe35:a6c4)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
873/tcp open  rsync
</code></pre>

## Shell dev

Vemos que el puerto del <code class="language-plaintext highlighter-rouge">rsync</code> esta abierto por <code class="language-plaintext highlighter-rouge">ipv6</code>, aprovechando el <code class="language-plaintext highlighter-rouge">LFI</code> que tenemos en la maquina victima enumeremos los archivos de configuracion.

El archivo de configuracion de <code class="language-plaintext highlighter-rouge">rsync</code> es <code class="language-plaintext highlighter-rouge">/etc/rsyncd.conf</code>

![](/assets/img/developer/3.png)

Vemos que la ruta donde se depositan los archivos que subamos a <code class="language-plaintext highlighter-rouge">rsync</code> es <code class="language-plaintext highlighter-rouge">/var/www/html/rsync_uploads</code>

Esta ruta existe en la pagina web por lo que todo lo que subamos a <code class="language-plaintext highlighter-rouge">rsync</code> lo podemos llegar a ver en la web.

![](/assets/img/developer/4.png)

Vemos la ruta del archivo <code class="language-plaintext highlighter-rouge">secrets file</code> este archivo contiene credenciales para el servicio <code class="language-plaintext highlighter-rouge">rsync</code> para que los usuarios puedan acceder remotamente.

![](/assets/img/developer/5.png)

Para que no nos de problemas el <code class="language-plaintext highlighter-rouge">rsync</code> voy agregar en el archivo <code class="language-plaintext highlighter-rouge">/etc/hosts </code> para que la direccion <code class="language-plaintext highlighter-rouge">ipv6</code> apunte a un dominio.

<code class="language-python"><span style="color: green;">❯ echo </span><span style="color: yellow;">"2800:00e2:2580:0437:0a00:27ff:fe35:a6c4 developer"</span><span class='p'> |</span><span style="color: green;"> sudo tee</span> <span class='p'>-a /etc/hosts</span></code>

Listemos que <code class="language-plaintext highlighter-rouge">Modulos</code> hay en <code class="language-plaintext highlighter-rouge">rsync</code>, un <code class="language-plaintext highlighter-rouge">Modulo</code> es carpeta compartida.

![](/assets/img/developer/6.png)

No nos reporta nada, puede ser que los modulos existentes esten ocultos, pero anteriormente en el archivo <code class="language-plaintext highlighter-rouge">/etc/rsyncd.conf</code> habia un comentario.

![](/assets/img/developer/7.png)

Intentemos usar este nombre, y funciona ahora nos pide contraseña.

![](/assets/img/developer/8.png)

Usemos las credenciales que obtuvimos anteriormente del archivo <code class="language-plaintext highlighter-rouge">/etc/rsyncd.secrets</code>

![](/assets/img/developer/9.png)

Como la web interpreta <code class="language-plaintext highlighter-rouge">codigo php</code> voy a subir un archivo el cual se encargue de enviarme una <code class="language-plaintext highlighter-rouge">Revershell</code>, para esto voy a utilizar [Chankro](https://github.com/TarlogicSecurity/Chankro), primero creo un script en bash.

![](/assets/img/developer/10.png)

Genero el archivo <code class="language-plaintext highlighter-rouge">php</code>.
![](/assets/img/developer/11.png)

Subo el archivo.

![](/assets/img/developer/12.png)

Ahora enviemos una peticion a el archivo que subimos para que se ejecute.

![](/assets/img/developer/13.png)

## Shell mike

Si revisamos los privilegios que tenemos a nivel de <code class="language-plaintext highlighter-rouge">sudoers</code> Podemos ejecutar el comando <code class="language-plaintext highlighter-rouge">awk</code> Como el usuario <code class="language-plaintext highlighter-rouge">mike</code>.
![](/assets/img/developer/14.png)

Si nos vamos a [gtfobins](https://gtfobins.github.io/gtfobins/awk/#shell) vemos que atraves del comando <code class="language-plaintext highlighter-rouge">awk</code> podemos lanzarnos una <code class="language-plaintext highlighter-rouge">shell</code>.

![](/assets/img/developer/15.png)

Ejecutamos el comando y obtenemos una <code class="language-plaintext highlighter-rouge">shell</code> como el usuario <code class="language-plaintext highlighter-rouge">mike</code>

![](/assets/img/developer/16.png)

## Shell james

Si nuevamente Revisamos los privilegios que tenemos a nivel de <code class="language-plaintext highlighter-rouge">sudoers</code> Podemos ver que tenemos la capacidad de ejecutar el comando <code class="language-plaintext highlighter-rouge">base64</code> como el usuario <code class="language-plaintext highlighter-rouge">james</code>

![](/assets/img/developer/17.png)

Teniendo este privilegio podemos leer cualquier archivo como el usuario <code class="language-plaintext highlighter-rouge">james</code>, Leamos el historico de comandos de este usuario leyendo el archivo <code class="language-plaintext highlighter-rouge">/home/james/.bash_history</code>.

![](/assets/img/developer/18.png)

Conectemos por ssh como el usuario <code class="language-plaintext highlighter-rouge">james</code>.

![](/assets/img/developer/19.png)

## Shell root

Como no tengo permisos ni nada interesante voy a utilizar <code class="language-plaintext highlighter-rouge">pspy</code> para monitorizar los comandos y tareas que se esten ejecutando en el sistema.

Hay una tarea que ejecuta root la cual se encarga de ejecutar un script de bash el cual esta en mi directorio personal.

![](/assets/img/developer/20.png)

Somos el propietario del archivo por lo que lo podemos modificar y cambiar el contenido para que nos envie una <code class="language-plaintext highlighter-rouge">ReverShell</code>.

![](/assets/img/developer/21.png)

Modificamos el archivo.

![](/assets/img/developer/22.png)

Despues de 1 minuto esperando a que se ejecutara la tarea nos llega una consola como el usuario <code class="language-plaintext highlighter-rouge">root</code>.

![](/assets/img/developer/root.png)

