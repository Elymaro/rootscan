#!/bin/bash

apt update

if ! which ipcalc >/dev/null 2>&1; then
   apt install ipcalc -y
fi
 
if ! which netexec >/dev/null 2>&1; then
   apt install pipx git
   pipx ensurepath
   pipx install git+https://github.com/Pennyw0rth/NetExec
fi

if ! which pret >/dev/null 2>&1; then
   git clone https://github.com/RUB-NDS/PRET.git
   cd PRET; chmod +x pret.py
   python2 -m pip install colorama pysnmP
   mv pret.py /usr/bin/pret
   pip install Discovery
fi

if ! which manspider >/dev/null 2>&1; then
   apt install python3-venv -y
   pip install pipx -y
   pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
   pipx ensurepath
   # for images (png, jpeg)
   apt install tesseract-ocr -y
   # for legacy document support (.doc)
   apt install antiword -y
   cp ~/.local/share/pipx/venvs/man-spider/bin/manspider /usr/bin/
fi

if ! which xsltproc >/dev/null 2>&1; then
   apt install xsltproc -y
fi

if ! which kerbrute >/dev/null 2>&1; then
   if ! dpkg -l | grep -q "^ii  golang-go "; then
      apt install golang-go -y
   fi 
   git clone https://github.com/ropnop/kerbrute
   cd kerbrute
   make linux
   cd dist
   cp kerbrute_linux_amd64 /usr/sbin/kerbrute
   cd ../..
   rm -rf kerbrute
fi

if [ ! -f "/usr/share/nmap/nmap-services.bkp" ]; then
   cp /usr/share/nmap/nmap-services /usr/share/nmap/nmap-services.bkp
fi
# Make update top-ports 1000 to include winrm service
curl https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-services -o /usr/share/nmap/nmap-services

if ! which proxychains >/dev/null 2>&1; then
   apt install proxychains4 -y
fi

if ! which ldapsearch >/dev/null 2>&1; then
   apt install ldap-utils -y
fi

if ! which snmpwalk >/dev/null 2>&1; then
   apt install snmp-mibs-downloader -y
fi
#Installation MIB SNMP :
if ! which snmpwalk >/dev/null 2>&1; then
   apt install download-mibs -y
   sed -i '/^mibs :/ s/^/# /' /etc/snmp/snmp.conf
fi

if ! which onesixtyone >/dev/null 2>&1; then
   apt install onesixtyone -y
fi

if ! which seclists >/dev/null 2>&1; then
   apt install seclists -y
fi
