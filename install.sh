#!/bin/bash
 
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
   pip install pipx
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
download-mibs
sed -i '/^mibs :/ s/^/# /' /etc/snmp/snmp.conf
