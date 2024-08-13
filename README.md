# RootScan

The aim of this script is to help and speed up the recognition phase in pentesting, although it is still necessary to carry out a more in-depth search manually.

Key features:

- **HTML report**: Scans ports and generates nmap reports in HTML format for easy reading.
- **Port filtering**: IPs with similar port opened are automatically recorded in a a same file (161.txt, 88.txt..).
- **Attack automation**: If machines are vulnerable, the tool automatically launches the Responder and NTLMRelayx.
- **Integrated Manspider**: Runs Manspider on machines with port 445 open to search for sensitive keywords (only available in NTLM mode).
- **Proxychains support**: Option to use proxychains available at start-up.
- **Kerberos support** : Automated support for NTLM and Kerberos

![image](https://github.com/Elymaro/rootscan/blob/main/assets/elymaro.lab.png)

Some elements can be modified on the targets (only in the SMB function). If this is the case, orange information will be displayed and the recovery commands will be written to a modifs.txt file. The -r option will be used to execute all of them in order to clean up the actions performed.

### Installation
```
git clone https://github.com/Elymaro/rootscan.git
cd rootscan ; chmod +x rootscan.sh
```
### Installation dependencies
```
chmod +x install.sh && ./install.sh
```

### Usage :

For the first start of a projet, you must use option **-f** or at least **-s nmap_fast**

Full enumeration with "b.robinson" acount on the 192.168.1.0/26 network
```
./rootscan.sh -o LAB001 -i eth0 -t 192.168.1.0/26 -u "b.robinson" -p "Kebxj6urt0o" -f
```
Enumeration with "b.robinson" account and his NT Hash. Script will try to enumerate on functions : "nmap_fast" and "smb"
```
./rootscan.sh -o LAB001 -i eth0 -t 192.168.1.17/32 -u "b.robinson" -H "08CFA7DDB10EB084FAC1CB72152B1E95" -s nmap_fast,smb
```
Full enumeration with "anonymous:anonymous" login expect on function "snmp" and "ldap"
```
./rootscan.sh -o LAB001 -i eth0 -t 192.168.1.17/32 -e snmp,ldap
```

Depending on the functions chosen, the script will attempt to dig down and retrieve as much data as possible.
For example SMB:
- Automatic NTLM / Kerberos support
- Attempt to connect in anonymous mode
- Connection attempt in guest mode
- Attempt to connect using the credentials provided
- Users extraction
- Shares discovery
- Exploitation of LSA / SAM / RDP activation / Defender deactivation / impersonate
- ...

The script will also attempt to recover the most popular exploits/misconfigurations such as :
- ms17-010
- zerologon
- petitpotam
- nopac
- spooler
- install_elevated
- gpp_password
- gpp_autologin
- ...

### Options
```
Usage: ./rootscan.sh -o ProjectName -i Interface -t rangeIP [-u Username [-p Password | -n HashNTLM]] -f

Options:
  -o  Project name (output directory)
  -i  Network interface
  -t  IP range (e.g., 192.168.1.17/32 or 192.168.1.128/27)
  -u  Username (optional)
  -p  Password (optional, either Password or HashNTLM must be provided, can be empty)
  -H  NTLM Hash (optional, either Password or HashNTLM must be provided, can be empty)
  -f  Execute all functions
  -e  Execute all functions, but exclude specific functions (-e rdp,winrm)
  -s  Select specific functions (-s rdp,winrm)
  -r  Restore modifications
  -h  Display help

Available functions:
  - nmap_fast    : Ports scan, Service versions scan (need to be done at least 1 time at the begin of a project)
  - relay        : Responder + NTLMRelayx
  - manspider    : Search sensitive elements (password, username, .. etc) on SMB Shares
  - vulns        : ms17-010, nopac, zerologon, MSOL creds, GPP_autologin, GPP_password, ...
  - ftp          : FTP enumeration
  - ssh          : SSH enumeration
  - winrm        : NFS enumeration
  - rdp          : WinRm enumeration
  - smtp         : RDP enumeration
  - nfs          : NFS enumeration
  - vnc          : VNC enumeration
  - zt           : Zone Transfer DNS
  - printers     : Looking for printers
  - snmp         : Looking for SNMP public communities
  - ldap         : Anonymous LDAP
  - ipmi         : ipmi enumeration
  - mssql        : MSSQL authentication
  - smb          : anonymous auth., guest auth., shares, users, lsa, dpapi, rdp session ..
  - prn          : PrintersScan
  - asp          : Try ASRepRoasting Attack
  - users        : Get-ADUsers
  - krb          : Try Kerberoasting Attack
  - web          : Try to identify web services
  - nmap_full    : Deep nmap scan
```

### Exemple HTML report

![image](https://github.com/Elymaro/rootscan/blob/main/assets/nmap_html.png)

## Contributors

  - [O.B. E](https://www.linkedin.com/in/omar-badis-elaffifi/)
  - [SAFEIT CONSULTING](https://www.linkedin.com/company/safeit-consulting/)

## Tools

  - [fortra](https://github.com/fortra) - impacket
  - [Pennyw0rth](https://github.com/Pennyw0rth) NetExec
  - [ropnop](https://github.com/ropnop) - Kerbrute
  - [blacklanternsecurity](https://github.com/blacklanternsecurity/MANSPIDER) - Manspider
