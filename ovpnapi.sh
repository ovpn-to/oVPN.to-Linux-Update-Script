#!/bin/bash
SCRIPTVERSION=40
# 
# oVPN.to API LINUX Updater
#

# modify these lines only if not exists in ovpnapi.conf
LASTUPDATEFILE="lastovpntoupdate.txt";
IPTABLESANTILEAK="/root/iptables.sh";
CVERSION="23x";

# do not change these lines
PFX="00"; PORT="443"; DOMAIN="vcp.ovpn.to"; API="xxxapi.php"; URL="https://${DOMAIN}:${PORT}/$API";
SSL1="CE:4F:88:43:F8:6B:B6:60:C6:02:C7:AB:9C:A9:2F:15:3A:9F:F4:65:A3:20:D0:11:A1:27:74:B4:07:B9:54:6A";
SSLB="CD:52:1C:A0:F9:24:67:10:71:C7:F2:D4:0E:58:33:A2:90:A6:95:7C:3B:6B:3B:37:A1:4C:E2:90:0E:98:5E:A9";
APICONFIGFILE="ovpnapi.conf";
DEVMODE=1; # NEVER change this value to 1!
requirements () {
	test ${DEVMODE} -eq 1 && echo -e "\nWarning! DEVMODE=1!\n";
	if test -f "/etc/os-release"; then	source /etc/os-release; echo -ne "${0}: v${SCRIPTVERSION} @ ($ID $VERSION `uname -r`:`uname -v`:`uname -m`) "; fi;

	if [ ! -z ${2} ]; then
		if [ ${2} = "force" ]; then FORCE=1; else FORCE=0; fi;
		if [ ${2} = "debug" ]; then DEBUG=1; else DEBUG=0; fi;
		if [ ! -z ${3} ] && [ ${3} = "debug" ]; then DEBUG=1; fi;
	else FORCE=0; DEBUG=0; fi;
	if ! test `whoami` = "root"; then 
		ROOT=0; echo "[user]";
		if [ ${FORCE} -eq 0 ]; then 
			echo -ne "no root: run with su -c '${0} ${1} ${2} ${3}'\n or continue as user?\n  (Y)es / (N)o : "; read READINPUT; 
			INPUT=`echo ${READINPUT} | tr '[:upper:]' '[:lower:]'`;
			if [ ! -z ${INPUT} ]&&([ ${INPUT} = "yes" ]||[ ${INPUT} = "y" ]); then ROOT=0; else echo "Aborted."; exit 1; fi;
		fi;
	else	ROOT=1; echo "[root]"; fi;

	which unzip >/dev/null && UNZIP="unzip";
	which 7z >/dev/null && UNZIP="7z";
	if which curl >/dev/null; then CURL="curl --connect-timeout 16 -s"; else echo "curl not found"; exit 1; fi;
	
	if which openvpn >/dev/null; then 
		OPENVPNBIN=`which openvpn`;
	else
		if test -f /usr/sbin/openvpn; then OPENVPNBIN=/usr/sbin/openvpn;
		elif test -f /usr/bin/openvpn; then OPENVPNBIN=/usr/bin/openvpn;
		else	echo "openvpn not found"; exit 1;
		fi;	
	fi;
	if ! which openssl >/dev/null; then echo "openssl not found"; exit 1; fi;
	if test -z $UNZIP; then echo "ERROR:unzip or 7z not found"; exit 1; fi;
	TESTCONN=`${CURL} ${URL}`;
	if test $? -gt 0; then echo "Connect to ${URL} failed.";
		if test -f ${IPTABLESANTILEAK}; then echo "Try: ${IPTABLESANTILEAK} unload"; fi;
		exit 1;
	fi;
	echo -ne "\nCheck SSL Fingerprint: ${DOMAIN} ";
	REMOTESSLCERT=`openssl s_client -servername ${DOMAIN} -connect ${DOMAIN}:${PORT} < /dev/null 2>/dev/null | openssl x509 -sha256 -fingerprint -noout -in /dev/stdin|cut -d= -f2`;
	if [ ${REMOTESSLCERT} = ${SSL1} ]; then 
		test ${DEBUG} -eq 1 && echo -e "REMOTESSL=${REMOTESSLCERT}\nLOCALSSL=${SSL}";
		echo "OK";
	elif [ ${REMOTESSLCERT} = ${SSLB} ]; then 
		echo "Site in Maintenance Mode! Please try again later!";
		exit 1
	else echo -e "Error: Invalid SSL Fingerprint @ ${DOMAIN} !\nREMOTE=${REMOTESSLCERT}\nLOCAL=${SSL}"; exit 1; fi;
		
	if test -f ${APICONFIGFILE}; then 
		source ${APICONFIGFILE};
		if [ ${ROOT} -eq 0 ] && [ ${OVPNPATH} = "/etc/openvpn" ]; then 
			OVPNPATH=~/.ovpn
			test -e ${OVPNPATH} || mkdir -v ${OVPNPATH}
			test $DEBUG -eq 1 && echo "DEBUG: OVPNPATH=${OVPNPATH}";
			if [ ! -L /etc/openvpn ]; then echo -e "\nError: /etc/openvpn is not a symbolic link to ${OVPNPATH} \n\nPlease do:\n\n~# su -c 'mv -v /etc/openvpn /etc/openvpn.bak'\n~# su -c 'ln -sfv ${OVPNPATH} /etc/openvpn'\n~# su -c 'mv -v /etc/openvpn.bak/* ${OVPNPATH}'\n"; exit 1; fi;
		fi;
	else
		echo -e "USERID=\"00000\";\nAPIKEY=\"0x123abc\";\nOCFGTYPE=\"lin\";\nOVPNPATH=\"/etc/openvpn\";\nCVERSION=\"23x\"; # options: 23x or 23x46 or 23x64\nIPTABLESANTILEAK=\"/root/iptables.sh\";\nLASTUPDATEFILE=\"lastovpntoupdate.txt\";" > ${APICONFIGFILE}
		echo -e "Please edit `pwd`/${APICONFIGFILE}:\n~# [nano|vim|gedit] ${APICONFIGFILE}";
		exit 1;
	fi;
	if ! test ${USERID} -gt 0; then echo "Invalid USERID in ${APICONFIGFILE}"; exit 1; fi
	if ! test `echo -n "${APIKEY}"|wc -c` -eq 128; then echo "Invalid APIKEY in ${APICONFIGFILE}"; exit 1; fi
	
	OPENVPNVERSION=`${OPENVPNBIN} --version | head -1 | cut -d" " -f2 | sed 's/\.//g'`;
	ODATA="uid=${USERID}&apikey=${APIKEY}&action=getovpnversion";
	test ${DEVMODE} -eq 1 && ODATA="uid=${USERID}&apikey=${APIKEY}&action=getovpnversion_devmode";
	REQ=`${CURL} --request POST ${URL} --data ${ODATA}|cut -d":" -f1`;
	if ! test ${REQ} = "AUTHOK"; then echo "Error: Invalid USERID or APIKEY or Account expired..."; exit 1; else echo "Check API Login: OK"; fi;

	SDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapish";
	test ${DEVMODE} -eq 1 && SDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapish_devmode";
	echo -n "Check SRC Version: ";
	REQUEST=`${CURL} --request POST ${URL} --data ${SDATA}`;
	RSV=`echo ${REQUEST}|cut -d: -f2`;
	if [ ${RSV} -gt ${SCRIPTVERSION} ]; then
		echo "v${RSV} available!";
		if [ ${FORCE} -eq 0 ]; then echo -n " Update now? (Y)es / (N)o : "; read READINPUT; else READINPUT="yes"; fi;
		INPUT=`echo ${READINPUT} | tr '[:upper:]' '[:lower:]'`;
		if [ ! -z ${INPUT} ]&&([ ${INPUT} = "yes" ]||[ ${INPUT} = "y" ]); then
			HASHDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapihash";
			test ${DEVMODE} -eq 1 && HASHDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapihash_devmode";
			HASHREQUEST=`${CURL} --request POST ${URL} --data ${HASHDATA}`;
			HASHSTRLEN=`echo -n ${HASHREQUEST} |wc -c`;
			if [ $HASHSTRLEN -eq 128 ]; then
				TMPFILE="ovpnapi.sh.v${RSV}";
				echo "Downloading Script Update...";
				timeout 30 ${CURL} "https://${DOMAIN}/files/ovpnapi.sh.v${RSV}" -o ${TMPFILE} || exit 1;
				LOCALHASH=`sha512sum ${TMPFILE} | cut -d" " -f1`;
				echo "REMOTE-HASH:${HASHREQUEST}";
				echo "LOCAL-HASH:${LOCALHASH}";
				if [ ${DEVMODE} -eq 1 ] || [ "${HASHREQUEST}" = "${LOCALHASH}" ]; then
					chmod +x ${TMPFILE};
					mv -v ${0} "${0}.${SCRIPTVERSION}";
					mv -v ${TMPFILE} ${0};	
					if ! test -x ${0}; then 	
						echo "SET manually: chmod +x ${0}";
						echo "RUN: ./${0} ${1} ${2} ${3}";
						exit 1;
					else
						echo "usage: ${0} ${1} ${2} ${3}";
						exit 0
					fi;					
				else
					echo "LOCAL/REMOTE HASH ERROR!";
					exit 1;
				fi;
			fi;
		else
			echo "${0} Script not updated.";
		fi;
	else
		echo "OK";
	fi;

	echo -n "Check VPN Client: ";
	test ${DEBUG} -eq 1 && echo -e "DEBUG:requirements:REQ=${REQ}";
	REQUEST=`${CURL} --request POST ${URL} --data ${ODATA}|cut -d: -f2`;
	test ${DEBUG} -eq 1 && echo -e "DEBUG:requirements:REQUEST=${REQUEST}";
	if [ -z ${REQUEST} ]; then echo "Request failed. exiting..."; exit 1; 
	elif [ ${OPENVPNVERSION} -lt ${REQUEST} ]; then
		if ([ ${ID} == "debian" ] && [ ${ROOT} -eq 1 ]) && ([ "${VERSION}" == "7 (wheezy)" ] || [ "${VERSION}" == "8 (jessie)" ]); then
			if test ${VERSION} = "7 (wheezy)"; then OSV="wheezy"; 
			elif test ${VERSION} = "8 (jessie)"; then OSV="jessie"; fi;
			ARCH=`openvpn --version | head -1 | cut -d" " -f3| cut -d"-" -f1`;
			if [ ${ARCH} = "x86_64" ]||[ ${ARCH} = "i686" ]||[ ${ARCH} = "i386" ]; then
				if [ ! -f /etc/apt/sources.list.d/swupdate.openvpn.net.list ]; then
					apt-key del E158C569 2>&1 > /dev/null
					wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -
					echo "deb http://swupdate.openvpn.net/apt ${OSV} main" > /etc/apt/sources.list.d/swupdate.openvpn.net.list
				fi;
				if [ -f /etc/apt/sources.list.d/swupdate.openvpn.net.list ]; then
					apt-get update && apt-get upgrade
				fi;
			else
				echo "ARCH not FOUND: ${ID} ${VERSION} ${ARCH} `uname -a`: Update your openVPN ${OPENVPNVERSION} Client manually to ${REQUEST}!";
			fi;
		else echo "Warning! Update your openVPN Client v${OPENVPNVERSION} manually to v${REQUEST}! OS ${ID}:${VERSION} not supported or not root... root=${ROOT}"; fi;
	elif [ ${OPENVPNVERSION} -ge ${REQUEST} ]; then
		echo "OK";
		test ${DEBUG} -eq 1 && echo "DEBUG: LOCALVERSION=${OPENVPNVERSION} REMOTEVERSION=${REQUEST}";
	else
		echo "FAIL!";
		exit 1
	fi;
	if [ "$OPENVPNVERSION" -ge "234" ] && [ -z ${CVERSION} ]; then CVERSION="23x"; fi;
	if [ "$OPENVPNVERSION" -lt "234" ] && [ -z ${CVERSION} ]; then CVERSION="22x"; fi;
	test ${DEBUG} -eq 1 && echo "DEBUG:requirements:CVERSION=$CVERSION";
	test ! -f ${LASTUPDATEFILE} && echo "0" > ${LASTUPDATEFILE};	
}



apirequestcerts () {
	echo -n "Download VPN Certs:";
	DATA="uid=${USERID}&apikey=${APIKEY}&action=requestcerts";
	REQUEST=`${CURL} --request POST ${URL} --data ${DATA}`;
	test ${DEBUG} -eq 1 && echo "DEBUG:apirequestcerts:REQUEST=${REQUEST}";
	while : 
	do	
		if [ ! -z ${REQUEST} ]; then echo -n " ${REQUEST}"; TIMEOUT=0; else let TIMEOUT="TIMEOUT+1"; echo -n "... timeout:${TIMEOUT}/10"; fi;
		if [ ! -z ${REQUEST} ] && [ ${REQUEST} = "submitted" ]; then echo -n "! please wait..."; fi;
		if [ ! -z ${REQUEST} ] && [ ${REQUEST} = "ready" ]; then break; fi;
		test ${TIMEOUT} -ge 10 && break;
		sleep 5; REQUEST=`${CURL} --request POST ${URL} --data ${DATA}`;
	done;
	test ${TIMEOUT} -ge 10 && (echo "Request timeout. exiting..."; exit 1) 

	if [ ! -z ${REQUEST} ] && [ ${REQUEST} = "ready" ]; then
		CERTFILE="oVPN.to_Certificates_${USERID}.zip";
		DATA="uid=${USERID}&apikey=${APIKEY}&action=getcerts";
		if test -e ${CERTFILE}; then rm -f ${CERTFILE}; fi
		REQUEST=`${CURL} --request POST ${URL} --data ${DATA} -o ${CERTFILE}`;
		if test -f ${OCFGFILE} && test -f ${CERTFILE}; then 
			echo -e "\noVPN Serverconfig downloaded to ${OCFGFILE}\noVPN Certificates downloaded to ${CERTFILE}";
			LASTACTIVECONFIGS=`ls ${OVPNPATH}/*ovpn.to*.conf 2>/dev/null`;

			# read tunX-ifs to backup
			for LASTCONF in ${LASTACTIVECONFIGS}; do
				SRVNAME=`echo ${LASTCONF}|rev|cut -d/ -f1|rev|cut -d. -f1,2,3,4`;
				TUNDATA=`grep -E "^dev\ tun[0-9]|^route-nopull|^fast-io|^nice|^up|^down|^script-security|^verb|^log|^socks-proxy|^http-proxy" ${LASTCONF}`;
				test $? -eq 0 && echo "${TUNDATA}" > "/tmp/${SRVNAME}" && TD=`echo "${TUNDATA}" | tr '\n' '|'` && echo -e " Backup: '${TD}' to /tmp/${SRVNAME}";
			done;
			OLDDIRS=`ls -d ${OVPNPATH}/*.ovpn.to 2>/dev/null`;
			for ODIR in ${OLDDIRS}; do if [ ${DEBUG} -eq 1 ]; then rm -rvf ${ODIR}; else rm -rf ${ODIR}; fi; done;			
			
			if [ ${DEBUG} -eq 1 ]; then RM="rm -vf"; else RM="rm -f"; fi
			${RM} ${OVPNPATH}/*.ovpn.to.ovpn ${OVPNPATH}/*.ovpn.to*.conf ${OVPNPATH}/ovpnproxy-authfile.txt ${OVPNPATH}/*.log;

			echo "Extracting...";
			if test ${UNZIP} = "unzip"; then 
				ECMD1="unzip ${OCFGFILE} -d ${OVPNPATH}";
				ECMD2="unzip ${CERTFILE} -d ${OVPNPATH}";
			fi;
			if test ${UNZIP} = "7z"; then 
				ECMD1="7z e -o${OVPNPATH} ${OCFGFILE} -y"; 
				ECMD2="7z x -o${OVPNPATH} ${CERTFILE} -y";
			fi;
			if [ ${DEBUG} -eq 1 ]; then $ECMD1; $ECMD2;	else	${ECMD1} 1>/dev/null; ${ECMD2} 1>/dev/null; fi;
			
			for LASTCONF in ${LASTACTIVECONFIGS}; do
				SRVNAME=`echo ${LASTCONF}|rev|cut -d/ -f1|rev|cut -d. -f1,2,3,4`;
				CHECKCONFIG=${OVPNPATH}/${SRVNAME};
				if [ -f ${CHECKCONFIG} ]; then
					mv ${CHECKCONFIG} ${LASTCONF} && echo "Enabled: ${LASTCONF}";
					if [ -f "/tmp/${SRVNAME}" ]; then
						TUNDATA=`cat "/tmp/${SRVNAME}"`;
						echo "$TUNDATA" | grep "^dev\ tun[0-9]" >/dev/null && sed -i '/^dev\ tun/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^route-nopull" >/dev/null && sed -i '/^route-nopull/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^fast-io" >/dev/null && sed -i '/^fast-io/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^up" >/dev/null && sed -i '/^up/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^script-security" >/dev/null && sed -i '/^script-security/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^verb" >/dev/null && sed -i '/^verb/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^log" >/dev/null && sed -i '/^log/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^socks-proxy" >/dev/null && sed -i '/^socks-proxy/d' ${LASTCONF};
						echo "$TUNDATA" | grep "^http-proxy" >/dev/null && sed -i '/^http-proxy/d' ${LASTCONF};
						echo -e "\n#RESTORED SETTINGS" >> ${LASTCONF};
						TD=`echo "${TUNDATA}" | tr '\n' '|'`; echo "${TUNDATA}" >> ${LASTCONF} && echo -e " Restore: '${TD}' to ${LASTCONF}\n" && rm -f "/tmp/${SRVNAME}";
					fi;
				 fi;
			done;
		
			if [ -f ${IPTABLESANTILEAK} ] && [ ${ROOT} -eq 1 ]; then				
				if [ ! -x ${IPTABLESANTILEAK} ]; then chmod +x ${IPTABLESANTILEAK}; fi
				echo "Found IPtables Anti-Leak Script ${IPTABLESANTILEAK}: reload rules!";
				${IPTABLESANTILEAK};
			elif [ -f ${IPTABLESANTILEAK} ] && [ ${ROOT} -eq 0 ]; then				
				if [ ! -x ${IPTABLESANTILEAK} ]; then chmod +x ${IPTABLESANTILEAK}; fi
				echo "Need root to reload IPtables Anti-Leak Script: su -c '${IPTABLESANTILEAK}'";
			else
				echo -e "$Warning! IPtables Anti-Leak Script NOT FOUND in: {IPTABLESANTILEAK}\nCheck https://raw.githubusercontent.com/ovpn-to/oVPN.to-IPtables-Anti-Leak/master/iptables.sh"; 
			fi;

			echo ${REMOTELASTUPDATE} > ${LASTUPDATEFILE};
			echo -e "\n####################\noVPN Update: Job done!";
		else
			echo "Error: Files not found '${OCFGFILE}' '${CERTFILE}'"
		fi;
	fi;
}


apigetconfigs () {
	OCFGFILE="oVPN.to_Configurations_${USERID}_${OCFGTYPE}_${CVERSION}.zip";
	echo -n "Download VPN Config: ";
	DATA="uid=${USERID}&apikey=${APIKEY}&action=getconfigs&version=${CVERSION}&type=${OCFGTYPE}";
	rm -f ${OCFGFILE}; 		
	REQUEST=`${CURL} --request POST ${URL} --data ${DATA} -o ${OCFGFILE}`;
	if test -f ${OCFGFILE}; then echo "ready"; else echo "Error getting oVPN Configs!"; exit 1; fi;
}


apicheckupdate () {
	DATA="uid=${USERID}&apikey=${APIKEY}&action=lastupdate";
	REQUEST=`${CURL} --request POST ${URL} --data ${DATA}`;
	if [ -z ${REQUEST} ]; then echo "Request failed. exiting..."; exit 1; fi;
	test ${DEBUG} -eq 1 && echo -e "DEBUG:apicheckupdate:REQUEST=${REQUEST}";
	REMOTELASTUPDATE=`echo ${REQUEST}|cut -d":" -f2`;
	echo  -n "Check SRV Update: ";
	if [ ${REMOTELASTUPDATE} -gt 0 ]; then LUPDATE=`cat ${LASTUPDATEFILE}`;
		if [ ${REMOTELASTUPDATE} -gt ${LUPDATE} ]; then echo "available!";
			if [ ${FORCE} -eq 0 ]; then echo -n "Update oVPN-Configs now? (Y)es / (N)o : "; read READINPUT; else READINPUT="yes"; fi;
			INPUT=`echo ${READINPUT} | tr '[:upper:]' '[:lower:]'`;
			if [ ! -z ${INPUT} ]&&([ ${INPUT} = "yes" ]||[ ${INPUT} = "y" ]); then
					apigetconfigs ${1} ${2} ${3};
					apirequestcerts ${1} ${2} ${3};
			else
				echo "Aborted.";
				exit 1;
			fi;
		else
			echo "OK";
			echo -e "\n####################\noVPN Update: Job done!";
			test ${DEBUG} -eq 1 && echo "\nForce update with:\n~# rm ${LASTUPDATEFILE}\n~# ${0} ${1} ${2} ${3}";
			exit 0;
		fi;
	fi;
}


if [ $# -lt 1 ]; then echo "Usage : [sudo] ${0} update [debug|force] [debug]"; exit 1; fi;

case "$1" in
'update')  

	requirements ${1} ${2} ${3};
	apicheckupdate ${1} ${2} ${3};
    ;;
*) echo "Usage : ${0} update [debug|force] [debug]"
   ;;
esac
