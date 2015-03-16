#!/bin/bash
# 
# oVPN.to API LINUX Updater
#
PFX="00";
SCRIPTVERSION="32";
PORT="443"; DOMAIN="vcp.ovpn.to"; API="xxxapi.php";
SSL="CE:4F:88:43:F8:6B:B6:60:C6:02:C7:AB:9C:A9:2F:15:3A:9F:F4:65:A3:20:D0:11:A1:27:74:B4:07:B9:54:6A";
IPTABLESANTILEAK="/root/iptables.sh";

requirements () {
	DEVMODE="0"; # NEVER change this value to 1!
	if ! test -z $2 && test $2 = "force"; then FORCE="1"; echo "FORCE=ON"; else FORCE="0"; fi;
	if ! test -z $2 && test $2 = "debug"; then ODEBUG="1"; echo "DEBUG=ON"; else ODEBUG="0"; fi;
	if ! test `whoami` = "root"; then echo -e "Error: run with su -c '$0 update $2'"; exit 1; fi;
	if test -e "/etc/os-release"; then
		source /etc/os-release;
		#if test $ID = "debian" && test $VERSION = "7 (wheezy)"; then
		#	echo "Error: unsupported OS $ID $VERSION! contact support@ovpn.to"; exit 1;
		#fi;
		echo "OS $ID $VERSION `uname -r`";
	fi;
	which unzip >/dev/null && UNZIP="unzip";
	which 7z >/dev/null && UNZIP="7z";
	which curl >/dev/null || (echo "ERROR:curl not found" && exit 1);
	which openvpn >/dev/null || (echo "openvpn not found" && exit 1);
	which openssl >/dev/null || (echo "openssl not found" && exit 1);
	if test -z $UNZIP; then echo "ERROR:unzip or 7z not found" && exit 1; fi;
	CERT=`openssl s_client -servername $DOMAIN -connect $DOMAIN:$PORT < /dev/null 2>/dev/null | openssl x509 -sha256 -fingerprint -noout -in /dev/stdin|cut -d= -f2`;
	if [ "$CERT" = "$SSL" ]; then if [ $ODEBUG -eq "1" ]; then echo -e "REMOTESSL=$CERT\nLOCALSSL=$SSL"; fi;
		echo "$DOMAIN SSL-Fingerprint checked against hardcoded: OK!";
	else echo -e "ERROR: Received invalid SSL-Fingerprint from Certificate at $DOMAIN !\nREMOTE=$CERT\nLOCAL=$SSL"; exit 1; fi;
	APICONFIGFILE="ovpnapi.conf";
	LASTUPDATEFILE="lastovpntoupdate.txt";
	if test -e $APICONFIGFILE; then 
		source $APICONFIGFILE;
	else
		echo "Please edit: `pwd`/$APICONFIGFILE";
		echo -e "USERID=\"00000\";\nAPIKEY=\"0x123abc\";\nOCFGTYPE=\"lin\";\nOVPNPATH=\"/etc/openvpn\";\n" > $APICONFIGFILE
		cat $APICONFIGFILE;
		exit 1;
	fi;
	if ! test $USERID -gt "0"; then echo "Invalid USERID in $APICONFIGFILE"; exit 1; fi
	if ! test `echo "$APIKEY"|wc -c` -eq "129"; then echo "Invalid APIKEY in $APICONFIGFILE"; exit 1; fi
	
	URL="https://$DOMAIN:$PORT/$API";
	OPENVPNVERSION=`openvpn --version | head -1 | cut -d" " -f2 | sed 's/\.//g'`;
	ODATA="uid=${USERID}&apikey=${APIKEY}&action=getovpnversion";
	REQ=`curl -s --request POST $URL --data $ODATA|cut -d":" -f1`;
	if ! test "$REQ" = "AUTHOK"; then echo "Invalid USERID or APIKEY"; exit 1; else echo "Login OK"; fi;

	SDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapish";
	test $DEVMODE -eq "1" && SDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapish_devmode" && \
		 echo "Warning! Using Developer-Mode for Script-Version Check!";
	REQUEST=`curl -s --request POST $URL --data $SDATA`;
	RSV=`echo "$REQUEST"|cut -d: -f2`;
	if [ $RSV -gt $SCRIPTVERSION ]; then
		echo -n "YOUR SCRIPT v${SCRIPTVERSION} IS OUT OF DATE! Remote=v${RSV}! Asking you to Update: ";
		if [ "$FORCE" -eq "0" ]; then echo -n "Update now? (Y)es / (N)o : "; read READINPUT; else READINPUT="yes"; echo " FORCED"; fi;
		INPUT=`echo $READINPUT | tr '[:upper:]' '[:lower:]'`;
		if [ ! -z $INPUT ]&&([ "$INPUT" = "yes" ]||[ "$INPUT" = "y" ]); then
			HASHDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapihash";
			test $DEVMODE -eq "1" && HASHDATA="uid=${USERID}&apikey=${APIKEY}&action=getlatestlinuxapihash_devmode" && \
				echo "Warning! Using Developer-Mode for Script-Hash Check!";
			HASHREQUEST=`curl -s --request POST $URL --data $HASHDATA`;
			HASHSTRLEN=`echo "$HASHREQUEST" |wc -c`;
			if [ $HASHSTRLEN -eq "129" ]; then
				TMPFILE="ovpnapi.sh.v${RSV}"
				wget "https://$DOMAIN/files/ovpnapi.sh.v${PFX}${RSV}" -O $TMPFILE;
				LOCALHASH=`sha512sum $TMPFILE | cut -d" " -f1`;
				echo "REMOTE-HASH:$HASHREQUEST";
				echo "LOCAL-HASH:$LOCALHASH";
				if [ "$HASHREQUEST" = "$LOCALHASH" ]; then
					chmod +x $TMPFILE;
					mv -v $TMPFILE ovpnapi.sh;	
					if ! test -x ovpnapi.sh; then 	
						echo "SET manually: chmod +x ovpnapi.sh";
						echo "RUN manually: ./ovpnapi.sh update debug";
						exit 1;
					else
						$0 update $2
					fi;
					
				else
					echo "LOCAL/REMOTE HASH ERROR!";
					exit 1;
				fi;
			fi;
		else
			echo "$0 Script not updated.";
		fi;
	else
		echo "$0 Script is up to date";
	fi;

	if [ $ODEBUG -eq "1" ]; then echo -e "DEBUG:requirements:REQ=$REQ"; fi;
	REQUEST=`curl -s --request POST $URL --data $ODATA|cut -d: -f2`;
	if [ $ODEBUG -eq "1" ]; then echo -e "DEBUG:requirements:REQUEST=$REQUEST"; fi;
	if [ $OPENVPNVERSION -lt $REQUEST ]; then 
		if [ "$ID" = "debian" ] && [ "$VERSION" = "7 (wheezy)" ]; then
			ARCH=`openvpn --version | head -1 | cut -d" " -f3| cut -d"-" -f1`;
			if [ "$ARCH" = "x86_64" ]; then 
				ARCH="amd64";
				SHA512SUM="c3966ac62d4b7bfb7e4be0db039d0b6da33fa947fef6e21e1ca98cbe94f9624fe09e0438f0bb3fea4bbee0736977390333c4a82a1d7d5835048f5f6793272089";
			elif [ "$ARCH" = "i686" ]||[ "$ARCH" = "i386" ]; then 
				ARCH="i386";
				SHA512SUM="abbac8e1c83a666445bdde804d0fca50c6e7174b1156efbd93d8d3028ce60f585c5bf5728c44a866dc7bbe122b40ae72623aa7a3d8de9d356d1433e2313a2b91";
			else
				echo "ARCH not FOUND: $ARCH `uname -a`";
			fi;			
			if ! test -z $SHA512SUM; then
				OVPNFILE="openvpn_2.3.6-debian0_$ARCH.deb";
				OVPNFILEURLA="https://swupdate.openvpn.net/apt/pool/wheezy/main/o/openvpn/$OVPNFILE";
				OVPNFILEURLB="https://$DOMAIN/files/release/$OVPNFILE";
				wget "$OVPNFILEURLB" -O "/usr/src/$OVPNFILE" || wget "$OVPNFILEURLA" -O "/usr/src/$OVPNFILE"
				if [ `sha512sum /usr/src/$OVPNFILE|cut -d" " -f1` = "$SHA512SUM" ]; then
					dpkg -i /usr/src/$OVPNFILE;
					exit 0;
				fi;
			fi;
		else
			echo "Warning! Update your openVPN $OPENVPNVERSION Client manually to $REQUEST!";
		fi;
	else
		echo "openVPN-Client is up2date.";
		if [ $ODEBUG -eq "1" ]; then echo "DEBUG: LOCALVERSION=$OPENVPNVERSION REMOTEVERSION=$REQUEST"; fi
	
	fi;
	if [ "$OPENVPNVERSION" -ge "234" ]; then CVERSION="23x"; fi;
	if [ "$OPENVPNVERSION" -lt "234" ]; then CVERSION="22x"; fi;
	if [ $ODEBUG -eq "1" ]; then echo "DEBUG:requirements:CVERSION=$CVERSION"; fi
	if ! test -e $LASTUPDATEFILE ; then echo "0" > $LASTUPDATEFILE; fi;	
}
requirements $1 $2;


apirequestcerts () {
	echo -n "Requesting oVPN Certificates: ";
	DATA="uid=${USERID}&apikey=${APIKEY}&action=requestcerts";
	REQUEST=`curl -s --request POST $URL --data $DATA`;
	if [ $ODEBUG -eq "1" ]; then echo "DEBUG:apirequestcerts:REQUEST=$REQUEST"; fi
	while : 
	do	
		echo -n "$REQUEST";
		if [ "$REQUEST" = "ready" ]; then break; fi;
		if [ "$REQUEST" = "submitted" ]; then echo -n "!please wait.."; fi;
		sleep 5; echo -n "."; REQUEST=`curl -s --request POST $URL --data $DATA`;
	done;
	if [ $REQUEST = "ready" ]; then
		CERTFILE="/tmp/ovpncerts${USERID}.zip";
		DATA="uid=${USERID}&apikey=${APIKEY}&action=getcerts";
		if test -e $CERTFILE; then rm -f $CERTFILE; fi
		REQUEST=`curl -s --request POST $URL --data $DATA -o $CERTFILE`;
		if test -e $OCFGFILE && test -e $CERTFILE; then 
			echo -e "\noVPN-Configs downloaded to $OCFGFILE\nCertificates downloaded to $CERTFILE";
			LASTACTIVECONFIG=`ls /etc/openvpn/*.conf 2>/dev/null | head -1 | grep "ovpn\.to"`;
			OLDDIRS=`ls -d ${OVPNPATH}/*.ovpn.to 2>/dev/null`;
			for ODIR in $OLDDIRS; do
				if [ $ODEBUG -eq "1" ]; then rm -rvf $ODIR; else rm -rf $ODIR; fi
			done;			
			
			if [ $ODEBUG -eq "1" ]; then 
				rm -vf $OVPNPATH/*.ovpn.to.ovpn $OVPNPATH/*.ovpn.to*.conf $OVPNPATH/ovpnproxy-authfile.txt;
			else
				rm -f $OVPNPATH/*.ovpn.to.ovpn $OVPNPATH/*.ovpn.to*.conf $OVPNPATH/ovpnproxy-authfile.txt;
			fi;
			echo "Extracting...";
			if test "$UNZIP" = "unzip"; then 
				ECMD1="unzip $OCFGFILE -d ${OVPNPATH}";
				ECMD2="unzip $CERTFILE -d ${OVPNPATH}";
			fi;
			if test "$UNZIP" = "7z"; then 
				ECMD1="7z e -o${OVPNPATH} ${OCFGFILE} "; 
				ECMD2="7z x -o${OVPNPATH} ${CERTFILE} ";
			fi;
			if [ $ODEBUG -eq "1" ]; then $ECMD1; $ECMD2;
			else	$ECMD1 1>/dev/null; $ECMD2 1>/dev/null;	fi;
			echo "$REMOTELASTUPDATE" > $LASTUPDATEFILE;
			if [ ! -z $LASTACTIVECONFIG ]; then
				CHECKCONFIG=`echo $LASTACTIVECONFIG | cut -d. -f1,2,3,4`;
				if [ -e $CHECKCONFIG ]; then
					echo "Enabling last enabled Server-Configuration $LASTACTIVECONFIG";
					mv -v $CHECKCONFIG $LASTACTIVECONFIG;
				else
					echo "Error. Last enabled Server-Configuration not found.";					
				fi;
			else
				echo "Warning: No enabled Server-Configuration found. You need a .conf file in /etc/openvpn.";
			fi
			if [ -e $IPTABLESANTILEAK ]; then
				if [ ! -x $IPTABLESANTILEAK ]; then chmod +x $IPTABLESANTILEAK; fi
				echo "Found IPtables Anti-Leak Script $IPTABLESANTILEAK  and will reload rules!";
				$IPTABLESANTILEAK;				
			else
				echo -e "$IPTABLESANTILEAK IPtables Anti-Leak Script NOT FOUND!\nCheck https://raw.githubusercontent.com/ovpn-to/oVPN.to-IPtables-Anti-Leak/master/iptables.sh"; 
			fi;
			echo -e "\n####################\noVPN Update: Job done!";
		else
			echo -e "\nERROR DOWNLOADING UPDATE!";
			exit 1;
		fi;
	fi;
}


apigetconfigs () {
	OCFGFILE="/tmp/ovpncfg${USERID}${OCFGTYPE}${CVERSION}.zip";
	echo -n "Requesting oVPN ConfigUpdate: ";
	DATA="uid=${USERID}&apikey=${APIKEY}&action=getconfigs&version=${CVERSION}&type=${OCFGTYPE}";
	rm -f $OCFGFILE; 		
	REQUEST=`curl -s --request POST $URL --data $DATA -o $OCFGFILE`;
	if test -e $OCFGFILE; then echo "ready"; else echo "Error!"; exit 1; fi;
}


apicheckupdate () {
	DATA="uid=${USERID}&apikey=${APIKEY}&action=lastupdate";
	REQUEST=`curl -s --request POST $URL --data $DATA`;
	if [ $ODEBUG -eq "1" ]; then echo -e "DEBUG:apicheckupdate:REQUEST=$REQUEST"; fi
	REMOTELASTUPDATE=`echo $REQUEST|cut -d":" -f2`;
	if [ $REMOTELASTUPDATE -gt "0" ]; then
		LUPDATE=`cat $LASTUPDATEFILE`;
		if [ $REMOTELASTUPDATE -gt $LUPDATE ]; then
			echo -n "Update available! ";
			if [ "$FORCE" -eq "0" ]; then echo -n "Update oVPN-Configs now? (Y)es / (N)o : "; read READINPUT; else READINPUT="yes"; echo "FORCED"; fi;
			INPUT=`echo $READINPUT | tr '[:upper:]' '[:lower:]'`;
			if [ ! -z $INPUT ]&&([ "$INPUT" = "yes" ]||[ "$INPUT" = "y" ]); then
					apigetconfigs;
					apirequestcerts;
			else
				echo "Aborted. Enter 'Y' to run update!";
				exit 1;
			fi;
		else
			echo "No Update available. Force update with: [sudo] rm $LASTUPDATEFILE; [sudo] $0 update";
			exit 0;
		fi;
	fi;
}


if [ $# -lt 1 ]; then echo "Usage : [sudo] $0 update [debug|force]"; exit 1; fi;

case "$1" in
'update')  echo  -n "Checking for oVPN Certs/Config-Update: "
	apicheckupdate
    ;;
*) echo "Usage : $0 update [debug|force]"
   ;;
esac
