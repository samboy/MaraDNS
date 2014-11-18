#!/bin/bash -e

#################################################################
# MaraConf - The MaraDNS Configurator          			#
# Written by: Daniel Zilli (zilli.daniel@gmail.com) with help   # 
# from Sam Trenholme.						#	
# License: BSD - http://www.maradns.org/license.html		#	
#								#
# v1.2.12.08 - 14/09/2007		  			#
###								#
# ChangeLog							#
# v1.2.12.08							#
# - Tiny bug fixes						#
#								#
# v1.2.12.03							#
# - I cleaned up andimproved all the code. Especially           #
#   all the questions. 						#		
# - First public stable release.				#
#								#
# v1.2.00 -beta05						#
# - All questions are treated now.				#
# - Fixed some loops.						#
# - Made the trapping function. 				# 
# - I think that "finished" the script. Now I will do some	# 
#   final tests and waiting the community feedback. 		#
# - Made the confirm's functions better.			#
# - Added a function to configure your resolv.conf file in 	#
#   recursive mode...if you want, of course.			#
# - Maraconf now has a man-page. :-)				#
# - This is my last beta, so I will be careful.			#
#								#
# v1.2.00 -beta04						#	
# - Explained what happens when you cancel the program.		#
# - Authoritative mode is working. Is test time!		#
#								#
# v1.2.00 -beta03						#	
# - Made the maraconf arguments Gnu/Linux "standart".		#
# - Started the work in the authoritative mode. Here I won't 	#
#   have the easy or hard way to configure. This is because, an #
#   authoritative server require more responsability. There is 	#
#   not default values too. I will use a wizard to guide the 	#
#   user in the task of configure an authoritative server.	# 
#								#
# v1.2.00 -beta02						#	
# - Changed the confirm function into two new. One to handle the#
#   mararc file and other to works with the zone files.		# 
# - The recursive functions are done!				#
# - Added one more note in the help explanation.		#
# - Now we have reasonable default values for the wizard.	#		
# - Only verbose interesting msg for the user.			#
# - Rewrittem some functions.					#	
# - Cleanup the code.						#	
# - Made this a beta release.				        #
# - Changed the number version. Till the stable release, I will #
#   use the v1.2.00 to identify that this is only for MaraDNS   #
#   1.2.x tree. After the stable release, I will try use the 	#
#   same number version of the stable MaraDNS package.		#
#								#		
# v1.2.00 -beta01                                               #
# - Some minor updates to the wording of the program            #
# - undocumented -e switch added to the program so it'll        #
#   safely fail if something goes amiss                         #
# - Some bugs in the program fixed                              #
# - Security audit done on the program                          #
# - Disclaimer still shown; I haven't renounced my USA          #
#   citizenship yet, so I still may have to deal with US        #
#   lawyers.                                                    #
#								#
# v1.2.00 -beta							#
# - You can now choose to copy the mararc to /etc.		#
# - Now the variables are treat, no more blank space into.	#
# - The recursive mode is working.				#	
# - Made better questions.					#
# - Cleanup done to the code					#
# - First beta release.						#
#################################################################

trap trapping 1 2 3 6

trapping() {
  echo 
  echo "For some reason, you canceled the program.  You have lost your changes"
  echo	
  exit 1
}

confirm_resolv() {
echo
read -p "Would you like to configure your /etc/resolv.conf ? (y/n) " YN
case "$YN" in 
	y|Y)
		if [ -e /etc/resolv.conf ] ; then
			BACKUP=resolv.conf.backup
			cp /etc/resolv.conf /etc/$BACKUP
			echo Current /etc/resolv.conf copied to /etc/$BACKUP
		fi
		echo "nameserver $IPADD" > /etc/resolv.conf
	;; 
	n|N)
		echo	
		echo "Don't forget to put the IP $IPADD in your /etc/resolv.conf file"
		echo
	;;
	*) 
		confirm_resolv	
	;; 
esac
}

confirm_mararc() {
echo
if [ -e /etc/$MARARC ] ; then
	echo -e "WARNING: /etc/$MARARC already exists; while this script"
	echo -e "will backup /etc/$MARARC, the contents of this file "
	echo -e "will change if you select 'y'."
fi
echo
read -p "Would like to copy the created mararc file to /etc? (y/n) " YN
case "$YN" in 
	y|Y)
		if [ -e /etc/$MARARC ] ; then
			BACKUP=$MARARC.$( date +%s )
			cp /etc/$MARARC /etc/$BACKUP
			echo Current /etc/$MARARC copied to /etc/$BACKUP
		fi
		cp -a $TMP/$MARARC /etc/
		confirm_resolv
	;; 
	n|N)
		echo	
		echo "Your mararc file is in $TMP"
		echo
	;;
	*) 
		confirm_mararc	
	;; 
esac
}

confirm_db() {
if [ -e /etc/maradns/db.$DOMAIN ] ; then
	echo
	echo -e "WARNING: /etc/maradns/db.$DOMAIN already exists;"
	echo -e "while this script will back it up, the contents"
	echo -e "of this file will change if you select 'y'."
fi
echo
read -p "Would like to copy the db.$DOMAIN file to /etc/maradns? (y/n) " YN
case "$YN" in 
	y|Y)
		if [ -e /etc/maradns/db.$DOMAIN ] ; then
			BACKUP=db.$DOMAIN.$( date +%s )
			cp /etc/maradns/db.$DOMAIN /etc/maradns/$BACKUP
			echo Current /etc/maradns/db.$DOMAIN copied to /etc/maradns/$BACKUP
		fi
		cp -a $TMP/tmp_zone /etc/maradns/db.$DOMAIN
	;; 
	n|N)
		cd $TMP
		mv tmp_zone db.$DOMAIN
		echo
		echo "Your db.$DOMAIN file is in $TMP"
		echo
	;;
	*) 
		confirm_db
	;; 
esac
}

#### RECURSIVE QUESTIONS #################
####
####
###
##
#
rec_easy() {
setterm -clear
echo -e "${DECOLINE}"
echo -e "| MaraConf ${VERSION} |"
echo -e "${DECOLINE}"
echo -e "|-> RECURSIVE DNS -> Easy way"
echo -e "|"
echo -e "| Enter the address that this DNS server runs on:"
echo -e "|--type your value or press ENTER to use default (127.0.0.1):"
echo -n -e "=> "
read IPADD	
echo -e "| Enter the ip allowed to perform recursive queries:"
echo -e "|--type your value or press ENTER to use default (127.0.0.1):"
echo -n -e "=> "
read IPREC	

# Treating the variables.
# Here I delete any blank space that the user typed. 
# If needed, default value are filled it. 
if [ "$IPADD" != "" ]; then
	IPADD=$( echo ${IPADD// } )
else
	IPADD="127.0.0.1"
fi	

if [ "$IPREC" != "" ]; then
	IPREC=$( echo ${IPREC// } )
else
	IPREC="127.0.0.1"
fi	

# Confirm the values entered.
# The loop is to ensure that the user will only choose y or n.
while [ -z "$opt" ]; do
echo
echo -e "Please confirm the values entered:"
echo -e "Q: Enter the address that this DNS server runs on:"
echo -e "A: $IPADD"
echo
echo -e "Q: Enter the ip allowed to perform recursive queries:"
echo -e "A: $IPREC"
echo
read -p "Is this the information that you entered correct? (y/n) " YN
# we must type something useful.
  case "$YN" in 
	y|Y) 	
		opt=ok
	;; 
	n|N) 	
		rec_easy
	;; 
	*) echo "--> Please type y or n to answer." 
	;; 
  esac
done
unset opt

# Create the mararc file.
cat << EOF > $TMP/$MARARC
# Base settings.
chroot_dir = "/etc/maradns"

# The addresses MaraDSN bind to.
ipv4_bind_addresses = "$IPADD"

# Addresses allowed to perform recursive queries.
recursive_acl = "$IPREC"

EOF

# Calling a function.
confirm_mararc
}

rec_hard() {
setterm -clear
echo -e "${DECOLINE}"
echo -e "| MaraConf ${VERSION} |"
echo -e "${DECOLINE}"
echo -e "|-> RECURSIVE DNS -> Hard way"
echo -e "|"
echo -e "| Enter with the address that this DNS server runs on:"
echo -e "|--type your value or press ENTER to use default (127.0.0.1):"
echo -n -e "=> "
read IPADD	
echo -e "| Enter with the ip allowed to perform recursive queries:"
echo -e "|--type your value or press ENTER to use default (127.0.0.1):"
echo -n -e "=> "
read IPREC	
echo -e "| What is the directory with all of the zone files?"
echo -e "|--type your value or press ENTER to use default (/etc/maradns):"
echo -n -e "=> "
read CHROOT	
echo -e "| What is the numeric UID MaraDNS will run as?"
echo -e "|--type your value or press ENTER to use default (99):"
echo -n -e "=> "
read NUID	
echo -e "| What is the numeric GID MaraDNS will run as?"
echo -e "|--type your value or press ENTER to use default (99):"
echo -n -e "=> "
read NGID	
echo -e "| Which is the maximum number of threads that MaraDNS is allowed to run?"
echo -e "|--type your value or press ENTER to use default (64):"
echo -n -e "=> "
read MNT	
echo -e "| Do you want make MaraDNS obscure (for security reason)?"
echo -e " 0) no (default)"
echo -e " 1) yes"
echo -n -e "=> "
read NOFING	
echo -e "| Choose the level of the messages we log to stdout (0,1,2,3)?"
echo -e " 0) No messages except for fatal parsing errors and the legal disclaimer"
echo -e " 1) Only start-up messages logged (default)"
echo -e " 2) Error queries logged"
echo -e " 3) All queries logged (but not very verbosely right now)"
echo -n -e "=> "
read NLOG	
echo -e "| Do you want to increase the time to process queries on some slow networks?"
echo -e "|--type your value or press ENTER to use default (2):"
echo -n -e "=> "
read TIMES
echo -e "| Do you want use other recursive DNS servers?"
echo -e " 0) no (default)"
echo -e " 1) yes"
echo -n -e "=> "  
read OTREC
if [ "$OTREC" == "1" ]; then
 echo -e "| Enter the IP address for the other recursive DNS server:"
 echo -n -e "=> "
 read OTRECIP
fi
    
# Treating the variables.
if [ "$IPADD" != "" ]; then
	IPADD=`echo ${IPADD// }`
else
	IPADD="127.0.0.1"
fi	

if [ "$IPREC" != "" ]; then
	IPREC=`echo ${IPREC// }`
else
	IPREC="127.0.0.1"
fi	

if [ "$CHROOT" != "" ]; then
	CHROOT=`echo ${CHROOT// }`
else
	CHROOT="/etc/maradns"
fi	

if [ "$NUID" != "" ]; then
	NUID=`echo ${NUID// }` 
else
	NUID="99"
fi

if [ "$NGID" != "" ]; then
	NGID=`echo ${NGID// }` 
else
	NGID="99"
fi

if [ "$MNT" != "" ]; then
	MNT=`echo ${MNT// }` 
else
	MNT="64"
fi

if [ "$NOFING" != "" ]; then
	NOFING=`echo ${NOFING// }` 
else
	NOFING="0"
fi

if [ "$NLOG" != "" ]; then
	NLOG=`echo ${NLOG// }` 
else
	NLOG="1"
fi

if [ "$TIMES" != "" ]; then
	TIMES=`echo ${TIMES// }` 
else
	TIMES="2"
fi

OTRECIP=`echo ${OTRECIP// }` 

# Confirm the values entered
while [ -z "$opt" ]; do
 echo
 echo -e "Please confirm the values entered:"
 echo -e "Q: Enter the address that this DNS server runs on:"
 echo -e "A: $IPADD"
 echo
 echo -e "Q: Enter the ip allowed to perform recursive queries:"
 echo -e "A: $IPREC"
 echo
 echo -e "Q: What is the directory with all of the zone files?"
 echo -e "A: $CHROOT"
 echo
 echo -e "Q: What is the numeric UID MaraDNS will run as?"
 echo -e "A: $NUID"
 echo
 echo -e "Q: What is the numeric GID MaraDNS will run as?:"
 echo -e "A: $NGID"
 echo
 echo -e "Q: Which is the maximum number of threads that MaraDNS is allowed to run?"
 echo -e "A: $MNT"
 echo
 echo -e "Q: Do you want make MaraDNS harder to detect (for security reason)?"
 echo -e "A: $NOFING"
 echo
 echo -e "Q: Choose the level of the messages we log to stdout (0,1,2,3)?"
 echo -e "A: $NLOG"
 echo
 echo -e "Q: Do you want to increase the time to process queries on some slow networks?"
 echo -e "A: $TIMES"
 echo
 echo -e "Q: Do you want to use other recursive DNS servers?"
 if [ "$OTRECIP" != "" ]; then
	echo -e "A: $OTRECIP"
 else
	echo -e "A: no"
 fi
 echo
 read -p "Is this the information that you entered correct? (y/n) " YN
 case "$YN" in 
	y|Y) 	
		opt=ok
	;; 
	n|N) 	 
		rec_hard		
	;; 
	*) echo "--> Please type y or n to answer." 
	;; 
 esac

done
unset opt

# create the mararc
cat << EOF > $TMP/$MARARC
# The addresses MaraDNS bind to.
ipv4_bind_addresses = "$IPADD"

# Addresses allowed to perform recursive queries.
recursive_acl = "$IPREC"

# The directory MaraDNS chroots to.
chroot_dir = "$CHROOT"

# The numeric UID that MaraDNS will run as.
maradns_uid = $NUID

# The numeric GID that MaraDNS will run as.
maradns_gid = $NGID

# The maximum number of threads or processes that MaraDNS is allowed to run at the same time.
maxprocs = $MNT

# Flag that allows MaraDNS to be harder to detect.
no_fingerprint = $NOFING

# The number of messages we log to stdout.
verbose_level = $NLOG

# Increasing the time to process queries on some slow networks.
timeout_seconds = $TIMES

EOF

if [ "$OTRECIP" != "" ]; then
cat << EOF >> $TMP/$MARARC
# Using others recursive servers.
upstream_servers = {}
upstream_servers["."] = "$OTRECIP"

EOF
fi

# Calling a function.
confirm_mararc
}

rec_screen() {
setterm -clear
    echo -e "${DECOLINE}"
    echo -e "| MaraConf ${VERSION} |"
    echo -e "${DECOLINE}"
    echo -e "|-> RECURSIVE DNS"
    echo -e "|"
    echo -e "|- How do you want to setup recursive dns?"
    echo -e "|"
    echo -e "| 1) The easy way (using a wizard)"
    echo -e "| 2) The hard way (for experienced users)"
    echo -e "| 0) Back"
    echo -e "|"
    echo -n -e "Choose a option [0-2] => "
    read ACTION
    echo -e ""
case $ACTION in
    	1)	rec_easy
	;;
	
	2) 	rec_hard
  	;;
	
	0)
		start
  	;;
  	*)	echo "Please type in a number between 0 - 2." 1>&2
		sleep 2s
		rec_screen
  	;;
esac	
}

#### AUTHORITATIVE QUESTIONS #################
####
####
###
##
#

autho_a() {
#
# A record.
read -p "| Do you want to setup an A record? (y/n) " YN
case "$YN" in 
	y|Y)	
		echo 
		echo -e "| Enter the IP address for the A record"
    		echo -n -e "=> "
    		read IPA
    		IPA=`echo ${IPA// }`
		
		# Save all the records here.
    		echo "$DOMAIN. $IPA" >> $TMP/tmp_zone
		
		# Ask again.
		while [ -z "$opt" ] ; do
		read -p "Do you want to setup an other A record? (y/n) " YN
			case "$YN" in
				y|Y) 
				# Here we go again.
				echo 
				echo -e "| Enter the IP address for the A record"
   				echo -n -e "=> "
  				read IPA	
 				IPA=`echo ${IPA// }`
		
				# Save all the records here.
    				echo "$DOMAIN. $IPA" >> $TMP/tmp_zone
				;;	
				n|N) break ; opt=ok ;;
				*) echo "--> Please type y or n to answer." ;;
			esac
		done
		unset opt 
	;; 
	n|N)
	return
	# Nothing happens here.
	;;
	*) 	
		echo "--> Please type y or n to answer."
		autho_a
	;; 
esac
}

autho_ns() {
#
# NS record.
read -p "| Do you want to setup a NS record? (y/n) " YN
case "$YN" in 
	y|Y)	
		echo 
		echo -e "| Enter the IP address for the NS record"
    		read IPNS
		IPNS=`echo ${IPNS// }`
		
		echo -e "| Enter with the hostname used with the NS record."
		echo -n -e "=> "
		read NS_HOST	
     		NS_HOST=`echo ${NS_HOST// }`
		
		# Save all the records here.
		echo "$DOMAIN. NS $NS_HOST.$DOMAIN." >> $TMP/tmp_zone
		echo "$NS_HOST.$DOMAIN.	$IPNS" >> $TMP/tmp_zone
		
		# Ask again.
		while [ -z "$opt" ] ; do
		read -p "Do you want to setup an other NS record? (y/n) " YN
			case "$YN" in
				y|Y) 
				# Here we go again.
				echo -e "| Enter the IP address for the NS record"
    				read IPNS
				IPNS=`echo ${IPNS// }`
		
				echo -e "| Enter with the hostname used with the NS record."
				echo -n -e "=> "
				read NS_HOST	
     				NS_HOST=`echo ${NS_HOST// }`
		
				# Save all the records here.
				echo "$DOMAIN. NS $NS_HOST.$DOMAIN." >> $TMP/tmp_zone
				echo "$NS_HOST.$DOMAIN.	$IPNS" >> $TMP/tmp_zone
				;;	
				n|N) break ; opt=ok ;;
				*) echo "--> Please type y or n to answer." ;;
			esac
		done
		unset opt 
	;; 
	n|N)
	return
	# Nothing happens here.
	;;
	*) 	
		echo "--> Please type y or n to answer."
		autho_ns
	;; 
esac
}

autho_mx() {
#
# MX record.
read -p "| Do you want to setup a MX record? (y/n) " YN
case "$YN" in 
	y|Y)	
		echo 
		echo -e "| Enter the IP address for the MX record"
		echo -n -e "=> "
		read IPMX
		IPMX=`echo ${IPMX// }`	
		echo -e "| Enter with the hostname used with the MX record."
		echo -n -e "=> "
		read MX_HOST	
     		MX_HOST=`echo ${MX_HOST// }`
	
		# Save all the records here.
		echo "$DOMAIN.	MX  10	$MX_HOST.$DOMAIN." >> $TMP/tmp_zone
		echo "$MX_HOST.$DOMAIN.	$IPNS" >> $TMP/tmp_zone
		
		# Ask again.
		while [ -z "$opt" ] ; do
		read -p "Do you want to setup an other MX record? (y/n) " YN
			case "$YN" in
				y|Y) 
				# Here we go again.
				echo -e "| Enter the IP address for the MX record"
				echo -n -e "=> "
				read IPMX
				IPMX=`echo ${IPMX// }`	
				echo -e "| Enter with the hostname used with the MX record."
				echo -n -e "=> "
				read MX_HOST	
     				MX_HOST=`echo ${MX_HOST// }`
	
				# Save all the records here.
				echo "$DOMAIN.	MX  10	$MX_HOST.$DOMAIN." >> $TMP/tmp_zone
				echo "$MX_HOST.$DOMAIN.	$IPNS" >> $TMP/tmp_zone
				;;	
				n|N) break ; opt=ok ;;
				*) echo "--> Please type y or n to answer." ;;
			esac
		done
		unset opt 
	;; 
	n|N)
	return
	# Nothing happens here.
	;;
	*) 	
		echo "--> Please type y or n to answer."
		autho_mx
	;; 
esac
}

autho_sn() {
#
# Single Names record.
read -p "| Do you want to setup a single name to ip? (y/n) " YN
case "$YN" in 
	y|Y)	
		echo 
		echo -e "| Enter with the hostname for the single name."
		echo -n -e "=> "
		read SN_HOST	
		SN_HOST=`echo ${SN_HOST// }`
		echo -e "| Enter the IP address for the single name."
		echo -n -e "=> "
		read IPSN     		
		IPSN=`echo ${IPSN// }`

		# Save all the records here.
		echo "$SN_HOST.$DOMAIN.	$IPSN" >> $TMP/tmp_zone
		
		# Ask again.
		while [ -z "$opt" ] ; do
		read -p "Do you want to setup an other single name? (y/n) " YN
			case "$YN" in
				y|Y) 
				# Here we go again.
				echo -e "| Enter with the hostname for the single name."
				echo -n -e "=> "
				read SN_HOST	
				SN_HOST=`echo ${SN_HOST// }`
				echo -e "| Enter the IP address for the single name."
				echo -n -e "=> "
				read IPSN     		
				IPSN=`echo ${IPSN// }`

				# Save all the records here.
				echo "$SN_HOST.$DOMAIN.	$IPSN" >> $TMP/tmp_zone
				;;	
				n|N) break ; opt=ok ;;
				*) echo "--> Please type y or n to answer." ;;
			esac
		done
		unset opt 
	;; 
	n|N)
	return
	# Nothing happens here.
	;;
	*) 	
		echo "--> Please type y or n to answer."
		autho_sn
	;; 
esac
}

# Configuring mararc file.
#
aut_mode() {
    setterm -clear
    echo -e "${DECOLINE}"
    echo -e "| MaraConf ${VERSION} |"
    echo -e "${DECOLINE}"
    echo -e "|-> AUTHORITATIVE DNS -> Configuring mararc:"
    echo -e "|"
    echo -e "| Enter the IP(s) address(es) that this DNS server runs on."
    echo -e "|--you must type the values separate by comma."
    echo -n -e "=> "
    read IPADD	
    echo -e "| Enter the domain."
    echo -e "|--you must type a value, there is no default here:"  	
    echo -n -e "=> "
    read DOMAIN	
   
    # Treating the variables.
    # Here I delete any blank space that the user typed and fill it with.
    # default value when needed. 
    IPADD=`echo ${IPADD// }`
    DOMAIN=`echo ${DOMAIN// }`

    # Confirm the values entered.
while [ -z "$opt" ] ; do
    echo
    echo -e "Please confirm the values entered:"
    echo -e "Q: Enter the address that this DNS server runs on:"
    echo -e "A: $IPADD"
    echo
    echo -e "Q: Enter the domain:"
    echo -e "A: $DOMAIN"
    echo
    read -p "Is this the information that you entered correct? (y/n) " YN
    case "$YN" in 
	y|Y) opt=ok
	;; 
	n|N) aut_mode
	;; 
	*) echo "--> Please type y or n to answer." 
	;; 
    esac
done
unset opt

# create the mararc
cat << EOF > $TMP/$MARARC
# Base settings.
hide_disclaimer = "YES"
chroot_dir = "/etc/maradns"

# The addresses MaraDSN bind to.
ipv4_bind_addresses = "$IPADD"

# Start the authoritative mode.
csv2 = {}

# Domain and file zone.
csv2["$DOMAIN."] = "db.$DOMAIN.com"

EOF

#
# Configuring  zone file.
#
INLOOP=1
while [ "$INLOOP" == "1" ] ; do
 setterm -clear
    echo -e "${DECOLINE}"
    echo -e "| MaraConf ${VERSION} |"
    echo -e "${DECOLINE}"
    echo -e "|-> AUTHORITATIVE DNS -> Configuring the zone file:"
    echo -e "|"

# A record.
autho_a

# NS record.
autho_ns

# MX record.
autho_mx

# Single names.
autho_sn

while [ -z "$opt" ]; do
    	echo
	echo -e "Please confirm the values entered:"
	if [ -f $TMP/tmp_zone ]; then
		cat $TMP/tmp_zone
	else
		echo "No zone file created, so we exit now."
		exit 0
	fi
	echo
	read -p "Is this the information that you entered correct? (y/n) " YN
	case "$YN" in 
		y|Y)	
			opt=ok 
			INLOOP=0
		;;
		n|N)
			opt=ok
		;;
		*)
			echo 
			echo "--> Please type y or n to answer."
		;;
	esac
done
done

confirm_db
}

start() {
    setterm -clear
    echo -e "${DECOLINE}"
    echo -e "| MaraConf ${VERSION} |"
    echo -e "${DECOLINE}"
    echo -e "|"
    echo -e "|- What would you like to setup?"
    echo -e "|"
    echo -e "| 1) Recursive DNS sever"
    echo -e "| 2) Authoritative DNS server"
    echo -e "| 0) Exit"
    echo -e "|"
    echo -n -e "Choose a option [0-2] => "
    read ACTION
    echo -e ""

   case $ACTION in
    	1)	rec_screen
	;;
	
	2) 	aut_mode
  	;;
	0)
		exit
  	;;
  	*)	echo "Please type in a number between 0-2." 1>&2
		sleep 2s
		start
  	;;
    esac	
}

##################
#### Start here ##
###
##

if [ `id -un` != root ]; then
    echo
    echo "You must be root to use maraconf !"
    echo
    exit
fi
    
# Variables. 
MARARC=mararc
TMP=~/tmp/maraconf

# Checking directories.
if [ ! -d ~/tmp ] ; then
	mkdir ~/tmp	
fi

rm -f $TMP/*
if [ ! -d $TMP ]; then
	mkdir $TMP
fi

# Menu.
DECOLINE="+--------------------------------+"
VERSION="v1.2.12.08           "

case "$1" in
	-s|--start)
		# Calling the function.
		clear
		start
	;;	
	-h|--help)
		# Msg screen.
		clear
		echo "####################################" 
		echo "# MaraDNS configurator 		   #"
		echo "####################################" 
		echo
		echo "This program is designed to help you setup a recursive and authoritative" 
		echo "DNS servers using MaraDNS.  What this script will do is create a mararc" 
		echo "file and the respective zone files for a domain, to be used for the"
		echo "authoritative server.  It should work on any Unix-like system that has" 
		echo "bash in /bin."
		echo 
		echo "Note1: this program will is not a substitute for DNS knowledge, but will"
		echo "help with some repetitive tasks.  If you wish further help with DNS, the"
		echo "MaraDNS tutorial included with MaraDNS is a good place to start."
		echo 
		echo "Note2: In the recursive mode, if you don't want to answer the questions,"
		echo "just press ENTER (return) to leave the program use some default values."
		echo "If you have any doubt or want to know how this program works, please use"
		echo "the maraconf' man-page."
		echo 
	;;
	*)
		echo 
		echo -e "Usage: maraconf OPTIONS"
		echo
		echo -e "OPTIONS:"
		echo -e "-s, --start  	initialize the configurator."
		echo -e "-h, --help	show a brief explanation."
		echo
		echo "MaraConf $VERSION"
		echo
	;;
esac
