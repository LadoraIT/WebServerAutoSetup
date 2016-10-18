#!/bin/bash

#########################################################################################
#											#
#  Script Name 	     : Ubuntu Server Configurator Installer				#
#  Supported Version : Ubuntu Server 9.04 ~ 15.04					#
#  Developer   	     : Ian Hersanto							#
#  Email       	     : ardie_b@yahoo.com					        #
#											#
#########################################################################################

UROOT=0
APACHE_DIR=/etc/apache2
NGINX_DIR=/etc/nginx
LIGHTTP_DIR=/etc/lighttpd
PROFTP_DIR=/etc/proftpd
DEFAULT_SHELL=`which nologin`
SSL_DIR=/etc/ssl/host
CONF_DIR=/etc/servconf
TEMP_DIR=/tmp
DEPRECATED=`apt-cache search php5-suhosin`
YLW=$(tput setaf 3)
NML=$(tput sgr0)
GRN=$(tput setaf 2)
MGT=$(tput setaf 5)
CYN=$(tput setaf 6)
RED=$(tput setaf 1)
BLU=$(tput setaf 153)
BLD=$(tput bold)
APACHE_SECURITY=2

# variables
PRIMARYNS=""
SECONDNS=""
VHOST="N"
DOMAIN=""
UUID=0
useMySQL=""
usePgSQL=""

useSSL=""
C=""
ST=""
L=""
O=""
OU=""
CN=""
ADDRESS=""

MEMSIZE=`grep MemTotal /proc/meminfo | awk '{print $2}'`
OSNAME=""
DISTRO=""
REPO=""

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
    printf "\n${NML}"
    exit 0;
}

function usage {
    printf "\n"
    printf "Options :\n"
    printf "\n"
    printf "  -u|--uninstall     	Uninstall package\n"
	printf "  -v|--verbose    	Show progress\n"
	printf "  -s|--apache-security 	Security Level { 1,2,3,4 }"
    printf "\n"
}

function info {
	printf "\n"
	echo
	printf "    Congratulations, you have successfully install your web server\n"
	printf "    Please note these settings for access information.\n"
	echo
	printf "    URL : http://$1\n"
	if [ ! -z "$4" ]; then
		printf "    HTTPS : https://$1\n"
	fi
	printf "    ----------------------------------------------\n"
	printf "    FTP HOST : $1\n"
	printf "    FTP USER : $2\n"
	printf "    FTP PASSWORD : $3\n"
	if [ ! -z "$5" ]; then
		printf "    ----------------------------------------------\n"
		printf "    MySQL Root Password : $3\n"
	fi
	if [ ! -z "$6" ]; then
		printf "    ----------------------------------------------\n"
		printf "    PostgreSQL postgres Password : $3\n"
	fi
	echo
}

# Check to see if this run by root
if [ "$UID" -ne "$UROOT" ]; then
   printf "${YLW}Warning : ${NML}Installer must be run by root or sudoers.\n"
   exit $?
fi

if [ ! -z "$1" ]; then
   if [ "$1" == "--uninstall" ] || [ "$1" == "-u" ]; then
	if [ -f /etc/servconf/servconf.ini ]; then
		source /etc/servconf/servconf.ini
		if [ "$OS" == "apache" ]; then
			if [ -f "/etc/init.d/apache2" ]; then /etc/init.d/apache2 stop; fi
			if [ "$(ls -A $APACHE_DIR)" ]; then
				arr=$(echo $(ls -A $APACHE_DIR/sites-available) | tr "\n" "\n")
				for x in $arr
				do
					if [ -f "$APACHE_DIR/sites-available/$x" ]; then rm -Rf $APACHE_DIR/sites-available/$x; fi
				done
			fi
			if [ -d $FCGI ]; then rm -Rf $FCGI; fi
		elif [ "$OS" == "nginx" ]; then
			# process nginx uninstallation here
			if [ -f "/etc/init.d/nginx" ]; then /etc/init.d/nginx stop; fi
			if [ "$(ls -A $NGINX_DIR)" ]; then
				arr=$(echo $(ls -A $NGINX_DIR/sites-available) | tr "\n" "\n")
				for x in $arr
				do
					if [ -f "$NGINX_DIR/sites-available/$x" ]; then rm -Rf $NGINX_DIR/sites-available/$x; fi
				done
			fi
			pkill php5-cgi
			if [ -f $TEMP_DIR/socket.pid ]; then rm -f $TEMP_DIR/socket.pid; fi
		elif [ "$OS" == "lighttpd" ]; then
			if [ -f /etc/init.d/lighttpd ]; then /etc/init.d/lighttpd stop; fi
			rm -f $LIGHTTP_DIR/sites-enabled/*
			if [ -d $LIGHTTP_DIR/vhost.d ]; then
				rm -Rf $LIGHTTP_DIR/vhost.d
			fi
			#pids=`pgrep php5-cgi`
			pkill php5-cgi
			if [ -f $TEMP_DIR/php.socket ]; then rm -f $TEMP_DIR/php.socket; fi
		fi
		if [ -d $HOMEDIR ] && [ "$HOMEDIR" != "/var/www" ]; then rm -Rf $HOMEDIR; fi
		# if [ ! -z "`cat /etc/passwd | grep $USER`" ]; then deluser $USER; fi
		if [ ! -z "`cat /etc/group | grep $GROUP`" ] && [ "$GROUP" != "www-data" ]; then 
			GID="`cat /etc/group | grep $GROUP | cut -d: -f3 | tail -1`";
			AD="`cat /etc/passwd | grep $GID | tr "\n" "\n"`";
			for x in $AD
			do
				USER="`cat /etc/passwd | grep $x | cut -d: -f1`";
				deluser $USER;
			done

			if [ "$GROUP" != "www-data" ]; then delgroup $GROUP; fi
			ufw delete allow proto tcp to any port $FW
		fi
		# Clean up /etc/rc.local
		LN=`awk '/^\ /{print NR}' /etc/rc.local`
		EOF=`wc -l /etc/rc.local | awk '{print($1)}'`
		if [ ! -z "$LN" ]; then
			echo "Clean up rc.local..."
			sed -i'.bak' '${LN},${EOF}d' /etc/rc.local
			echo " " >> /etc/rc.local
			echo "exit 0" >> /etc/rc.local
			if [ -f /etc/rc.local.bak ]; then rm -f /etc/rc.local.bak; fi
		fi
		ufw delete allow 21
		ufw delete limit 22
		ufw delete allow 22
		ufw delete allow 80
		ufw delete allow 443

		if [ -f "/etc/init.d/proftpd" ]; then /etc/init.d/proftpd stop; fi
		if [ -f "/etc/init.d/nginx" ]; then
			apt-get -y --purge remove lighttpd nginx
			PERL=`netstat -ap | grep :8999 | sed "s/[a-zA-Z*/_ ]//g" | cut -d: -f3`
			PHP=`netstat -ap | grep :9000 | sed "s/[-a-zA-Z*_ ]//g" | cut -d: -f3 | cut -d/ -f1`
			if [ ! -z "$PHP" ]; then kill $PHP; fi
			if [ ! -z "$PERL" ]; then kill $PERL; fi
			sed -i '/spawn-fcgi/c\' /etc/rc.local
		fi
		if [ -f "/etc/init.d/fastcgi" ]; then
			update-rc.d -f fastcgi remove
			rm -f /etc/init.d/fastcgi
		fi
		apt-get -y --purge remove $UNINSTALL
		if [ "$OS" == "lighttpd" ]; then
			rm -Rf $LIGHTTP_DIR
		fi
		rm -Rf /etc/servconf
	fi

	if [ ! -z "`ls /etc/init.d | grep mysql`" ]; then
		ufw delete allow 3306
		CMD=`ls /etc/init.d | grep mysql$`
		/etc/init.d/$CMD stop
		apt-get -y --purge remove mysql-server;
	fi
	if [ ! -z "`ls /etc/init.d | grep postgresql`" ]; then
		ufw delete allow 5432
		CMD=`ls /etc/init.d | grep postgresql`
		/etc/init.d/$CMD stop
		apt-get -y --purge remove $CMD
	fi
	ufw disable
	if [ -f "/etc/servconf/ftpd.passwd" ]; then rm /etc/servconf/ftpd.passwd; fi
	if [ -f "/etc/servconf/ftpd.group" ]; then rm /etc/servconf/ftpd.group; fi
	apt-get -y autoremove
	exit 0;
   else
   	echo "Error : Unknown parameter $1"
   	usage;
   fi
fi

if [ -d "$CONF_DIR" ]; then
	printf "\n${YLW}Warning : ${NML}Cannot start installer because web server already exist.\n\n"
    exit 0;
fi

# Check to see if computer connected to internet
clear;
printf "${YLW}Testing internet connection${NML}\nPlease wait"
while true; do echo -n .; sleep 1; done &
VERSION=`cat /etc/issue.net | cut -d ' ' -f2`
OSNAME=`wget -qO-  "http://old-releases.ubuntu.com/releases/$VERSION/" |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)(?:Ubuntu)?\s*<\/title/si'`;
REPO="http://old-releases.ubuntu.com/ubuntu/"
isNEW=0
if [ -z "$OSNAME" ]; then
	OSNAME=`wget -qO-  "http://releases.ubuntu.com/releases/$VERSION/" |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)(?:Ubuntu)?\s*<\/title/si'`
	if [ ! -z "$OSNAME" ]; then 
		REPO="http://releases.ubuntu.com/ubuntu/";
		isNEW=1
	else
		printf "\n${YLW}Warning : ${NML}To run this installer your network must be connected to internet.\n\n"
		kill $!; trap 'kill $!' SIGTERM
		echo done
		exit 0;
	fi
fi

DISTRO=$(echo $OSNAME | awk -F '(' '{print $2}' | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]')

kill $!; trap 'kill $!' SIGTERM
echo done

function log {
	echo $1 >> install.log
}

function writecnf {
	if [ ! -d "/etc/servconf" ]; then mkdir /etc/servconf; fi
	echo "$1" >> /etc/servconf/servconf.ini
}

function setup_thread_mode {
	# setup_thread_mode N admin adm1ns /home/wwwroot 192.168.75.133 Y
	# $1 = DNS, $2 = $user, $3 = $passwd, $4 = $homedir, $5 = domain, $6 = $vhost

	#if [ "$1" == "Y" ]; then echo "Configuring BIND..."; fi
	writecnf "OS=apache"
	writecnf "mod=mpm_prefork"

	echo "Configuring Apache..."
	# Setting Up Security
	if [ -d "$APACHE_DIR/conf.d" ] && [ -f "$APACHE_DIR/conf.d/security" ]; then
		echo "Setting up apache security..."
		if [ $APACHE_SECURITY == 3 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Prod/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 2 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Prod/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 1 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Minimal/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 0 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Full/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		fi
	fi

	# Creating home dir
	# if vhost use $4/sites/$5
	# if standard use only $4
	if [ "$5" != "N" ]; then homedir=$4/sites/$5; else homedir=$4; fi
	writecnf "HOMEDIR=$4"
	arr=$(echo $homedir | tr "\/" "\n")
	prefix=""
	for x in $arr
	do
		prefix+="/$x"
		if [ ! -d "$prefix" ]; then mkdir $prefix; fi
		inc=$(expr $inc + 1)
	done
	if [ "`echo "$5" | grep -E "^(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])$"`" == "$5" ]; then
		grpname="intranet"
		DOMAIN="$5"
		isIP="true"
	elif [ "`echo "$5" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$5" ]; then
		LAST_SITE_GID=`cat /etc/group | grep site | cut -d: -f1 | tail -1 | sed 's/[^0-9]*//g'`
		if [ -z "$LAST_SITE_GID" ]; then
			grpname="site001"
		else
			grpidx=$(expr $LAST_SITE_GID + 1)
			SITEGRP=$( printf '%03o' $grpidx)
			grpname="site$SITEGRP"
		fi
		DOMAIN="$5"
	elif [ "$5" == "N" ]; then
		DOMAIN="localhost";
		grpname="www-data";
	fi
	DUMP_GRP="`grep $grpname /etc/group`"
	if [ -z "$DUMP_GRP" ]; then
		echo "- Adding group name $grpname..."
		addgroup $grpname;
		#writecnf "GROUP=$grpname"
	fi

	if [ "$5" != "N" ]; then
		echo "Preparing site directory..."
		if [ ! -d $prefix/logs ]; then mkdir $prefix/logs; fi
		if [ ! -d $prefix/cgi-bin ]; then mkdir $prefix/cgi-bin; fi
		if [ ! -d $prefix/public_html ]; then mkdir $prefix/public_html; fi
		if [ ! -d $prefix/public_ftp ]; then mkdir $prefix/public_ftp; fi
		if [ ! -d $prefix/cert ]; then mkdir $prefix/cert; fi
		if [ ! -d $prefix/database ]; then mkdir $prefix/database; fi
		if [ ! -d $prefix/conf ]; then mkdir $prefix/conf; fi
		if [ ! -d $prefix/temp ]; then mkdir $prefix/temp; fi
		SSL_DIR="$prefix/cert"
		LAST_GID=`grep "$grpname" /etc/group | cut -d: -f3`
		if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
		adduser --home $homedir --gid $LAST_GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
		usermod --password $3 $2
		UUID="`grep $2 /etc/passwd | cut -d: -f3`"
		chown -cR $2:$grpname $prefix/public_html
		chown -cR $2:$grpname $prefix/public_ftp
		chmod -R g+rwx $prefix/public_ftp
		chown -cR $2:$grpname $prefix/database
		chmod -R g+rwx $prefix/database
		chown -cR $2:$grpname $prefix/temp
		chown -cR $2:$grpname $prefix/cgi-bin
		chmod -R g+rwx $prefix/cgi-bin
		chmod -R g+rwx $prefix/public_html
		chmod 777 $prefix/temp
		writecnf "USER=$2"
	else
		LAST_GID=`grep "$grpname" /etc/group | cut -d: -f3`
		if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
		adduser --home $homedir --gid $LAST_GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
		usermod --password $3 $2
		UUID="`grep $2 /etc/passwd | cut -d: -f3`"
		chown -cR $2:$grpname $homedir
		chmod -R g+rwx $homedir
		writecnf "USER=$2"
	fi
	#--------------------------------------------------------------------------------------------------
	if [ "$5" == "N" ] && [ "$homedir" != "/var/www" ]; then
		rm -Rf $APACHE_DIR/sites-enabled/000-default
		echo "<VirtualHost *:80>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ServerAdmin webmaster@$DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   DocumentRoot $homedir" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory />" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options FollowSymLinks" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride None" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory $homedir>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options Indexes FollowSymLinks MultiViews" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride All" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Order allow,deny" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory "/usr/lib/cgi-bin">" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride None" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Order allow,deny" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ErrorLog /var/log/apache2/error.log" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # Possible values include: debug, info, notice, warn, error, crit," >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # alert, emerg." >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   LogLevel warn" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   CustomLog /var/log/apache2/access.log combined" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "</VirtualHost>" >> $APACHE_DIR/sites-available/$DOMAIN
		if [ -f "$APACHE_DIR/sites-enabled/$DOMAIN" ]; then rm $APACHE_DIR/sites-enabled/$DOMAIN; fi
		ln -s $APACHE_DIR/sites-available/$DOMAIN $APACHE_DIR/sites-enabled/$DOMAIN
		if [ "$useSSL" == "Y" ]; then
			sed -i "s/_default_/$DOMAIN/" $APACHE_DIR/sites-available/default-ssl
			sed -i "s/ServerAdmin webmaster@localhost/ServerAdmin webmaster@$DOMAIN/" $APACHE_DIR/sites-available/default-ssl
			sed -i "s/DocumentRoot \/var\/www/DocumentRoot $homedir/" $APACHE_DIR/sites-available/default-ssl
		fi
	elif [ "$6" == "Y" ]; then
		if [ -f "$APACHE_DIR/sites-enabled/000-default" ]; then rm $APACHE_DIR/sites-enabled/000-default; fi
		echo "<VirtualHost *:80>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ServerAdmin webmaster@$DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ServerName $DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   DocumentRoot $homedir/public_html" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory />" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options FollowSymLinks" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride None" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory $homedir/public_html>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options Indexes FollowSymLinks MultiViews" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride All" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Order allow,deny" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ScriptAlias /cgi-bin/ $homedir/cgi-bin/" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory "$homedir/cgi-bin">" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride None" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Order allow,deny" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   ErrorLog $homedir/logs/error.log" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # Possible values include: debug, info, notice, warn, error, crit," >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # alert, emerg." >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   LogLevel warn" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   CustomLog $homedir/logs/access.log combined" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "</VirtualHost>" >> $APACHE_DIR/sites-available/$DOMAIN
		if [ -f "$APACHE_DIR/sites-enabled/$DOMAIN" ]; then rm $APACHE_DIR/sites-enabled/$DOMAIN; fi
		ln -s $APACHE_DIR/sites-available/$DOMAIN $APACHE_DIR/sites-enabled/$DOMAIN
		if [ "$useSSL" == "Y" ]; then
			echo "<IfModule mod_ssl.c>" >> $prefix/conf/https.conf
			echo "    <VirtualHost _default_:443>" >> $prefix/conf/https.conf
			echo "          ServerAdmin webmaster@$DOMAIN" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "          DocumentRoot $prefix/public_html" >> $prefix/conf/https.conf
			echo "          <Directory />" >> $prefix/conf/https.conf
			echo "              Options FollowSymLinks" >> $prefix/conf/https.conf
			echo "              AllowOverride None" >> $prefix/conf/https.conf
			echo "          </Directory>" >> $prefix/conf/https.conf
			echo "          <Directory $prefix/public_html/>" >> $prefix/conf/https.conf
			echo "              Options Indexes FollowSymLinks MultiViews" >> $prefix/conf/https.conf
			echo "              AllowOverride None" >> $prefix/conf/https.conf
			echo "              Order allow,deny" >> $prefix/conf/https.conf
			echo "              allow from all" >> $prefix/conf/https.conf
			echo "          </Directory>" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "          ScriptAlias /cgi-bin/ $prefix/cgi-bin/" >> $prefix/conf/https.conf
			echo "          <Directory "$prefix/cgi-bin">" >> $prefix/conf/https.conf
			echo "              AllowOverride None" >> $prefix/conf/https.conf
			echo "              Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" >> $prefix/conf/https.conf
			echo "              Order allow,deny" >> $prefix/conf/https.conf
			echo "              Allow from all" >> $prefix/conf/https.conf
			echo "          </Directory>" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "          ErrorLog $prefix/logs/error.log" >> $prefix/conf/https.conf
			echo "          # Possible values include: debug, info, notice, warn, error, crit," >> $prefix/conf/https.conf
			echo "          # alert, emerg." >> $prefix/conf/https.conf
			echo "          LogLevel warn" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "          CustomLog $prefix/logs/ssl_access.log combined" >> $prefix/conf/https.conf
			echo "          #   SSL Engine Switch:" >> $prefix/conf/https.conf
			echo "          #   Enable/Disable SSL for this virtual host." >> $prefix/conf/https.conf
			echo "          SSLEngine on" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "          #   A self-signed (snakeoil) certificate can be created by installing" >> $prefix/conf/https.conf
			echo "          #   the ssl-cert package. See" >> $prefix/conf/https.conf
			echo "          #   /usr/share/doc/apache2.2-common/README.Debian.gz for more info." >> $prefix/conf/https.conf
			echo "          #   If both key and certificate are stored in the same file, only the" >> $prefix/conf/https.conf
			echo "          #   SSLCertificateFile directive is needed." >> $prefix/conf/https.conf
			echo "          SSLCertificateFile    $SSL_DIR/$DOMAIN.crt" >> $prefix/conf/https.conf
			echo "          SSLCertificateKeyFile $SSL_DIR/$DOMAIN.key" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo '          <FilesMatch "\.(cgi|shtml|phtml|php)$">' >> $prefix/conf/https.conf
			echo "              SSLOptions +StdEnvVars" >> $prefix/conf/https.conf
			echo "          </FilesMatch>" >> $prefix/conf/https.conf
			echo "          <Directory /usr/lib/cgi-bin>" >> $prefix/conf/https.conf
			echo "              SSLOptions +StdEnvVars" >> $prefix/conf/https.conf
			echo "          </Directory>" >> $prefix/conf/https.conf
			echo "          BrowserMatch ".*MSIE.*" \" >> $prefix/conf/https.conf
			echo "          nokeepalive ssl-unclean-shutdown \" >> $prefix/conf/https.conf
			echo "          downgrade-1.0 force-response-1.0" >> $prefix/conf/https.conf
			echo " " >> $prefix/conf/https.conf
			echo "    </VirtualHost>" >> $prefix/conf/https.conf
			echo "</IfModule>" >> $prefix/conf/https.conf
		fi
	fi

	echo "Configuring Proftpd..."
	if [ ! -f "$CONF_DIR/proftpd.conf.bak" ]; then 
		echo "Backing up proftpd original configuration..."; 
		cp $PROFTP_DIR/proftpd.conf $CONF_DIR/proftpd.conf.bak;
	else
		if [ -f "$PROFTP_DIR/proftpd.conf" ]; then rm $PROFTP_DIR/proftpd.conf; fi
		CWD=`dirname $0`
		cd /
		cp $CONF_DIR/proftpd.conf.bak $PROFTP_DIR/proftpd.conf
		cd ${CWD}
	fi

	sed -i 's/UseReverseDNS\s.*//' $PROFTP_DIR/proftpd.conf
	sed -i 's/UseIPv6\s.*/UseIPv6                         Off\nUseReverseDNS                   Off/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# DefaultRoot\s.*/DefaultRoot			~/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# RequireValidShell\s.*/RequireValidShell		     Off/' $PROFTP_DIR/proftpd.conf
	PASV=$(( $RANDOM % 1200 + 50190 ))
	TOPORT=`expr $PASV + 501`
	sed -i "s/# PassivePorts\s.*/PassivePorts		$PASV $TOPORT/" $PROFTP_DIR/proftpd.conf
read -r -d '' TEST <<EOF
AuthOrder                       mod_auth_file.c
AuthUserFile                    /etc/proftpd/ftpd.passwd
AuthGroupFile                   /etc/proftpd/ftpd.group

#PAM authentication
PersistentPasswd                off
AuthPAM                         off
EOF
	sed -i 's/# AuthOrder\s.*/AuthOrder  mod_auth_file.c\nAuthUserFile  \/etc\/servconf\/ftpd.passwd\nAuthGroupFile  \/etc\/servconf\/ftpd.group\n\n#PAM Authentication\nPersistentPasswd    Off\nAuthPAM    Off/' $PROFTP_DIR/proftpd.conf
	if [ -z "`grep /bin/false /etc/shells`" ]; then echo "/bin/false" >> /etc/shells; fi
	CWD=`dirname $0`
	cd /etc/servconf
	echo $3 | ftpasswd --stdin --passwd --name $2 --gid $LAST_GID  --uid $UUID --home $homedir --shell /bin/false
	ftpasswd --gid $LAST_GID --name $grpname --member $2 --group
	cd ${CWD}
	echo "Configuring Firewall..."
	ufw default deny
	ufw allow 21   # ftp
	ufw allow 22   # ssh
	ufw limit 22   # brute force protect
	ufw allow 80   # web
	ufw allow 443  # https
	ufw allow proto tcp to any port $PASV:$TOPORT
	writecnf "FW=$PASV:$TOPORT"
	#update-rc.d -f ufw default
	if [ "$DISTRO" == "jaunty" ] || [ "$DISTRO" == "karmic" ]; then
		ufw enable << EOF
y
EOF
   else 
	ufw --force enable
   fi

   if [ "$useSSL" == "Y" ]; then
	openssl genrsa -out server.key 2048
	touch openssl.cnf
	cat >> openssl.cnf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = $C
ST = $ST
L = $L
O = $O
OU = $OU
CN = $CN
emailAddress = $ADDRESS
EOF
	openssl req -config openssl.cnf -new -key server.key -out server.csr
	openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
	if [ -d "/etc/ssl" ]; then
		if [ ! -d "/etc/ssl/host" ]; then mkdir /etc/ssl/host; fi
		if [ "$SSL_DIR" != "/etc/ssl/host" ]; then
            mv ./server.key $SSL_DIR/$DOMAIN.key
            mv ./server.crt $SSL_DIR/$DOMAIN.crt
            mv ./server.csr $SSL_DIR/$DOMAIN.csr
        else
            mv ./server.key /etc/ssl/host/$DOMAIN.key
            mv ./server.crt /etc/ssl/host/$DOMAIN.crt
            mv ./server.csr /etc/ssl/host/$DOMAIN.csr
        fi
    fi
   fi

	a2enmod rewrite
	echo "Restarting apache..."
	/etc/init.d/apache2 restart
	/etc/init.d/proftpd restart
	if [ "$useSSL" == "Y" ]; then
		info $DOMAIN $2 $3 1 $useMySQL $usePgSQL
	else
		info $DOMAIN $2 $3 $useMySQL $usePgSQL
	fi
}

function setup_fcgi_mode {
	# setup_fcgi_mode N administrator adm1ns /home/wwwroot 192.168.75.133 Y
	# setup_fcgi_mode N administrator adm1ns /home/wwwroot N
	# $1 = DNS, $2 = $user, $3 = $passwd, $4 = $homedir, $5 = domain, $6 = $vhost
	if [ "$1" == "Y" ]; then echo "Configuring BIND..."; fi
	writecnf "OS=apache"

	echo "Configuring Apache..."
	if [ -d "$APACHE_DIR/conf.d" ] && [ -f "$APACHE_DIR/conf.d/security" ]; then
		echo "Setting up apache security..."
		if [ $APACHE_SECURITY == 3 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Prod/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 2 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Prod/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Off/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 1 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Minimal/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		elif [ $APACHE_SECURITY == 0 ]; then
			SCH=`grep ServerTokens /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  Full/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep ServerSignature /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
			SCH=`grep TraceEnable /etc/apache2/conf.d/security | tail -1`
			RPL=`echo $SCH | sed -e 's/\s.*/  On/g'`
			sed -i "s/$SCH/$RPL/" /etc/apache2/conf.d/security
		fi
	fi

	a2enmod rewrite
	a2enmod actions
	a2enmod suexec
	a2enmod ssl

	if [ "$5" != "N" ]; then homedir=$4/sites/$5; else homedir=$4; fi
	writecnf "HOMEDIR=$4"
	
	arr=$(echo $homedir | tr "\/" "\n")
	prefix=""
	for x in $arr
	do
		prefix+="/$x"
		if [ ! -d "$prefix" ]; then mkdir $prefix; fi
		inc=$(expr $inc + 1)
	done
	
	if [ "`echo "$5" | grep -E "^(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])$"`" == "$5" ]; then
		# IP Address
		grpname="intranet"
		DOMAIN="$5"
		isIP="true"
	elif [ "`echo "$5" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$5" ]; then
		# Domain Name
		LAST_SITE_GID=`cat /etc/group | grep site | cut -d: -f1 | tail -1 | sed 's/[^0-9]*//g'`
		if [ -z "$LAST_SITE_GID" ]; then
			grpname="site001"
		else
			grpidx=$(expr $LAST_SITE_GID + 1)
			SITEGRP=$( printf '%03o' $grpidx)
			grpname="site$SITEGRP"
		fi

		# Split domain names and check for subdomain eg : ns1 or ns2
		IFS='.' read -a array <<< "$6"
		if [ ${#array[@]} -gt 2 ]; then
			i=0
			for x in "${array[@]}"
			do
				if [ $i -gt 0 ]; then DOM[$i]="$x"; fi
				i=$(expr $i + 1)
			done
			DOMAIN=$(IFS=.; echo "${DOM[*]}")
		else DOMAIN="$5"
		fi
	elif [ "$5" == "N" ]; then
		DOMAIN="localhost";
		grpname="intranet";
		isIP="true"
	fi

	DUMP_GRP=`grep $grpname /etc/group`
	#echo "DETECT EXISTING group $DUMP_GRP"
	if [ -z "$DUMP_GRP" ]; then
		echo "- Adding group name $grpname..."
		addgroup $grpname;
		writecnf "GROUP=$grpname"
	fi

   if [ "$5" != "N" ]; then
      echo "Preparing site directory..."
      if [ ! -d "$prefix/logs" ]; then mkdir $prefix/logs; fi
      if [ ! -d "$prefix/cgi-bin" ]; then mkdir $prefix/cgi-bin; fi
      if [ ! -d "$prefix/public_html" ]; then mkdir $prefix/public_html; fi
      if [ ! -d "$prefix/public_ftp" ]; then mkdir $prefix/public_ftp; fi
      if [ ! -d "$prefix/cert" ]; then mkdir $prefix/cert; fi
      if [ ! -d "$prefix/database" ]; then mkdir $prefix/database; fi
      if [ ! -d "$prefix/conf" ]; then mkdir $prefix/conf; fi
      if [ ! -d "$prefix/temp" ]; then mkdir $prefix/temp; fi
      SSL_DIR="$prefix/cert"
	  # make sure this GID is not exists
      LAST_GID=`grep "$grpname" /etc/group | cut -d: -f3`
      if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
      adduser --home $homedir --gid $LAST_GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
      usermod --password $3 $2
      UUID="`grep $2 /etc/passwd | cut -d: -f3`"
      chown -cR $2:$grpname $prefix/public_html
      chown -cR $2:$grpname $prefix/public_ftp
	  chmod -R g+rwx $prefix/public_ftp
      chown -cR $2:$grpname $prefix/database
	  chmod -R g+rwx $prefix/database
      chown -cR $2:$grpname $prefix/temp
	  chown -cR $2:$grpname $prefix/cgi-bin
      chmod -R g+rwx $prefix/cgi-bin
      chmod -R g+rwx $prefix/public_html
      echo "<?php" >> $prefix/public_html/index.php
      echo "phpinfo();" >> $prefix/public_html/index.php
      echo "?>" >> $prefix/public_html/index.php
      chown -cR $2:$grpname $prefix/public_html/index.php
      chmod 777 $prefix/temp
      writecnf "USER=$2"
   else
      LAST_GID=`grep "$grpname" /etc/group | cut -d: -f3`
      if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
      adduser --home $homedir --gid $LAST_GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
      usermod --password $3 $2
      UUID="`grep $2 /etc/passwd | cut -d: -f3`"
      chown -cR $2:$grpname $homedir
	  echo "<?php" >> $prefix/index.php
      echo "phpinfo();" >> $prefix/index.php
      echo "?>" >> $prefix/index.php
      chown -cR $2:$grpname $prefix/index.php
      chmod -R g+rwx $homedir
      writecnf "USER=$2" 
   fi

   arr=$(echo $homedir | tr "/" "\n")
   i=0
   path=""
   for x in $arr
   do
      if [ $i -eq 0 ]; then path="$x"; fi
      i=`expr $i + 1`
   done
   parent="/$path"
   if [ ! -z "$path" ] && [ ! -d "$path" ]; then mkdir $path; fi
   path="/$path/fcgi.d"
   writecnf "FCGI=$path"
 
   # CREATE Fcgi Directory Exec
   hash=`echo -n $DOMAIN | md5sum | cut -d\  -f1`
   duid="${hash:0:8}-${hash:8:4}-${hash:12:4}-${hash:16:4}-${hash:20:12}"
   if [ ! -d "$path" ]; then
      mkdir $path;
      mkdir $path/$duid
      echo "#!/bin/sh" >> $path/$duid/php-fcgi-exec
      echo "export PHPRC=$prefix/conf" >> $path/$duid/php-fcgi-exec
      cgi=`which php5-cgi`
      echo "exec $cgi -d open_basedir=$prefix" >> $path/$duid/php-fcgi-exec
      chmod +x $path/$duid/php-fcgi-exec
      chown -cR $2:$grpname $path/$duid
   fi

   # Setup SUEXEC apache
   if [ -f "$APACHE_DIR/suexec/www-data" ]; then rm -Rf $APACHE_DIR/suexec/www-data; fi
   echo "$parent" >> $APACHE_DIR/suexec/www-data
   echo "$homedir/cgi-bin" >> $APACHE_DIR/suexec/www-data

	if [ "$5" != "N" ]; then
		if [ -f "$APACHE_DIR/sites-enabled/000-default" ]; then rm -Rf $APACHE_DIR/sites-enabled/000-default; fi
		if [ -f "$prefix/conf/httpd.conf" ]; then rm $prefix/conf/httpd.conf; fi
		echo "<VirtualHost $DOMAIN:80>" >> $prefix/conf/httpd.conf
		if [ -z "$isIP" ]; then
			echo "   ServerAdmin webmaster@$DOMAIN" >> $prefix/conf/httpd.conf
			echo "   ServerName $DOMAIN" >> $prefix/conf/httpd.conf
		else
			echo "   ServerAdmin webmaster@localhost" >> $prefix/conf/httpd.conf
			#echo "   ServerName loca" >> $prefix/conf/httpd.conf
		fi
		echo "   DocumentRoot $prefix/public_html" >> $prefix/conf/httpd.conf
		
		if [ "`echo "$DOMAIN" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$DOMAIN" ]; then
			echo "   ServerAlias www.$DOMAIN" >> $prefix/conf/httpd.conf
		fi
		echo "   <IfModule mod_fcgid.c>" >> $prefix/conf/httpd.conf
		echo "       SuexecUserGroup $2 $grpname" >> $prefix/conf/httpd.conf
		#echo "       PHP_Fix_Pathinfo_Enable 1" >> $prefix/conf/httpd.conf
		echo "       Action php-fcgi /fcgi-bin/php-fcgi-exec" >> $prefix/conf/httpd.conf
		echo "       DefaultInitEnv PHPRC $prefix/conf/" >> $prefix/conf/httpd.conf
		echo "       Alias /fcgi-bin/ $path/$duid/" >> $prefix/conf/httpd.conf
		echo "       AddType application/x-httpd-php .php" >> $prefix/conf/httpd.conf
		echo "       FCGIWrapper $path/$duid/php-fcgi-exec .php" >> $prefix/conf/httpd.conf
		echo "   </IfModule>" >> $prefix/conf/httpd.conf
		echo "   <Directory $prefix/public_html>" >> $prefix/conf/httpd.conf
		echo "       AddHandler fcgid-script  .php" >> $prefix/conf/httpd.conf
		echo "       Options Indexes FollowSymLinks MultiViews +ExecCGI" >> $prefix/conf/httpd.conf
		echo "       AllowOverride All" >> $prefix/conf/httpd.conf
		echo "       Order deny,allow" >> $prefix/conf/httpd.conf
		echo "       allow from all" >> $prefix/conf/httpd.conf
		echo "   </Directory>" >> $prefix/conf/httpd.conf
		echo "" >> $prefix/conf/httpd.conf
		echo "   ErrorLog $prefix/logs/error.log" >> $prefix/conf/httpd.conf
		echo "" >> $prefix/conf/httpd.conf
		echo "   # Possible values include: debug, info, notice, warn, error, crit," >> $prefix/conf/httpd.conf
		echo "   # alert, emerg." >> $prefix/conf/httpd.conf
		echo "   LogLevel warn" >> $prefix/conf/httpd.conf
		echo "" >> $prefix/conf/httpd.conf
		echo "   CustomLog $prefix/logs/access.log combined" >> $prefix/conf/httpd.conf
		echo "</VirtualHost>" >> $prefix/conf/httpd.conf
		if [ "$useSSL" == "Y" ]; then
			echo "<IfModule mod_ssl.c>" >> $prefix/conf/httpd.conf
			echo "    <VirtualHost $DOMAIN:443>" >> $prefix/conf/httpd.conf
			echo "          ServerAdmin webmaster@$DOMAIN" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "          DocumentRoot $prefix/public_html" >> $prefix/conf/httpd.conf
			echo "          <Directory />" >> $prefix/conf/httpd.conf
			echo "              Options FollowSymLinks" >> $prefix/conf/httpd.conf
			echo "              AllowOverride None" >> $prefix/conf/httpd.conf
			echo "          </Directory>" >> $prefix/conf/httpd.conf
			echo "   		<IfModule mod_fcgid.c>" >> $prefix/conf/httpd.conf
			echo "       		SuexecUserGroup $2 $grpname" >> $prefix/conf/httpd.conf
			#echo "       		PHP_Fix_Pathinfo_Enable 1" >> $prefix/conf/httpd.conf
			echo "       		Action php-fcgi /fcgi-bin/php-fcgi-exec" >> $prefix/conf/httpd.conf
			echo "       		DefaultInitEnv PHPRC $prefix/conf/" >> $prefix/conf/httpd.conf
			echo "       		Alias /fcgi-bin/ $path/$duid/" >> $prefix/conf/httpd.conf
			echo "       		AddType application/x-httpd-php .php" >> $prefix/conf/httpd.conf
			echo "       		FCGIWrapper $path/$duid/php-fcgi-exec .php" >> $prefix/conf/httpd.conf
			echo "   		</IfModule>" >> $prefix/conf/httpd.conf
			echo "          <Directory $prefix/public_html/>" >> $prefix/conf/httpd.conf
			echo "				AddHandler fcgid-script  .php" >> $prefix/conf/httpd.conf
			echo "              Options Indexes FollowSymLinks MultiViews +ExecCGI" >> $prefix/conf/httpd.conf
			echo "              AllowOverride All" >> $prefix/conf/httpd.conf
			echo "              Order allow,deny" >> $prefix/conf/httpd.conf
			echo "              allow from all" >> $prefix/conf/httpd.conf
			echo "          </Directory>" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "          ScriptAlias /cgi-bin/ $prefix/cgi-bin/" >> $prefix/conf/httpd.conf
			echo "          <Directory "$prefix/cgi-bin">" >> $prefix/conf/httpd.conf
			echo "              AllowOverride None" >> $prefix/conf/httpd.conf
			echo "              Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" >> $prefix/conf/httpd.conf
			echo "              Order allow,deny" >> $prefix/conf/httpd.conf
			echo "              Allow from all" >> $prefix/conf/httpd.conf
			echo "          </Directory>" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "          ErrorLog $prefix/logs/error.log" >> $prefix/conf/httpd.conf
			echo "          # Possible values include: debug, info, notice, warn, error, crit," >> $prefix/conf/httpd.conf
			echo "          # alert, emerg." >> $prefix/conf/httpd.conf
			echo "          LogLevel warn" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "          CustomLog $prefix/logs/ssl_access.log combined" >> $prefix/conf/httpd.conf
			echo "          #   SSL Engine Switch:" >> $prefix/conf/httpd.conf
			echo "          #   Enable/Disable SSL for this virtual host." >> $prefix/conf/httpd.conf
			echo "          SSLEngine on" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "          #   A self-signed (snakeoil) certificate can be created by installing" >> $prefix/conf/httpd.conf
			echo "          #   the ssl-cert package. See" >> $prefix/conf/httpd.conf
			echo "          #   /usr/share/doc/apache2.2-common/README.Debian.gz for more info." >> $prefix/conf/httpd.conf
			echo "          #   If both key and certificate are stored in the same file, only the" >> $prefix/conf/httpd.conf
			echo "          #   SSLCertificateFile directive is needed." >> $prefix/conf/httpd.conf
			echo "          SSLCertificateFile    $SSL_DIR/$DOMAIN.crt" >> $prefix/conf/httpd.conf
			echo "          SSLCertificateKeyFile $SSL_DIR/$DOMAIN.key" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo '          <FilesMatch "\.(cgi|shtml|phtml|php)$">' >> $prefix/conf/httpd.conf
			echo "              SSLOptions +StdEnvVars" >> $prefix/conf/httpd.conf
			echo "          </FilesMatch>" >> $prefix/conf/httpd.conf
			echo "          <Directory /usr/lib/cgi-bin>" >> $prefix/conf/httpd.conf
			echo "              SSLOptions +StdEnvVars" >> $prefix/conf/httpd.conf
			echo "          </Directory>" >> $prefix/conf/httpd.conf
			echo " " >> $prefix/conf/httpd.conf
			echo "    </VirtualHost>" >> $prefix/conf/httpd.conf
			echo "</IfModule>" >> $prefix/conf/httpd.conf
		fi
		if [ -z "`grep '$DOMAIN' $APACHE_DIR/httpd.conf`" ]; then
			if [ -z "$DEPRECATED" ]; then 
				sed -i '1i ServerName localhost' $APACHE_DIR/apache2.conf; 
				rm -f $APACHE_DIR/sites-enabled/*
				ln -s $prefix/conf/httpd.conf $APACHE_DIR/sites-enabled/$DOMAIN
			else
				echo "Include $prefix/conf/httpd.conf" >> $APACHE_DIR/httpd.conf;
			fi
		fi
		if [ -f "/etc/php5/cgi/php.ini" ]; then 
			cp /etc/php5/cgi/php.ini $prefix/conf
			prefixes=`echo "$prefix" | sed -e 's/\//\\\\\//g'`
			sed -i "s/;upload_tmp_dir =/upload_tmp_dir = $prefixes\/temp/" $prefix/conf/php.ini
			sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 10M/' $prefix/conf/php.ini
			sed -i 's/disable_functions =/disable_functions = system,exec,show_source,mysql_list_dbs,ini_alter,openlog,syslog,dl,pfsockopen,symlink,link,apache_setenv,apache_child_terminate,apache_get_modules,apache_get_version,apache_note,chgrp,ini_restore,passthru,shell_exec,popen,proc_open,proc_get_status,proc_terminate,proc_close,set_time_limit,proc_nice,virtual,mb_send_mail/' $prefix/conf/php.ini
			sed -i 's/safe_mode = Off/safe_mode = On/' $prefix/conf/php.ini
			sed -i 's/expose_php = On/expose_php = Off/' $prefix/conf/php.ini
			writecnf "VHOST=1"
		fi
	else
		if [ -f "$prefix/conf/httpd.conf" ]; then rm $prefix/conf/httpd.conf; fi
		rm -Rf $APACHE_DIR/sites-enabled/*;
		if [ -z "$isIP" ]; then
			echo "<VirtualHost $DOMAIN:80>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   ServerAdmin webmaster@$DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   ServerName $DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   ServerAlias www.$DOMAIN" >> $APACHE_DIR/sites-available/$DOMAIN
		else
			echo "<VirtualHost *:80>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   ServerAdmin webmaster@localhost" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   ServerName localhost" >> $APACHE_DIR/sites-available/$DOMAIN
		fi
		echo "   DocumentRoot $prefix" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <IfModule mod_fcgid.c>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       SuexecUserGroup $2 $grpname" >> $APACHE_DIR/sites-available/$DOMAIN
		#echo "       PHP_Fix_Pathinfo_Enable 1" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Action php-fcgi /fcgi-bin/php-fcgi-exec" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       DefaultInitEnv PHPRC /etc/php5/cgi/" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Alias /fcgi-bin/ $path/$duid" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AddType application/x-httpd-php .php" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       FCGIWrapper $path/$duid/php-fcgi-exec .php" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </IfModule>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   <Directory $prefix>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AddHandler fcgid-script  .php" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Options Indexes FollowSymLinks MultiViews +ExecCGI" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       AllowOverride All" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       Order deny,allow" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "       allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		if [ ! -d "/var/log/apache2" ]; then
			mkdir /var/log/apache2
		fi
		echo "   ErrorLog /var/log/apache2/error.log" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # Possible values include: debug, info, notice, warn, error, crit," >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   # alert, emerg." >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   LogLevel warn" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "   CustomLog /var/log/apache2/access.log combined" >> $APACHE_DIR/sites-available/$DOMAIN
		echo "</VirtualHost>" >> $APACHE_DIR/sites-available/$DOMAIN
		if [ -z "$DEPRECATED" ]; then 
			sed -i '1i ServerName localhost' $APACHE_DIR/apache2.conf;
		fi
		if [ "$useSSL" == "Y" ]; then
			echo "<IfModule mod_ssl.c>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "    <VirtualHost *:443>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          ServerAdmin webmaster@localhost" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          DocumentRoot $prefix" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          <Directory />" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              Options FollowSymLinks" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              AllowOverride None" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   	<IfModule mod_fcgid.c>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "       		SuexecUserGroup $2 $grpname" >> $APACHE_DIR/sites-available/$DOMAIN
			#echo "       		PHP_Fix_Pathinfo_Enable 1" >> $prefix/conf/httpd.conf
			echo "       		Action php-fcgi /fcgi-bin/php-fcgi-exec" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "       		DefaultInitEnv PHPRC /etc/php5/cgi/" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "       		Alias /fcgi-bin/ $path/$duid/" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "       		AddType application/x-httpd-php .php" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "       		FCGIWrapper $path/$duid/php-fcgi-exec .php" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "   		</IfModule>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          <Directory $prefix/>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "				AddHandler fcgid-script  .php" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              Options Indexes FollowSymLinks MultiViews +ExecCGI" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              AllowOverride All" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              Order allow,deny" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              allow from all" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          ErrorLog /var/log/apache2/ssl_error.log" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          # Possible values include: debug, info, notice, warn, error, crit," >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          # alert, emerg." >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          LogLevel warn" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          CustomLog /var/log/apache2/ssl_access.log combined" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   SSL Engine Switch:" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   Enable/Disable SSL for this virtual host." >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          SSLEngine on" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   A self-signed (snakeoil) certificate can be created by installing" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   the ssl-cert package. See" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   /usr/share/doc/apache2.2-common/README.Debian.gz for more info." >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   If both key and certificate are stored in the same file, only the" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          #   SSLCertificateFile directive is needed." >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          SSLCertificateFile    $SSL_DIR/$DOMAIN.crt" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          SSLCertificateKeyFile $SSL_DIR/$DOMAIN.key" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo '          <FilesMatch "\.(cgi|shtml|phtml|php)$">' >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              SSLOptions +StdEnvVars" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          </FilesMatch>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          <Directory /usr/lib/cgi-bin>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "              SSLOptions +StdEnvVars" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "          </Directory>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo " " >> $APACHE_DIR/sites-available/$DOMAIN
			echo "    </VirtualHost>" >> $APACHE_DIR/sites-available/$DOMAIN
			echo "</IfModule>" >> $APACHE_DIR/sites-available/$DOMAIN
		fi
		ln -s $APACHE_DIR/sites-available/$DOMAIN $APACHE_DIR/sites-enabled/$DOMAIN
		if [ -f "/etc/php5/cgi/php.ini" ]; then
			tar -zcvf /etc/php5/cgi/php.tar.gz /etc/php5/cgi/php.ini;
			sed -i "s/;upload_tmp_dir =/upload_tmp_dir = \/etc\/php5\/cgi/" /etc/php5/cgi/php.ini
			sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 10M/' /etc/php5/cgi/php.ini
			sed -i 's/disable_functions =/disable_functions = system,exec,passthru,shell_exec,popen,proc_open,proc_get_status,proc_terminate,proc_close,proc_nice/' /etc/php5/cgi/php.ini
			sed -i 's/safe_mode = Off/safe_mode = On/' /etc/php5/cgi/php.ini
			sed -i 's/expose_php = On/expose_php = Off/' $prefix/conf/php.ini
			writecnf "VHOST=0" 
		fi
	fi
   
   echo "Configuring Proftpd..."
   if [ ! -f "$CONF_DIR/proftpd.conf.bak" ]; then
        echo "Backing up proftpd original configuration...";
        cp $PROFTP_DIR/proftpd.conf $CONF_DIR/proftpd.conf.bak;
   else
        if [ -f "$PROFTP_DIR/proftpd.conf" ]; then rm $PROFTP_DIR/proftpd.conf; fi
        CWD=`dirname $0`
        cd /
        cp $CONF_DIR/proftpd.conf.bak $PROFTP_DIR/proftpd.conf
        cd ${CWD}
   fi

   sed -i 's/UseReverseDNS\s.*//' $PROFTP_DIR/proftpd.conf
   sed -i 's/UseIPv6\s.*/UseIPv6                         Off\nUseReverseDNS                   Off/' $PROFTP_DIR/proftpd.conf
   sed -i 's/# DefaultRoot\s.*/DefaultRoot                      ~/' $PROFTP_DIR/proftpd.conf
   sed -i 's/# RequireValidShell\s.*/RequireValidShell               Off/' $PROFTP_DIR/proftpd.conf
   PASV=$(( $RANDOM % 1200 + 50190 ))
   TOPORT=`expr $PASV + 501`
   sed -i "s/# PassivePorts\s.*/PassivePorts              $PASV $TOPORT/" $PROFTP_DIR/proftpd.conf
#Just Template
read -r -d '' TEST <<EOF
AuthOrder                       mod_auth_file.c
AuthUserFile                    /etc/proftpd/ftpd.passwd
AuthGroupFile                   /etc/proftpd/ftpd.group

#PAM authentication
PersistentPasswd                off
AuthPAM                         off
EOF

   sed -i 's/# AuthOrder\s.*/AuthOrder  mod_auth_file.c\nAuthUserFile  \/etc\/servconf\/ftpd.passwd\nAuthGroupFile  \/etc\/servconf\/ftpd.group\n\n#PAM Authentication\nPersistentPasswd    Off\nAuthPAM    Off/' $PROFTP_DIR/proftpd.conf
   if [ -z "`grep /bin/false /etc/shells`" ]; then echo "/bin/false" >> /etc/shells; fi
   CWD=`dirname $0`
   cd /etc/servconf
   echo $3 | ftpasswd --stdin --passwd --name $2 --gid $LAST_GID  --uid $UUID --home $homedir --shell /bin/false
   ftpasswd --gid $LAST_GID --name $grpname --member $2 --group
   cd ${CWD}

   echo "Configuring Firewall..."
   ufw default deny
   ufw allow 21   # ftp
   ufw allow 22   # ssh
   ufw limit 22   # brute force protect
   ufw allow 80   # web
   ufw allow 443  # https
   ufw allow proto tcp to any port $PASV:$TOPORT
   writecnf "FW=$PASV:$TOPORT"
   #update-rc.d -f ufw default
   if [ "$DISTRO" == "jaunty" ] || [ "$DISTRO" == "karmic" ]; then
        ufw enable << EOF
y
EOF
   else
        ufw --force enable
   fi

   if [ "$useSSL" == "Y" ]; then
	# to open certificate file run this :
	# openssl x509 -in certificate.crt -text -noout

        openssl genrsa -out server.key 2048
        touch openssl.cnf
        cat >> openssl.cnf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = $C
ST = $ST
L = $L
O = $O
OU = $OU
CN = $CN
emailAddress = $ADDRESS
EOF
        openssl req -config openssl.cnf -new -key server.key -out server.csr
        openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
	if [ -d "/etc/ssl" ]; then
           if [ ! -d "/etc/ssl/host" ]; then mkdir /etc/ssl/host; fi
           if [ "$SSL_DIR" != "/etc/ssl/host" ]; then
                mv ./server.key $SSL_DIR/$DOMAIN.key
                mv ./server.crt $SSL_DIR/$DOMAIN.crt
                mv ./server.csr $SSL_DIR/$DOMAIN.csr
           else
                mv ./server.key /etc/ssl/host/$DOMAIN.key
                mv ./server.crt /etc/ssl/host/$DOMAIN.crt
                mv ./server.csr /etc/ssl/host/$DOMAIN.csr
           fi
        fi
   fi

	echo "Restarting apache..."
	/etc/init.d/apache2 restart
	/etc/init.d/proftpd restart
	if [ "$useSSL" == "Y" ]; then
		info $DOMAIN $2 $3 1 $useMySQL $usePgSQL
	else
		info $DOMAIN $2 $3 $useMySQL $usePgSQL
	fi
}

function setup_lighttpd {
	# setup_lighttpd N administrator adm1ns /home/wwwroot 192.168.75.133 Y
	# setup_lighttpd N administrator adm1ns /home/wwwroot N
	# $1 = DNS, $2 = $user, $3 = $passwd, $4 = $homedir, $5 = domain, $6 = $vhost
	writecnf "OS=lighttpd"
	if [ "$5" != "N" ]; then homedir=$4/sites/$5; else homedir=$4; fi

	writecnf "HOMEDIR=$4"
	# Create document root directory
	arr=$(echo $homedir | tr "\/" "\n")
	prefix=""
	for x in $arr
	do
		prefix+="/$x"
		if [ ! -d "$prefix" ]; then mkdir $prefix; fi
		inc=$(expr $inc + 1)
	done

	# Check to see if domain is ip address or domain
	if [ "`echo "$5" | grep -E "^(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])$"`" == "$5" ]; then
		# IP Address
		grpname="intranet"
		DOMAIN="$5"
	elif [ "`echo "$5" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$5" ]; then
		# Domain Name
		# Define group for multiple domain
		if [ "$6" == "Y" ]; then
			LAST_SITE_GID=`cat /etc/group | grep site | cut -d: -f1 | tail -1 | sed 's/[^0-9]*//g'`
			if [ -z "$LAST_SITE_GID" ]; then 
				grpname="site001"
				SITEGRP="001"
			else
				grpidx=$(expr $LAST_SITE_GID + 1)
				SITEGRP=$( printf '%03o' $grpidx)
				grpname="site$SITEGRP"
			fi
		else
			grpname="www-data"
		fi
		# Split domain names and check for subdomain eg : ns1 or ns2
		IFS='.' read -a array <<< "$6"
		if [ ${#array[@]} -gt 2 ]; then
			i=0
			for x in "${array[@]}"
			do
				if [ $i -gt 0 ]; then DOM[$i]="$x"; fi
				i=$(expr $i + 1)
			done
			DOMAIN=$(IFS=.; echo "${DOM[*]}")
		else DOMAIN="$5"
		fi
	elif [ "$5" == "N" ]; then
		DOMAIN="localhost";
		grpname="intranet";
	fi

	DUMP_GRP=`grep $grpname /etc/group`
	if [ -z "$DUMP_GRP" ]; then
		echo "- Adding group name $grpname..."
		addgroup $grpname;
		writecnf "GROUP=$grpname"
	else writecnf "GROUP=$grpname"
	fi

	if [ "$5" != "N" ]; then
		echo "Preparing site directory..."
		if [ ! -d "$prefix/logs" ]; then mkdir $prefix/logs; fi
		if [ ! -d "$prefix/cgi-bin" ]; then mkdir $prefix/cgi-bin; fi
		if [ ! -d "$prefix/public_html" ]; then mkdir $prefix/public_html; fi
		if [ ! -d "$prefix/public_ftp" ]; then mkdir $prefix/public_ftp; fi
		if [ ! -d "$prefix/cert" ]; then mkdir $prefix/cert; fi
		if [ ! -d "$prefix/database" ]; then mkdir $prefix/database; fi
		if [ ! -d "$prefix/conf" ]; then mkdir $prefix/conf; fi
		if [ ! -d "$prefix/temp" ]; then mkdir $prefix/temp; fi
		# Adding user
		# make sure this GID is not exists
		GID=`grep "$grpname" /etc/group | cut -d: -f3`
		if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
		adduser --home $homedir --gid $GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
		usermod --password $3 $2
		chown -cR $2:$grpname $prefix/public_html
		chown -cR $2:$grpname $prefix/public_ftp
		chown -cR $2:$grpname $prefix/cert
		chown -cR $2:$grpname $prefix/cgi-bin
		chown -cR $2:$grpname $prefix/temp
		chown -cR www-data:www-data $prefix/logs
		chmod 666 $prefix/public_ftp
		chmod -R g+rwx $prefix/cert
		chmod -R g+rwx $prefix/cgi-bin
		chmod -R g+rwx $prefix/public_html
		chmod -R g+rwx $prefix/public_ftp
		echo "<?php" >> $prefix/public_html/index.php
		echo "phpinfo();" >> $prefix/public_html/index.php
		echo "?>" >> $prefix/public_html/index.php
		chown -cR $2:$grpname $prefix/public_html/index.php
		chmod 777 $prefix/temp
		# Set default template for rewrite
		echo "# --- YOUR CUSTOM REWRITE RULES ---" >> $prefix/conf/rewrite.conf
		chown -cR $2:$grpname $prefix/conf/rewrite.conf
		chmod 666 $prefix/conf/rewrite.conf
		writecnf "USER=$2"
		# Prepare vhost config
		if [ ! -d "$LIGHTTP_DIR/vhost.d" ]; then mkdir $LIGHTTP_DIR/vhost.d; fi
		domain_name=`echo "$DOMAIN" | sed -r 's/[\.]+/\\\./g'`
		echo "\$HTTP[\"host\"] =~ \"^(www\.)?$domain_name$\" {" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\tserver.document-root = \"$homedir/public_html\"" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\taccesslog.filename = \"$homedir/logs/access.log\"" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\tserver.errorlog = \"$homedir/logs/error.log\"" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\tfastcgi.server    = ( \".php\" =>" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\t\t((" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\t\t\t\"socket\" => \"$homedir/logs/socket.pid\"," >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\t\t\t\"broken-scriptfilename\" => \"enable\"" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\t\t))" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo -e "\t)" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo "}" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo "" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo "include \"../..$homedir/conf/rewrite.conf\"" >> $LIGHTTP_DIR/vhost.d/$DOMAIN
		echo "include \"vhost.d/$DOMAIN\"" >> $LIGHTTP_DIR/lighttpd.conf
		sed -i 's/#           "mod_rewrite",/            "mod_rewrite",/' $LIGHTTP_DIR/lighttpd.conf

		# setup FastCGI service
		CWD=`dirname $0`
		uudecode $0
		tar xvf conf.tar.gz -C $TEMP_DIR fastcgi
		cp -f $TEMP_DIR/fastcgi /etc/init.d/fastcgi
		rm -f $TEMP_DIR/fastcgi
		rm -f $CWD/conf.tar.gz
		update-rc.d fastcgi defaults

		# Set custom php.ini
		if [ -f "/etc/php5/cgi/php.ini" ]; then cp /etc/php5/cgi/php.ini $prefix/conf; fi
		prefixes=`echo "$prefix" | sed -e 's/\//\\\\\//g'`
		sed -i "s/;upload_tmp_dir =/upload_tmp_dir = $prefixes\/temp/" $prefix/conf/php.ini
		sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 10M/' $prefix/conf/php.ini
		sed -i 's/disable_functions =/disable_functions = system,exec,show_source,mysql_list_dbs,ini_alter,openlog,syslog,dl,pfsockopen,symlink,link,chgrp,ini_restore,passthru,shell_exec,popen,proc_open,proc_get_status,proc_terminate,proc_close,set_time_limit,proc_nice,virtual,mb_send_mail/' $prefix/conf/php.ini
		sed -i 's/safe_mode = Off/safe_mode = On/' $prefix/conf/php.ini
		sed -i 's/expose_php = On/expose_php = Off/' $prefix/conf/php.ini
		chown -cR root:root $prefix/conf/php.ini
	else
		# Adding user
		# make sure this GID is not exists
		GID=`grep "$grpname" /etc/group | cut -d: -f3`
		if [ ! -z "`grep $2:x /etc/passwd`" ]; then deluser $2; fi
		adduser --home $homedir --gid $GID --shell $DEFAULT_SHELL --gecos "" $2 --disabled-login --no-create-home
		usermod --password $3 $2

		chown -cR www-data:www-data $homedir
		wwwroot=`echo "$homedir" | sed -e 's/\//\\\\\//g'`
		sed -i "s/server.document-root       = \"\/var\/www\/\"/server.document-root       = \"$wwwroot\"/" $LIGHTTP_DIR/lighttpd.conf 
		# Registering autoboot script on server reboot
		if [ -f "/etc/rc.local" ]; then rm /etc/rc.local; fi
		echo "#!/bin/sh -e" >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# rc.local" >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# This script is executed at the end of each multiuser runlevel." >> /etc/rc.local
		echo "# Make sure that the script will \"exit 0\" on success or any other" >> /etc/rc.local
		echo "# value on error." >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# In order to enable or disable this script just change the execution" >> /etc/rc.local
		echo "# bits." >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# By default this script does nothing." >> /etc/rc.local
		echo " " >> /etc/rc.local
		echo "su -m www-data -c \"/usr/bin/php5-cgi -d open_basedir=$homedir -b /tmp/php.socket&\"" >> /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		su -m www-data -c "/usr/bin/php5-cgi -d open_basedir=$homedir -b /tmp/php.socket&"

		# Prepare php default template file
                echo "<?php" >> $homedir/index.php
                echo "phpinfo();" >> $homedir/index.php
                echo "?>" >> $homedir/index.php
                chown -cR $2:$grpname $homedir/index.php
	fi

	# Configuring FTP
	echo "Configuring Proftpd..."
	if [ ! -f "$CONF_DIR/proftpd.conf.bak" ]; then
		echo "Backing up proftpd original configuration...";
		cp $PROFTP_DIR/proftpd.conf $CONF_DIR/proftpd.conf.bak;
	else
		if [ -f "$PROFTP_DIR/proftpd.conf" ]; then rm $PROFTP_DIR/proftpd.conf; fi
		CWD=`dirname $0`
		cd /
		cp $CONF_DIR/proftpd.conf.bak $PROFTP_DIR/proftpd.conf
		cd ${CWD}
	fi

	sed -i 's/UseReverseDNS\s.*//' $PROFTP_DIR/proftpd.conf
	sed -i 's/UseIPv6\s.*/UseIPv6                         Off\nUseReverseDNS                   Off/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# DefaultRoot\s.*/DefaultRoot                      ~/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# RequireValidShell\s.*/RequireValidShell               Off/' $PROFTP_DIR/proftpd.conf
	PASV=$(( $RANDOM % 1200 + 50190 ))
	TOPORT=`expr $PASV + 501`
	sed -i "s/# PassivePorts\s.*/PassivePorts              $PASV $TOPORT/" $PROFTP_DIR/proftpd.conf

	sed -i 's/# AuthOrder\s.*/AuthOrder  mod_auth_file.c\nAuthUserFile  \/etc\/servconf\/ftpd.passwd\nAuthGroupFile  \/etc\/servconf\/ftpd.group\n\n#PAM Authentication\nPersistentPasswd    Off\nAuthPAM    Off/' $PROFTP_DIR/proftpd.conf
	if [ -z "`grep /bin/false /etc/shells`" ]; then echo "/bin/false" >> /etc/shells; fi
	CWD=`dirname $0`
	cd /etc/servconf
	if [ -f "/etc/servconf/ftpd.passwd" ]; then rm /etc/servconf/ftpd.passwd; fi
	if [ -f "/etc/servconf/ftpd.group" ]; then rm /etc/servconf/ftpd.group; fi
	UUID="`grep $2 /etc/passwd | cut -d: -f3 | tail -1`"
	echo "--- ftpasswd --stdin --passwd --name $2 --gid $GID  --uid $UUID --home $homedir --shell /bin/false ---"
	echo $3 | ftpasswd --stdin --passwd --name $2 --gid $GID  --uid $UUID --home $homedir --shell /bin/false
	echo "---  ftpasswd --gid $GID --name $grpname --member $2 --group "
	ftpasswd --gid $GID --name $grpname --member $2 --group
	cd ${CWD}

	# SETUP OPENSSL
	if [ "$SSL" == "Y" ]; then
		# to open certificate file run this :
		# openssl x509 -in certificate.crt -text -noout

		openssl genrsa -out server.key 2048
		touch openssl.cnf
		cat >> openssl.cnf <<EOF
[ req ] 
prompt = no 
distinguished_name = req_distinguished_name 

[ req_distinguished_name ] 
C = $C 
ST = $ST 
L = $L 
O = $O 
OU = $OU 
CN = $CN 
emailAddress = $ADDRESS 
EOF
	openssl req -config openssl.cnf -new -key server.key -out server.csr
        openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
        if [ "$SSL_DIR" != "/etc/ssl/host" ]; then
           mv ./server.key $SSL_DIR/$DOMAIN.key
           mv ./server.crt $SSL_DIR/$DOMAIN.crt
           mv ./server.csr $SSL_DIR/$DOMAIN.csr
        else
		   if [ ! -d "/etc/ssl/host" ]; then mkdir /etc/ssl/host; fi
           mv ./server.key /etc/ssl/host/$DOMAIN.key
           mv ./server.crt /etc/ssl/host/$DOMAIN.crt
           mv ./server.csr /etc/ssl/host/$DOMAIN.csr
        fi
	fi

	echo "Configuring Firewall..."
	ufw default deny
	ufw allow 21   # ftp
	ufw allow 22   # ssh
	ufw limit 22   # brute force protect
	ufw allow 80   # web
	ufw allow 443  # https
	ufw allow proto tcp to any port $PASV:$TOPORT
	writecnf "FW=$PASV:$TOPORT"
	#update-rc.d -f ufw default
	if [ "$DISTRO" == "jaunty" ] || [ "$DISTRO" == "karmic" ]; then
        ufw enable << EOF
y
EOF
	else
        ufw --force enable
	fi

	lighty-enable-mod fastcgi
	lighty-enable-mod fastcgi-php
	lighty-enable-mod simple-vhost
	/etc/init.d/lighttpd force-reload
	/etc/init.d/proftpd restart
	if [ "$5" != "N" ]; then /etc/init.d/fastcgi start; fi
	if [ "$useSSL" == "Y" ]; then
		info $DOMAIN $2 $3 1 $useMySQL $usePgSQL
	else
		info $DOMAIN $2 $3 $useMySQL $usePgSQL
	fi
}

function setup_nginx {
	# parameters :
	#   $LIVESERVER $SRVOPT $USERNAME $PASSWORD $DOC_ROOT $DOMAIN $VHOST ${EXT[@]};
	# setup_nginx N administrator adm1ns /home/wwwroot 192.168.75.133 Y
	# setup_nginx N administrator adm1ns /home/wwwroot N
	# $1 = DNS, $2 = $user, $3 = $passwd, $4 = $homedir, $5 = domain, $6 = $vhost

	if [ "`echo "$5" | grep -E "^(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])$"`" == "$5" ]; then
		# IP Address
		grpname="intranet"
		DOMAIN="$5"
		isIP="true"
	elif [ "`echo "$5" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$5" ]; then
		# Domain Name
		LAST_SITE_GID=`cat /etc/group | grep site | cut -d: -f1 | tail -1 | sed 's/[^0-9]*//g'`
		if [ -z "$LAST_SITE_GID" ]; then 
			grpname="site001"
			SITEGRP="001"
		else
			grpidx=$(expr $LAST_SITE_GID + 1)
			SITEGRP=$( printf '%03o' $grpidx)
			grpname="site$SITEGRP"
		fi
		# Split domain names and check for subdomain eg : ns1 or ns2
		IFS='.' read -a array <<< "$6"
		if [ ${#array[@]} -gt 2 ]; then
			i=0
			for x in "${array[@]}"
			do
				if [ $i -gt 0 ]; then DOM[$i]="$x"; fi
				i=$(expr $i + 1)
			done
			DOMAIN=$(IFS=.; echo "${DOM[*]}")
		else DOMAIN="$5"
		fi
		#sed -i "s/server_name  localhost;/server_name  www.$DOMAIN $DOMAIN;/" /tmp/site.conf
	elif [ "$5" == "N" ]; then
		DOMAIN="localhost";
		grpname="intranet";
	fi

	writecnf "OS=nginx"
	writecnf "HOMEDIR=$4"
	if [ "$5" != "N" ]; then homedir=$4/sites/$5; else homedir=$4; fi

	DUMP_GRP=`grep $grpname /etc/group`
	#echo "DETECT EXISTING group $DUMP_GRP"
	if [ -z "$DUMP_GRP" ]; then
		echo "- Adding group name $grpname..."
		addgroup $grpname;
		writecnf "GROUP=$grpname"
	else writecnf "GROUP=$grpname"
	fi

	if [ "$5" != "N" ]; then
		echo "Preparing Web Root Folders..."
		echo "Make dir $homedir"
		writecnf "VHOST=1"
		arr=$(echo $homedir | tr "\/" "\n")
		prefix=""
		for x in $arr
		do
			prefix+="/$x"
			if [ ! -d "$prefix" ]; then mkdir $prefix; fi
			inc=$(expr $inc + 1)
		done

		# Create default user
		GID=`cat /etc/group | grep $grpname | cut -d: -f3`
		basedir=`echo "$homedir" | sed -e 's/\//\\\\\//g'`
		USERID=`cat /etc/passwd | sed -n "/[[:digit:]]/p" | sed -n "/$basedir/p" | cut -d: -f3 | tail -1`
		if [ -z "$USERID" ]; then adduser --home $homedir --shell $DEFAULT_SHELL --gid $GID --gecos "" $2 --disabled-login --no-create-home; fi

		# -- START FOLDER PREPARATION --
		# Creating virtual host template folders...
		if [ ! -d "$prefix/logs" ]; then 
			mkdir $prefix/logs;
			chown -cR www-data:www-data $prefix/logs
		fi
		if [ ! -d "$prefix/cgi-bin" ]; then 
			mkdir $prefix/cgi-bin;
			chown -cR $2:$grpname $prefix/cgi-bin
			chmod -R g+rwx $prefix/cgi-bin
		fi
		if [ ! -d "$prefix/public_html" ]; then 
			mkdir $prefix/public_html; 
			chown -cR $2:$grpname $prefix/public_html
			chmod -R g+rwx $prefix/public_html
		fi
		if [ ! -d "$prefix/public_ftp" ]; then
			mkdir $prefix/public_ftp; 
			chown -cR $2:$grpname $prefix/public_ftp
			chmod -R g+rwx $prefix/public_ftp
		fi
		if [ ! -d "$prefix/cert" ]; then 
			mkdir $prefix/cert; 
			chown -cR $2:$grpname $prefix/cert
			chmod -R g+rwx $prefix/cert
		fi
		if [ ! -d "$prefix/database" ]; then 
			mkdir $prefix/database; 
			chown -cR $2:$grpname $prefix/database
			chmod -R g+rwx $prefix/database
		fi
		if [ ! -d "$prefix/conf" ]; then mkdir $prefix/conf; fi
		if [ ! -d "$prefix/temp" ]; then 
			mkdir $prefix/temp; 
			chown -cR $2:$grpname $prefix/temp
			chmod 777 $prefix/temp
		fi

		# count files on nginx config dir
		#NUM=`ls -l $NGINX_DIR/sites-enabled | wc -l`
		#SITEGRP=$( printf '%03o' $NUM)
		#GRP=`grep site$SITEGRP /etc/group`

		# Prepare php default template file
		echo "<?php" >> $prefix/public_html/index.php
		echo "phpinfo();" >> $prefix/public_html/index.php
		echo "?>" >> $prefix/public_html/index.php
		chown -cR $2:$grpname $prefix/public_html/index.php
		chmod 777 $prefix/temp

		# -- END OF FOLDER PREPARATION --

		# -- PREPARE NGINX & PHP
		if [ -f "/etc/php5/cgi/php.ini" ]; then cp /etc/php5/cgi/php.ini $prefix/conf; fi
		prefixes=`echo "$prefix" | sed -e 's/\//\\\\\//g'`
		sed -i "s/;upload_tmp_dir =/upload_tmp_dir = $prefixes\/temp/" $prefix/conf/php.ini
		sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 10M/' $prefix/conf/php.ini
		sed -i 's/disable_functions =/disable_functions = system,exec,show_source,mysql_list_dbs,ini_alter,openlog,syslog,dl,pfsockopen,symlink,link,chgrp,ini_restore,passthru,shell_exec,popen,proc_open,proc_get_status,proc_terminate,proc_close,set_time_limit,proc_nice,virtual,mb_send_mail/' $prefix/conf/php.ini
		sed -i 's/safe_mode = Off/safe_mode = On/' $prefix/conf/php.ini
		sed -i 's/expose_php = On/expose_php = Off/' $prefix/conf/php.ini
		chown -cR root:root $prefix/conf/php.ini

		if [ "$NUM" -gt 1 ]; then rm $NGINX_DIR/sites-enabled/*; fi
		uudecode $0
		tar zxf conf.tar.gz -C $TEMP_DIR
		rm conf.tar.gz
		if [ "$useSSL" == "Y" ]; then cp $TEMP_DIR/site-ssl.conf $NGINX_DIR/sites-available/$DOMAIN
		else cp $TEMP_DIR/site-std.conf $NGINX_DIR/sites-available/$DOMAIN
		fi
		if [ -f $TEMP_DIR/site-std.conf ]; then rm $TEMP_DIR/site-*.conf; fi
		if [ -f $TEMP_DIR/info.pl ]; then rm $TEMP_DIR/info.pl; fi

		home=`echo "$prefix" | sed -e 's/\//\\\\\//g'`
		if [ ! -z "$isIP" ]; then
			sed -i "s/server_name  localhost;$/server_name  _;/" $NGINX_DIR/sites-available/$DOMAIN
		else
			sed -i "s/server_name  localhost;$/server_name  www.$DOMAIN $DOMAIN;/" $NGINX_DIR/sites-available/$DOMAIN
		fi
		sed -i "s/access_log  \/var\/log\/nginx\/localhost.access.log;$/access_log  $home\/logs\/access.log;/" $NGINX_DIR/sites-available/$DOMAIN
		sed -i "s/error_log   \/var\/log\/nginx\/localhost.error.log;$/error_log  $home\/logs\/error.log;/" $NGINX_DIR/sites-available/$DOMAIN
		#sed -i "s/root   \/var\/www\/nginx-default;$/root   $home\/public_html;/" $NGINX_DIR/sites-available/$DOMAIN
		if [ -z "$DEPRECATED" ]; then
			LN=`awk "/#_root$/{print NR}" $NGINX_DIR/sites-available/$DOMAIN | head -1`
			sed -i $(expr $LN)"s/#_root/root $home\/public_html;/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i $(expr $LN + 1)'s/#_index/index index.php index.html index.htm;/' $NGINX_DIR/sites-available/$DOMAIN
		else
			LN=`awk "/#root$/{print NR}" $NGINX_DIR/sites-available/$DOMAIN | head -1`
            sed -i $(expr $LN)"s/#root/root $home\/public_html;/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i $(expr $LN + 1)'s/#index/index index.php index.html index.htm;/' $NGINX_DIR/sites-available/$DOMAIN
		fi
		sed -i "s/include _;$/include $home\/conf\/rewrite.conf;/" $NGINX_DIR/sites-available/$DOMAIN
		sed -i "s/fastcgi_pass   127.0.0.1:9000;$/fastcgi_pass   unix:$home\/logs\/socket.pid;/" $NGINX_DIR/sites-available/$DOMAIN
		sed -i "s/fastcgi_param  SCRIPT_FILENAME  \/var\/www\/nginx-default/fastcgi_param  SCRIPT_FILENAME  $home\/public_html/" $NGINX_DIR/sites-available/$DOMAIN
		if [ "$useSSL" == "Y" ]; then
			SSL_DIR=$prefix/cert
			writecnf "SSL=1"
			if [ -z "$DEPRECATED" ]; then
                        	LN=`awk "/#_root$/{print NR}" $NGINX_DIR/sites-available/$DOMAIN | head -1`
	                        sed -i $(expr $LN)"s/#_root/root $home\/public_html;/" $NGINX_DIR/sites-available/$DOMAIN
	                        sed -i $(expr $LN + 1)'s/#_index/index index.php index.html index.htm;/' $NGINX_DIR/sites-available/$DOMAIN
	                else
	                        LN=`awk "/#root$/{print NR}" $NGINX_DIR/sites-available/$DOMAIN | head -1`
	                        sed -i $(expr $LN)"s/#root/root $home\/public_html;/" $NGINX_DIR/sites-available/$DOMAIN
	                        sed -i $(expr $LN + 1)'s/#index/index index.php index.html index.htm;/' $NGINX_DIR/sites-available/$DOMAIN
	                fi
			sed -i "s/$(cat $NGINX_DIR/sites-available/$DOMAIN | sed -n "/server_name localhost;/p")/	server_name $DOMAIN;/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i "s/\/var\/www\/nginx-default/$home\/public_html/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i "s/ssl_certificate \/home\/admins\/server.crt;$/ssl_certificate $home\/cert\/$DOMAIN.crt;/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i "s/ssl_certificate_key \/home\/admins\/server.key;$/ssl_certificate_key $home\/cert\/$DOMAIN.key;/" $NGINX_DIR/sites-available/$DOMAIN
			sed -i "s/fastcgi_pass 127.0.0.1:9000;/fastcgi_pass   unix:$home\/logs\/socket.pid;/" $NGINX_DIR/sites-available/$DOMAIN
		fi

		echo "# --- YOUR CUSTOM NGINX REWRITE RULES ---" >> $prefix/conf/rewrite.conf
		chmod 666 $prefix/conf/rewrite.conf
		chown -cR $2:$grpname $prefix/conf/rewrite.conf
		ln -s $NGINX_DIR/sites-available/$DOMAIN $NGINX_DIR/sites-enabled/$DOMAIN

		# setup FastCGI service
		CWD=`dirname $0`
		cp -f $TEMP_DIR/fastcgi /etc/init.d/fastcgi
		rm -f $TEMP_DIR/fastcgi
		update-rc.d fastcgi defaults
	else
		echo "Preparing Web Root Folders..."
		echo "Make dir $homedir"
		arr=$(echo $homedir | tr "\/" "\n")
		prefix=""
			for x in $arr
			do
				prefix+="/$x"
				if [ ! -d "$prefix" ]; then mkdir $prefix; fi
				inc=$(expr $inc + 1)
			done

		# Create site group and default user
		GID=`cat /etc/group | grep $grpname | cut -d: -f3`
		basedir=`echo "$homedir" | sed -e 's/\//\\\\\//g'`
		USERID=`cat /etc/passwd | sed -n "/[[:digit:]]/p" | sed -n "/$basedir/p" | cut -d: -f3 | tail -1`
		if [ -z "$USERID" ]; then adduser --home $homedir --shell $DEFAULT_SHELL --gid $GID --gecos "" $2 --disabled-login --no-create-home; fi

        # Prepare php default template file
		echo "<?php" >> $homedir/index.php
		echo "phpinfo();" >> $homedir/index.php
		echo "?>" >> $homedir/index.php
		chown -cR $2:$grpname $homedir/index.php

		home=`echo "$prefix" | sed -e 's/\//\\\\\//g'`
		sed -i "s/localhost;$/$DOMAIN;/" $NGINX_DIR/sites-available/default
		sed -i "s/\/var\/www\/nginx-default/$home/" $NGINX_DIR/sites-available/default
		sed -i "s/index  index.html index.htm;$/index  index.php index.html index.htm;/" $NGINX_DIR/sites-available/default
		LN=`awk '/\#location ~ \\\.php/{print NR}' /etc/nginx/sites-available/default | tail -1`
		sed -i $(expr $LN)'s/\#//' $NGINX_DIR/sites-available/default
		#sed -i "s/#location ~ \.php$ {/location ~ \.php$ {/" $NGINX_DIR/sites-available/default
		sed -i "s/#fastcgi_index  index.php;/fastcgi_index  index.php;/" $NGINX_DIR/sites-available/default
		sed -i "s/#fastcgi_pass   127.0.0.1:9000;$/fastcgi_pass   unix:\/tmp\/socket.pid;/" $NGINX_DIR/sites-available/default
        sed -i "s/#fastcgi_param  SCRIPT_FILENAME  \/scripts/fastcgi_param  SCRIPT_FILENAME  $home/" $NGINX_DIR/sites-available/default
		#REP=`cat $NGINX_DIR/sites-available/default | sed -n "N;/\#includefastcgi_params;/p" | sed -e "s/includefastcgi_params/include fastcgi_params/" | sed -e "s/#//"`
		# Get the line number of occurence
		#LN=`cat /etc/nginx/sites-available/default | sed -n "N;/#includefastcgi_params;/p" | 
		LN=`awk '/#includefastcgi_params;/{print NR}' /etc/nginx/sites-available/default`
		sed -i "s/\#includefastcgi_params;/include fastcgi_params;/" $NGINX_DIR/sites-available/default
		# Replace comment from occurence line number
		sed -i $(expr $LN + 1)'s/\#//' $NGINX_DIR/sites-available/default

		if [ "$useSSL" == "Y" ]; then
			writecnf "SSL=1"
			# Remove HTTPS configuration lines
			LN=`awk '/# HTTPS/{print NR}' $NGINX_DIR/sites-available/default`
			TOTAL=`echo wc -l /etc/nginx/sites-available/default|awk '{print($1)}'`
			sed -i".bak" '${LN},${TOTAL}d' $NGINX_DIR/sites-available/default
                        SSL_DIR=/etc/ssl/host
			echo "# HTTPS server" >> $NGINX_DIR/sites-available/default
			echo "#\n\n" >> $NGINX_DIR/sites-available/default
			echo "server {" >> $NGINX_DIR/sites-available/default
			echo "        listen 443;" >> $NGINX_DIR/sites-available/default
			echo "        server_name $DOMAIN;" >> $NGINX_DIR/sites-available/default
			echo "        ssl on;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_certificate /etc/ssl/host/$DOMAIN.crt;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_certificate_key /etc/ssl/host/$DOMAIN.key;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_session_timeout 5m;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_protocols SSLv2 SSLv3 TLSv1;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_ciphers ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;" >> $NGINX_DIR/sites-available/default
			echo "        ssl_prefer_server_ciphers on;" >> $NGINX_DIR/sites-available/default
			echo "        location / {" >> $NGINX_DIR/sites-available/default
			echo "           root $homedir;" >> $NGINX_DIR/sites-available/default
			echo "           index index.php index.html index.htm index.pl;" >> $NGINX_DIR/sites-available/default
			echo "        }" >> $NGINX_DIR/sites-available/default
			echo "        location ~ \.php$ {" >> $NGINX_DIR/sites-available/default
			echo "                fastcgi_pass unix:/tmp/socket.pid;" >> $NGINX_DIR/sites-available/default
			echo "                fastcgi_index index.php;" >> $NGINX_DIR/sites-available/default
			echo "                fastcgi_param SCRIPT_FILENAME $homedir\$fastcgi_script_name;" >> $NGINX_DIR/sites-available/default
			echo "                include fastcgi_params;" >> $NGINX_DIR/sites-available/default
			echo "        }" >> $NGINX_DIR/sites-available/default
			echo "        #location ~ \.pl|cgi$ {" >> $NGINX_DIR/sites-available/default
			echo "        #        try_files $uri =404;" >> $NGINX_DIR/sites-available/default
			echo "        #        gzip off;" >> $NGINX_DIR/sites-available/default
			echo "        #        fastcgi_pass 127.0.0.1:8999;" >> $NGINX_DIR/sites-available/default
			echo "        #        fastcgi_index index.pl;" >> $NGINX_DIR/sites-available/default
			echo "        #        fastcgi_param SCRIPT_FILENAME /var/www/nginx-default$fastcgi_script_name;" >> $NGINX_DIR/sites-available/default
			echo "        #        include fastcgi_params;" >> $NGINX_DIR/sites-available/default
			echo "        #}" >> $NGINX_DIR/sites-available/default
			echo "}" >> $NGINX_DIR/sites-available/default
		fi

		# Registering autoboot script on server reboot
		if [ -f "/etc/rc.local" ]; then rm /etc/rc.local; fi
		echo "#!/bin/sh -e" >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# rc.local" >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# This script is executed at the end of each multiuser runlevel." >> /etc/rc.local
		echo "# Make sure that the script will \"exit 0\" on success or any other" >> /etc/rc.local
		echo "# value on error." >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# In order to enable or disable this script just change the execution" >> /etc/rc.local
		echo "# bits." >> /etc/rc.local
		echo "#" >> /etc/rc.local
		echo "# By default this script does nothing." >> /etc/rc.local
		echo " " >> /etc/rc.local
		echo "su -m www-data -c \"/usr/bin/php5-cgi -d open_basedir=$homedir -b /tmp/socket.pid&\"" >> /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		su -m www-data -c "/usr/bin/php5-cgi -d open_basedir=$homedir -b /tmp/socket.pid&"
	fi

	# Configuring FTP
	echo "Configuring Proftpd..."
	if [ ! -f "$PROFTP_DIR/proftpd.bak.conf" ]; then
		echo "Backing up proftpd original configuration...";
		cp $PROFTP_DIR/proftpd.conf $PROFTP_DIR/proftpd.bak.conf;
	else
		if [ -f "$PROFTP_DIR/proftpd.conf" ]; then rm $PROFTP_DIR/proftpd.conf; fi
		CWD=`dirname $0`
		cd /
		cp $PROFTP_DIR/proftpd.bak.conf $PROFTP_DIR/proftpd.conf
		cd ${CWD}
	fi

	sed -i 's/UseReverseDNS\s.*//' $PROFTP_DIR/proftpd.conf
	sed -i 's/UseIPv6\s.*/UseIPv6                         Off\nUseReverseDNS                   Off/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# DefaultRoot\s.*/DefaultRoot                      ~/' $PROFTP_DIR/proftpd.conf
	sed -i 's/# RequireValidShell\s.*/RequireValidShell               Off/' $PROFTP_DIR/proftpd.conf
	PASV=$(( $RANDOM % 1200 + 50190 ))
	TOPORT=`expr $PASV + 501`
	sed -i "s/# PassivePorts\s.*/PassivePorts              $PASV $TOPORT/" $PROFTP_DIR/proftpd.conf

	sed -i 's/# AuthOrder\s.*/AuthOrder  mod_auth_file.c\nAuthUserFile  \/etc\/servconf\/ftpd.passwd\nAuthGroupFile  \/etc\/servconf\/ftpd.group\n\n#PAM Authentication\nPersistentPasswd    Off\nAuthPAM    Off/' $PROFTP_DIR/proftpd.conf
	if [ -z "`grep /bin/false /etc/shells`" ]; then echo "/bin/false" >> /etc/shells; fi
	CWD=`dirname $0`
	cd /etc/servconf
	if [ -f "/etc/servconf/ftpd.passwd" ]; then rm /etc/servconf/ftpd.passwd; fi
	if [ -f "/etc/servconf/ftpd.group" ]; then rm /etc/servconf/ftpd.group; fi
	basedir=`echo "$homedir" | sed -e 's/\//\\\\\//g'`
	echo "----- cat /etc/passwd | sed -n '/[[:digit:]]\\{${#GID}\\}/p' | sed -n '/$basedir/p' | cut -d: -f3  -----"
	USERID=`cat /etc/passwd | sed -n "/[[:digit:]]/p" | sed -n "/$basedir/p" | cut -d: -f3 | tail -1`
	echo "----- echo $3 | ftpasswd --stdin --passwd --name $2 --gid $GID  --uid $USERID --home $homedir --shell /bin/false  ----"
	echo $3 | ftpasswd --stdin --passwd --name $2 --gid $GID  --uid $USERID --home $homedir --shell /bin/false
	ftpasswd --gid $GID --name $grpname --member $2 --group
	cd ${CWD}

	# SETUP OPENSSL
	if [ "$useSSL" == "Y" ]; then
		# to open certificate file run this : 
		# openssl x509 -in certificate.crt -text -noout

		openssl genrsa -out server.key 2048
		touch openssl.cnf
		cat >> openssl.cnf <<EOF
[ req ] 
prompt = no 
distinguished_name = req_distinguished_name 

[ req_distinguished_name ] 
C = $C 
ST = $ST 
L = $L 
O = $O 
OU = $OU 
CN = $CN 
emailAddress = $ADDRESS 
EOF
	openssl req -config openssl.cnf -new -key server.key -out server.csr
        openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
        if [ "$SSL_DIR" != "/etc/ssl/host" ]; then
           mv ./server.key $SSL_DIR/$DOMAIN.key
           mv ./server.crt $SSL_DIR/$DOMAIN.crt
           mv ./server.csr $SSL_DIR/$DOMAIN.csr
       else
	   if [ ! -d "/etc/ssl/host" ]; then mkdir /etc/ssl/host; fi
           mv ./server.key /etc/ssl/host/$DOMAIN.key
           mv ./server.crt /etc/ssl/host/$DOMAIN.crt
           mv ./server.csr /etc/ssl/host/$DOMAIN.csr
      fi
fi

	echo "Configuring Firewall..."
	ufw default deny
	ufw allow 21   # ftp
	ufw allow 22   # ssh
	ufw limit 22   # brute force protect
	ufw allow 80   # web
	ufw allow 443  # https
	ufw allow proto tcp to any port $PASV:$TOPORT
	writecnf "FW=$PASV:$TOPORT"
	#update-rc.d -f ufw default
	if [ "$DISTRO" == "jaunty" ] || [ "$DISTRO" == "karmic" ]; then
        ufw enable << EOF
y
EOF
	else
        ufw --force enable
	fi

	echo "Starting nginx..."
	/etc/init.d/nginx restart
	/etc/init.d/proftpd restart
	if [ -f /etc/init.d/fastcgi ]; then /etc/init.d/fastcgi start; fi
	if [ "$useSSL" == "Y" ]; then
		info $DOMAIN $2 $3 1 $useMySQL $usePgSQL
	else
		info $DOMAIN $2 $3 $useMySQL $usePgSQL
	fi
}

function install {
	echo "Please wait while setup downloading packages"

	# Extracting php5 extensions from params
	declare -a EXT
	i=0
	for f in "$@"; 
	do
		if [ ! -z "`echo $f | grep php5`" ]; then EXT[i]="$f"; fi
		i="`expr $i + 1`"
	done

	if [ -d "/etc/servconf/" ]; then mkdir /etc/servconf; fi
	if [ -f /etc/servconf/servconf.ini ]; then rm -Rf /etc/servconf/servconf.ini; fi

	DB=""
	while true; do echo -n .; sleep 1; done &
	apt-get -y update > /dev/null
	kill $!; trap 'kill $!' SIGTERM
    echo done
	if [ "$2" == "4" ] || [ "$2" == "5" ] || [ "$2" == "6" ] || [ "$2" == "7" ]; then
	    if [ -z "$DB" ]; then 
			DB=" mysql-server  php5-mysql"; 
			useMySQL="Y"
		fi
	fi
	if [ "$2" -ge 8 ]; then
	    case "$VERSION" in
			("9.04") DB=" postgresql-8.3 php5-pgsql";;
			("9.10") DB=" postgresql-8.3 php5-pgsql";;
			("10.04") DB=" postgresql-8.4 php5-pgsql";;
			("10.04.1") DB=" postgresql-8.4 php5-pgsql";;
			("10.04.2") DB=" postgresql-8.4 php5-pgsql";;
			("10.04.3") DB=" postgresql-8.4 php5-pgsql";;
			("10.04.4") DB=" postgresql-8.4 php5-pgsql";;
			("10.10") DB=" postgresql-8.4 php5-pgsql";;
			("11.04") DB=" postgresql-8.4 php5-pgsql";;
			("11.10") DB=" postgresql-8.4 php5-pgsql";;
			("12.04") DB=" postgresql-9 php5-pgsql";;
			("12.04.1") DB=" postgresql-9 php5-pgsql";;
			("12.04.2") DB=" postgresql-9 php5-pgsql";;
			("12.04.3") DB=" postgresql-9 php5-pgsql";;
			("12.10") DB=" postgresql php5-pgsql";;
			("13.04") DB=" postgresql php5-pgsql";;
			("13.10") DB=" postgresql php5-pgsql";;
			("14.04") DB=" postgresql php5-pgsql";;
			("14.04.1") DB=" postgresql php5-pgsql";;
			("14.10") DB=" postgresql php5-pgsql";;
	    esac
		usePgSQL="Y"
	fi
	if [ "$2" == "12" ] || [ "$2" == "13" ] || [ "$2" == "14" ] || [ "$2" == "15" ]; then DB="$DB mysql-server php5-mysql"; fi
	if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
	    #echo "mysql-server/root_password string $4" | debconf-set-selections
		#echo "mysql-server/root_password_again string $4" | debconf-set-selections
		debconf-set-selections <<< 'mysql-server mysql-server/root_password password $4'
		debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password $4'
	fi

	apt-get -y install debconf-utils
	echo "proftpd-basic shared/proftpd/inetd_or_standalone select standalone" | debconf-set-selections
	if [ -z "$DEPRECATED" ]; then
		PACKAGES="proftpd-basic"
	else
		PACKAGES="proftpd php5-suhosin"
	fi
	# Is this used as DNS server
	if [ "$1" == "Y" ]; then
	    # DNS Server Mode, please choose FCGI or use ModPHP
	    if [ "$2" == "5" ] || [ "$2" == "9" ] || [ "$2" == "13" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install bind9 bind9utils dnsutils sharutils apache2 libapache-mod-security apache2-mpm-worker apache2-suexec-custom apache2-utils apache2.2-common libapache2-mod-fcgid $PACKAGES php5 php5-cli php5-cgi php-pear ${EXT[@]} #> install.log
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"bind9 bind9utils dnsutils sharutils apache2 libapache-mod-security apache2-mpm-worker apache2-suexec-custom apache2-utils apache2.2-common libapache2-mod-fcgid $PACKAGES php5 php5-cli php5-cgi php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			#    DNS  USER PWD DIR DOMAIN VHOST
			setup_fcgi_mode $1 $3 $4 $5 $6 $8
	    elif [ "$2" == "3" ] || [ "$2" == "7" ] || [ "$2" == "11" ] || [ "$2" == "15" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install bind9 bind9utils dnsutils sharutils lighttpd $PACKAGES php5-cgi php5-cli php-pear ${EXT[@]}
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"bind9 bind9utils dnsutils sharutils lighttpd $PACKAGES php5-cgi php5-cli php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_lighttpd $1 $3 $4 $5 $6 $7
		elif [ "$2" == "2" ] || [ "$2" == "6" ] || [ "$2" == "10" ] || [ "$2" == "14" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install bind9 bind9utils dnsutils sharutils nginx $PACKAGES php5-cgi php5-cli php-pear ${EXT[@]}
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"bind9 bind9utils dnsutils sharutils nginx $PACKAGES php5-cgi php5-cli php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_nginx $1 $3 $4 $5 $6 $7
		else
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install bind9 bind9utils dnsutils sharutils apache2 libapache-mod-security apache2-mpm-prefork libapache2-mod-php5 $PACKAGES php5 php5-cli php5-cgi php-pear ${EXT[@]} #> install.log
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"bind9 bind9utils dnsutils sharutils apache2 libapache-mod-security apache2-mpm-prefork libapache2-mod-php5 $PACKAGES php5 php5-cli php5-cgi php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_thread_mode $1 $3 $4 $5 $6 $8 #> install.log
		fi
	else
	    if [ "$2" == "5" ] || [ "$2" == "9" ] || [ "$2" == "13" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install sharutils apache2 libapache-mod-security apache2-mpm-worker apache2-suexec-custom apache2-utils apache2.2-common libapache2-mod-fcgid $PACKAGES php5 php5-cli php-pear ${EXT[@]} #> install.log
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"sharutils apache2 libapache-mod-security apache2-mpm-worker apache2-suexec-custom apache2-utils apache2.2-common libapache2-mod-fcgid $PACKAGES php5 php5-cli php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_fcgi_mode $1 $3 $4 $5 $6 $7
	    elif [ "$2" == "3" ] || [ "$2" == "7" ] || [ "$2" == "11" ] || [ "$2" == "15" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install sharutils lighttpd $PACKAGES php5-cgi php5-cli php-pear ${EXT[@]}
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"sharutils lighttpd $PACKAGES php5-cgi php5-cli php-pear $extension \"" 
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_lighttpd $1 $3 $4 $5 $6 $7
	    elif [ "$2" == "2" ] || [ "$2" == "6" ] || [ "$2" == "10" ] || [ "$2" == "14" ]; then
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install sharutils nginx $PACKAGES libfcgi-perl php5-cgi php5-cli php-pear ${EXT[@]}
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"sharutils nginx $PACKAGES libfcgi-perl php5-cgi php5-cli php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			setup_nginx $1 $3 $4 $5 $6 $7
	    else
			apt-get -y --reinstall -o Dpkg::Options::="--force-confmiss" install sharutils apache2 libapache-mod-security apache2-mpm-prefork libapache2-mod-php5 $PACKAGES php5 php5-cli php-pear ${EXT[@]} #> install.log
			extension="${EXT[@]}"
			writecnf "UNINSTALL=\"sharutils apache2 libapache-mod-security apache2-mpm-prefork libapache2-mod-php5 $PACKAGES php5 php5-cli php-pear $extension \""
			if [ ! -z "$DB" ]; then
				echo "Installing Database..."
				export DEBIAN_FRONTEND=noninteractive
				apt-get -q -y install $DB #> install.log
				if [ ! -z "`echo "$DB" | grep 'mysql'`" ]; then
					/etc/init.d/mysql restart
				fi
			fi
			# $LIVESERVER $USER $PASSWD $DOC_ROOT $DOMAIN $VHOST
			setup_thread_mode $1 $3 $4 $5 $6 $7;
	    fi
	fi
    #kill $!; trap 'kill $!' SIGTERM
    #echo done
}

clear

printf "${YLW}***********************************************************************\n"
printf "*               Ubuntu Server Configuration Installer                 *\n"
printf "*                  Supported version (9.04 - 15.10)                   *\n"
printf "*                         ardie_b@yahoo.com                           *\n"
printf "*                     			                              *\n"
printf "*                                                                     *\n"
printf "*  License : GNU GPL v3.0                                             *\n"
printf "*  						                      *\n"
printf "*  Permission to use, copy, modify, and/or distribute this software   *\n"
printf "*  for any purpose with or without fee is hereby granted, provided    *\n"
printf "*  that the above copyright notice and this permission notice appear  *\n"
printf "*  in all copies.                                                     *\n"
printf "*                                                                     *\n"
printf "*  THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL      *\n"
printf "*  WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED      *\n"
printf "*  WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE   *\n"
printf "*  AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUEN   *\n"
printf "*  TIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, *\n"
printf "*  DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR   *\n"
printf "*  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE    *\n"
printf "*  USE OR PERFORMANCE OF THIS SOFTWARE.                               *\n"
printf "*                                                                     *\n"
printf "***********************************************************************${NML}\n"
echo
printf "Installed OS  : ${YLW}$OSNAME${NML}\n"
RAM=$(expr $MEMSIZE / 1000)
printf "Installed RAM : ${YLW}$RAM MB${NML}\n"
echo

# Updating apt repository to released.ubuntu.com
if [ "$isNEW" == 0 ]; then
  mv /etc/apt/sources.list /etc/apt/sources.old.list
  echo "# APT Repository update for unsupported ubuntu version" >> /etc/apt/sources.list
  echo "# Generated by Ubuntu Server Configuration from http://www.syntaxweaver.com" >> /etc/apt/sources.list
  echo "# " >> /etc/apt/sources.list
  echo "" >> /etc/apt/sources.list
  echo "# Required" >> /etc/apt/sources.list
  echo "deb $REPO $DISTRO main restricted universe multiverse" >> /etc/apt/sources.list
  echo "deb $REPO $DISTRO-updates main restricted universe multiverse" >> /etc/apt/sources.list
  echo "deb $REPO $DISTRO-security main restricted universe multiverse" >> /etc/apt/sources.list
  echo "# Optional" >> /etc/apt/sources.list
  echo "#deb $REPO $DISTRO-backports main restricted universe multiverse" >> /etc/apt/sources.list
fi

if [ -f /etc/timezone ]; then
  TZ=`cat /etc/timezone`
  printf "${YLW}$TZ ${NML}is your current Time Zone, use this setting ? [Y/n] ${YLW}"
  while read tzdata; do
    case "$tzdata" in
       y) break;;
       Y) break;;
       n) break;;
       N) break;;
       '') break;;
       *) printf "${NML}${RED}Incorrect answer!\n${YLW}$TZ ${NML}is your current Time Zone, use this setting ? [Y/n] ${YLW}";;
    esac
  done
  printf "${NML}"
  if [ "$tzdata" == "n" ] || [ "$tzdata" == "N" ]; then
     dpkg-reconfigure tzdata
  elif [ -z "$tzdata" ]; then
     tzdata="Y"
  fi
fi

   # exprimental not yet implemented
   LIVESERVER='N'

   printf "Do you want to use virtual host support (host multiple sites) [Y/n] : ${YLW}"
   while read VHOST; do
    case "$VHOST" in
       y) break;;
       Y) break;;
       n) VHOST='N'; break;;
       N) break;;
       '')break;;
       *) printf "${NML}${RED}Incorrect answer!\n${NML}Do you want to use virtual host support (host multiple sites) [Y/n] : ${YLW}";;
    esac
  done
  printf "${NML}"
  if [ -z "$VHOST" ] || [ "$VHOST" == "y" ] || [ "$VHOST" == "Y" ]; then
     printf "What is your domain name [yourdomainname.com or ip address] : ${YLW}"
     while read DOMAIN; do
	 len=`expr ${#DOMAIN}`
	if [ $len -gt 0 ]; then
	   if [ "`echo "$DOMAIN" | grep -Po '(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)'`" == "$DOMAIN" ]; then break;
	   elif [ "`echo $DOMAIN | grep -E "^(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])$"`" == "$DOMAIN" ]; then break;
	   elif [ -z "$DOMAIN" ]; then  printf "${RED}Domain name is not valid !\n${NML}What is your domain name [yourdomainname.com or ip address] : ${YLW}"
	   else printf "${RED}Domain name is not valid !\n${NML}What is your domain name [yourdomainname.com or ip address] : ${YLW}"
	   fi
	else printf "${RED}Domain name is not valid !\n${NML}What is your domain name [yourdomainname.com or ip address] : ${YLW}"
	fi
     done
     VHOST='Y'
  else DOMAIN="";
  fi
  printf "${NML}"


function is_int() { return $(test "$@" -eq "$@" > /dev/null 2>&1); }
echo
z=1
arr=$(echo $(ifconfig | awk -F "[: ]+" '/inet addr:/ { if ($4 != "127.0.0.1") print $4 }') | tr "\n" "\n")
for x in $arr
do
    echo "$z. $x";
    z=$(expr $z + 1);
done

z=$(expr $z - 1)

printf "Which IP address do you want to assign to this host : ${YLW}"
while read MAINIP; do
   if $(is_int "${MAINIP}");
   then
        if [ "${MAINIP}" -le 0 ] || [ "${MAINIP}" -gt "$z" ]; then
            printf "${RED}Invalid value!\n${NML}Which IP address do you want to assign to this host : ${YLW}"
        else break;
        fi
   else
       printf "${RED}Invalid value!\n${NML}Which IP address do you want to assign to this host : ${YLW}"
   fi
done

printf "${NML}\n"
printf "Please provide administrator username for main website : ${YLW}"
while read USERNAME; do
   if [ ! -z "$USERNAME" ] && [ "`echo "$USERNAME" | grep -o -w '^[a-z][-a-z0-9]*\w\{4,15\}\$'`" == "$USERNAME" ]; then break;
   else printf "${NML}${RED}Invalid characters or minimul length 5 chars not match!\n${NML}Please provide administrator username for main website : ${YLW}"
   fi
done

printf "${NML}"
printf "Please provide password : "
stty_orig=`stty -g`
stty -echo
while read PASSWORD; do
	if [ -z "$PASSWORD" ]; then
	   printf "${RED}Password cannot empty!\n${NML}Please provide password : "
	else break;
	fi
done
stty $stty_orig
echo
clear
printf "\n"
echo "[${BLD}Standard${NML}] ${YLW}(Min RAM 256 MB)${NML}"
echo "1.  ${GRN}Apache2, PHP5, Proftpd${NML}"
echo "2.  ${GRN}Nginx, PHP5, Proftpd${NML}"
echo "3.  ${GRN}Lighttpd, PHP5, Proftpd${NML}"
printf "\n[${BLD}MySQL${NML}] ${YLW}(Min RAM 2GB)${NML}\n"
echo "4.  ${GRN}Apache2, MySQL, PHP5, Proftpd ${YLW}(Small Site)${NML}" 
echo "5.  ${GRN}Apache2 with ${CYN}FastCGI${GRN}, MySQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "6.  ${GRN}Nginx, MySQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "7.  ${GRN}Lighttpd, MySQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
printf "\n[${BLD}PostgreSQL${NML}] ${YLW}(Min RAM 2GB)${NML}\n"
echo "8.  ${GRN}Apache2, PostgreSQL, PHP5, Proftpd ${YLW}(Small Site)${NML}"
echo "9.  ${GRN}Apache2 with ${CYN}FastCGI${GRN}, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "10. ${GRN}Nginx, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "11. ${GRN}Lighttpd, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
printf "\n[${BLD}MySQL, PostgreSQL${NML}] ${YLW}(Min RAM 4GB)${NML}\n"
echo "12. ${GRN}Apache2, MySQL, PostgreSQL, PHP5, Proftpd ${YLW}(Small Site)${NML}"
echo "13. ${GRN}Apache2 with ${CYN}FastCGI${GRN}, MySQL, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "14. ${GRN}Nginx, MySQL, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo "15. ${GRN}Lighttpd$, MySQL, PostgreSQL, PHP5, Proftpd ${YLW}(Web Hosting)${NML}"
echo
printf "Select your prefered server configuration [1 - 15] : ${YLW}"
SRVOPT=0
while read options; do
  case "$options" in
    1) SRVOPT=$options; break;;
    2) SRVOPT=$options; break;;
    3) SRVOPT=$options; break;;
    4) SRVOPT=$options; break;;
    5) SRVOPT=$options; break;;
    6) SRVOPT=$options; break;;
    7) SRVOPT=$options; break;;
    8) SRVOPT=$options; break;;
    9) SRVOPT=$options; break;;
    10) SRVOPT=$options; break;;
    11) SRVOPT=$options; break;;
    12) SRVOPT=$options; break;;
    13) SRVOPT=$options; break;;
    14) SRVOPT=$options; break;;
    15) SRVOPT=$options; break;;
    *) printf "${RED}Incorrect value option!\n${NML}Select your prefered server configuration [1 - 15] : " ;;
  esac
done

printf "${NML}Where do you want to place your default web documents [ default : /var/www ] : ${YLW}"
while read DOC_ROOT; do
   if [ "`echo "$DOC_ROOT" | grep -Eow "(^\/([a-zA-Z0-9\ \/_-])+)+"`" = "$DOC_ROOT" ]; then break;
   else printf "${NML}${RED}Invalid directory name!\n${NML}Where do you want to place your default web documents [ default : /var/www ] : ${YLW}"
   fi
done
printf "${NML}"
if [ -z "$DOC_ROOT" ]; then DOC_ROOT='/var/www'; fi
echo
echo "To install these extension fill it with comma separated"
printf "0.  ${GRN}don't install any of these ${MGT}(Default)${NML}\n"
printf "1.  ${GRN}cURL${NML}\n"
printf "2.  ${GRN}GD Library${NML}\n"
printf "3.  ${GRN}Image Magick${NML}\n"
printf "4.  ${GRN}IMAP${NML}\n"
printf "5.  ${GRN}Interbase${NML}\n"
printf "6.  ${GRN}MCrypt${NML}\n"
printf "7.  ${GRN}Memcached${NML}\n"
printf "8.  ${GRN}ODBC${NML}\n"
printf "9.  ${GRN}SNMP${NML}\n"
printf "10. ${GRN}SQLite${NML}\n"
printf "11. ${GRN}Sybase / MS SQL Server${NML}\n"
printf "12. ${GRN}Tidy${NML}\n"
printf "13. ${GRN}XCache${NML}\n"
printf "14. ${GRN}XmlRpc${NML}\n"
printf "15. ${GRN}XSL${NML}\n"
echo
printf "Do you want to install one of these PHP extensions [ 1,2,6,8,... ] : ${YLW}"
if [ "$VERSION" == "9.04" ] || [ "$VERSION" == "9.10" ]; then
   extension=('None' 'php5-curl' 'php5-gd' 'php5-imagick' 'php5-imap' 'php5-interbase' 'php5-mcrypt' 'php5-memcache' 'php5-odbc' 'php5-snmp' 'php5-sqlite' 'php5-sybase' 'php5-tidy' 'php5-xcache' 'php5-xmlrpc' 'php5-xsl');
else
   extension=('None' 'php5-curl' 'php5-gd' 'php5-imagick' 'php5-imap' 'php5-interbase' 'php5-mcrypt' 'php5-memcached' 'php5-odbc' 'php5-snmp' 'php5-sqlite' 'php5-sybase' 'php5-tidy' 'php5-xcache' 'php5-xmlrpc' 'php5-xsl');
fi
inc=0
declare -a EXT
declare -a UNKNOWN
while read enum; do
   if [ ! -z $enum ]; then
      arr=$(echo $enum | tr "," "\n")

      for x in $arr
      do
         #echo ${extension[$x]}
	 NUM=`awk -v var="$x" 'BEGIN{ printf"%0.f\n", var}'`
         if [ ! -z "${extension[$NUM]}" ]; then
            EXT[$inc]="${extension[$NUM]}"
         else
            UNKNOWN[${#UNKNOWN[@]}]="$x"
	 fi
         inc=$(expr $inc + 1)
      done
      #echo ${#EXT[@]} "<>" $inc
      if [ ${#EXT[@]} != $inc ]; then
        printf "${RED}${UNKNOWN[*]} is not an option!\n${NML}Do you want to install one of these PHP extensions [ 1,2,6,8,... ] : ${YLW}";
        inc=0;
        i=${#UNKNOWN[@]}
        until [  $i -eq -1 ]; do
           unset UNKNOWN[$i]
           i=$(expr $i - 1)
        done
        #echo "CURRENT ARRAY LENGTH : ${#UNKNOWN[@]}"
        i=${#EXT[@]}
        until [  $i -eq -1 ]; do
           unset EXT[$i]
           i=$(expr $i - 1)
        done
        #echo "ARRAY LENGTH : ${#EXT[@]}"
      elif [ ${#EXT[@]} == $inc ]; then break;
      fi
   else break;
   fi
done

#for (( i=0; i<${#EXT[@]}; i++ ));
#do
#   echo ${EXT[$i]}
#done

printf "${NML}Do you want to generate self-signed SSL certificate [Y/n] : ${YLW}"
while read useSSL; do
  case "$useSSL" in
    y) useSSL="Y"; break;;
    Y) break;;
    n) useSSL="N"; break;;
    N) useSSL="N"; break;;
    '') useSSL="Y"; break;;
    *) printf "${NML}${RED}Incorrect answer!\n${NML}Do you want to generate self-signed SSL certificate [Y/n] : ${YLW}";;
  esac
done
printf "\n${NML}"
if [ -z $useSSL ] || [ "$useSSL" == "y" ] || [ "$useSSL" == "Y" ]; then
    printf "Country Name (2 letter code) [AU] : ${YLW}"
    while read C; do
       CN=`echo "$C" | grep -E '^[a-zA-Z]{2,2}'`
       if [ ${#CN} -eq 2 ]; then
          NAME=`echo $C | tr '[:lower:]' '[:upper:]'`;
	  C="$NAME"
	  break;
       else printf "${NML}${RED}Invalid country code!\n${NML}Country Name (2 letter code) [AU] : ${YLW}"
       fi
    done
    printf "${NML}State or Province Name (full name) [Some-State] : ${YLW}"
    read ST;
    ST=`echo $ST | tr " " "\n" | nawk ' { out = out" "toupper(substr($0,1,1))substr($0,2) } END{ print substr(out,2) } '`
    printf "${NML}Locality Name (eg, city) [] : ${YLW}"
    read L;
    L=`echo $L | tr " " "\n" | nawk ' { out = out" "toupper(substr($0,1,1))substr($0,2) } END{ print substr(out,2) } '`
    printf "${NML}Organization Name (eg, company) [Internet Widgits Pty Ltd] : ${YLW}"
    read O;
    O=`echo $O | tr " " "\n" | nawk ' { out = out" "toupper(substr($0,1,1))substr($0,2) } END{ print substr(out,2) } '`
    printf "${NML}Organizational Unit Name (eg, section) [] : ${YLW}"
    read OU;
    OU=`echo $OU | tr " " "\n" | nawk ' { out = out" "toupper(substr($0,1,1))substr($0,2) } END{ print substr(out,2) } '`
    printf "${NML}Common Name (eg, YOUR name) [] : ${YLW}"
    read CN;
    CN=`echo $CN | tr " " "\n" | nawk ' { out = out" "toupper(substr($0,1,1))substr($0,2) } END{ print substr(out,2) } '`
    printf "${NML}Email Address [] : ${YLW}"
    while read ADDRESS; do
       if [ ! -z "$ADDRESS" ] && [ "`echo "$ADDRESS" | grep -E -o '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'`" == "$ADDRESS" ]; then
           break;
       else printf "${NML}${RED}Incorrect email!\n${NML}Email Address [] : "
       fi
    done
    printf "${NML}\n\n"
    useSSL="Y"
fi

printf "${NML}Do you want to start installation ? [Y/n] : ${YLW}"
while read start; do
  case "$start" in
    y) start="Y"; break;;
    Y) break;;
    n) start="N"; break;;
    N) break;;
    '') start="Y"; break;;
    *) printf "${NML}${RED}Incorrect answer!\n${NML}Do you want to start installation ? [Y/n] : ${YLW}";;
  esac
done

if [ "$start" == "Y" ]; then
	clear
	printf "${NML}"
	if [ "`echo "$LIVESERVER" | sed -e 's/^ *//' -e 's/ *$//'`" == "N" ]; then
		install $LIVESERVER $SRVOPT $USERNAME $PASSWORD $DOC_ROOT $DOMAIN $VHOST ${EXT[@]};
	else
		install $LIVESERVER $SRVOPT $USERNAME $PASSWORD $DOC_ROOT $PRIMARYNS $SECONDNS $VHOST ${EXT[@]};
	fi
else
	printf "${NML}"
fi


exit 0;
begin 644 conf.tar.gz
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
9*[NR*[NR*[NR*[NR*__I\CO@3#XQ`%``````
`
end
