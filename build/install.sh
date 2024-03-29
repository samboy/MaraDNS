#!/bin/sh

# Shell script which installs the MaraDNS files in the appropriate directories

# Set the directory with the build-related scripts 
if [ -z "$BUILDDIR" ] ; then
	BUILDDIR="build"
fi

# Set the directory which is the top-level MaraDNS directory
if [ -z "$TOPLEVEL" ] ; then
	TOPLEVEL=$( pwd )
fi

cd $TOPLEVEL

# We call install.locations to set BIN, SBIN, MAN1, MAN8, and DOCS
# It is in a separate file to insure that install.sh and uninstall.sh
# have the same values
. $BUILDDIR/install.locations

# Make sure that the various install directories actually exist
if [ ! -d "$BIN" ] ; then
	echo The directory $BIN does not exist.  Please edit the file
	echo install.locations by hand.
	exit 2
fi
if [ ! -d "$SBIN" ] ; then
	echo The directory $SBIN does not exist.  Please edit the file
	echo install.locations by hand.
	exit 3
fi
if [ ! -d "$MAN1" ] ; then
	echo The directory $MAN1 does not exist.  Please edit the file
	echo install.locations by hand.
	exit 4
fi
if [ ! -d "$MAN5" ] ; then
	echo The directory $MAN5 does not exist.  Please edit the file
	echo install.locations by hand.
	exit 7
fi
if [ ! -d "$MAN8" ] ; then
	echo The directory $MAN8 does not exist.  Please edit the file
	echo install.locations by hand.
	exit 5
fi

# Make sure we have a place to put documents
# Thanks to Paul Howard for the following six lines
if [ ! -d "$( dirname $DOCS )" ] ; then
	if ! mkdir "$( dirname $DOCS )" ; then
		echo unable to make the $( dirname $DOCS ) directory. 
		exit 6
	fi
fi
if [ ! -d "$DOCS" ] ; then
	if ! mkdir "$DOCS" ; then
		echo unable to make the $DOCS directory. 
		exit 6
	fi
fi

echo Installing MaraDNS, placing programs in $BIN and $SBIN,
echo man pages in $MAN1, $MAN5, 
echo and $MAN8, and documents in $DOCS

# Place the binaries in $BIN and $SBIN

# Install the maradns binary
cd $TOPLEVEL/server
echo Installing maradns
if [ -x maradns ] ; then
	# We remove the file first to avoid the "text file busy" problem
	if [ -f $SBIN/maradns ] ; then
		rm $SBIN/maradns
	fi
	cp maradns $SBIN
	echo maradns installed
elif [ -x maradns.authonly ] ; then
	# We remove the file first to avoid the "text file busy" problem
	if [ -f $SBIN/maradns.authonly ] ; then
		rm $SBIN/maradns.authonly
	fi
	cp maradns.authonly $SBIN
	echo maradns installed as maradns.authonly
else
	echo unable to find maradns binary to install
	echo please make sure program sucessfully compiled
	exit 1
fi

# Install coLunacyDNS and lunacy
cd $TOPLEVEL/coLunacyDNS
# coLunacyDNS: The Lua-based DNS server
if [ -x coLunacyDNS ] ; then
	if [ -f $SBIN/coLunacyDNS ] ; then
		rm $SBIN/coLunacyDNS
	fi
	cp coLunacyDNS $SBIN
	echo coLunacyDNS installed
fi
# Lunacy: A fork of Lua 5.1.  Used to build docs and run tests with
# MaraDNS, so we don’t need to use a non-standard scripting language
cd lunacy
if [ -x lunacy ] ; then
	cp lunacy $BIN
	echo lunacy installed
fi

# Install the Deadwood binary
cd $TOPLEVEL/deadwood-*/src/
echo Installing Deadwood
if [ -x Deadwood ] ; then
	if [ -f $SBIN/Deadwood ] ; then
		rm $SBIN/Deadwood
	fi
	cp Deadwood $SBIN
	echo Deadwood installed
fi

# Install the block hash tools
cd $TOPLEVEL/deadwood-*/tools/blockhash
if [ -x blockHashMake ] ; then
	cp blockHashMake $BIN
	echo blockHashMake installed
	cp blockHashRead $BIN
	echo blockHashRead installed
fi


# Install the getzone and fetchzone binaries
cd $TOPLEVEL/tcp
echo Installing getzone and fetchzone
cp getzone fetchzone $BIN
echo getzone and fetchzone installed

# Install the zoneserver binary
echo installing zoneserver
# We remove the file first to avoid the "text file busy" problem
if [ -f $SBIN/zoneserver ] ; then
	rm $SBIN/zoneserver
fi
cp zoneserver $SBIN
echo zoneserver installed

# Install the askmara binary
echo installing askmara
cd $TOPLEVEL/tools
if [ -f $BIN/askmara ] ; then
	rm $BIN/askmara
fi
cp askmara $BIN
echo askmara installed

# Install the duende tool
# We remove the file first to avoid the "text file busy" problem
echo installing duende
if [ -f $BIN/duende ] ; then
	rm $BIN/duende
fi
cp duende $BIN
echo duende installed

# Place the man pages in $MAN1, $MAN5, and $MAN8
if [ -d $TOPLEVEL/doc/$LANGUAGE/man ] ; then
	cd $TOPLEVEL/doc/$LANGUAGE/man
else
	cd $TOPLEVEL/doc/en/man
fi
cp askmara.1 getzone.1 fetchzone.1 $MAN1
cp blockHashRead.1 blockHashMake.1 $MAN1
cp maradns.8 zoneserver.8 duende.8 $MAN8
cp csv1.5 csv2.5 csv2_txt.5 mararc.5 $MAN5

# Place all the documents in $DOCS
cd ..
mkdir $DOCS > /dev/null 2>&1
cp -r * $DOCS
cd $TOPLEVEL
cp maradns.gpg.key $DOCS

# Add Deadwood man page
cp deadwood-*/doc/Deadwood.1 $MAN1
# Add default dwood3rc file for Deadwood
if [ ! -f $RPM_BUILD_ROOT/etc/dwood3rc ] ; then
	cat deadwood-*/doc/dwood3rc | \
		sed 's/127.0.0.1\"/127.0.0.2\"/' | \
		sed 's/\/etc\/deadwood/\/etc\/maradns/' \
		> $RPM_BUILD_ROOT/etc/dwood3rc
else
	echo /etc/dwood3rc already there, not replacing
fi

# If the system in question does not already have configuration files,
# place example configuration files in /etc
if [ -d doc/$LANGUAGE/examples ] ; then
	cd doc/$LANGUAGE/examples
else
	cd doc/en/examples
fi

# $RPM_BUILD_ROOT was added at the request of one of my users
if [ ! -f $RPM_BUILD_ROOT/etc/mararc ] ; then
	cp example_mararc $RPM_BUILD_ROOT/etc/mararc
else 
	echo /etc/mararc already there, not replacing
fi
if [ ! -d $RPM_BUILD_ROOT/etc/maradns ] ; then
	mkdir $RPM_BUILD_ROOT/etc/maradns
	chmod 755 $RPM_BUILD_ROOT/etc/maradns
fi
if [ ! -d $RPM_BUILD_ROOT/etc/maradns/logger ] ; then
	# The duende tool *needs* an /etc/maradns/logger directory
	# Note that duende uses an absolute path
	mkdir $RPM_BUILD_ROOT/etc/maradns/logger
fi
if [ ! -f $RPM_BUILD_ROOT/etc/maradns/db.example.net ] ; then
	cp example_csv2 $RPM_BUILD_ROOT/etc/maradns/db.example.net
fi

# Finally, set up the startup files, as needed
# Go back to the top-level MaraDNS directory
cd $TOPLEVEL

if [ -d /etc/systemd/system ] ; then
	echo Adding MaraDNS systemd startup scripts
	cd $TOPLEVEL/build/systemd/
	for a in *service ; do
		cat $a | awk '
		{sub(/\/usr\/local\/bin/,"'$SBIN'")
		 print $0}
			' > /etc/systemd/system/$a
	done
	systemctl enable maradns
	systemctl enable deadwood
	echo Service startup files installed in /etc/systemd/system
	echo To start the services:
	echo systemctl start maradns \# Starts MaraDNS
	echo systemctl start deadwood \# Starts Deadwood
	exit 0
fi

if [ "$1" != "--unsupported" ] ; then
	echo Only systemd is supported for having MaraDNS run at system start
	echo up.  
	echo
	echo There are scripts which may \(or may not\) work with sysvinit
	echo and/or OpenRC.  These scripts are unsupported but might get
	echo you started.  To attempt to get MaraDNS to start up at system
	echo boot time on a non-systemd system, run the following.
	echo
	echo $0 --unsupported
	echo
	echo THIS IS NOT SUPPORTED.  If any issues are found, please
	echo fix them and then submit a pull \(merge\) request.
	echo
	echo Again, MaraDNS/Deadwood have been installed, but will not
	echo start up at system boot.
	exit 0
fi

echo THE FOLLOWING MIGHT WORK BUT IS NOT SUPPORTED

RCTOP=/etc/rc.d
echo Systemd not found, trying ${RPM_BUILD_ROOT}${RCTOP}/init.d instead
if [ ! -d ${RPM_BUILD_ROOT}${RCTOP}/init.d ] ; then
	echo ${RPM_BUILD_ROOT}${RCTOP}/init.d not found...
	RCTOP=/etc
	echo Trying ${RPM_BUILD_ROOT}${RCTOP}/init.d instead
fi
if [ ! -d ${RPM_BUILD_ROOT}${RCTOP}/init.d ] ; then
	echo ${RPM_BUILD_ROOT}${RCTOP}/init.d not found
	echo FATAL
	echo Please install this to run at system start up by hand
	exit 1
fi

# And copy over the init files if this system looks to be a sysVish init
# system
# Please note that while there are hacks for this to work with OpenRC,
# and they work with the version of OpenRC included with Alpine 3.14,
# OpenRC actually isn’t supported, since it uses yet another non-standard
# format for launching services.

if [ -d ${RPM_BUILD_ROOT}${RCTOP}/init.d ] ; then
	echo Adding MaraDNS startup scripts
	if [ ! -f ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns ] ; then
	      # Non-Posix OpenRC stuff
	      if [ -e /sbin/openrc-run ] ; then
		echo '#!/sbin/openrc-run' > \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns
		echo '#!/sbin/openrc-run' > \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.deadwood
		echo '#!/sbin/openrc-run' > \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.zoneserver
	      fi # End OpenRC stuff
	      touch ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns
	      touch ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.deadwood
	      touch ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.zoneserver
	      chmod 755 ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns
	      chmod 755 ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.deadwood
	      chmod 755 ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.zoneserver
	      cat $BUILDDIR/mara.startup >> \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns
	      cat $BUILDDIR/zoneserver.startup >> \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.zoneserver
	      cat $BUILDDIR/deadwood.startup >> \
	          ${RPM_BUILD_ROOT}${RCTOP}/init.d/maradns.deadwood
	fi
	if cd ${RPM_BUILD_ROOT}${RCTOP}/rc3.d/ ; then
		echo Starting up MaraDNS at runlevel 3
		rm S60maradns 2> /dev/null
		rm K60maradns.zoneserver 2> /dev/null
		rm S60maradns.deadwood 2> /dev/null
		ln -s ../init.d/maradns S60maradns
		ln -s ../init.d/maradns.zoneserver K60maradns.zoneserver
		ln -s ../init.d/maradns.deadwood S60maradns.deadwood
	else 
		echo Unable to find ${RPM_BUILD_ROOT}${RCTOP}/rc3.d/
		echo trying rc-update
		rc-update add maradns 3
	fi
	if cd ${RPM_BUILD_ROOT}${RCTOP}/rc5.d/ ; then
		echo starting up MaraDNS at runlevel 5
		rm S60maradns 2> /dev/null
		rm K60maradns.zoneserver 2> /dev/null
		rm S60maradns.deadwood 2> /dev/null
		ln -s ../init.d/maradns S60maradns
		ln -s ../init.d/maradns.zoneserver K60maradns.zoneserver
		ln -s ../init.d/maradns.deadwood S60maradns.deadwood
	else
		echo Unable to find ${RPM_BUILD_ROOT}${RCTOP}/rc5.d/
		echo trying rc-update
		rc-update add maradns 5
		if [ "$?" == "1" ] ; then
			echo rc-update failed at runlevel 5, trying default
			rc-update add maradns
		fi
	fi
	echo Files copied to ${RCTOP}
	exit 0
fi

echo
echo RUNNING MARADNS ON THIS INIT SYSTEM AT SYSTEM BOOT IS NOT SUPPORTED
exit 0
