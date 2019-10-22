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
# And copy over the init files if this system looks to be a sysVish init
# system
if [ -d $RPM_BUILD_ROOT/etc/rc.d/init.d ] ; then
	echo Adding MaraDNS startup scripts
	if [ ! -f $RPM_BUILD_ROOT/etc/rc.d/init.d/maradns ] ; then
	      cp $BUILDDIR/mara.startup $RPM_BUILD_ROOT/etc/rc.d/init.d/maradns
	      cp $BUILDDIR/zoneserver.startup \
	          $RPM_BUILD_ROOT/etc/rc.d/init.d/maradns.zoneserver
	      cp $BUILDDIR/deadwood.startup \
	          $RPM_BUILD_ROOT/etc/rc.d/init.d/maradns.deadwood
	      chmod 755 $RPM_BUILD_ROOT/etc/rc.d/init.d/maradns.deadwood
	fi
	if cd $RPM_BUILD_ROOT/etc/rc.d/rc3.d/ ; then
		echo Starting up MaraDNS at runlevel 3
		rm S60maradns 2> /dev/null
		rm K60maradns.zoneserver 2> /dev/null
		rm S60maradns.deadwood 2> /dev/null
		ln -s ../init.d/maradns S60maradns
		ln -s ../init.d/maradns.zoneserver K60maradns.zoneserver
		ln -s ../init.d/maradns.deadwood S60maradns.deadwood
	fi
	if cd $RPM_BUILD_ROOT/etc/rc.d/rc5.d/ ; then
		echo starting up MaraDNS at runlevel 5
		rm S60maradns 2> /dev/null
		rm K60maradns.zoneserver 2> /dev/null
		rm S60maradns.deadwood 2> /dev/null
		ln -s ../init.d/maradns S60maradns
		ln -s ../init.d/maradns.zoneserver K60maradns.zoneserver
		ln -s ../init.d/maradns.deadwood S60maradns.deadwood
	fi
fi

