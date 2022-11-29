#!/bin/sh


# Shell script which uninstalls the MaraDNS files 

# We call install.locations to set BIN, SBIN, MAN1, and MAN8
# It is in a separate file to insure that install.sh and uninstall.sh
# have the same values
if [ -z "$BUILDDIR" ] ; then
        BUILDDIR="build"
fi
. $BUILDDIR/install.locations

if [ -z "$SBIN" ] ; then
	echo Problem removing files.
	exit 1
fi

echo Removing MaraDNS by erasing programs in $BIN and $SBIN,
echo man pages in $MAN1 and $MAN8, and the directory tree $DOCS
cd $SBIN
rm maradns zoneserver Deadwood coLunacyDNS
cd $BIN
rm askmara getzone lunacy
cd $MAN1
rm askmara.1 getzone.1 Deadwood.1
cd $MAN8
rm maradns.8 zoneserver.8
rm -fr $DOCS
# Remove system start up files
if [ -d /etc/systemd/system ] ; then
	systemctl stop maradns
	systemctl disable maradns
	systemctl stop deadwood
	systemctl disable deadwood
	systemctl stop colunacydns
	systemctl disable colunacydns
	rm /etc/systemd/system/colunacydns.service  
	rm /etc/systemd/system/deadwood.service  
	rm /etc/systemd/system/maradns.service
fi

# The following will normally not run, this is for the older pre-systemd
# files
if [ -d /etc/rc.d/init.d ] ; then
	echo Removing MaraDNS startup scripts
	rm /etc/rc.d/rc3.d/S60maradns
	rm /etc/rc.d/rc5.d/S60maradns
	rm /etc/rc.d/init.d/maradns
	rm /etc/rc.d/rc3.d/K60maradns.zoneserver
	rm /etc/rc.d/rc5.d/K60maradns.zoneserver
	rm /etc/rc.d/init.d/maradns.zoneserver
	rm /etc/rc.d/rc3.d/S60maradns.deadwood
	rm /etc/rc.d/rc5.d/S60maradns.deadwood
	rm /etc/rc.d/init.d/maradns.deadwood
fi
# /etc/rc.d/ hasn't been used for a long time
if [ -e /etc/init.d/maradns ] ; then
	echo Removing MaraDNS startup scripts
	rm /etc/rc3.d/S60maradns
	rm /etc/rc5.d/S60maradns
	rm /etc/init.d/maradns
	rm /etc/rc3.d/K60maradns.zoneserver
	rm /etc/rc5.d/K60maradns.zoneserver
	rm /etc/init.d/maradns.zoneserver
	rm /etc/rc3.d/S60maradns.deadwood
	rm /etc/rc5.d/S60maradns.deadwood
	rm /etc/init.d/maradns.deadwood
fi

echo Note that cahced copies of man pages may still be lurking around
echo
echo Not removing configuration files.  If you wish to completely purge 
echo MaraDNS from your system, rm /etc/mararc, /etc/dwood3rc and the 
echo /etc/maradns/ directory, as well as any cached copies of MaraDNS man pages

