#!/bin/sh

cat > /dev/null << EOF
This is a command which will use Steven Black's blacklist to add
a large blacklist to Deadwood.  To use this script, on a UNIX-like
system (e.g. Linux, maybe MacOS), type in the following command from
the directory containing this:

mkdir /etc/deadwood/
mkdir /etc/deadwood/execfile/
./make.blacklist.sh > /etc/deadwood/execfile/blacklist

Once this "blacklist" file is created, add the following line to
the end of one's dwood3rc file:

execfile("blacklist")

Note that each entry takes over one kilobyte to store, so Deadwood 
needs about 70 megabytes to use this blacklist.
EOF

curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | \
	grep '0.0.0.0' | tr -d '"' | awk '{print $2}' | \
		tr -dc 'a-z0-9\-\.\n' | sort -u | awk '
		BEGIN {print "reject_aaaa = 1"
		       print "ip4 = {}"
		       print "maximum_cache_elements = 100000"}
		{print "ip4[\"" $1 ".\"] = \"172.31.23.17\""}'
