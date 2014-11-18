#!/bin/bash

ZONELIST=/etc/maradns.zonelist
# For security reasons, put this file in a directory that only root
# may write to.
TEMP=/root/tmp/foo

cd /etc/maradns

cat $ZONELIST | awk '{print "fetchzone "$1" "$2" > '$TEMP'"
                      print "if [ $? -eq 0 ] ; then"
                      print "    mv '$TEMP' db."$1
                      print "fi";}' | sh
