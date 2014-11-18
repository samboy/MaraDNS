#!/bin/bash

# For security reasons, put this file in a directory that only root
# may write to. 
TEMP=/root/tmp/foo

cd /etc/maradns
fetchzone example.com 127.0.0.1 > $TEMP
if [ $? -eq 0 ] ; then
        mv $TEMP db.example.com
fi
fetchzone example.org 127.0.0.1 > $TEMP
if [ $? -eq 0 ] ; then
        mv $TEMP db.example.org
fi
fetchzone example.net 127.0.0.1 > $TEMP
if [ $? -eq 0 ] ; then
        mv $TEMP db.example.net
fi

