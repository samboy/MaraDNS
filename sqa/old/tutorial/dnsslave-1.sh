#!/bin/bash

cd /etc/maradns
fetchzone example.com 127.0.0.1 > db.example.com
fetchzone example.org 127.0.0.1 > db.example.org
fetchzone example.net 127.0.0.1 > db.example.net

