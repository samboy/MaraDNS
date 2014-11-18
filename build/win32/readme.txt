This directory contains some files from MaraDNS ported to win32.  These
programs have only been tested on Windows XP and may or may not work on
other versions of Windows.

These files were compiled using mingw32.

MaraDNS is a multithreaded application, and needs the pthreadGC2.dll file
to run.  This file is licensed under the LGPL; basically, in order to
distribute this file, the corresponding pthreads-w32-2-8-0-release.tar.lzma
file must also be included.

MaraDNS is a DNS server; this means that MaraDNS will allow you to get
online in case you are on a network with a broken DNS server.  Askmara is
a tool that can be used to help debug DNS problems.

Both programs are run in a command-line shell; maradns.exe can also be
run as a Windows NT/XP service.  To get a command line shell, go to 
start->run, and type in "cmd" as the program to run.  Enter the directory 
that contains this README.txt file.

"run_maradns.bat" will start the DNS server.  If you are able to ping
sites outside your local network, but are unable to access web sites, 
this program will do DNS resolution for you.  When MaraDNS is started
this way, the shell window that run_maradns.bat is opened from needs 
to stay open while MaraDNS is running.

run_maradns may also be ran by double-clicking on it.  Again, when
started this way, be sure to keep this command shell open while using 
MaraDNS as a DNS server to access the internet.

For details on how to run MaraDNS as a Windows service that doesn't need 
a command shell window, read the file Service.html. 

To make MaraDNS your DNS server, go to Start->Control Panel->Network
Connections, and right click on "Local Area Connection" (or the name of
the connection you use to get on the internet).  Select "Properties" and
double click on "Ineternet Protocol (TCP/IP)" (you may have to scroll
down to see this).  Click on the dot to the left of "Use the following
DNS server address" and put "127.0.0.1" as the DNS server address.

At this point, you will be able to use the internet without needing an
external DNS server.

Both MaraDNS and Askmara need internet access to run; please have any
installed firewall grant this access.

The file Askmara.html explains how to use Askmara.
