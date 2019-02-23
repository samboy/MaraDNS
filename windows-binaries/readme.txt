IMPORTANT: Before running this program, you must run the program MkSecretTxt
to create a file called "secret.txt".  

ALSO: With MaraDNS 2.0, most users will want to run Deadwood instead.

This directory contains some files from MaraDNS ported to win32.  These
programs have only been tested on Windows XP and may or may not work on
other versions of Windows.

These files were compiled using mingw32.

MaraDNS is a DNS server; this means that MaraDNS will allow you to get
online in case you are on a network with a broken DNS server.  Askmara is
a tool that can be used to help debug DNS problems.

Deadwood is a stable release of the recursive nameserver MaraDNS 2.0
uses.  Users who need DNS recursion (using a DNS server to resolve other 
names) need to use Deadwood instead of MaraDNS.  Please look in the 
Deadwood directory for more information.

Both programs are run in a command-line shell; maradns.exe can also be
run as a Windows NT/XP service.  To get a command line shell, go to 
start->run, and type in "cmd" as the program to run.  Enter the directory 
that contains this README.txt file.

"run_maradns.bat" will start the DNS server.  When MaraDNS is started
this way, the shell window that run_maradns.bat is opened from needs 
to stay open while MaraDNS is running.  Also note that, since 
Deadwood now does MaraDNS' recursion, this will not do anything
interesting unless one wishes to serve zones with MaraDNS (and said
zones will need to be added and configured).

run_maradns may also be ran by double-clicking on it.  Again, when
started this way, be sure to keep this command shell open while using 
MaraDNS as a DNS server to access the internet.

For details on how to run MaraDNS as a Windows service that doesn't need 
a command shell window, read the file Service.html.  Please note that 
Deadwood, unlike MaraDNS, is a standalone Windows service.

To make Deadwood your DNS server, go to Start->Control Panel->Network
Connections, and right click on "Local Area Connection" (or the name of
the connection you use to get on the internet).  Select "Properties" and
double click on "Ineternet Protocol (TCP/IP)" (you may have to scroll
down to see this).  Click on the dot to the left of "Use the following
DNS server address" and put "127.0.0.1" as the DNS server address.

At this point, you will be able to use the internet without needing an
external DNS server.

MaraDNS, Deadwood, and Askmara need internet access to run; please have any
installed firewall grant this access.

The file Askmara.html explains how to use Askmara.
