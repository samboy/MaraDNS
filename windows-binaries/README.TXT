These binaries were made against commit 
8ad85076107fb6a8d1a9ed4b0323c41af6293ca6 (February 12, 2014). 

These binaries are compiled with the '-g' flag to give them full debugging
symbols.  Since Deadwood is normally a Windows service, it can not be
run in gdb unless it is run with the '--nodaemon' argument, e.g.

	gdb ./Deadwood.exe
	(gdb) set args --nodaemon dwood3rc.txt
	(gdb) run

Should the program crash, type in the following command to get a full
stack trace:

	(gdb) bt

gdb (the debugger for programs compiled with the GNU toolchain) can be
found at http://samiam.org/software/gdb-5.2.1-1.exe

Note that Deadwood.exe needs to be run in the same directory with 
secret.txt and dwood3rc.txt (or have those files copied over to
the directory with this version of Deadwood.exe)

Since gdb is GPL: http://samiam.org/software/gdb-5.2.1-1-src.tar.bz2
