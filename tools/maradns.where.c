#include <stdio.h>

main() {
        int a;
        printf("maradns.exe is no longer included with the Windows 32-bit\n"
"build of MaraDNS.  There are various ways to run the authoritative MaraDNS\n"
"server in Windows, including Windows Subsystem for Linux, using Docker\n"
"(which uses Hyper-V) to run MaraDNS, running it in a VMware virtual\n"
"machine running Linux, or using Cygwin to run MaraDNS.\n"
"\n"
"Cygwin is now a fully supported way to run MaraDNS in Windows.  For\n"
"details, please read Cygwin.txt\n"
"\n"
"There are no plans to stop making the Deadwood.exe native Windows service.\n"
"\n"
"Press the enter key to exit this program\n");
        fflush(stdout);
        a = getc(stdin);
        return 0;
}
