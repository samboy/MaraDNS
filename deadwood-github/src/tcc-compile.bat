tcc.exe  -DMINGW -Wall -c -o DwStr.o DwStr.c
tcc.exe  -DMINGW -Wall -c -o DwMararc.o DwMararc.c
tcc.exe  -DMINGW -Wall -c -o DwRadioGatun.o DwRadioGatun.c
tcc.exe  -DMINGW -Wall -c -o DwSocket.o DwSocket.c
tcc.exe  -DMINGW -Wall -c -o DwUdpSocket.o DwUdpSocket.c
tcc.exe  -DMINGW -Wall -c -o DwTcpSocket.o DwTcpSocket.c
tcc.exe  -DMINGW -Wall -c -o DwSys.o DwSys.c
tcc.exe  -DMINGW -Wall -c -o DwMain.o DwMain.c 
tcc.exe  -DMINGW -Wall -c -o DwHash.o DwHash.c
tcc.exe  -DMINGW -Wall -c -o DwCompress.o DwCompress.c
tcc.exe  -DMINGW -Wall -c -o DwDnsStr.o DwDnsStr.c
tcc.exe  -DMINGW -Wall -c -o DwRecurse.o DwRecurse.c
tcc.exe  -Wall -c -o DwDict.o DwDict.c
tcc.exe  -DMINGW -Wall -o Deadwood.exe DwWinSvc.c DwStr.o DwMararc.o DwRadioGatun.o DwSocket.o DwUdpSocket.o DwTcpSocket.o DwSys.o DwMain.o DwHash.o DwCompress.o DwDnsStr.o DwRecurse.o DwDict.o -lwsock32 -ladvapi32
