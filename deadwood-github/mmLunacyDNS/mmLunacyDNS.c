/* Copyright (c) 2009-2020 Sam Trenholme
 *
 * TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * This software is provided 'as is' with no guarantees of correctness or
 * fitness for purpose.
 *
 * This software links to Lunacy, a fork of Lua 5.1
 * Lua license is in the file COPYING
 */

/* mmLunacyDNS: A tiny DNS server which uses Lua for configuration and
 * for the main loop.  This is Lunacy, a fork of Lua 5.1, and it's 
 * embedded in the compiled binary
 */

#include <stdint.h>
#ifdef MINGW
#include <winsock.h>
#include <wininet.h>
#ifndef FD_SETSIZE
#define FD_SETSIZE 512
#endif /* FD_SETSIZE */
#include <winsock.h>
#include <wininet.h>
#define socklen_t int32_t
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* MINGW */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

/* Luancy stuff */
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

/* We use a special SOCKET type for easier Windows porting */
#ifndef MINGW
#define SOCKET int
#endif

/* Log a message */
#ifndef MINGW
void log_it(char *message) {
	if(message != NULL) {
		puts(message);
	}
}
#else /* MINGW */
FILE *LOG = 0;
int isInteractive = 0;
void log_it(char *message) {
        SYSTEMTIME t;
        char d[256];
        char h[256];
	if(isInteractive == 1) {
		puts(message);
		return;
	}
	if(LOG == 0) {
		return;
	}
        GetLocalTime(&t);
        GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &t,
                NULL, d, 250);
        GetTimeFormat(LOCALE_SYSTEM_DEFAULT, TIME_FORCE24HOURFORMAT, &t,
                NULL, h, 250);
        fprintf(LOG,"%s %s: ",d,h);
	if(message != NULL) {
		fprintf(LOG,"%s\n",message);
	} else {
		fprintf(LOG,"NULL string\n",message);
	}
}
#endif /* MINGW */
	

/* Set this to 0 to stop the server */
int serverRunning = 1;

/* This is the header placed before the 4-byte IP; we change the last four
 * bytes to set the IP we give out in replies */
char p[17] =
"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x7f\x7f\x7f";

/* Set the IP we send in response to DNS queries */
uint32_t set_return_ip(char *returnIp) {
        uint32_t ip;

	if(returnIp == NULL) {
		returnIp = "127.0.0.1";
	}
        /* Set the IP we give everyone */
        ip = inet_addr(returnIp);
        ip = ntohl(ip);
        p[12] = (ip & 0xff000000) >> 24;
        p[13] = (ip & 0x00ff0000) >> 16;
        p[14] = (ip & 0x0000ff00) >>  8;
        p[15] = (ip & 0x000000ff);
        return ip;
}

/* Convert a NULL-terminated string like "10.1.2.3" in to an IP */
uint32_t get_ip(char *stringIp) {
	uint32_t ip = 0;
        /* Set the IP we bind to (default is "0", which means "all IPs) */
        if(stringIp != NULL) {
        	ip = inet_addr(stringIp);
	}
        /* Return the IP we bind to */
        return ip;
}

#ifdef MINGW
void windows_socket_start() {
        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2,2);
        WSAStartup( wVersionRequested, &wsaData);
}
#endif /* MINGW */

/* Get port: Get a port locally and return the socket the port is on */
SOCKET get_port(uint32_t ip, struct sockaddr_in *dns_udp) {
        SOCKET sock;
        int len_inet;
	struct timeval noblock;
        noblock.tv_sec = 1; 
        noblock.tv_usec = 0; 

        /* Bind to port 53 */
#ifdef MINGW
        windows_socket_start();
#endif /* MINGW */
        sock = socket(AF_INET,SOCK_DGRAM,0);
        if(sock == -1) {
                perror("socket error");
                exit(0);
        }
#ifdef MINGW
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
		(char *)&noblock, sizeof(struct timeval));
#endif /* MINGW */
        memset(dns_udp,0,sizeof(struct sockaddr_in));
        dns_udp->sin_family = AF_INET;
        dns_udp->sin_port = htons(53);
        dns_udp->sin_addr.s_addr = ip;
        if(dns_udp->sin_addr.s_addr == INADDR_NONE) {
                log_it("Problem with bind IP");
                exit(0);
        }
        len_inet = sizeof(struct sockaddr_in);
        if(bind(sock,(struct sockaddr *)dns_udp,len_inet) == -1) {
                perror("bind error");
#ifdef MINGW
		printf("WSAGetLastError code: %d\n",WSAGetLastError());
#endif /* MINGW */
                exit(0);
        }

        /* Linux kernel bug */
        /* fcntl(sock, F_SETFL, O_NONBLOCK); */

        return sock;
}

static int mmDNS_log (lua_State *L) {
	const char *message = luaL_checkstring(L,1);
	log_it((char *)message);
	return 0;	
}	

static const luaL_Reg mmDNSlib[] = {
	{"log", mmDNS_log},
	{NULL, NULL}
};

lua_State *init_lua(char *fileName) {
	char useFilename[512];
	lua_State *L = luaL_newstate(); // Initialize Lua
	// Add string, math, and bit32.
	// Don't add everything (io, lfs, etc. allow filesystem access)
	lua_pushcfunction(L, luaopen_string);
	lua_pushstring(L, "string");
	lua_call(L, 1, 0);
	lua_pushcfunction(L, luaopen_math);
	lua_pushstring(L, "math");
	lua_call(L, 1, 0);
	lua_pushcfunction(L, luaopen_bit32);
	lua_pushstring(L, "bit32");
	lua_call(L, 1, 0);
	luaL_register(L, "mmDNS", mmDNSlib);
	
	/* The filename we use is {executable name}.lua.  
         * {executable name} is the name this is being called as,
         * usually mmLunacyDNS (or mmLunacyDNS.exe in Windows).
         * This way, if we want multiple Lua configuration files for
         * different use cases, we simple copy the binary (or link
         * to it) to make it use a different .lua configuration file.
         */
	if(fileName != NULL && *fileName != 0) {
		int a;
		int lastDot = 505;
		// Find the final '.' in the executable name
		for(a = 0; a < 500; a++) {
			if(fileName[a] == 0) {
				break;
			}
			if(fileName[a] == '.') {
				lastDot = a;
			}
			if(fileName[a] == '/' || fileName[a] == 92) { 
				lastDot = 505;
			}
		}
		for(a = 0; a < 500; a++) {
			useFilename[a] = *fileName;
			if(*fileName == 0 || a >= lastDot) {
				break;
			}
			fileName++;
		}
		useFilename[a] = '.'; a++;
		useFilename[a] = 'l'; a++;
		useFilename[a] = 'u'; a++;
		useFilename[a] = 'a'; a++;
		useFilename[a] = 0;
	} else {
		// Yes, it is possible to make argv[0] null
		strcpy(useFilename,"mmLunacyDNS.lua");
	}

	// Open and parse the .lua file
	if(luaL_loadfile(L, useFilename) == 0) {
		if(lua_pcall(L, 0, 0, 0) != 0) {
			log_it("Unable to parse lua file with name:");
			log_it(useFilename);
			log_it((char *)lua_tostring(L,-1));
			return NULL;
		}		
	} else {
		log_it("Unable to open lua file with name:");
		log_it(useFilename);
		log_it((char *)lua_tostring(L,-1));
		return NULL;
	}
	return L;
}

/* Convert a raw over-the-wire DNS name (in) in to a human-readable
 * name.  Anything that is not [A-Za-z0-9\-\_] is converted in to {hex}
 * where "hex" is a hex number 
 */
int humanDNSname(char *in, char *out, int max) {
	int labelLen = 0;
	int inPoint = 0;
	int outPoint = 0;
	labelLen = in[inPoint];
	while(labelLen > 0) {
		char see = 0;
		if(inPoint >= max || outPoint >= max) {
			return -1;
		}
		inPoint++;
		see = in[inPoint];
		if((see >= '0' && see <= '9') ||
                   (see >= 'a' && see <= 'z') ||
                   (see >= 'A' && see <= 'Z') ||
		    see == '-' || see == '_') {
			if(outPoint >= max) {return -1;}
			out[outPoint] = see;
			outPoint++;
		} else { // Hex escape of anything not "safe"
			int left = (see >> 4) & 15;
			int right = see & 15;
			if(outPoint + 5 >= max) {return -1;}
			out[outPoint] = '{'; outPoint++;
			if(left < 10) {
				out[outPoint] = '0' + left;
			} else {
				out[outPoint] = 'a' + (left - 10);
			}
			outPoint++;
			if(right < 10) {
				out[outPoint] = '0' + right;
			} else {
				out[outPoint] = 'a' + (right - 10);
			}
			outPoint++;
			out[outPoint] = '}'; outPoint++;
		}
		labelLen--;
		if(labelLen == 0) {
			inPoint++;
			labelLen = in[inPoint];
			if(outPoint >= max) {return -1;}
			out[outPoint] = '.';
			outPoint++;
		}
	}
	if(outPoint >= max) {return -1;}
	out[outPoint] = 0;
	return inPoint;
}


/* Give a Lua state, which is the file 'config.lua' read, run the
 * server */
void runServer(lua_State *L) {
        int a, len_inet;
        SOCKET sock;
        char in[515];
        socklen_t lenthing = sizeof(in);
        struct sockaddr_in dns_udp;
        uint32_t ip = 0; /* 0.0.0.0; default bind IP */
        int leni = sizeof(struct sockaddr);

	// Get bindIp from the Lua program 
        lua_getglobal(L,"bindIp"); // Push "bindIp" on to stack
        if(lua_type(L, -1) == LUA_TSTRING) {
		char *bindIp;
		bindIp = (char *)lua_tostring(L, -1); 
		ip = get_ip(bindIp);
	} else {
		log_it("Unable to get bindIp; using 0.0.0.0");
	}
	lua_pop(L, 1); // Remove result from stack, restoring the stack

        sock = get_port(ip,&dns_udp);

	log_it("Running mmLunacyDNS");

        /* Now that we know the IP and are on port 53, process incoming
         * DNS requests */
        while(serverRunning == 1) {
		char query[500];
		int qLen = -1;
		uint32_t fromIp; /* Who sent us a query */
		char fromString[128]; /* String of sending IP */
                /* Get data from UDP port 53 */
                len_inet = recvfrom(sock,in,255,0,(struct sockaddr *)&dns_udp,
                        &lenthing);
                /* Roy Arends check: We only answer questions */
                if(len_inet < 3 || (in[2] & 0x80) != 0x00) {
                        continue;
                }
		// IPv6 support is left as an exercise for the reader
		if(dns_udp.sin_family != AF_INET) {
			continue;
		}
		fromIp = dns_udp.sin_addr.s_addr;
		fromIp = ntohl(fromIp);
		snprintf(fromString,120,"%d.%d.%d.%d",fromIp >> 24,
			(fromIp & 0xff0000) >> 16,
			(fromIp & 0xff00) >> 8,
			fromIp & 0xff);
		log_it(fromString);

                /* Prepare the reply */
                if(len_inet > 12 && in[5] == 1) {
                        /* Make this an answer */
                        in[2] |= 0x80;
                        in[7]++;
			in[11] = 0; // Ignore EDNS
                }
		qLen = humanDNSname(in + 12, query, 490);
	 	if(qLen > 0) {
			int qType = -1;
			qType = (in[13 + qLen] * 256) + in[14 + qLen];
			lua_getglobal(L, "processQuery");

			// Function input is a table, which I will call "t"
			lua_newtable(L);

			// t["mmQuery"] = query, where "query" is the
			// dns query made (with a trailing dot), such
			// as "caulixtla.com." or "lua.org."	
			lua_pushstring(L,"mmQuery");
			lua_pushstring(L,query);
			lua_settable(L, -3);

			// t["mmQtype"] is a number with the query type
			lua_pushstring(L,"mmQtype");
			lua_pushinteger(L,(lua_Integer)qType);
			lua_settable(L, -3);
			
			// t["mmFromIP"] is the IP the query came from,
			// in the form of a human-readable string
			lua_pushstring(L,"mmFromIP");
			lua_pushstring(L,fromString);
			lua_settable(L, -3);

			// t["mmFromIPtype"] is a number with the number
			// 4, for IPv4
			lua_pushstring(L,"mmFromIPtype");
			lua_pushinteger(L,(lua_Integer)4);
			lua_settable(L, -3);

			if (lua_pcall(L, 1, 1, 0) == 0) {
				const char *rs;
				// Pull mmType from return table
				rs = NULL;
				if(lua_type(L, -1) == LUA_TTABLE) {
					lua_getfield(L, -1, "mm1Type");
				        if(lua_type(L, -1) == LUA_TSTRING) {
						rs = luaL_checkstring(L, -1);
					}
				}
				if(rs != NULL && rs[0] == 'A' && rs[1] == 0) {
					lua_pop(L, 1); 
					lua_getfield(L, -1, "mm1Data");
				        if(lua_type(L, -1) == LUA_TSTRING) {
						rs = luaL_checkstring(L, -1);						} else {
						lua_pop(L, 1);
						rs = NULL;
					}
				} else if(rs != NULL) {
					lua_pop(L, 1);
					rs = NULL;
				}
				if(rs != NULL) {
					set_return_ip((char *)rs);
					len_inet = 17 + qLen;
                			for(a=0;a<16;a++) {
                        			in[len_inet + a] = p[a];
                			}

                			/* Send the reply */
                			sendto(sock,in,len_inet + 16,0, 
					    (struct sockaddr *)&dns_udp, leni);
					lua_pop(L, 1); 
				}
			} else {
				log_it("Error calling function processQuery");
				log_it((char *)lua_tostring(L, -1));
			}
		}
        }
}

#ifndef MINGW
int main(int argc, char **argv) {
	lua_State *L;
	char *look;

        printf("mmLunacyDNS version 2020-07-24 starting\n\n");
	// Get bindIp and returnIp from Lua script
	if(argc == 1) {
		log_it("Only debug (interactive) mode supported.");
		log_it("Running as a daemon not supported yet.");
		log_it("Usage: mmLunacyDNS -d {config file}");
		return 1;
	} 
        look = argv[1];
	if(look == 0) {
		log_it("Error getting command line args.");
		return 1;
	}
	if(look[0] != '-' || look[1] != 'd') {
		log_it("Only debug (interactive) mode supported.");
		log_it("Running as a daemon not supported yet.");
		log_it("Usage: mmLunacyDNS -d {config file}");
		return 1;
	} 
        if(argc == 2) {
		L = init_lua(argv[0]); // Initialize Lua
	} else if(argc == 3) {
		L = init_lua(argv[2]); // Initialize Lua
	} else {
		log_it("Only debug (interactive) mode supported.");
		log_it("Running as a daemon not supported yet.");
		log_it("Usage: mmLunacyDNS -d {config file}");
		return 1;
	}
	if(L == NULL) {
		log_it("Fatal error opening lua config file");
		return 1;
	}
	runServer(L);
}
#else /* MINGW */

/* This program is a Windows service; I would like to thank Steve Friedl who
   put a public domain simple Windows service on his web site at unixwiz.net;
   his public domain code made it possible for me to write the Win32
   service code.

   After compiling, one needs to install this service:

        mmLunacyDNS.exe --install

   Then one can start the service:

        net start mmLunacyDNS

   (It can also be started from Control Panel -> Administrative tools ->
    Services; look for the "mmLunacyDNS" service)

   To stop the service:

        net stop mmLunacyDNS

   (Or from the Services control panel)

   To remove the service:

        mmLunacyDNS.exe --remove

   This program should compile and run in a MinGW-3.1.0-1 +
   MSYS-1.0.10 environment.  I use a Windows XP virtual machine to compile
   this program.

 */


static SERVICE_STATUS           sStatus;
static SERVICE_STATUS_HANDLE    hServiceStatus = 0;
#define COUNTOF(x)       (sizeof(x) / sizeof((x)[0]) )

/* Install the service so it's in Windows' list of services */
void svc_install_service() {
        char szPath[512], svcbinary[550];

        GetModuleFileName( NULL, szPath, COUNTOF(szPath) );
        /* Call the program as "{name} service" so it knows to start as
         * a service */
        if (strstr(szPath, " ") != NULL) {
                snprintf(svcbinary, COUNTOF(svcbinary), "\"%s\" service",
                        szPath);
        } else {
                snprintf(svcbinary, COUNTOF(svcbinary), "%s service", szPath);
        }

        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL,
                                SC_MANAGER_CREATE_SERVICE);

        SC_HANDLE hService = CreateService(
                        hSCManager,
                        "mmLunacyDNS",                   /* name of service */
                        "mmLunacyDNS: https://maradns.samiam.org/",
                        /* name to display */
                        SERVICE_ALL_ACCESS,           /* desired access */
                        SERVICE_WIN32_OWN_PROCESS,    /* service type */
                        SERVICE_AUTO_START,           /* start type */
                        SERVICE_ERROR_NORMAL,         /* error control type */
                        svcbinary,                    /* service's binary */
                        NULL,                         /* no load order grp */
                        NULL,                         /* no tag identifier */
                        "",                           /* dependencies */
                        0,                     /* LocalSystem account */
                        0);                    /* no password */

        if(hService == NULL) {
                printf("Problem creating service\n");
        } else {
                printf(
         "mmLunacyDNS service installed; start with: net start mmLunacyDNS\n");
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

}

/* Remove the service from Windows' list of services; it's probably a good
 * idea to stop the service first */
void svc_remove_service() {
        SC_HANDLE hService = 0;
        SC_HANDLE hSCManager = OpenSCManager(0,0,0);
        hService = OpenService  (hSCManager,"mmLunacyDNS",DELETE);
        if(DeleteService(hService) == 0) {
                printf("Problem deleting service\n");
        } else {
                printf("mmLunacyDNS service removed\n");
        }
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
}

/* Handle a request to stop the service */
void svc_service_control(DWORD dwControl) {
        switch (dwControl) {
                case SERVICE_CONTROL_SHUTDOWN:
                case SERVICE_CONTROL_STOP:

                sStatus.dwCurrentState  = SERVICE_STOP_PENDING;
                sStatus.dwCheckPoint    = 0;
                sStatus.dwWaitHint      = 2000; /* Two seconds */
                sStatus.dwWin32ExitCode = 0;
                serverRunning = 0;

                default:
                        sStatus.dwCheckPoint = 0;
        }
        SetServiceStatus(hServiceStatus, &sStatus);
}

/* This is the code that is invoked when the service is started */
void svc_service_main(int argc, char **argv) {
        char *a = 0, *b = 0, d = 0;
        int c = 0;
        char szPath[512];
	lua_State *L;

        hServiceStatus = RegisterServiceCtrlHandler(argv[0],
                (void *)svc_service_control);
        if(hServiceStatus == 0) {
                return;
        }

        sStatus.dwServiceType                   = SERVICE_WIN32_OWN_PROCESS;
        sStatus.dwCurrentState                  = SERVICE_START_PENDING;
        sStatus.dwControlsAccepted              = SERVICE_ACCEPT_STOP
                                                | SERVICE_ACCEPT_SHUTDOWN;
        sStatus.dwWin32ExitCode                 = 0;
        sStatus.dwServiceSpecificExitCode       = 0;
        sStatus.dwCheckPoint                    = 0;
        sStatus.dwWaitHint                      = 2 * 1000; /* Two seconds */
        sStatus.dwCurrentState = SERVICE_RUNNING;

        SetServiceStatus(hServiceStatus, &sStatus);

        /* Set the CWD to the directory the service runs in */
        GetModuleFileName( NULL, szPath, COUNTOF(szPath) );
        a = szPath;
        while(*a != 0 && c < 250) {
                if(*a == '/' || *a == '\\') {
                        b = a;
                }
                a++;
                c++;
        }
        if(b != 0) {
                d = *b;
                *b = 0; /* Now ARGV[0] is the path to the program */
                chdir(szPath);
                *b = d;
        }

        LOG = fopen("mmLunacyDNSLog.txt","ab");
        log_it("==mmLunacyDNS started==");
        L = init_lua(argv[0]);
	if(L == NULL) {
		fprintf(LOG,"FATAL: Can not init Lua state!\n");
		exit(1);
	}
	runServer(L);
	log_it("==mmLunacyDNS stopped==");
        fclose(LOG);	

        /* Clean up the stopped service; otherwise we get a nasty error in
           Win32 */
        sStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatus, &sStatus);

}

/* The main() function that calls the service */
int main(int argc, char **argv) {

        int a=0;
        char *b;
        int action = 0;

        static SERVICE_TABLE_ENTRY      Services[] = {
                { "mmLunacyDNS",  (void *)svc_service_main },
                { 0 }
        };
        if(argc > 1) {

                /* Are we started as a service? */
                if (strcmp(argv[1], "service") == 0) {
                        if (!StartServiceCtrlDispatcher(Services)) {
                                printf("Fatal: Can not start service!\n");
                                return 1;
                        }
                        return 0;
                }

                b = argv[1];
                for(a=0;a<5 && *b;a++) {
                        if(*b == 'r') { /* --remove */
                                action = 1;
                        } else if(*b == 'd') { /* --nodaemon or -d */
                                action = 2;
                        }
                        b++;
                }
                if(action == 1) { /* --remove */
                        svc_remove_service();
                } else if(action == 2) { /* --nodaemon or -d */
			lua_State *L;
			isInteractive = 1;
			L = init_lua(argv[0]);
			if(L != NULL) {
				runServer(L);
			} else {
				puts("Fatal: Can not init Lua");
				exit(1);
			}
                } else { /* --install */
                        svc_install_service();
                }
        } else {
                printf("mmLunacyDNS version 2020-07-24\n\n");
                printf(
	            "mmLunacyDNS is a DNS server that is a Windows service\n\n"
                    "To install this service:\n\n\tmmLunacyDNS --install\n\n"
                    "To remove this service:\n\n\tmmLunacyDNS --remove\n\n");
        }
        return 0;
}
#endif /* MINGW */
