/* Copyright (c) 2007-2020 Sam Trenholme
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

/* coLunacyDNS: A small DNS server which uses Lua for configuration and
 * for the main loop.  This is Lunacy, a fork of Lua 5.1, and it's
 * embedded in the compiled binary (Lunacy is a superset of Lua 5.1
 * with a version of bitop added).
 */

#include <stdint.h>
#ifdef MINGW
#include <winsock.h>
#include <wininet.h>
#include <wincrypt.h>
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
#include <time.h>
#include <grp.h>
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
#define closesocket(a) close(a)
#endif

// Timestamp handling
int64_t the_time = -1;

/* On systems with a 32-bit time_t, anything before July 26, 2020
 * is assumed to be a time stamp after 2038; this allows us
 * to have dates from mid-2020 until mid-2156.  But, really,
 * this is 2020, there are no mainstream Linux distributions with
 * 32-bit support anymore, and anyone who needs to use 32-bit code to
 * save memory should avoid timestamps altogeter or use the
 * x32 ABI (which does have a 64-bit time_t while keeping pointers
 * 32 bits in size)
 *
 * THIS ONLY AFFECTS THINGS WHEN time_t IS 32-BIT 
 * THIS DOES NOT AFFECT WINDOWS 32-BIT BUILDS */
#define DW_MINTIME 1595787855

/* Set a 64-bit timestamp; same form as Deadwood's timestamp.
 * Epoch (0) is when the Blake's 7 episode Gambit was originally 
 * broadcast; each second has 256 "ticks". 
 * MacOS users will need to use FALLBACK_TIME; Windows has its
 * own quirky way to get 64-bit timestamps; Posix-compatible
 * sub-seconds has its own interface.  This handles all of that
 * mess; in addition, there is some attempt, but only when time_t is
 * 32-bits in size, to have things limp along after the January 19, 
 * 2038 rollover by assuming that, if the time stamp is in the past, we 
 * are actually in 2038 or later.  I checked, and on the 64-bit CentOS 8,
 * when running a 32-bit binary, post-2038 timestamps are still dynamic
 * and can give a correct timestamp when adjusted (on Windows, the 32-bit
 * Posix layer stops having functional timestamps come 2038).
 */
void set_time() {
#ifdef FALLBACK_TIME
        time_t sys_time;
        sys_time = time(0);
        if(sizeof(sys_time) > 4) {
                if(sys_time != -1) {
                        the_time = sys_time - 290805600;
                }
        } else {
                if(sys_time < DW_MINTIME) {
                        the_time = sys_time + 4004161696U;
                } else {
                        the_time = sys_time - 290805600;
                }
        }
        the_time <<= 8; /* Each second has 256 "ticks" */
#else /* FALLBACK_TIME */
#ifndef MINGW
        struct timespec posix_time;
        time_t coarse;
        long fine;
        long result;
        result = clock_gettime(CLOCK_REALTIME, &posix_time);
        if(result == 0) { /* Successful getting time */
                coarse = posix_time.tv_sec;
                fine = posix_time.tv_nsec;
                if(sizeof(coarse) > 4) {
                        if(coarse != -1) {
                                the_time = coarse - 290805600;
                        }
                } else {
                        if(coarse < DW_MINTIME) {
                                the_time = coarse + 4004161696U;
                        } else {
                                the_time = coarse - 290805600;
                        }
                }
                the_time <<= 8;
                fine /= 3906250; /* 256 "ticks" per second */
                if(fine > 0 && fine <= 256) {
                        the_time += fine;
                }
        }
#else /* MINGW */
        FILETIME win_time = { 0, 0 };
	uint64_t calc_time = 0;
        GetSystemTimeAsFileTime(&win_time);
        calc_time = win_time.dwHighDateTime & 0xffffffff;
        calc_time <<= 32;
        calc_time |= (win_time.dwLowDateTime & 0xffffffff);
        calc_time *= 2;
        calc_time /= 78125;
        calc_time -= 3055431475200LL;
        the_time = calc_time;
#endif /* MINGW */
#endif /* FALLBACK_TIME */
}

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
		fflush(stdout);
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
        fflush(LOG);
}
#endif /* MINGW */
// END timestamp handling

// BEGIN strong random number generation
// This compact code comes from https://github.com/samboy/rg32hash
// This is an implementation of RadioGatun[32]
// This implementation has been tested and verified to be correct
// against all official RadioGatun[32] test vectors, in addition to
// a test vector to verify this code handles a UTF-8 string the same
// way the RadioGatun[32] reference code does.  This code does not 
// generate any warnings when compiled with -Wall -Wpedantic in both
// GCC 8.3.1 and Clang 9.0.1.  This is correct C code.
#include <stdint.h> // Public domain random numbers
#define rz uint32_t // NO WARRANTY
#define rnp(a) for(c=0;c<a;c++)
void rnf(rz*a,rz*b){rz m=19,A[45],x,o=13,c,y,r=0;rnp(12)b[c+c%3*o]^=a
[c+1];rnp(m){r=(c+r)&31;y=c*7;x=a[y++%m];x^=a[y%m]|~a[(y+1)%m];A[c]=A
[c+m]=x>>r|x<<(32-r)%32;}for(y=39;y--;b[y+1]=b[y])a[y%m]=A[y]^A[y+1]^
A[y+4];*a^=1;rnp(3)a[c+o]^=b[c*o]=b[c*o+o];}void rnl(rz*u,rz*w,char*v
){rz s,q,c;rnp(40)w[c]=u[c%19]=0;for(;;rnf(u,w)){rnp(3){for(q=0;q<4;)
{w[c*13]^=s=(*v?255&*v:1)<<8*q++;u[16+c]^=s;if(!*v++){rnp(17)rnf(u,w)
;return;}}}}}rz rn(rz*m,rz*b,rz*a){if(*a&2)rnf(m,b);return m[*a^=3];}

// Random number generator state
uint32_t rgX_belt[40], rgX_mill[19], rgX_phase = 0;

void init_rng() {
	char noise[67];
	rgX_phase = 2;

#ifndef MINGW	
	int a = 0;
	FILE *rfile = NULL;
	rfile = fopen("/dev/urandom","rb");
	if(rfile == NULL) {
		log_it("You do not have /dev/urandom");
		log_it("I refuse to run under these conditions");
		exit(1);
	}
	for(a=0;a<64;a++) {
		int b;
		b = getc(rfile);
		if(b == 0) {
			b = 1;
		}
		noise[a] = b;
	}
	noise[64] = 0;
#else // MINGW
	HCRYPTPROV CryptContext;
	int q;
	q = CryptAcquireContext(&CryptContext, NULL, NULL, PROV_RSA_FULL,
                CRYPT_VERIFYCONTEXT);
	if(q == 1) {
		q = CryptGenRandom(CryptContext, 48, noise);
	}
	if(q == 0) {
		log_it("I can not generate strong random numbers");
		log_it("I refuse to run under these conditions");
		exit(1);
	}
	CryptReleaseContext(CryptContext,0);
	for(q=0;q<56;q++) {
		if(noise[q] == 0) {
			noise[q] = 1;
		}
	}
	noise[64] = 0;
#endif // MINGW

	rnl(rgX_mill,rgX_belt,noise);
}

uint32_t rand32() {
	if(rgX_phase == 0) {
		init_rng();
	}
	return rn(rgX_mill, rgX_belt, &rgX_phase);
}

uint32_t rgX16_place = 0, rgX16_num = 0;

uint32_t rand16() {
	if(rgX16_place == 0) {
		rgX16_num = rand32();
		rgX16_place = 1;
		return rgX16_num >> 16;
	}
	rgX16_place = 0;
	return rgX16_num & 65535;
}
	
// END random number API
	
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
        noblock.tv_sec = 0;
        noblock.tv_usec = 50000; // Strobe 20 times a second

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

// A 16 bit unsigned random number
static int coDNS_rand16 (lua_State *L) {
	lua_Number r = (lua_Number)rand16();
	lua_pushnumber(L, r);
	return 1;
}

// A 32 bit unsigned random number
static int coDNS_rand32 (lua_State *L) {
	lua_Number r = (lua_Number)rand32();
	lua_pushnumber(L, r);
	return 1;
}

// This returns a Deadwood, not Unix, timestamp
static int coDNS_timestamp(lua_State *L) {
	lua_Number r = (lua_Number)the_time;
	lua_pushnumber(L, r);
	return 1;
}

// Log a string (run in the Lua script)
static int coDNS_log (lua_State *L) {
        const char *message = luaL_checkstring(L,1);
        log_it((char *)message);
        return 0;
}

// We solve a DNS name by having the coroutine yield and then
// returning when we can give a reasonable answer
static int coDNS_solve (lua_State *L) {
	return lua_yield(L, lua_gettop(L));
}

/* Traverse a table like this: 
   key = nil
   while true do 
     key = coDNS.key(t, key)
     if not key then break else coDNS.log(key .. "," .. t[key]) end
   end
*/
#ifdef XTRA
static int coDNS_key(lua_State *L) {
	if(lua_type(L,1) != LUA_TTABLE) {
		lua_pushboolean(L, 0);
		return 1;
	}
	lua_settop(L, 2);
	if(lua_next(L, 1)) {
		return 2;
	}
	lua_pushboolean(L, 0);
	return 1;
}
#endif // XTRA

static const luaL_Reg coDNSlib[] = {
	{"rand16", coDNS_rand16},
	{"rand32", coDNS_rand32},
	{"timestamp", coDNS_timestamp},
        {"log", coDNS_log},
	{"solve", coDNS_solve},
#ifdef XTRA
	{"key", coDNS_key},
#endif // XTRA
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
        luaL_register(L, "coDNS", coDNSlib);
	lua_pop(L, 1); // _G.coDNS

	// Do not come crying to me if, after uncommenting the 
  	// following line, and running an untrusted Lua script,
	// bad things happen.
	// luaL_openlibs(L);

	// The gloabl table _coThreads will store active threads
	// so they do not get eaten by the garbage collector
	lua_newtable(L);
	lua_setglobal(L, "_coThreads"); 
	

        /* The filename we use is {executable name}.lua.
         * {executable name} is the name this is being called as,
         * usually coLunacyDNS (or coLunacyDNS.exe in Windows).
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
                strcpy(useFilename,"coLunacyDNS.lua");
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

/* On *NIX, drop non-root stuff once we bind to port 53 */
void sandbox() {
#ifndef MINGW
        unsigned char *c = 0;
        gid_t g = 99;
        if(chroot(".") == -1) {
                log_it("chroot() failed"); exit(1);
        }
        if(setgroups(1,&g) == -1) {
                log_it("setgroups() failed"); exit(1);
        }
        if(setgid(99) != 0) { // Yes, 99 is hard wired to minimize space
                log_it("setgid() failed"); exit(1);
        }
        if(setuid(99) != 0) {
                log_it("setuid() failed"); exit(1);
        }
        if(setuid(0) == 0) {
                log_it("Your kernel\'s setuid() is broken"); exit(1);
        }
#endif
}

/* Create a sockaddr_in that will be bound to a given port; this is
 * used by the code that binds to a randomly chosen port */
void setup_bind(struct sockaddr_in *dns_udp, uint16_t port) {
        if(dns_udp == 0) {
                return;
        }
        memset(dns_udp,0,sizeof(dns_udp));
        dns_udp->sin_family = AF_INET;
        dns_udp->sin_addr.s_addr = htonl(INADDR_ANY);
        dns_udp->sin_port = htons(port);
        return;
}

/* This tries to bind to a random port up to 10 times; should it fail
 * after 10 times, it returns a -1 */
int do_random_bind(SOCKET s) {
        struct sockaddr_in dns_udp;
        int a = 0;
        int success = 0;

        for(a = 0; a < 10; a++) {
                /* Set up random source port to bind to, between 20200
                 * and 24296 */
                setup_bind(&dns_udp, 20200 + (rand16() & 0xfff));
                /* Try to bind to that port */
                if(bind(s, (struct sockaddr *)&dns_udp, sizeof(dns_udp))!=-1) {
                        success = 1;
                        break;
                }
        }
        if(success == 0) { /* Bind to random port failed */
                return -1;
        }
        return 1;
}

/* Give a Lua state, which is the file 'config.lua' read, run the
 * server */
SOCKET startServer(lua_State *L) {
        SOCKET sock;
        struct sockaddr_in dns_udp;
        uint32_t ip = 0; /* 0.0.0.0; default bind IP */

        // Get bindIp from the Lua program
        lua_getglobal(L,"bindIp"); // Push "bindIp" on to stack
        if(lua_type(L, -1) == LUA_TSTRING) {
                char *bindIp;
                bindIp = (char *)lua_tostring(L, -1);
                ip = get_ip(bindIp);
        } else {
                log_it("Unable to get bindIp; using 0.0.0.0");
        }
        lua_pop(L, 1); // Remove _G.bindIp from stack, restoring the stack

	// No we have an IP, bind to port 53
        sock = get_port(ip,&dns_udp);
	sandbox(); // Drop root and chroot()
        log_it("Running coLunacyDNS");
	return sock;
}


// Process an incoming DNS query
void processQueryC(lua_State *L, SOCKET sock, char *in, int inLen, 
		   uint32_t fromIp, uint16_t fromPort) {
        char query[500];
        int qLen = -1;
        char fromString[128]; /* String of sending IP */
        int leni = sizeof(struct sockaddr);
	struct sockaddr_in dns_out;
	memset(&dns_out,0,sizeof(struct sockaddr_in));
	dns_out.sin_family = AF_INET;
	dns_out.sin_port = htons(fromPort);
	dns_out.sin_addr.s_addr = htonl(fromIp);

        snprintf(fromString,120,"%d.%d.%d.%d",fromIp >> 24,
                (fromIp & 0xff0000) >> 16,
                (fromIp & 0xff00) >> 8,
                 fromIp & 0xff);

        /* Prepare the reply */
        if(inLen > 12 && in[5] == 1) {
                /* Make this an answer */
                in[2] |= 0x80;
                in[7]++;
                in[11] = 0; // Ignore EDNS
        }
        qLen = humanDNSname(in + 12, query, 490);
        if(qLen > 0) {
                int qType = -1;
		lua_State *LT;
		int thread_status;
		char threadName[32];
		snprintf(threadName,27,
			"%08x%08x%08x",rand32(),rand32(),rand32());

		LT = lua_newthread(L);
		lua_getfield(L, LUA_GLOBALSINDEX, "_coThreads"); // Lua 5.1
		lua_pushstring(L,threadName);
		lua_pushvalue(L,-3); // Copy LT thread pointer to stack top
		lua_settable(L,-3); // Pop two from top, put in table
		lua_pop(L, 1); // Pointer to LT thread

                qType = (in[13 + qLen] * 256) + in[14 + qLen];
                lua_getglobal(LT, "processQuery");

                // Function input is a table, which I will call "t"
                lua_newtable(LT);

                // t["mmQuery"] = query, where "query" is the
                // dns query made (with a trailing dot), such
                // as "caulixtla.com." or "lua.org."
                lua_pushstring(LT,"mmQuery");
                lua_pushstring(LT,query);
                lua_settable(LT, -3);

                // t["mmQtype"] is a number with the query type
                lua_pushstring(LT,"mmQtype");
                lua_pushinteger(LT,(lua_Integer)qType);
                lua_settable(LT, -3);

                // t["mmFromIP"] is the IP the query came from,
                // in the form of a human-readable string
                lua_pushstring(LT,"mmFromIP");
                lua_pushstring(LT,fromString);
                lua_settable(LT, -3);

                // t["mmFromIPtype"] is a number with the number
                // 4, for IPv4
                lua_pushstring(LT,"mmFromIPtype");
                lua_pushinteger(LT,(lua_Integer)4);
                lua_settable(LT, -3);

                thread_status = lua_resume(LT, 1);
		// For now coroutine.yield (make that coDNS.solve)
                // returns a table with
		// t.answer = "Not implemented yet" then
		// immediately continues running the thread
		while(thread_status == LUA_YIELD) {
			lua_newtable(LT);
			lua_pushstring(LT,"answer");
			lua_pushstring(LT,"Not implemented yet");
			lua_settable(LT,-3);
			thread_status = lua_resume(LT, 1);
		}
		if(thread_status == 0) {	
                        const char *rs;
                        // Pull mmType from return table
                        rs = NULL;
                        if(lua_type(LT, -1) == LUA_TTABLE) {
                                lua_getfield(LT, -1, "mm1Type");
                                if(lua_type(LT, -1) == LUA_TSTRING) {
                                        rs = luaL_checkstring(LT, -1);
                                }
                        }
                        if(rs != NULL && rs[0] == 'A' && rs[1] == 0) {
                                lua_pop(LT, 1);
                                lua_getfield(LT, -1, "mm1Data");
                                if(lua_type(LT, -1) == LUA_TSTRING) {
                                        rs = luaL_checkstring(LT, -1);
                                } else {
                                       lua_pop(LT, 1);
                                       rs = NULL;
                                }
                        } else if(rs != NULL) {
                                lua_pop(LT, 1);
                                rs = NULL;
                        }
                        if(rs != NULL) {
				int a;
                                set_return_ip((char *)rs);
                                inLen = 17 + qLen;
                                for(a=0;a<16;a++) {
                                        in[len_inet + a] = p[a];
                                }

                                /* Send the reply */
                                sendto(sock,in,len_inet + 16,0,
                                       (struct sockaddr *)&dns_out, leni);
                                lua_pop(LT, 1);
                        }
                } else {
                        log_it("Error calling function processQuery");
                        log_it((char *)lua_tostring(LT, -1));
                }
		// Derefernce the thread so it can be collected
		lua_getfield(L, LUA_GLOBALSINDEX, "_coThreads"); // Lua 5.1
		lua_pushstring(L,threadName);
		lua_pushnil(L); // This will delete the table entry
		lua_settable(L, -3);
        }
}

void runServer(lua_State *L, SOCKET sock) {
        char in[515];
        socklen_t lenthing = sizeof(in);
        int a, len_inet;
        struct sockaddr_in dns_in;

        /* Now that we know the IP and are on port 53, process incoming
         * DNS requests */
        while(serverRunning == 1) {
                uint32_t fromIp; /* Who sent us a query */
                uint16_t fromPort; /* On which port */
		
                /* Get data from UDP port 53 */
                len_inet = recvfrom(sock,in,255,0,(struct sockaddr *)&dns_in,
                        &lenthing);
		set_time(); // Keep timestamp up to date
                /* Roy Arends check: We only answer questions */
                if(len_inet < 3 || (in[2] & 0x80) != 0x00) {
                        continue;
                }
                // IPv6 support is left as an exercise for the reader
                if(dns_in.sin_family != AF_INET) {
                        continue;
                }
                fromIp = dns_in.sin_addr.s_addr;
                fromIp = ntohl(fromIp);
		fromPort = ntohs(dns_in.sin_port);
		processQueryC(L, sock, in, len_inet, fromIp, fromPort);
	}
}

#ifndef MINGW
int main(int argc, char **argv) {
        lua_State *L;
        char *look;
	SOCKET sock;

	if(argc != 2 || *argv[1] == '-') {
        	printf("coLunacyDNS version 2020-07-27 starting\n\n");
	}
	set_time(); // Run this frequently to update timestamp
        // Get bindIp and returnIp from Lua script
        if(argc == 1) {
                log_it("Only debug (interactive) mode supported.");
                log_it("Running as a daemon not supported yet.");
                log_it("Usage: coLunacyDNS -d {config file}");
                return 1;
        }
        look = argv[1];
        if(look == 0) {
                log_it("Error getting command line args.");
                return 1;
        }
        if(look[0] == '-' && look[1] != 'd') {
                log_it("Only debug (interactive) mode supported.");
                log_it("Running as a daemon not supported yet.");
                log_it("Usage: coLunacyDNS -d {config file}");
                return 1;
        }
	// Allow testing of the strong prng algorithm
	if(argc == 2 && look[0] != '-') {
		uint32_t j;
		int z;
		rgX_phase = 2;
		rnl(rgX_mill,rgX_belt,look);		
		for(z = 0; z < 8; z++) {
			j = rn(rgX_mill,rgX_belt,&rgX_phase);	
			j = (j << 24 | (j & 0xff00) << 8 |
                             (j & 0xff0000) >> 8 | j >> 24);
			printf("%08x",j);
		}
		puts("");
		return 0;
	}
        if(argc == 2) {
                L = init_lua(argv[0]); // Initialize Lua
        } else if(argc == 3) {
                L = init_lua(argv[2]); // Initialize Lua
        } else {
                log_it("Only debug (interactive) mode supported.");
                log_it("Running as a daemon not supported yet.");
                log_it("Usage: coLunacyDNS -d {config file}");
                return 1;
        }
        if(L == NULL) {
                log_it("Fatal error opening lua config file");
                return 1;
        }
	sock = startServer(L);
        runServer(L,sock);
}
#else /* MINGW */

/* This program is a Windows service; I would like to thank Steve Friedl who
   put a public domain simple Windows service on his web site at unixwiz.net;
   his public domain code made it possible for me to write the Win32
   service code.

   After compiling, one needs to install this service:

        coLunacyDNS.exe --install

   Then one can start the service:

        net start coLunacyDNS

   (It can also be started from Control Panel -> Administrative tools ->
    Services; look for the "coLunacyDNS" service)

   To stop the service:

        net stop coLunacyDNS

   (Or from the Services control panel)

   To remove the service:

        coLunacyDNS.exe --remove

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
                        "coLunacyDNS",                   /* name of service */
                        "coLunacyDNS: https://maradns.samiam.org/",
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
         "coLunacyDNS service installed; start with: net start coLunacyDNS\n");
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

}

/* Remove the service from Windows' list of services; it's probably a good
 * idea to stop the service first */
void svc_remove_service() {
        SC_HANDLE hService = 0;
        SC_HANDLE hSCManager = OpenSCManager(0,0,0);
        hService = OpenService  (hSCManager,"coLunacyDNS",DELETE);
        if(DeleteService(hService) == 0) {
                printf("Problem deleting service\n");
        } else {
                printf("coLunacyDNS service removed\n");
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
	SOCKET sock;

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

	set_time(); // Run this frequently to update timestamp

        LOG = fopen("coLunacyDNSLog.txt","ab");
        log_it("==coLunacyDNS started==");
        L = init_lua(argv[0]);
        if(L == NULL) {
                fprintf(LOG,"FATAL: Can not init Lua state!\n");
                exit(1);
        }
	sock = startServer(L);
        runServer(L,sock);
        log_it("==coLunacyDNS stopped==");
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
                { "coLunacyDNS",  (void *)svc_service_main },
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
			SOCKET sock;
			set_time(); 
                        isInteractive = 1;
                        L = init_lua(argv[0]);
                        if(L != NULL) {
				sock = startServer(L);
                                runServer(L,sock);
                        } else {
                                puts("Fatal: Can not init Lua");
                                exit(1);
                        }
                } else { /* --install */
                        svc_install_service();
                }
        } else {
                printf("coLunacyDNS version 2020-07-27\n\n");
                printf(
                    "coLunacyDNS is a DNS server that is a Windows service\n\n"
                    "To install this service:\n\n\tcoLunacyDNS --install\n\n"
                    "To remove this service:\n\n\tcoLunacyDNS --remove\n\n");
        }
        return 0;
}
#endif /* MINGW */
