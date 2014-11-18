/* Copyright (c) 2002 Sam Trenholme
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
 */

/* This is a version of getzone which does not convert the raw data in to
   MaraDNS' "csv1" zone file format; instead, it shows us the raw DNS
   packets on standard out.  Designed to be used to make input for
   test_zoneserver.c
 */

/* Language-specific labels */
#include "../tcp/getzone_locale.h"

/* Other includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "../MaraDns.h"
/* Function prototypes */
#include "../dns/functions_dns.h"
#include "../libs/MaraHash.h"
#include "../parse/functions_parse.h"
extern int decomp_init();

void harderror(char *why) {
    printf("%s%s%s%s",LF,L_FATAL_COMMENT,why,LF); /* "\n", "# Fatal error: ", why, "\n" */
    exit(3);
    }

void timeout() {
    harderror(L_TIMEOUT); /* "Connection timed out" */
    }

/* OK, get a load of this.  There are many older versions of
   BIND out there that completely, I mean, completely ignore the
   RFCs.  Instead of sending a compressed DNS packet, it sends
   a single resource record which it considers a "DNS packet".
   The only way to search for this is to see if the first part
   of the message is a DNS packet.  Since this behavior is
   not RFC complient, the "is this a buggy bind 8 packet"
   seacher will only allow /[A-Z][a-z][0-9]\-\_/ (perl5 regex)
   in a DNS name (we include _ because too many Microsoft shops
   have _ in their computer names)

   Input: A potential BIND-buggy DNS packet
   Output: 0 if it looks RFC complient, 1 if it's a !@#$ BIND4/8 packet,
           and -1 (JS_ERROR) if the sky fell down (actually, we just assume
           that it is a normal DNS packet with data which happens to look
           like a demented dlabel packet)

 */

int bind_bug_check(js_string *packet) {
    int place, len;
    place = 0;
    len = *packet->string;
    if(len <= 0 || len >= 64)
        return 0; /* This doesn't mean it's kosher; just that it is
                     not the kind of trash Bind 8 spews */
    while(len > 0 && len < 64) {
        while(len > 0) {
            unsigned char fina; /* Yes, I am pathetic enough to name
                                   variables after whatever beautiful
                                   latina has last caught my fancy */
            len--;
            place++;
            if(place > packet->unit_count || place > packet->max_count)
                return 1; /* Again, doesn't mean it's kosher */
            /* The /[A-Z][a-z][0-9]\-_/ regex; I'm doing this by
               sorting the regex in ASCII order and stopping if
               something is in a "hole" outside the regex 'cause I
               am too tired right now to do a big and/or expression */
            fina = *(packet->string + place);
            if(fina < '-') /* The first ASCII character in this regex */
                return 1;
            if(fina > '-' && fina < '0')
                return 1;
            if(fina > '9' && fina < 'A')
                return 1;
            if(fina > 'Z' && fina < '_')
                return 1;
            if(fina > '_' && fina < 'a')
                return 1;
            if(fina > 'z') /* UTF-8 in domain names would probably be
                              a reasonable option if BIND was not the
                              dominant DNS server out there */
                return 1;
            /* End of regex */
            }
        len = *(packet->string + place);
        }
    if(len == 0)
        return 0;
    return 1;
    }


/* Usage: getzone <zone name> <zone server IP> */

int main(int argc, char **argv) {
    int sock, preference;
    int len_inet, length, place = 0, result;
    int soa_count = 0;
    struct sockaddr_in zone_server; /* AF_INET */
    js_string *send, *zone, *get, *expand, *mxexpand;
    /* ( Sending and getting data from the client ) */
    q_header header;
    q_rr rr;
    rr_soa soa;
    int qclass = 1;

    unsigned char len[2];

    if((argc < 3 && argc > 4) || argv[1] == 0 || argv[2] == 0) {
        harderror(L_USAGE); /* "Usage: getzone zone_name zone_server_IP" */
        }
    if(argc == 4 && argv[3] == 0) {
        harderror(L_USAGE); /* "Usage: getzone zone_name zone_server_IP" */
        }

    /* Set up an option to change the query class */
    if(argc == 4 && atoi(argv[3]) == 255)
        qclass = 255;

    /* Create a timeout alarm */
    signal(SIGALRM,timeout);
    alarm(300); /* 5 minutes */

    /* Create a socket to the zone server */
    memset(&zone_server,0,sizeof zone_server);
    zone_server.sin_family = AF_INET;
    zone_server.sin_port = htons(53);
    zone_server.sin_addr.s_addr = inet_addr(argv[2]);

    if(zone_server.sin_addr.s_addr == INADDR_NONE)
        harderror(L_VALID_IP); /* "Please use a valid IP for the zone server" */

    len_inet = sizeof zone_server;

    /* Create a TCP/IP socket */
    sock = socket(PF_INET,SOCK_STREAM,0);
    if(sock == -1)
        harderror(L_NO_SOCK); /* "Unable to create TCP socket" */

    /* Connect to the zone server */
    if(connect(sock,(struct sockaddr *)&zone_server,len_inet) == -1)
        harderror(L_NO_CONNECT); /* "Unable to connect to zone server" */

    /* OK, create a query to send over the connection */
    if((send = js_create(256,1)) == 0)
        harderror(L_NO_SEND); /* "Unable to create send string object" */

    /* The 12-byte header to send to the DNS server */
    header.id = 45;
    header.qr = 0;
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    header.rd = 0;
    header.ra = 0;
    header.z = 0;
    header.rcode = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    if(make_hdr(&header,send) == JS_ERROR)
        harderror(L_NO_HEADER); /* "Unable to make DNS header" */

    if((zone = js_create(128,1)) == 0)
        harderror(L_NO_ZSTRING); /* "Unable to create zone string object" */

    if(js_qstr2js(zone,"A") == JS_ERROR)
        harderror(L_QSTR2JS_ERROR); /* "qstr2js" */

    if(js_qappend(argv[1],zone) == JS_ERROR)
        harderror(L_APPEND_Z); /* "Unable to append zone string to zone object" */

    /* Append trailing dot, if needed */
    if(*(zone->string + zone->unit_count - 1) != '.')
        if(js_qappend(".",zone) == JS_ERROR)
            harderror(L_APPEND_D); /* "Unable to append dot at end of zone string object" */

    /* Convert zone in to raw "over-the-wire" UDP data */
    if(hname_2rfc1035(zone) == JS_ERROR)
        harderror(L_INVALID_NAME); /* "Invalid form of zone name" */

    /* Append raw binary zone to data to send to server */
    if(js_append(zone,send) == JS_ERROR)
        harderror(L_APPEND_ZS); /* "Can not append zone string to send string" */

    /* Append query type and query class to data */
    if(js_adduint16(send,252) == JS_ERROR)
        harderror(L_ADD_QT); /* "Could not add query type to send" */
    if(js_adduint16(send,qclass) == JS_ERROR)
        harderror(L_ADD_QC); /* "Could not add query class to send" */

    /* Question formed, now send question to server */
    len[0] = (send->unit_count & 0xff00) >> 8;
    len[1] = send->unit_count & 0xff;
    if(write(sock,len,2) == -1)
        harderror(L_SEND_2BYTE); /* "Could not send 2-byte length header to zone server" */
    if(write(sock,send->string,send->unit_count) == -1)
        harderror(L_SEND_QUERY); /* "Could not send query to zone server" */

    if((rr.name = js_create(257,1)) == 0)
        harderror(L_C_RRNAME); /* "Could not create rr.name" */
    if((soa.mname = js_create(257,1)) == 0)
        harderror(L_MNAME); /* "Could not create soa.mname" */
    if((soa.rname = js_create(257,1)) == 0)
        harderror(L_RNAME); /* "Could not create soa.rname" */

    while(recv(sock,len,2,MSG_WAITALL) == 2) {

        int is_buggy_bind_packet = 0;
        /* Get the length of the reply from the server */
        length = ((len[0] << 8) & 0xff00) | (len[1] & 0xff);

        if(length < 12)
           harderror(L_NOT_MANLY); /* "Response from server is not long enough to hold header" */

        /* Allocate the string "get" */
        if((get = js_create(length + 7,1)) == 0)
            harderror(L_NO_GET); /* "Could not allocate memory for get string" */
        if((expand = js_create((length + 7) * 4,1)) == 0)
            harderror(L_NO_EXPAND); /* "Could not allocate memory for expand string" */

        if((length = recv(sock,get->string,length,MSG_WAITALL)) == -1)
            harderror(L_SERVER); /* "Could not get packet from server" */

        get->unit_count = length;

        show_esc_stdout(get);
        printf("\n");
        fflush(stdout);
        js_destroy(get);

        }
    return 0; /* Success */
    }

