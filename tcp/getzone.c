/* Copyright (c) 2002-2014 Sam Trenholme
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

/* Language-specific labels */
#include "getzone_locale.h"

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

int no_cname_warnings = 1; /* So we can link to MaraBigHash.o */
int csv2_tilde_handling = 0; /* For some reason, we link to the
                              * csv2 parser */
int dns_records_served = 0; /* This is used by MaraDNS.c */

void harderror(char *why) {
    printf("%s%s%s%s",LF,L_FATAL_COMMENT,why,LF); /* "\n", "# Fatal error: ", why, "\n" */
    exit(3);
    }

void timeout() {
    harderror(L_TIMEOUT); /* "Connection timed out" */
    }

/* Usage: getzone <zone name> <zone server IP> */

int main(int argc, char **argv) {
    int sock, preference;
    int len_inet, length, place, result;
    int soa_count = 0;
    struct sockaddr_in zone_server; /* AF_INET */
    js_string *send, *zone, *get, *expand, *mxexpand;
    /* ( Sending and getting data from the client ) */
    q_header header;
    q_rr rr;
    rr_soa soa;
    int qclass = 1;

    unsigned char len[2];

    if(argv[1] == 0 || argv[2] == 0) {
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

        /* Decompress that */
        decomp_init(0);
        if(decompress_data(get,expand) == JS_ERROR) {
            harderror(L_DECOMPRESS); /* "Fatal error performing decompression" */
            }

        if(read_hdr(expand,&header) == JS_ERROR)
            harderror(L_RHEADER); /* "Could not read header from server" */

        /* Stop on any error codes */
        if(header.rcode != 0) {
            switch(header.rcode) {
                case 1:
                    harderror(L_FORMAT); /* "Format error" */
                case 2:
                    harderror(L_SERVER_FAIL); /* "Server failure" */
                case 3:
                    harderror(L_NAME); /* "Name error" */
                case 4:
                    harderror(L_NOTIMPL); /* "Not implemented" */
                case 5:
                    harderror(L_REFUSE); /* "Refused" */
                default:
                    harderror(L_RCODE); /* "Rcode > 5" */
                }
            }


        /* Move past any and all questions */

        place = 12;
        if(header.qdcount > 0) {
            result = dlabel_length(expand,place);
            if(result == -1)
                harderror(L_DLABEL); /* "Invalid dlabel in question" */
            place += result;
            place += 4;
            header.qdcount--;
            }

        /* Convert the answers to csv1-compatible lines in a MaraDNS Zone
           file */
        while(header.ancount > 0) {
            result = read_rr_h(expand,&rr,place);
            if(result == -1)
                harderror(L_READ_RR_H); /* "Fatal error running read_rr_h" */
            place += result;
            js_destroy(get);

            /* Make sure that rr.name is in baliwick.  If not, then
               put in an "Out of baliwick" warning and comment out
               the offending line */
            if((get = js_create(rr.name->unit_count + 7,1)) == 0)
                harderror(L_CGET); /* "Can not make get string" */
            if(js_copy(rr.name,get) == JS_ERROR)
                harderror(L_GET_COPY); /* "Fatal error copying name to get" */
            get->encoding = zone->encoding;
            result = 0; /* Out of baliwick */
            if(js_issame(get,zone) == 1)
                result = 1; /* In baliwick */
            while(result == 0 && get->unit_count > zone->unit_count) {
                bobbit_label(get);
                if(js_issame(get,zone) == 1)
                    result = 1; /* In baliwick */
                }
            if(result == 0) /* If out of baliwick */
                printf("%s%s%s",L_BALIWICK,LF,L_HASH); /* "# Disabled out-of-baliwick record follows" */
            if((get = js_create((int)(rr.rdlength) + 7,1)) == 0)
                harderror(L_CGET); /* "Can not make get string" */
            if(js_substr(expand,get,place,rr.rdlength) == -1)
                harderror(L_RDDATA); /* "Problem getting rddata" */
            switch(rr.type) {
                case RR_SOA:
                    soa_count++;
                    if(soa_count > 1) /* Then the zone has ended */
                        exit(0);
                    /* Translate all the fields, going to failover
                       mode (Make this an "Unsupported" data type)
                       if needed */
                    if(read_soa(get,&soa,0) == JS_ERROR)
                        goto failover;
                    if(hname_translate(rr.name,RR_SOA) == JS_ERROR)
                        goto failover;
                    if(hname_translate(soa.mname,RR_A) == JS_ERROR)
                        goto failover;
                    if(soa.mname->unit_count < 1)
                        goto failover;
                    if(email_translate(soa.rname) == JS_ERROR)
                        goto failover;
                    show_esc_stdout(rr.name);
                    printf("|%u",rr.ttl);
                    *(soa.mname->string) = '|';
                    show_esc_stdout(soa.mname);
                    show_esc_stdout(soa.rname);
                    printf("|%u|%d|%d|%d|%u\n",soa.serial,(int)soa.refresh,
                           (int)soa.retry,(int)soa.expire,
                           soa.minimum);
                    break;
                case RR_A:
                    if(get->unit_count != 4)
                        goto failover;
                    if(hname_translate(rr.name,RR_A) == JS_ERROR)
                        harderror(L_TRANS); /* "Problem translating A record name" */
                    show_esc_stdout(rr.name);
                    printf("|%u|%d.%d.%d.%d\n",rr.ttl,*(get->string),
                           *(get->string + 1),*(get->string + 2),
                           *(get->string + 3));
                    break;
                case RR_MX:
                    if(get->unit_count < 3)
                        goto failover;
                    mxexpand = js_create(512,1);
                    if(mxexpand == 0)
                        goto failover;
                    preference = ((*(get->string) & 0xff) << 8) |
                                  (*(get->string + 1) & 0xff);
                    if(js_substr(get,mxexpand,2,get->unit_count - 2)
                       == JS_ERROR)
                        goto failover;
                    if(hname_translate(rr.name,RR_MX) == JS_ERROR)
                        goto failover;
                    if(hname_translate(mxexpand,RR_MX) == JS_ERROR)
                        goto failover;
                    if(expand->unit_count < 1)
                        goto failover;
                    *(expand->string) = '|';
                    *(mxexpand->string) = '|';
                    show_esc_stdout(rr.name);
                    printf("|%u|%d",rr.ttl,preference);
                    show_esc_stdout(mxexpand);
                    printf("%s",LF); /* "\n" */
                    js_destroy(mxexpand);
                    break;
                case RR_TXT:
                    if(get->unit_count < 1)
                        goto failover;
                    if(*(get->string) != get->unit_count - 1)
                        goto failover;
                    *(get->string) = '|';
                    if(hname_translate(rr.name,RR_TXT) == JS_ERROR)
                        goto failover;
                    show_esc_stdout(rr.name);
                    printf("|%u",rr.ttl);
                    show_esc_stdout(get);
                    printf("%s",LF); /* "\n" */
                    break;
                case RR_NS:
                case RR_PTR:
                case RR_CNAME:
                    if(hname_translate(rr.name,rr.type) == JS_ERROR)
                        harderror(L_HNAME); /* "Hname problem" */
                    if(hname_translate(get,RR_A) == JS_ERROR)
                        goto failover;
                    if(get->unit_count < 1)
                        goto failover;
                    *(get->string) = '|';
                    show_esc_stdout(rr.name);
                    printf("|%u",rr.ttl);
                    show_esc_stdout(get);
                    printf("%s",LF); /* "\n" */
                    break;
                default:
                failover:
                    if(hname_translate(rr.name,RR_A) == JS_ERROR)
                        harderror(L_HNAME); /* "Hname problem" */
                    if(rr.name->unit_count < 1)
                        harderror(L_ZERO); /* "No 0-length names!" */
                    *(rr.name->string) = 'U';
                    show_esc_stdout(rr.name);
                    printf("|%u|%u|",rr.ttl,rr.type);
                    show_esc_stdout(get);
                    printf("%s",LF); /* "\n" */
                }
            place += rr.rdlength;
            header.ancount--;
            }
        js_destroy(get);
        js_destroy(expand);

        }
    return 0; /* Success */
    }

