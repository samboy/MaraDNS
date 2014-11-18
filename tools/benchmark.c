/* Copyright (c) 2002-2005 Sam Trenholme
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

/* Simple testing DNS resolving client.  This sends out simple
   queries to DNS servers and prints out to stdout the replies
   it receives.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "../MaraDns.h"
/* All of the labels */
#include "askmara_labels_en.h"

#include "../dns/functions_dns.h"


int querynum;

int harderror(char *msg) {
    printf("%s%s%s",L_HARD_ERROR,msg,L_NEWLINE);
    exit(1);
    }

void timeout() {
    printf("Query failed on query number %d\n",querynum);
    exit(1);
    }

int main(int argc, char **argv) {
    char *server_address = NULL;
    struct sockaddr_in dns_udp;
    int len_inet; /* Length */
    int s; /* Socket */
    js_string *outdata; /* Outgoing data */
    js_string *indata, *uindata; /* Incoming data (uncompressed version) */
    q_header header; /* header data */
    q_question question;
    int place,count;

    /* Determine what the query string is */
    if(argc < 2 || argc > 3)
        harderror(L_USAGE);

    /* Determine what IP address to bind to */
    if(argc == 3)
        server_address = argv[2];
    else
        server_address = "127.0.0.3";

    if((indata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_INDATA);
    if((uindata = js_create(2048,1)) == 0)
       harderror(L_JS_CREATE_UINDATA);
    if((outdata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_OUTDATA);
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);
    /* Create a UDP client socket */
    if((s = socket(AF_INET,SOCK_DGRAM,0)) == -1)
        harderror(L_SOCKET);

    /* Create a socket address to use with sendto() */
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET;
    dns_udp.sin_port = htons(53);
    if((dns_udp.sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE)
        harderror(L_MAL_IP);

    len_inet = sizeof(dns_udp);

    /* Format a DNS request */
    /* DNS header -> using dig defaults */
    header.id = 6;
    header.qr = 0;
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    header.rd = 1;
    header.ra = 0;
    header.z = 0;
    header.rcode = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Create a DNS question , and put it in raw UDP format */
    /* DNS question -> looking up an A record... */
    question.qclass = 1; /* ...on the internet */
    if(js_qstr2js(question.qname,argv[1]) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make 'Aexample.com.' raw UDP data */

    place = hname_2rfc1035(question.qname);
    if(place == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = place;

    /* Make a string containing the RAW UDP query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    /* Create an timeout alarm */
    signal(SIGALRM,timeout);
    alarm(10); /* 10 seconds */

    /* The core of the stress test for the server */
    for(querynum = 0; querynum < 50000; querynum++) {

     /* Send out a DNS request */
     if(sendto(s,outdata->string,outdata->unit_count,0,
       (struct sockaddr *)&dns_udp,len_inet) < 0)
        harderror(L_UDP_NOSEND); /* Unable to send UDP packet */

     /* Wait for a reply from the DNS server */
     if((count = recvfrom(s,indata->string,indata->max_count,0,
                        (struct sockaddr *)&dns_udp,
                        (socklen_t *)&len_inet)) < 0)
        harderror(L_DNS_R_ERROR); /* Problem getting DNS server response */

     if(querynum % 1000 == 0)
        printf("%d queries performed\n",querynum);

    }
   return 0;
   }

