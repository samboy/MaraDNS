/* Copyright (c) 2002,2003 Sam Trenholme
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

/* Simple testing DNS resolving server.  All this does is
   bind to port 53, become nobody, and then print out in stdout
   the queries it receives (with all header information visible)
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
#include "../MaraDns.h"

int harderror(char *msg) {
    printf("Hard error: %s\n",msg);
    exit(1);
    }

main(int argc, char **argv) {
    char *bind_address;
    struct sockaddr_in dns_udp, client;
    int len_inet; /* Length */
    int s; /* Socket */
    int q; /* Used for binding, etc */
    js_string *indata; /* Incoming data */
    js_string *outdata; /* Incoming data */
    js_file desc;
    q_header header; /* header data */
    q_question question;
    int counter,place,count;

    /* Determine what IP address to bind to */
    if(argc == 2)
        bind_address = argv[1];
    else
        bind_address = "127.0.0.3";

    if((indata = js_create(512,1)) == 0)
       harderror("js_create with indata");
    if((outdata = js_create(512,1)) == 0)
       harderror("js_create with indata");
    if((question.qname = js_create(512,1)) == 0)
       harderror("js_create with qname");

    /* Get the contents for the outgoing DNS reply */
    js_qstr2js(indata,"rtest.reply");
    if(js_open_read(indata,&desc) == JS_ERROR)
        harderror("Unable to read rtest.reply");
    if(js_read(&desc,outdata,151) == JS_ERROR)
        harderror("Unable to read rtest.reply contents");
    js_close(&desc);

    /* Create a UDP socket */
    if((s = socket(AF_INET,SOCK_DGRAM,0)) == -1)
        harderror("Socket");

    /* Create a socket address to use with bind() */
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET;
    dns_udp.sin_port = htons(53);
    if((dns_udp.sin_addr.s_addr = inet_addr(bind_address)) == INADDR_NONE)
        harderror("Malformed IP");

    len_inet = sizeof(dns_udp);

    /* Bind to the socket.  Note that we have to be root to do this */
    if(bind(s,(struct sockaddr *)&dns_udp,len_inet) == -1)
        harderror("Binding problem--must be root");

    /* Drop elevated privileges */
    if(setuid(99) != 0)
        harderror("setuid failed");

    /* Make sure they are dropped */
    if(setuid(0) == 0)
        harderror("we still have root privileges!");

    /* loop to handle requests */
    for(;;) {
        if((counter = recvfrom(s,indata->string,512,0,
           (struct sockaddr *)&client,&len_inet)) < 0)
           continue; /* No processing if bad request */
        if(counter < indata->max_count)
            indata->unit_count = counter;
        else
            continue;
        printf("\nReceived DNS query\n");
        if(read_hdr(indata,&header) == JS_ERROR) {
            printf("Error processing header\n");
            continue;
            }
        /* Print the contents */
        printf("Query id: %d\n",header.id);
        printf("Query type: %d\n",header.qr);
        printf("Opcode: %d\n",header.opcode);
        printf("Authoritative: %d\n",header.aa);
        printf("Truncated: %d\n",header.tc);
        printf("Recurs desired: %d\n",header.rd);
        printf("Recurs available: %d\n",header.ra);
        printf("Z data: %d\n",header.z);
        printf("Result code: %d\n",header.rcode);
        printf("Num Questions: %d\n",header.qdcount);
        printf("Num Answers: %d\n",header.ancount);
        printf("Number NS records: %d\n",header.nscount);
        printf("Number additional records: %d\n",header.arcount);
        printf("\n");

        /* Look at all the questions being asked */

        place = 12; /* Header is 12 bytes */
        for(counter = 0;counter < header.qdcount;counter++) {
            count = read_question(indata,&question,place);
            if(count < 0) /* Error handling */
                break;
            place += count;
            printf("Question name: ");
            hname_translate(question.qname,question.qtype);
            js_show_stdout(question.qname);
            printf("\nQuestion type: %d\n",question.qtype);
            printf("Question class: %d\n",question.qclass);
            }

        /* Send to the client a reply */
        sendto(s,outdata->string,151,0,(struct sockaddr *)&client,len_inet);
        }

    }

