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

/* This simply listens on port 53 and does nothing with what
   it receives, simulating a dead host.
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
        recvfrom(s,indata->string,512,0,(struct sockaddr *)&client,&len_inet);
        }

    }

