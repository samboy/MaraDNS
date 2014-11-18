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

/* This is a version of askmara modified for security testing purposes.
   This verifies that a DNS server discards queries which are marked as
   being an answer instead of a query. */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../MaraDns.h"
/* All of the labels */
#include "../tools/askmara_labels_en.h"
/* Yes, we use the RNG to make the psudo-random number */
#include "../rng/rng-api-fst.h"

/* Generate a psudo-random query-id based on the hostname we give it.
   This helps us test the server against a large number of query IDs */

u_int16_t gen_id(char *hostname) {
    /* May as well bring out the bug guns (e.g. our RNG) */
    MARA_BYTE r_inBlock[17],r_outBlock[17],r_binKey[17];
    MARA_BYTE r_keyMaterial[320];
    keyInstance r_keyInst;
    cipherInstance r_cipherInst;
    unsigned char crypto_key[34];
    int desc, len;

    if(hostname == 0)
        return JS_ERROR;

    /* Initialize the keys, including the "binKey" (is this used?) */
    memset(r_binKey,'0',16);
    memset(crypto_key,'z',16);
    /* Make the first 32 characters of the hostname the key (padded by the
       z character) */
    strncpy(crypto_key,hostname,16);
    /* Set the plaintext block to '0000000000000000' */
    memset(r_inBlock,'0',16);

    if(makeKey(&r_keyInst, DIR_ENCRYPT, 128, crypto_key) != 1)
        return JS_ERROR;
    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1)
        return JS_ERROR;
    if(blockEncrypt(&r_cipherInst,&r_keyInst,r_inBlock,128,r_outBlock) != 128)
        return JS_ERROR;

    return ((r_outBlock[0] << 8) & 0xff00) | (r_outBlock[1] & 0x00ff);
    }

int harderror(char *msg) {
    printf("%s%s%s",L_HARD_ERROR,msg,L_NEWLINE);
    exit(1);
    }

main(int argc, char **argv) {
    char *server_address = NULL;
    struct sockaddr_in dns_udp, server;
    int len_inet; /* Length */
    int s; /* Socket */
    int q; /* Used for binding, etc */
    js_string *outdata; /* Outgoing data */
    js_string *indata, *uindata; /* Incoming data (uncompressed version) */
    js_string *qstring; /* String to store the question we ask the server */
    q_header header; /* header data */
    q_question question;
    int counter,place,count,qtype;
    fd_set rx_set; /* Using select() because if its timeout option */
    int maxd;      /* select() */
    int idnum;
    struct timeval tv;  /* select() */
    int n; /* Select() return value */
    int rtype;
    int soa_ns = 0; /* Is this a "not there" or a referral */

    /* Determine what the query string is */
    if(argc < 2 || argc > 3)
        harderror(L_USAGE);

    /* Determine what IP address to connect to */
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
    if((qstring = js_create(512,1)) == 0)
       harderror("Can not create qstring string");
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

    idnum = gen_id(argv[1]); /* Make a psudo-random number based on the
                                first 32 characters of the request to send
                                to the server */

    /* Format a DNS request */
    /* DNS header */
    header.id = idnum; /* Psudo-random number */
    header.qr = 1; /* It is an answer */
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    header.rd = 1; /* Recursion desired */
    header.ra = 0;
    header.z = 0;
    header.rcode = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Create a DNS question (answer?), and put it in raw UDP format */
    /* DNS question -> looking up an A record... */
    question.qclass = 1; /* ...on the internet */
    if(js_qstr2js(question.qname,argv[1]) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make 'Aexample.com.' raw UDP data */

    qtype = hname_2rfc1035(question.qname);
    if(qtype == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = qtype;

    if(js_copy(question.qname,qstring) == JS_ERROR)
        harderror("Problem copying question.qname to qstring");

    /* Make a string containing the RAW UDP query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    /* Send out a DNS request */
    if(sendto(s,outdata->string,outdata->unit_count,0,
       (struct sockaddr *)&dns_udp,len_inet) < 0)
        harderror(L_UDP_NOSEND); /* Unable to send UDP packet */

    /* Wait for a reply from the DNS server */
    FD_ZERO(&rx_set);
    FD_SET(s,&rx_set);
    maxd = s + 1;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    n = select(maxd,&rx_set,NULL,NULL,&tv);
    if(n == -1)  /* select error */
        harderror("Select() failed");
    if(n == 0) /* Timeout */ {
        printf("Result: timeout\n");
        exit(0);
        }
    if((count = recvfrom(s,indata->string,indata->max_count,0,
                        (struct sockaddr *)&dns_udp,&len_inet)) < 0)
        harderror(L_DNS_R_ERROR); /* Problem getting DNS server response */

    printf("Warning: This server does not check the qr bit!\n");
    exit(1);

    }
