/* Copyright (c) 2002-2007 Sam Trenholme
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

/* This is like askmara, but sends psudorandom noise and doesn't wait
   for an answer.  Used in stress testing, where we do not need to
   see the answer */

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
/* Yes, we use the RNG to make the pseudo-random number */
#include "../rng/rng-api-fst.h"

int verbose_mode = 0; /* Whether to have short or verbose output */

/* The crypto state */

MARA_BYTE r_inBlock[17],r_outBlock[17],r_binKey[17];
MARA_BYTE r_keyMaterial[320];
keyInstance r_keyInst;
cipherInstance r_cipherInst;
unsigned char crypto_key[34];

/* Generate a pseudo-random length (from 0 to 1024) on the seed we give it.
   This also initializes the RNG */

int gen_len(char *seed) {
    int desc, len;

    if(seed == 0)
        return JS_ERROR;

    /* Initialize the keys, including the "binKey" (is this used?) */
    memset(r_binKey,'0',16);
    memset(crypto_key,'z',16);
    /* Make the first 16 characters of the hostname the key (padded by the
       z character) */
    strncpy(crypto_key,seed,16);
    /* Set the plaintext block to 'zzzzzzzzzzzzzzzz' */
    memset(r_inBlock,'z',16);
    /* If the hostname is longer than 16 characters, make the plaintext
       the longer part of the hostname */
    if(strlen(seed) > 16)
        strncpy(r_inBlock,seed+16,16);

    if(makeKey(&r_keyInst, DIR_ENCRYPT, 128, crypto_key) != 1)
        return JS_ERROR;
    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1)
        return JS_ERROR;
    if(blockEncrypt(&r_cipherInst,&r_keyInst,r_inBlock,128,r_outBlock) != 128)
        return JS_ERROR;

    return ((r_outBlock[0] << 8) & 0x0300) | (r_outBlock[1] & 0x00ff);
    }

/* Make 1024 bytes of pseudo-random noise; this needs to be run
 * after gen_len above */
char *noise() {
        char *out;
        int a,b;
        out = malloc(1030);
        if(out == 0) {
                printf("FATAL: Can not allocate memory!\n");
                exit(0);
        }
        for(a = 0; a < 1024; a += 16) {
                r_inBlock[0] = (a << 8) & 0x03;
                r_inBlock[1] = a & 0xff;
                if(blockEncrypt(&r_cipherInst,&r_keyInst,
                                r_inBlock,128,r_outBlock) != 128) {
                        free(out);
                        return 0;
                }
                for(b = 0; b < 16; b++) {
                        out[a + b] = r_outBlock[b];
                }
        }
        return out;
}

int harderror(char *msg) {
    if(verbose_mode == 0)
        printf("# ");
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
    q_header header; /* header data */
    q_question question;
    int counter,place,count;
    fd_set rx_set; /* Using select() because if its timeout option */
    int maxd;      /* select() */
    struct timeval tv;  /* select() */
    int n; /* Select() return value */
    char *white = NULL; /* White noise */
    int len = 0;

    /* Determine what the query string is */
    if(argc < 2 || argc > 4)
        harderror(L_USAGE);

    /* See if we are in verbose mode or not */
    verbose_mode = 0;
    if(argc >= 3 && *argv[1] == '-')
        verbose_mode = 1;

    /* Determine what IP address to connect to */
    if(argc == 3 + verbose_mode)
        server_address = argv[2 + verbose_mode];
    else
        server_address = "127.0.0.1";

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
    /* When debugging MaraDNS on systems where I do not have root, it is
       useful to be able to contact a MaraDNS server running on a high
       port number.  However, DNS_PORT should be 53 otherwise (defined
       in MaraDNS.h) */
    dns_udp.sin_port = htons(DNS_PORT);
    if((dns_udp.sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE)
        harderror(L_MAL_IP);

    len_inet = sizeof(dns_udp);

    /* Format a DNS request */
    /* DNS header -> using dig defaults */
    len = gen_len(argv[1 + verbose_mode]);
    header.id = len;
    header.qr = 0;
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

    /* Create a DNS question , and put it in raw UDP format */
    /* DNS question -> looking up an A record... */
    question.qclass = 1; /* ...on the internet */
    if(js_qstr2js(question.qname,argv[1 + verbose_mode]) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make sure that the csv1-compatible output hashes all non-RR
       output */
    if(verbose_mode == 0)
        printf("# ");

    printf("#Sending %d bytes of random data to %s\n",len,server_address);

    /* Make 'Aexample.com.' raw UDP data */

    place = hname_2rfc1035(question.qname);
    if(place == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = place;

    /* Make a string containing the RAW UDP query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    /* Send out a DNS request */

    white = noise();
    if(sendto(s,white,len,0,
       (struct sockaddr *)&dns_udp,len_inet) < 0)
        harderror(L_UDP_NOSEND); /* Unable to send UDP packet */

    /* Bye bye */
    exit(0);
    return 0;
    }

