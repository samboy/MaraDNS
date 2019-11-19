/* Copyright (c) 2002-2019 Sam Trenholme
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

/* This is a version of askmara modified for regression testing purposes.
   Instead of verbosely telling us the entire reply from the server,
   this one simply tells us whether the answer is what we asked for,
   a "host not there" reply, a nxdomain reply, an error from the
   server, or if it timed out before we got a reply. */

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
    /* May as well bring out the bug guns (e.g. our secure RNG) */
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
    memset(crypto_key,'z',33);
    /* Make the first 16 characters of the hostname the key (padded by the
       z character) */
    strncpy(crypto_key,hostname,16);
    /* Set the plaintext block to 'zzzzzzzzz...' */
    memset(r_inBlock,'z',16);
    /* If the hostname is longer than 16 characters, make the plaintext
       the longer part of the hostname */
    if(strlen(hostname) > 16)
    strncpy(r_inBlock,hostname+16,16);

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
#ifdef DEBUG
    printf("idnum: %d\n",idnum);
#endif

    /* Format a DNS request */
    /* DNS header */
    header.id = idnum; /* Psudo-random number */
    header.qr = 0; /* It is a question */
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
        exit(7);
        }
    if((count = recvfrom(s,indata->string,indata->max_count,0,
                        (struct sockaddr *)&dns_udp,&len_inet)) < 0)
        harderror(L_DNS_R_ERROR); /* Problem getting DNS server response */

    indata->unit_count = count;

    decompress_data(indata,uindata);

    if(read_hdr(uindata,&header) == JS_ERROR) {
        printf("Result: Currupt DNS header\n");
        exit(9);
        }

    /* If the header ID is not the same as what we sent them, this is an
       error */
    if(header.id != idnum) {
        printf("Result: Bad ID (expected %d, got %d)\n",idnum,header.id);
        exit(10);
        }

    /* Make sure the reply is marked as a reply */
    if(header.qr != 1) {
        printf("Result: Reply not marked as reply\n");
        exit(11);
        }

    /* If the response code was not 0, show them the error */
    if(header.rcode != 0) {
        switch(header.rcode) {
            case 1:
                printf("Result: Format error\n");
                exit(1);
            case 2:
                printf("Result: Server failure\n");
                exit(2);
            case 3:
                printf("Result: NXDOMAIN\n");
                exit(0);
            case 4:
                printf("Result: Not implemented\n");
                exit(4);
            case 5:
                printf("Result: Query refused\n");
                exit(5);
            default:
                printf("Result: Unknown rcode %d\n",header.rcode);
                exit(6);
            }
        }

    /* Return error if no reply from server */
    if(header.ancount == 0 && header.nscount == 0 && header.arcount == 0) {
        printf("Result: We have no answers!\n");
        exit(8);
        }

    if(header.qdcount > 1) {
        printf("Result: qdcount is greater than one");
        exit(3);
        }

    /* Make sure that, if we have a question section in the reply,
       the question is the same as what we sent to the server */

    /* Get all of the questions in the reply */
    place = 12;
    for(counter = 0;counter < header.qdcount;counter++) {
        count = read_question(uindata,&question,place);
        if(count < 0) /* Error handling */
            harderror(L_QERROR); /* Error reading question */
        place += count;
        /* Check to make sure the question name is the same */
        if(js_issame(question.qname,qstring) != 1) {
            printf("The question they sent us is not the one we sent them\n");
            exit(12);
            }
        if(question.qtype != qtype) {
            printf("The question type they sent has been changed\n");
            exit(13);
            }
        if(question.qclass != 1) /* Internet class */ {
            printf("The question class they sent has been changed\n");
            exit(14);
            }
        }

    /* Get all of the answers in the reply */
    /* Get all of the an replies */
    for(counter = 0; counter < header.ancount; counter++) {
        if(out_answer(uindata,&place) < 0) {
            printf("Problem reading answer\n");
            exit(15);
            }
        }

    /* Get all of the ns replies */
    for(counter = 0; counter < header.nscount; counter++) {
        rtype = out_answer(uindata,&place);
        if(rtype < 0) {
            printf("Problem reading authority record\n");
            exit(16);
            }
        if(rtype == RR_SOA) {
            soa_ns = 1;
            }
        }

    /* Get all of the ar replies */
    for(counter = 0; counter < header.arcount; counter++) {
        if(out_answer(uindata,&place) < 0) {
            printf("Problem reading additional record\n");
            exit(17);
            }
        }

    if(header.ancount > 0)
        printf("Result: Answer from server\n");
    else {
        if(soa_ns == 0) {
            printf("Result: Referral from server\n");
            }
        else {
            printf("Result: No such host form server\n");
            }
        }
    exit(0);

    }

/* Parse the answer part of a DNS query.
   input: pointer to js_string with uncompressed UDP data
          pointer to where we are in that string
   output: negative number on error, type of record on success
*/

int out_answer(js_string *uindata,int *place) {

    q_rr rr_hdr;
    rr_soa soa;
    rr_mx mx;
    int count;

    /* Create the needed strings */
    if((rr_hdr.name = js_create(512,1)) == 0)
       harderror(L_HNAME_OA); /* js_create with hname in oa */
    if((soa.mname = js_create(512,1)) == 0)
       harderror(L_C_MNAME); /* js_create with soa.mname in oa */
    if((soa.rname = js_create(512,1)) == 0)
       harderror(L_C_RNAME); /* js_create with soa.rname in oa */
    if((mx.exchange = js_create(512,1)) == 0)
       harderror(L_C_MXEXC); /* js_create with mx.exchange in oa */

    /* Start printing out the data header */
    count = read_rr_h(uindata,&rr_hdr,*place);
    if(count < 0)
        return -2; /* Error reading rr in AN section */
    *place += count;
    if(rr_hdr.type == RR_SOA) {
        if(read_soa(uindata,&soa,*place) == JS_ERROR)
            return -3; /* Problem reading the SOA */
        }
    else if(rr_hdr.type == RR_MX) {
        if(uindata->unit_count < *place + 2)
            return -4; /* Problem reading MX */
        mx.preference = ((*(uindata->string + *place) & 0xff) << 8) |
                          (*(uindata->string + *place + 1) & 0xff);
        if(read_ns(uindata,mx.exchange,*place + 2) < 0)
            return -4; /* Problem reading MX */
        }
    else if(rr_hdr.type == RR_NS || rr_hdr.type == RR_CNAME ||
            rr_hdr.type == RR_PTR) {
        if(read_ns(uindata,mx.exchange,*place) < 0)
            return -6; /* Problem reading NS/CNAME/PTR */
        }
    else if(rr_hdr.type == RR_A) {
        if(uindata->unit_count < *place + 4)
            return -5; /* Problem reading A record */
        }
    else if(rr_hdr.type = RR_TXT) {
        printf("%s",L_TXT); /* Text String */
        if(read_txt(uindata,mx.exchange,*place) < 0)
            return -7; /* Problem reading TXT record */
        }

    *place += rr_hdr.rdlength; /* To do: read the RD data itself for
                                  all MaraDNS supported RRs */

    return rr_hdr.type;
    }

