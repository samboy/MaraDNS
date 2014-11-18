/* Copyright (c) 2002-2010 Sam Trenholme
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
   it receives.  This version creates TCP queries instead of
   UDP queries.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#ifndef MINGW32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif
#include "../MaraDns.h"
/* All of the labels */
#include "askmara_labels_en.h"
/* BEGIN RNG USING CODE */
/* Yes, we use the RNG to make the psudo-random number */
#include "../rng/rng-api-fst.h"
/* END RNG USING CODE */

#include "../libs/MaraHash.h"
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"

int verbose_mode = 0; /* Whether to have short or verbose output;
                         1: verbose output; any other value: short output */
int timeout = 21;

unsigned short dns_port = DNS_PORT;

/* So -Wall doesn't gag */
extern int decomp_init();

/* Defining finctions which are part of askmara-tcp.c */
int verbose_output(js_string *uindata);
int csv1_compatible_output(js_string *uindata, js_string *query);
int out_answer(js_string *uindata,int *place);
int csv1_answer(js_string *uindata, int *place, js_string *query);

/* Octal escape any non-ASCII sequences in the askmara output; almost idential
   to show_esc_stdout */
int escape_stdout(js_string *js) {
    int counter = 0;
    unsigned char this;

    /* Sanity checks */
    if(js_has_sanity(js) < 0)
        return -1;
    if(js->unit_size != 1)
        return -1;

    while(counter < js->unit_count) {
        this = *(js->string + counter);
        if(this < 32 || this > 126)
            printf("\\%03o",this);
        else if(this == '\\')
            printf("\\%c",this);
        else
            printf("%c",this);
        counter++;
        }
    return 1;
    }

/* Generate a psudo-random query-id based on the hostname we give it.
   This helps us test the server against a large number of query IDs */

u_int16_t gen_id(char *hostname) {
    /* BEGIN RNG USING CODE */
    /* May as well bring out the bug guns (e.g. our secure RNG) */
    MARA_BYTE r_inBlock[17],r_outBlock[17],r_binKey[17];
    keyInstance r_keyInst;
    cipherInstance r_cipherInst;
    unsigned char crypto_key[34];
    int counter;
    char *mc1, *mc2;
    /* END RNG USING CODE */
    int ret = 4321;

    /* BEGIN RNG USING CODE */
    if(hostname == 0)
        return JS_ERROR;

    /* Initialize the keys, including the "binKey" (is this used?) */
    memset(r_binKey,'0',16);
    mc1 = "";
    mc2 = mc1;
    /* Set the crypto key to '' (UTF-8 encoding) */
    for(counter = 0; counter < 16; counter++) {
        *(crypto_key + counter) = *mc2;
        mc2++;
        if(*mc2 == 0)
           mc2 = mc1;
        }
    /*memset(crypto_key,'',16);*/
    /* Make the first 16 characters of the hostname the key (padded by the
        character--do you see a n~ there?) */
    strncpy((char *)crypto_key,hostname,16);
    /* Set the plaintext block to '' (UTF-8 encoding) */
    mc2 = mc1;
    for(counter = 0; counter < 16; counter++) {
        *(r_inBlock + counter) = *mc2;
        mc2++;
        if(*mc2 == 0)
           mc2 = mc1;
        }
    /*memset(r_inBlock,'',16);*/
    /* If the hostname is longer than 16 characters, make the plaintext
       the longer part of the hostname */
    if(strlen(hostname) > 16)
    strncpy((char *)r_inBlock,hostname+16,16);

    if(makeKey(&r_keyInst, DIR_ENCRYPT, 128, (char *)crypto_key) != 1)
        return JS_ERROR;
    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1)
        return JS_ERROR;
    if(blockEncrypt(&r_cipherInst,&r_keyInst,r_inBlock,128,r_outBlock) != 128)
        return JS_ERROR;

    ret = ((r_outBlock[0] << 8) & 0xff00) | (r_outBlock[1] & 0x00ff);
    /* END RNG USING CODE */
    return ret;
    }

int harderror(char *msg) {
    if(verbose_mode != 1)
        printf("# ");
    printf("%s%s%s",L_HARD_ERROR,msg,L_NEWLINE);
    exit(1);
    }

int main(int argc, char **argv) {
    char *server_address = NULL;
#if defined IPV6 && ! defined __CYGWIN__
    struct sockaddr_in6 server;
#else
    struct sockaddr_in server;
#endif
    int len_inet; /* Length */
    int s; /* Socket */
    js_string *outdata; /* Outgoing data */
    js_string *indata, *uindata; /* Incoming data (uncompressed version) */
    q_header header; /* header data */
    q_question question;
    int place,count;
    int nrd = 0; /* whether recursion is desired or not 1: No recursion;
                   0: recursion desired */
    int id;
    int attempts = 10;
    unsigned char len[2];
    int length;

    /* Determine what the query string is */
    verbose_mode = 0;
    timeout = 31;
    server_address = "127.0.0.3";
    argc--;
    argv++;
    while(argc > 0) {
        if(argv[0] [0]== '-' && argv[0][1] == 'v')
            verbose_mode = 1;
        else if(argv[0][0] == '-' && argv[0][1] == 'n')
            nrd = 1;
        else if(argv[0][0] == '-' && argv[0][1] == 'p') {
            if(argc < 2) {
                harderror(L_USAGE);
                }
            argc--;
            argv++;
            dns_port = atoi(*argv);
            if(dns_port < 1 || dns_port > 32000) {
                    harderror("Wrong port number\n");
                }
            }
        else if(argv[0][0] == '-' && argv[0][1] == 't') {
            if(argc < 2) {
                harderror(L_USAGE);
                }
            argc--;
            argv++;
            timeout = atoi(*argv);
            if(timeout < 1)
               harderror( L_INVALID_TIMEOUT);
            verbose_mode = 2;
            }
        else if (argv[0][0] != '-')
            break;
        else
            harderror(L_USAGE);
        argc--;
        argv++;
        }

    /* we expect now the query string and possibly the server */
    if(argc<1)
        harderror(L_USAGE);

    /* Determine what IP address to connect to */
    if(argc>1)
        server_address = argv[1];

    if((indata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_INDATA);
    if((uindata = js_create(2048,1)) == 0)
       harderror(L_JS_CREATE_UINDATA);
    if((outdata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_OUTDATA);
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);

    /* Create a socket address */
    memset(&server,0,sizeof(server));
#if defined IPV6 && ! defined __CYGWIN__
    if ( strchr(server_address,':') != NULL) {
        /* assume that we have an IPv6 address */

        /* Create a TCP socket */
        if((s = socket(PF_INET6,SOCK_STREAM,0)) == -1)
            harderror(L_SOCKET);

        server.sin6_family = AF_INET6;
        server.sin6_port = htons(dns_port);
        if( inet_pton(AF_INET6, server_address, &server.sin6_addr) < 1) {
            harderror(L_MAL_IP);
            }
        len_inet = sizeof(struct sockaddr_in6);
        }
    else {
        if((s = socket(PF_INET,SOCK_STREAM,0)) == -1)
            harderror(L_SOCKET);
        ((struct sockaddr_in*)&server)->sin_family = AF_INET;
        ((struct sockaddr_in*)&server)->sin_port = htons(dns_port);
        if((((struct sockaddr_in*)&server)->sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE)
            harderror(L_MAL_IP);
        len_inet = sizeof(struct sockaddr_in);
        }
#else
    if((s = socket(PF_INET,SOCK_STREAM,0)) == -1)
        harderror(L_SOCKET);

    server.sin_family = AF_INET;
    /* When debugging MaraDNS on systems where I do not have root, it is
       useful to be able to contact a MaraDNS server running on a high
       port number.  However, DNS_PORT should be 53 otherwise (defined
       in MaraDNS.h) */
    server.sin_port = htons(dns_port);
    if((server.sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE)
        harderror(L_MAL_IP);
    len_inet = sizeof(struct sockaddr_in);
#endif

    id = gen_id(argv[0]);
    /* Format a DNS request */
    /* DNS header */
    header.id = id;
    header.qr = 0;
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    header.rd = 1 - nrd; /* Recursion desired */
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
    if(js_qstr2js(question.qname,argv[0]) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make sure that the csv1-compatible output hashes all non-RR
       output */
    if(verbose_mode != 1)
        printf("# ");
    if(dns_port==DNS_PORT)
        printf("%s%s%s",L_QUERYING,server_address,L_NEWLINE); /* Querying the server with the IP... */
    else
        printf("%s%s#%d%s",L_QUERYING,server_address, dns_port,L_NEWLINE); /* Querying the server with the IP... */

    /* Make 'Aexample.com.' raw UDP data */

    place = hname_2rfc1035(question.qname);
    if(place == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = place;

    /* Make a string containing the RAW UDP query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    do {
        /* Connect to the zone server */
        if(connect(s,(struct sockaddr *)&server,len_inet) == -1)
        /* Determine how long it is */
        printf("DEBUG: outdata->unit_count %d\n",outdata->unit_count);
        len[0] = (outdata->unit_count & 0xff00) >> 8;
        len[1] = outdata->unit_count & 0xff;

        /* Send out how long the request is */
        if(write(s,len,2) == -1) {
            harderror("XXX No error message yet 271");
            }

        /* Send out a DNS request */
        if(write(s,outdata->string,outdata->unit_count) == -1)
           harderror("XXX No error message yet 276");

        /* Wait for a reply from the DNS server */
        recv(s,len,2,MSG_WAITALL);
        length = ((len[0] << 8) & 0xff00) | (len[1] & 0xff);
        if(length < 12)
            harderror("XXX No error message yet 282");
        if((count = recv(s,indata->string,length,MSG_WAITALL)) < 0)
            harderror(L_DNS_R_ERROR); /* Problem getting DNS server response */

        if(count != length)
             harderror("Length of reply not same as stated length");

        indata->unit_count = count;

        /* Get the ID from the remote response */
        if(count > 2) {
           id = (*(indata->string) << 8) | *(indata->string + 1);
           }
        else {
           id = header.id + 1;
           }

        attempts--;

        /* If the id doesn't match, get a reply again */
        } while(id != header.id && attempts > 0);

    decomp_init(0);
    decompress_data(indata,uindata);

    /*
    escape_stdout(indata);
    printf("%s%s",L_NEWLINE,L_NEWLINE);
    escape_stdout(uindata);
    */

    if(verbose_mode == 1)
        verbose_output(uindata);
    else
        csv1_compatible_output(uindata,question.qname);

    return 0;
    }

/* Verbose form of askmara output
   input: Pointer to js_string object with uncompressed UDP data
   output: None, shows data on standard output
*/

int verbose_output(js_string *uindata) {

    int place,counter,count;
    q_question question;
    q_header header;

    /* Allocate memory for the question.qname string */
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);

    /* Print out the reply -- cut 'n paste from rtest.c */
    if(read_hdr(uindata,&header) == JS_ERROR)
        harderror(L_INHEADER_CONV); /* Problem converting inheader */

    printf("%s%s",L_SERVER_REPLY,L_NEWLINE); /* Server reply */
    printf("%s%d%s",L_QUERY_ID,header.id,L_NEWLINE); /* Query ID */
    printf("%s%d%s",L_QUERY_TYPE,header.qr,L_NEWLINE); /* Query type */
    printf("%s%d%s",L_OPCODE,header.opcode,L_NEWLINE); /* Opcode */
    printf("%s%d%s",L_AUTHORITATIVE,header.aa,L_NEWLINE); /* Auth. */
    printf("%s%d%s",L_TRUNCATED,header.tc,L_NEWLINE); /* Truncated */
    printf("%s%d%s",L_RD,header.rd,L_NEWLINE); /* Recursion desired */
    printf("%s%d%s",L_RA,header.ra,L_NEWLINE); /* Recursion available */
    printf("%s%d%s",L_Z_DATA,header.z,L_NEWLINE); /* Z-Data */
    printf("%s%d%s",L_RC,header.rcode,L_NEWLINE); /* Result code */
    printf("%s%d%s",L_QDCOUNT,header.qdcount,L_NEWLINE); /* Num. questions */
    printf("%s%d%s",L_ANCOUNT,header.ancount,L_NEWLINE); /* Num. answers */
    printf("%s%d%s",L_NSCOUNT,header.nscount,L_NEWLINE); /* Num. NS RRs */
    printf("%s%d%s",L_ARCOUNT,header.arcount,L_NEWLINE); /* Num. Additional */
    printf("%s",L_NEWLINE);

    /* Get all of the questions in the reply */
    place = 12;
    for(counter = 0;counter < header.qdcount;counter++) {
        count = read_question(uindata,&question,place);
        if(count < 0) /* Error handling */
            harderror(L_QERROR); /* Error reading question */
        place += count;
        printf("%s",L_QNAME); /* Question name */
        hname_translate(question.qname,question.qtype);
        escape_stdout(question.qname);
        printf("%s%s%d%s",L_NEWLINE,L_QTYPE,question.qtype,L_NEWLINE);
        printf("%s%d%s",L_QCLASS,question.qclass,L_NEWLINE); /* Ques. Class */
        }

    /* Get all of the answers in the reply */
    /* Get all of the an replies */
    printf("%s%s%s",L_NEWLINE,L_ANREP,L_NEWLINE);
    for(counter = 0; counter < header.ancount; counter++)
        out_answer(uindata,&place);

    /* Get all of the ns replies */
    printf("%s%s%s",L_NEWLINE,L_NSREP,L_NEWLINE);
    for(counter = 0; counter < header.nscount; counter++)
        out_answer(uindata,&place);

    /* Get all of the ar replies */
    printf("%s%s%s",L_NEWLINE,L_ARREP,L_NEWLINE);
    for(counter = 0; counter < header.arcount; counter++)
        out_answer(uindata,&place);

    return 1;
    }


/* Parse the answer part of a DNS query.
   input: pointer to js_string with uncompressed UDP data
          pointer to where we are in that string
   output: outputs to stdout the data in that string
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
            harderror(L_RR_ERR); /* Error reading rr in AN section */
        *place += count;
        hname_translate(rr_hdr.name,rr_hdr.type);
        printf("%s",L_RNAME); /* Record name */
        escape_stdout(rr_hdr.name);
        printf("\nRecord type: %d\n",rr_hdr.type);
        printf("Record class: %d\n",rr_hdr.class);
        printf("Record TTL: %u\n",rr_hdr.ttl);
        printf("Record length: %d\n",rr_hdr.rdlength);
        printf("%s",L_NEWLINE);
        if(rr_hdr.type == RR_SOA) {
            if(read_soa(uindata,&soa,*place) == JS_ERROR)
                harderror(L_READSOA);
            hname_translate(soa.mname,RR_SOA);
            hname_translate(soa.rname,RR_MX);
            printf("%s",L_S_MNAME); /* SOA mname */
            escape_stdout(soa.mname);
            printf("%s%s",L_NEWLINE,L_S_RNAME); /* SOA rname */
            escape_stdout(soa.rname);
            printf("%s%s%u%s",L_NEWLINE,L_S_SERIAL,soa.serial,L_NEWLINE);
            printf("%s%d%s",L_S_REFRESH,(int)soa.refresh,L_NEWLINE);
            printf("%s%d%s",L_S_RETRY,(int)soa.retry,L_NEWLINE);
            printf("%s%d%s",L_S_EXPIRE,(int)soa.expire,L_NEWLINE);
            printf("%s%u%s",L_S_MINIMUM,soa.minimum,L_NEWLINE);
            }
        else if(rr_hdr.type == RR_MX) {
            if(uindata->unit_count < *place + 2)
                return JS_ERROR;
            mx.preference = ((*(uindata->string + *place) & 0xff) << 8) |
                             (*(uindata->string + *place + 1) & 0xff);
            read_ns(uindata,mx.exchange,*place + 2);
            printf("%s%d%s",L_M_PREF,mx.preference,L_NEWLINE); /* MX pref. */
            printf("%s",L_M_EX); /* MX exchange */
            hname_translate(mx.exchange,RR_MX);
            escape_stdout(mx.exchange);
            printf("%s%s",L_NEWLINE,L_NEWLINE);
            }
        else if(rr_hdr.type == RR_NS || rr_hdr.type == RR_CNAME ||
                rr_hdr.type == RR_PTR) {
            printf("%s",L_DATA); /* Data: */
            read_ns(uindata,mx.exchange,*place);
            hname_translate(mx.exchange,rr_hdr.type);
            escape_stdout(mx.exchange);
            printf("%s%s",L_NEWLINE,L_NEWLINE);
            }
        else if(rr_hdr.type == RR_A) {
            if(uindata->unit_count < *place + 4)
                return JS_ERROR;
            /* Display the IP of the data */
            printf("%s%d%s%d%s%d%s%d%s%s",L_IP,*(uindata->string + *place),
                   L_DOT,*(uindata->string + *place + 1),
                   L_DOT,*(uindata->string + *place + 2),
                   L_DOT,*(uindata->string + *place + 3),L_NEWLINE,L_NEWLINE);
            }
        else if(rr_hdr.type == RR_AAAA) {
            unsigned short *p;
            if(uindata->unit_count < *place + 16)
                return JS_ERROR;
            /* Display the IP of the data */
            /* Display the IP of the data */
            p = (unsigned short*)(uindata->string + *place);
            printf("%s%d%x:%x:%x:%x:%x:%x:%x:%x%s%s",L_IP,*(uindata->string + *place),
                       htons(*(p + 0 )),
                       htons(*(p + 1)),
                       htons(*(p + 2)),
                       htons(*(p + 3)),
                       htons(*(p + 4)),
                       htons(*(p + 5)),
                       htons(*(p + 6)),
                       htons(*(p + 7)),L_NEWLINE,L_NEWLINE);
            }
        else if(rr_hdr.type == RR_TXT) {
            printf("%s",L_TXT); /* Text String */
            read_txt(uindata,mx.exchange,*place);
            escape_stdout(mx.exchange);
            printf("%s%s",L_NEWLINE,L_NEWLINE);
            }
        else
            printf("%s%d%s%s",L_UNSUP,rr_hdr.type,L_NEWLINE,L_NEWLINE);

        *place += rr_hdr.rdlength; /* To do: read the RD data itself for
                                      all MaraDNS supported RRs */

        return 0;
        }

/* csv1-compatible form of askmara output
   input: Pointer to js_string object with uncompressed UDP data,
          Raw UDP for of the question
   output: None, shows data on standard output
*/

int csv1_compatible_output(js_string *uindata, js_string *query) {

    int place,counter,count;
    q_question question;
    q_header header;

    /* Allocate memory for the question.qname string */
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);

    /* Get the header of the reply */
    if(read_hdr(uindata,&header) == JS_ERROR)
        harderror(L_INHEADER_CONV); /* Problem converting inheader */

    /* Move past the questions */
    place = 12;
    for(counter = 0;counter < header.qdcount;counter++) {
        count = read_question(uindata,&question,place);
        if(count < 0) /* Error handling */
            harderror(L_QERROR); /* Error reading question */
        printf("# Question: ");
        if(hname_translate(question.qname,question.qtype) == JS_ERROR)
            harderror(L_QERROR);
        show_esc_stdout(question.qname);
        printf("\n");
        place += count;
        }

    /* Get all of the answers in the reply */

    /* Get all of the an replies */
    for(counter = 0; counter < header.ancount; counter++)
        csv1_answer(uindata,&place,query);

    /* Get all of the ns replies */
    printf("# %s%s",L_NSREP,L_NEWLINE);
    for(counter = 0; counter < header.nscount; counter++)
        csv1_answer(uindata,&place,query);

    /* Get all of the ar replies */
    printf("# %s%s",L_ARREP,L_NEWLINE);
    for(counter = 0; counter < header.arcount; counter++)
        csv1_answer(uindata,&place,query);

    return 1;
    }


/* Parse the answer part of a DNS query.
   input: pointer to js_string with uncompressed UDP data,
          pointer to where we are in that string,
          raw UDP form of the question asked
   output: outputs to stdout the data in that string
*/

int csv1_answer(js_string *uindata, int *place, js_string *query) {

    q_rr rr_hdr;
    rr_soa soa;
    rr_mx mx;
    int count;
    js_string *lower1, *lower2;

    /* Create the needed strings */
    if((rr_hdr.name = js_create(512,1)) == 0)
       harderror(L_HNAME_OA); /* js_create with hname in oa */
    if((soa.mname = js_create(512,1)) == 0)
       harderror(L_C_MNAME); /* js_create with soa.mname in oa */
    if((soa.rname = js_create(512,1)) == 0)
       harderror(L_C_RNAME); /* js_create with soa.rname in oa */
    if((mx.exchange = js_create(512,1)) == 0)
       harderror(L_C_MXEXC); /* js_create with mx.exchange in oa */
    if((lower1 = js_create(512,1)) == 0)
       harderror(L_C_MXEXC); /* js_create with mx.exchange in oa */
    if((lower2 = js_create(512,1)) == 0)
       harderror(L_C_MXEXC); /* js_create with mx.exchange in oa */

    /* Start printing out the data header */
    count = read_rr_h(uindata,&rr_hdr,*place);
    if(count < 0)
        harderror(L_RR_ERR); /* Error reading rr in AN section */
    *place += count;

    /* Display a hash if the record name is not the same as the
       query (case_insensitive matching) */
    js_copy(query,lower1);
    js_copy(rr_hdr.name,lower2);
    lower1->encoding = JS_US_ASCII;
    lower2->encoding = JS_US_ASCII;
    js_tolower(lower1);
    js_tolower(lower2);
    if(js_issame(lower1,lower2) != 1)
        printf("#");

    hname_translate(rr_hdr.name,rr_hdr.type);
    escape_stdout(rr_hdr.name);
    /* We also show the type if this is an unsupported record type */
    if(rr_hdr.type != RR_A &&
       rr_hdr.type != RR_AAAA &&
       rr_hdr.type != RR_NS &&
       rr_hdr.type != RR_CNAME &&
       rr_hdr.type != RR_SOA &&
       rr_hdr.type != RR_PTR &&
       rr_hdr.type != RR_MX &&
       rr_hdr.type != RR_TXT)
        printf("|%d",rr_hdr.type);
    printf("|%u",rr_hdr.ttl);
    if(rr_hdr.type == RR_SOA) {
        if(read_soa(uindata,&soa,*place) == JS_ERROR)
            harderror(L_READSOA);
        hname_translate(soa.mname,RR_SOA);
        hname_translate(soa.rname,RR_MX);
        printf("|"); /* SOA mname */
        escape_stdout(soa.mname);
        printf("|"); /* SOA rname */
        escape_stdout(soa.rname);
        printf("|%u",soa.serial);
        printf("|%d",(int)soa.refresh);
        printf("|%d",(int)soa.retry);
        printf("|%d",(int)soa.expire);
        printf("|%u\n",soa.minimum);
        }
    else if(rr_hdr.type == RR_MX) {
        if(uindata->unit_count < *place + 2)
            return JS_ERROR;
        mx.preference = ((*(uindata->string + *place) & 0xff) << 8) |
                         (*(uindata->string + *place + 1) & 0xff);
        read_ns(uindata,mx.exchange,*place + 2);
        printf("|%d",mx.preference); /* MX pref. */
        hname_translate(mx.exchange,-2); /* Makes the char a pipe */
        escape_stdout(mx.exchange);
        printf("\n");
        }
    else if(rr_hdr.type == RR_NS || rr_hdr.type == RR_CNAME ||
            rr_hdr.type == RR_PTR) {
        read_ns(uindata,mx.exchange,*place);
        hname_translate(mx.exchange,-2); /* First char is a pipe */
        escape_stdout(mx.exchange);
        printf("\n");
        }
    else if(rr_hdr.type == RR_A) {
        if(uindata->unit_count < *place + 4)
            return JS_ERROR;
        /* Display the IP of the data */
        printf("|%d%s%d%s%d%s%d\n",*(uindata->string + *place),
               L_DOT,*(uindata->string + *place + 1),
               L_DOT,*(uindata->string + *place + 2),
               L_DOT,*(uindata->string + *place + 3));
        }
    else if(rr_hdr.type == RR_AAAA) {
        unsigned short *p;
        if(uindata->unit_count < *place + 16)
            return JS_ERROR;
        /* Display the IP of the data */
        /* Display the IP of the data */
        p = (unsigned short*)(uindata->string + *place);
        printf("|%x:%x:%x:%x:%x:%x:%x:%x\n",
                   htons(*(p + 0 )),
                   htons(*(p + 1)),
                   htons(*(p + 2)),
                   htons(*(p + 3)),
                   htons(*(p + 4)),
                   htons(*(p + 5)),
                   htons(*(p + 6)),
                   htons(*(p + 7)));
        }
    else if(rr_hdr.type == RR_TXT) {
        printf("|");
        read_txt(uindata,mx.exchange,*place);
        escape_stdout(mx.exchange);
        printf("\n");
        }
    else {
        printf("|\n");
        }

    *place += rr_hdr.rdlength; /* To do: read the RD data itself for
                                  all MaraDNS supported RRs */

    return 0;
    }

