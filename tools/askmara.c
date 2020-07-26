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
   it receives.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#ifndef MINGW32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else /* MINGW32 */
#include <winsock.h>
#include <wininet.h>
#endif /* MINGW32 */
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

int verbose_output(js_string *uindata);
int csv2_compatible_output(js_string *uindata, js_string *query);
int out_answer(js_string *uindata,int *place);
int csv2_answer(js_string *uindata, int *place, js_string *query);
/* escape_stdout_csv2: From parse/Csv2_esc_txt.c and defined in
   parse/Csv2_functions.h */
extern int escape_stdout_csv2(js_string *js);

int verbose_mode = 0; /* Whether to have short or verbose output;
                         1: verbose output; any other value: short output */
int timeout = 21;

unsigned short dns_port = DNS_PORT;

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

uint16_t gen_id(char *hostname) {
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
    struct sockaddr_in dns_udp;
    struct sockaddr_in *pdns_udp = &dns_udp;
#ifdef IPV6
    struct sockaddr_in6 dns_udp6;
#endif
    int len_inet; /* Length */
    int s = -1; /* Socket */
    js_string *outdata; /* Outgoing data */
    js_string *indata, *uindata; /* Incoming data (uncompressed version) */
    q_header header; /* header data */
    q_question question;
    int place,count;
    fd_set rx_set; /* Using select() because if its timeout option */
    int maxd;      /* select() */
    struct timeval tv;  /* select() */
    int n; /* Select() return value */
    int nrd = 0; /* whether recursion is desired or not 1: No recursion;
                    0: recursion desired */
    int id;
    int attempts = 10;
    int desired_rr = -1; /* This is used to determine what RR type the
                            user desires */
    char *temp;

#ifdef MINGW32
    int err;
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2,2);
    err = WSAStartup(wVersionRequested, &wsaData);
#endif /* MINGW32 */
    /* Determine what the query string is */
    verbose_mode = 0;
    timeout = 31;
    server_address = ASKMARA_DEFAULT_SERVER;
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
    if(argc>1)
        server_address = argv[1];

    if((indata = js_create(4512,1)) == 0)
       harderror(L_JS_CREATE_INDATA);
    if((uindata = js_create(12048,1)) == 0)
       harderror(L_JS_CREATE_UINDATA);
    if((outdata = js_create(4512,1)) == 0)
       harderror(L_JS_CREATE_OUTDATA);
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);

    /* Create a socket address to use with sendto() */
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET;
    /* When debugging MaraDNS on systems where I do not have root, it is
       useful to be able to contact a MaraDNS server running on a high
       port number.  However, DNS_PORT should be 53 otherwise (defined
       in MaraDNS.h) */
    dns_udp.sin_port = htons(dns_port);
    len_inet = sizeof(dns_udp);

    if((dns_udp.sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE) {
#ifdef IPV6
        memset(&dns_udp6,0,sizeof(dns_udp6));
        dns_udp6.sin6_family = AF_INET6;
        dns_udp6.sin6_port = htons(dns_port);
        if( inet_pton(AF_INET6, server_address, &dns_udp6.sin6_addr) < 1) {
#endif
            harderror(L_MAL_IP);
#ifdef IPV6
        } else {
            len_inet = sizeof(dns_udp6);
            pdns_udp = (struct sockaddr_in*)&dns_udp6;
            if((s = socket(AF_INET6,SOCK_DGRAM,0)) == -1)
                harderror(L_SOCKET);
            }
#endif
    } else {
         /* Create a UDP IPv4 client socket */
        if((s = socket(AF_INET,SOCK_DGRAM,0)) == -1)
            harderror(L_SOCKET);
        }


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
    /* We now allow people to specify any numeric record in this format:
     * 40:t1.example.com., where 40 is the numeric rrtype */

    temp = argv[0];
    if(temp == 0) {
            printf("Wrong number of arguments to askmara\n");
            exit(43);
    }
    if(*temp >= '0' && *temp <= '9') {
        int td = 0;
        desired_rr = 0;
        for(td = 0; td < 7; td++) {
                if(*temp < '0' || *temp > '9') {
                        break;
                }
                desired_rr *= 10;
                desired_rr += *temp - '0';
                temp++;
        }
        if(*temp != ':') {
                printf("Invalid numeric rtype\n");
                exit(44);
        }
        *temp = 'A';
    }

    if(js_qstr2js(question.qname,temp) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make sure that the csv1-compatible output hashes all non-RR
       output */
    if(verbose_mode != 1)
        printf("# ");
    if(dns_port==DNS_PORT)
        printf("%s%s%s",L_QUERYING,server_address,L_NEWLINE); /* Querying the server with the IP... */
    else
        printf("%s%s#%d%s",L_QUERYING,server_address,dns_port,L_NEWLINE); /* Querying the server with the IP... */

    /* Make 'Aexample.com.' raw UDP data */

    place = hname_2rfc1035(question.qname);
    if(place == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = place;
    /* 40:name.example.com. style queries */
    if(desired_rr >= 0 && desired_rr <= 65535) {
            question.qtype = desired_rr;
    }

    /* Make a string containing the RAW UDP query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    do {
        /* Send out a DNS request */
        if(sendto(s,outdata->string,outdata->unit_count,0,
          (struct sockaddr *)pdns_udp,len_inet) < 0)
           harderror(L_UDP_NOSEND); /* Unable to send UDP packet */

        /* Wait for a reply from the DNS server */
        FD_ZERO(&rx_set);
        FD_SET(s,&rx_set);
        maxd = s + 1;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        n = select(maxd,&rx_set,NULL,NULL,&tv);
        if(n == -1)  /* select error */
            harderror("Select() failed");
        if(n == 0) /* Timeout */
            harderror("Timeout");
        if((count = recvfrom(s,indata->string,indata->max_count,0,
                        (struct sockaddr *)pdns_udp,
                        (socklen_t *)&len_inet)) < 0)
            harderror(L_DNS_R_ERROR); /* Problem getting DNS server response */

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
        csv2_compatible_output(uindata,question.qname);

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

/* csv2-compatible form of askmara output
   input: Pointer to js_string object with uncompressed UDP data,
          Raw UDP for of the question
   output: None, shows data on standard output
*/

int csv2_compatible_output(js_string *uindata, js_string *query) {

    int place,counter,count;
    q_question question;
    q_header header;

    /* Allocate memory for the question.qname string */
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);

    /* Get the header of the reply */
    if(read_hdr(uindata,&header) == JS_ERROR)
        harderror(L_INHEADER_CONV); /* Problem converting inheader */

    if(header.tc == 1) {
        printf("# Remote server said: TRUNCATED\n");
    }

    /* If not 0, show them the rcode from the remote server */
    switch(header.rcode) {
        case 1:
                printf("# Remote server said: FORMAT ERROR\n");
                break;
        case 2:
                printf("# Remote server said: SERVER FAILURE\n");
                break;
        case 3:
                printf("# Remote server said: NAME ERROR\n");
                break;
        case 4:
                printf("# Remote server said: NOT IMPLEMENTED\n");
                break;
        case 5:
                printf("# Remote server said: REFUSED\n");
                break;
        case 0:
                break;
        default:
                printf("# Non-RFC1035 RCODE %d sent from remote server\n",
                       header.rcode);
        }

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
        csv2_answer(uindata,&place,query);

    /* Get all of the ns replies */
    printf("# %s%s",L_NSREP,L_NEWLINE);
    for(counter = 0; counter < header.nscount; counter++)
        csv2_answer(uindata,&place,query);

    /* Get all of the ar replies */
    printf("# %s%s",L_ARREP,L_NEWLINE);
    for(counter = 0; counter < header.arcount; counter++)
        csv2_answer(uindata,&place,query);

    return 1;
    }


/* Parse the answer part of a DNS query.
   input: pointer to js_string with uncompressed UDP data,
          pointer to where we are in that string,
          raw UDP form of the question asked
   output: outputs to stdout the data in that string
*/

int csv2_answer(js_string *uindata, int *place, js_string *query) {

    q_rr rr_hdr;
    rr_soa soa;
    rr_mx mx;
    int count;
    js_string *lower1, *lower2;
    js_string *t;

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
    t = js_create(256,1);
    if(js_copy(rr_hdr.name,t) == JS_ERROR) {
            harderror("Couldn't copy hostname");
    }
    t->string++;
    t->unit_count--;
    escape_stdout(t);
    t->string--;
    t->unit_count++;
    js_destroy(t);
    if(rr_hdr.type == RR_SOA) {
        if(read_soa(uindata,&soa,*place) == JS_ERROR)
            harderror(L_READSOA);
        hname_translate(soa.mname,RR_MAGIC_SPACE);
        hname_translate(soa.rname,RR_MAGIC_EMAIL);
        printf(" +%u",rr_hdr.ttl);
        printf(" soa"); /* SOA mname */
        escape_stdout(soa.mname);
        escape_stdout(soa.rname);
        printf(" %u",soa.serial);
        printf(" %d",(int)soa.refresh);
        printf(" %d",(int)soa.retry);
        printf(" %d",(int)soa.expire);
        printf(" %u\n",soa.minimum);
        }
    else if(rr_hdr.type == RR_MX) {
        if(uindata->unit_count < *place + 2)
            return JS_ERROR;
        mx.preference = ((*(uindata->string + *place) & 0xff) << 8) |
                         (*(uindata->string + *place + 1) & 0xff);
        read_ns(uindata,mx.exchange,*place + 2);
        printf(" +%u mx %d",rr_hdr.ttl,mx.preference); /* MX pref. */
        hname_translate(mx.exchange,RR_MAGIC_SPACE); /* Makes the char a
                                                      * space */
        escape_stdout(mx.exchange);
        printf("\n");
        }
    else if(rr_hdr.type == RR_NS || rr_hdr.type == RR_CNAME ||
            rr_hdr.type == RR_PTR) {
        printf(" +%u",rr_hdr.ttl);
        switch(rr_hdr.type) {
                case RR_NS:
                        printf(" ns");
                        break;
                case RR_CNAME:
                        printf(" cname");
                        break;
                case RR_PTR:
                        printf(" ptr");
                        break;
                }
        read_ns(uindata,mx.exchange,*place);
        hname_translate(mx.exchange,RR_MAGIC_SPACE); /* First char is space */
        escape_stdout(mx.exchange);
        printf("\n");
        }
    else if(rr_hdr.type == RR_A) {
        if(uindata->unit_count < *place + 4)
            return JS_ERROR;
        /* Display the IP of the data */
        printf(" +%u a %d%s%d%s%d%s%d\n", rr_hdr.ttl,
                        *(uindata->string + *place),
               L_DOT,*(uindata->string + *place + 1),
               L_DOT,*(uindata->string + *place + 2),
               L_DOT,*(uindata->string + *place + 3));
        }
    else if(rr_hdr.type == RR_AAAA) {
        unsigned short *p;
        if(uindata->unit_count < *place + 16)
            return JS_ERROR;
        /* Display the IP of the data */
        p = (unsigned short*)(uindata->string + *place);
        printf(" +%u aaaa %x:%x:%x:%x:%x:%x:%x:%x\n", rr_hdr.ttl,
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
        int len,p;
        len = rr_hdr.rdlength;
        p = *place;
        printf(" +%u txt ",rr_hdr.ttl);
        /* XXX: This doesn't correctly handle multi-chunked TXT data */
        while(len > 0) {
            int q;
            q = read_txt(uindata,mx.exchange,p);
            if(q < 0) {
                printf("Problem reading TXT record\n");
                exit(1);
                }
            q++;
            escape_stdout_csv2(mx.exchange);
            len -= q;
            p += q;
            if(len > 0) {
                printf(";");
                }
            else {
                printf("\n");
                }
            }
         }
    else {
        printf(" +%u raw %d ",rr_hdr.ttl,rr_hdr.type);
        if(js_substr(uindata,mx.exchange,*place,rr_hdr.rdlength) == JS_ERROR) {
                printf("Problem copying string over\n");
                exit(55);
        }
        escape_stdout_csv2(mx.exchange);
        printf(" \n");
        }

    *place += rr_hdr.rdlength; /* To do: read the RD data itself for
                                  all MaraDNS supported RRs */
    return 0;
    }


