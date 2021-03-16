/* Copyright (c) 2002-2021 Sam Trenholme
 * Contributions made by Albert Lee (He made a valuable 1-line fix
 * back in 2005 to work around a kernel bug which was making MaraDNS
 * freeze up)
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

/* This is the core TCP DNS server */

/* Language specific labels */
#include "zoneserver_en.h"

/* Include stuff needed to be a TCP server */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "../server/read_kvars.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifndef DARWIN
#include <sys/resource.h>
#endif
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
/* BEGIN RNG USING CODE */
#include "../rng/rng-api-fst.h"
/* END RNG USING CODE */
/* Function prototypes */
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"
#include "../parse/Csv2_database.h"
#include "../parse/Csv2_read.h"
#include "../parse/Csv2_functions.h"
#include "functions_tcp.h"

/* One global variable: The number of children processes running */
int num_children = 0;
/* Another global variable: How many times they have run srng() before */
int srng_place = 0;
/* Yet another global variable: How csv2 zone files handle the tilde
 * character */
int csv2_tilde_handling = 2;
/* And another global variable: How much logging we do */
int verbose = 0;
/* Placeholder; dns_records_served is used by MaraDNS.c */
int dns_records_served = 0;
/* The last global variable: The IP of the UDP server we forward queries
   to */
int udp_forward_server = 0;

int dns_port = 53; /* The default port for the zoneserver to listen on */

int no_cname_warnings = 1; /* So we can link to MaraBigHash.o */

/* Signal handler for handling the exit of a child */
void handle_childs() {
    if(waitpid(0,NULL,WNOHANG) > 0)
        num_children--;
}

/* Signal handler for termination of the root process */
void handle_term() {
    killpg(getpgrp(), SIGTERM);
    exit(0);
}

/* Print out log messages
   Input: Null-terminated string with the message to log
   Output: JS_SUCCESS on success, JS_ERROR on error
*/

int mlog(char *logmessage) {

    if(logmessage == 0)
        return JS_ERROR;
    printf("%s%s%s",L_LOG,logmessage,LF); /* "Log: ", logmessage, LF */

    return JS_SUCCESS;
    }

/* Handler to handle fatal errors.
   Input: Pointer to null-terminalted string with fatal error
   Output: MaraDNS exits
*/

void harderror(char *why) {
    printf("%s%s%s",L_FATAL,why,LF); /* "Fatal error: ", why, "\n" */
    killpg(getpgrp(), SIGTERM); /* Don't leave orphaned children */
    exit(3);
    }

/* Secure psudo-random number generator.  Input: none.  Output: 16 bits
   of nice entropy
   WARNING: This must be run once as root before fork()ing; then it
   is run in the child process */

uint16 srng() {
/* BEGIN RNG USING CODE */
    js_string *kvar_query;
    js_string *srng_filename;
    unsigned char prng_seed[34];
    int desc, counter, max;
    pid_t process_id = 0;
    char path[MAXPATHLEN + 2];
    uint16 ret;
    static MARA_BYTE r_inBlock[17],r_outBlock[17],r_binSeed[17];
    static keyInstance r_seedInst;
    static cipherInstance r_cipherInst;

    if(srng_place == 0) {
        if((kvar_query = js_create(256,1)) == 0) {
            /* We must not continue in case of fatal error */
            printf("AIEEEEE! I can not init string to make srng!\n");
            exit(1);
            }
        if((srng_filename = js_create(256,1)) == 0) {
            /* We must not continue in case of fatal error */
            printf("AIEEEEE! I can not init string to make srng filename!\n");
            exit(1);
            }
        /* Determine which file to read key from */
        if(js_qstr2js(kvar_query,"random_seed_file") == JS_ERROR) {
            printf("AIEEEEE! I can not set up srng!\n");
            exit(1);
            }
        /* OK, now get the filename */
        if(read_kvar(kvar_query,srng_filename) != JS_SUCCESS) {
            srng_place = -1;
            /* This means each child process trying to forward
               queries will raz the end user; we must do it this way
               so that old mararc files work with the new zoneserver */
            }

        /* Default random_seed_file: /dev/urandom */
        if(js_length(srng_filename) == 0) {
                if(js_qstr2js(srng_filename,"/dev/urandom") != JS_SUCCESS) {
                        printf("AIEEEE! Can not set default random_seed_file");
                        exit(1);
                        }
                }

        /* OK, now start doing the RNG stuff */
        memset(r_inBlock,0,16);
        time((time_t *)&r_inBlock[0]); /* Change it every second */
        memset(r_binSeed,0,16);
        /* Read the key in from the file */
        if(js_js2str(srng_filename,path,MAXPATHLEN) == JS_ERROR) {
            printf("AIEEEEEE!  I can't convert random_seed_file filename.\n");
            exit(1);
            }
        if((desc = open(path,O_RDONLY)) == -1) {
            printf("AIEEEE! I can not read the random_seed_file file!\n");
            printf("Make sure that ");
            printf("%s",path);
            printf(" points to a valid filename!\n");
            }
        if(read(desc,prng_seed,16) != 16) { /* 16 bytes: 128-bit seed */
            printf("AIEEEE! I can not read 16 bytes from random_seed_file!\n");
            printf("Make sure that ");
            printf("%s",path);
            printf(" is at least 16 bytes long!\n");
            }
        close(desc);
        srng_place = 1;
        return(0);
        }
    else if(srng_place == -1) {
        printf("I could not get value for random_seed_file.\n");
        printf("You must have this set in your mararc file.\n");
        printf("Please add something like this to the mararc file\n");
        printf("you are using:\n");
        printf("\n\trandom_seed_file = \"/dev/urandom\"\n\n");
        exit(1);
        }
    /* OK, if this is the first time we actually use it, do some more
       initizalizing */
    else if(srng_place == 1) {
        /* In order to guarantee that two MaraDNS processes do not use the
           same prng seed, we exclusive-or the prng seed with the process-id
           of the maradns process */
        process_id = getpid();
        max = sizeof(pid_t);
        if(max > 15)
            max = 15;
        for(counter = 0; counter < max; counter++) {
            prng_seed[15 - counter] ^= process_id & 0xff;
            process_id >>= 8;
            }
        /* Initialize the PRNG with the seed in question */
        if(makeKey(&r_seedInst, DIR_ENCRYPT, 128, (char *)prng_seed) != 1) {
            printf("AIEEE! Not able to make key\n");
            exit(1);
            }
        if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1) {
            printf("AIEEE! Not able to cinit\n");
            exit(1);
            }
        if(blockEncrypt(&r_cipherInst,&r_seedInst,r_inBlock,128,r_outBlock)
           != 128) {
            printf("AIEEE! Not able to benc\n");
            exit(1);
            }
        ret = ((r_outBlock[0] & 0xff) << 8) |
              (r_outBlock[1] & 0xff);
        srng_place = 2;
        return ret;
        }
    else if(srng_place < 14) {
        ret = ((r_outBlock[srng_place] & 0xff) << 8) |
              (r_outBlock[srng_place + 1] & 0xff);
        srng_place += 2;
        return ret;
        }
    else {
        printf("AIEEEE!  srng has been run too many times!\n");
        exit(1);
        }
    printf("AIEEE! We should never get here in srng()\n");
    exit(1);
/* END RNG USING CODE */
    return 12;
    }

/* Bind to TCP dns_port.
   Input: pointer to socket to bind on, js_string with the dotted-decimal
          ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int tcpbind(int *sock, uint32 ip) {
    int len_inet; /* Length */
    struct sockaddr_in dns_tcp;
    int on = 1;

    /* Sanity checks */
    if(sock == 0)
        return JS_ERROR;
    if(ip == 0xffffffff)
        return JS_ERROR;

    /* This will convert ip into the correct form */
    ip = htonl(ip);

    /* Create a raw TCP socket */
    if((*sock = socket(PF_INET,SOCK_STREAM,0)) == -1) {
        return JS_ERROR;
        }
    /* Allow the socket to be reused more quickly (makes testing
     * easier) */
    if(setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                  sizeof(on)) == -1) {
        return JS_ERROR;
        }

    /* Choose an IP and port to bind to */
    memset(&dns_tcp,0,sizeof(dns_tcp));
    dns_tcp.sin_family = AF_INET;
    dns_tcp.sin_port = htons(dns_port);
    if((dns_tcp.sin_addr.s_addr = ip) == INADDR_NONE)
        return JS_ERROR;

    len_inet = sizeof(dns_tcp);

    /* Bind to the socket.  Note that we usually have to be root to do this */
    if(bind(*sock,(struct sockaddr *)&dns_tcp,len_inet) == -1) {
        printf("Unable to bind to to IP: ");
        printf("%s",strerror(errno));
        printf("\n");
        return JS_ERROR;
    }

    /* Set up an active listen on the socket */
    if(listen(*sock,250) == -1)
        return JS_ERROR;

    /* We are now on TCP dns_port.  Leave */
    return JS_SUCCESS;
    }

/* Start a TCP connection on socket sock.
   Input: pointer to socket, pointer to 1st ACL list, pointer to 2nd ACL
          list, 3rd ACL list, max elements allowed in both acl lists,
          the permissions they are allowed to have
          (LSB: On 1st ACL list, 2nd bit: on second ACL list, 3rd bit:
           on 3rd ACL list)
          NOTE: If they are only on the third ACL list, the gettcp will
          disconnect them and exit
   Output: Integer value of TCP connection on success, JS_ERROR on error
           (or permission denied)
*/

int gettcp(int *sock, ipv4pair *acl1, ipv4pair *acl2, ipv4pair *acl3,
           int max, int *perm) {
    int ret, counter;
    struct sockaddr_in adr_clnt;
    int len_inet;
    uint32 ip;

    len_inet = sizeof(adr_clnt);
    ret = accept(*sock, (struct sockaddr *)&adr_clnt,
                 (socklen_t *)&len_inet);
    if(ret == -1)
        return JS_ERROR;

    /* Make sure the client is authorized to connect to the zone server */
    ip = htonl(adr_clnt.sin_addr.s_addr);
    *perm = 0;
    /* First ACL list */
    counter = 0;
    while(counter < max && (acl1[counter]).ip != 0xffffffff) {
        if((ip & (acl1[counter]).mask) ==
           ((acl1[counter]).ip & (acl1[counter]).mask))
            *perm = 1;
        counter++;
        }

    /* Second ACL list */
    counter = 0;
    while(counter < max && (acl2[counter]).ip != 0xffffffff) {
        if((ip & (acl2[counter]).mask) ==
           ((acl2[counter]).ip & (acl2[counter]).mask))
            *perm += 2;
        counter++;
        }

    /* Third ACL list */
    counter = 0;
    while(counter < max && (acl3[counter]).ip != 0xffffffff) {
        if((ip & (acl3[counter]).mask) ==
           ((acl3[counter]).ip & (acl3[counter]).mask))
            *perm += 4;
        counter++;
        }

    if((*perm & 3) == 0) {
        /* OK, they were not on the ACL list.  Clise the connection and
           return an error */
        close(ret);
        if(verbose >= 4) {
                printf("Failed zone transfer attempt from IP %d.%d.%d.%d\n",
                ip >> 24,
                (ip >> 16) & 0xff,
                (ip >> 8) & 0xff,
                ip & 0xff);
                }
        return JS_ERROR;
        }
    else {
        return ret;
        }

    /* We should never get here */
    close(ret);
    return JS_ERROR;
    }

/* Given a socket TCP connection, the IP of a UDP dns server to contact,
   and a DNS packet, connect to the UDP DNS server, send the packet, and
   give the reply over the TCP connection.  Finally, close the TCP
   connection.

   Output: JS_SUCCESS on success; JS_ERROR on error */

int convert_query(int tcp_connect, void *udp_ip, int udp_ip_type,
                  js_string *packet, int perm_mask) {

    /* Magic voodoo to write *NIX TCP code */
    struct sockaddr_in dns_udp, server;
    /* int udp_socket; */
    int s, result;
    fd_set rx_set;
    struct timeval timeout;
    int *ipv4_ip;
    int n, maxd, tcp_id, udp_id;
    int len_inet;

    js_string *outdata, *indata;
    int sid, len;
    unsigned char get[2];
    q_header header; /* header data */

    /* Sanity checks */
    if(js_has_sanity(packet) != JS_SUCCESS)
        return JS_ERROR;
    if(udp_ip_type != 4) /* Only IPV4 for now */
        return JS_ERROR;

    tcp_id = (*(packet->string) << 8) | *(packet->string + 1);

    /*printf("DEBUG udp_ip is %p\n",udp_ip); */
    /* Send a UDP packet with the query in question */
    ipv4_ip = (int *)udp_ip;
    /*printf("DEBUG ipv4_ip is %d\n",*ipv4_ip);*/
    if(*ipv4_ip == 0xffffffff || *ipv4_ip == 0) { /* 255.255.255.255 and
                                                     0.0.0.0 */
        return JS_ERROR;
        }
    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    if((server.sin_addr.s_addr = htonl(*ipv4_ip)) == INADDR_NONE) {
        return JS_ERROR;
        }
    /* Create a secure psudo-random port number to bind to */
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET;
    /* The address we send the query from */
    dns_udp.sin_addr.s_addr = htons(INADDR_ANY);
    len_inet = sizeof(dns_udp);
    /* Format the DNS request */
    sid = srng();
    header.id = sid;
    header.qr = 0;
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    /* If they are on our recursive ACL list, we forward with recursion
       desired.  Otherwise, we forward without requesting for recursion */
    if((perm_mask & 4) == 4) {
        header.rd = 1;
        }
    else {
        header.rd = 0;
        }
    header.ra = 0;
    header.z = 0;
    header.rcode = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    /* Make a beginning of a DNS query from that header */
#ifdef AUTHONLY
    if((outdata = js_create(12345,1)) == 0) {
        return JS_ERROR;
        }
#else
    if((outdata = js_create(2500,1)) == 0) {
        return JS_ERROR;
        }
#endif
    if(make_hdr(&header,outdata) == JS_ERROR) {
        js_destroy(outdata);
        return JS_ERROR;
        }
    /* Now, append the question which is contained in the query */
    len = dlabel_length(packet,12);
    len += 2;
    /* Add the query and query type */
    if(js_substr_append(packet,outdata,12,len) == JS_ERROR) {
        js_destroy(outdata);
        return JS_ERROR;
        }
    /* Add the class, 1 for "internet" */
    if(js_adduint16(outdata,1) == JS_ERROR) {
        js_destroy(outdata);
        return JS_ERROR;
        }
    /* Send out the now-formed DNS request */

    /* Create a UDP client socket */
    if((s = socket(AF_INET,SOCK_DGRAM,0)) == -1) {
        js_destroy(outdata);
        return JS_ERROR;
        }

    /* Bind to a secure psudo-random address and port */
    /* XXX have this try multiple times before giving up */
    dns_udp.sin_port = htons(15000 + (srng() & 4095));
    if(bind(s,(struct sockaddr *)&dns_udp,sizeof(dns_udp)) < 0) {
        js_destroy(outdata);
        return JS_ERROR;
        }
    /*printf("DEBUG: About to send out UDP packet to %d...\n",*ipv4_ip);*/
    result = sendto(s,outdata->string,outdata->unit_count,0,
                    (struct sockaddr *)&server,len_inet);
    if(result < 0) {
        close(s);
        js_destroy(outdata);
        return JS_ERROR;
        }

    FD_ZERO(&rx_set);
    FD_SET(s,&rx_set);
    maxd = s + 1;
    timeout.tv_sec = 5; /* Five second timeout */
    timeout.tv_usec = 0;
    n = select(maxd,&rx_set,NULL,NULL,&timeout);
    if(n <= 0) { /* Timeout or select error */
        close(s);
        js_destroy(outdata);
        return JS_ERROR;
        }

    /* Get reply from the DNS server */
    if((indata = js_create(4100,1)) == 0) {
        return JS_ERROR;
        }
    /*printf("DEBUG about to get UDP packet from remote server\n");*/
    result = recvfrom(s,indata->string,indata->max_count,0,
                      (struct sockaddr *)&dns_udp,
                      (socklen_t *)&len_inet);
    if(result < 0) {
        close(s);
        /*printf("DEBUG: Never got reply from UDP server\n");*/
        js_destroy(outdata);
        js_destroy(indata);
        return JS_ERROR;
        }

    /* Now that we are done with the socket, close it */
    close(s);

    /*printf("DEBUG got packet from remote server\n");*/

    indata->unit_count = result;
    /* Make sure that the data is sane */
    if(decompress_data(indata,outdata) == JS_ERROR) {
         js_destroy(outdata);
         js_destroy(indata);
         return JS_ERROR;
         }

    /* Make sure IDs match */
    udp_id = (*(outdata->string) << 8) | *(outdata->string + 1);
    if(udp_id != sid) {
         js_destroy(outdata);
         js_destroy(indata);
         return JS_ERROR;
         }

    /*printf("DEBUG tcp_id: %d udp_id: %d sid: %d\n",tcp_id,udp_id,sid);*/

    /* Make sure the reply has the ID number of the TCP request */
    *(outdata->string) = (tcp_id & 0xff00) >> 8;
    *(outdata->string + 1) = tcp_id & 0xff;

    /* Now, send the data over the TCP connection */
    get[0] = (outdata->unit_count & 0xff00) >> 8;
    get[1] = outdata->unit_count & 0xff;
    if(write(tcp_connect,get,2) == -1) {
        js_destroy(outdata);
        js_destroy(indata);
        return JS_ERROR;
        }
    if(write(tcp_connect,outdata->string,outdata->unit_count) == -1) {
        js_destroy(outdata);
        js_destroy(indata);
        return JS_ERROR;
        }
    /* close the connection after the forward query is sent */
    close(tcp_connect);
    /*printf("DEBUG gave client reply, bye bye!\n");*/
    return JS_SUCCESS;
    }

/* Given a socket TCP connection, serve a zone over the connection in
   question.
   Input: socket that TCP connection is on, What the connecter is allowed to do
      (0: Nothing
       1: Only transfer zone files
       2: Only forward queries
       3: Both)
   Ouput: JS_SUCCESS or JS_ERROR
*/

int serve_zone(int connect, int perms) {
    int length, rr_type;
    q_header header, soa_reply_header;
    js_file desc;
    unsigned char get[2];
    js_string *name, *data, *zone, *query, *response, *soa, *filename,
              *binzone;
    int is_soa = 1, soa_q = 0;
    int counter;
    uint32 ttl;

    desc.buffer = 0;

    /* 30-second idle timeout */
    alarm(30);

    /* Create the js_string objects */
    if((name = js_create((MAX_RECORD_LENGTH * 2) + 3,1)) == 0)
        return JS_ERROR;
    if(js_set_encode(name,MARA_LOCALE) == JS_ERROR)
        return JS_ERROR;
    if((data = js_create((MAX_RECORD_LENGTH * 2) + 3,1)) == 0) {
        js_destroy(name);
        return JS_ERROR;
        }
    if(js_set_encode(data,MARA_LOCALE) == JS_ERROR)
        goto clean_nd;

    /* Get the Zone query length header */
    if(connect == 1) {
        if(read(0,get,2) != 2)
            goto clean_nd;
        }
    else {
        if(recv(connect,get,2,MSG_WAITALL) != 2)
            goto clean_nd;
        }

    /* Determine how long the actual query will be */
    length = (get[0] & 0xff) << 8 | (get[1] & 0xff);
    if(length > 380)
        goto clean_nd;

    /* Get the actual query */
    if(connect == 1) {
        if(read(0,name->string,length) != length)
            goto clean_nd;
        }
    else {
        if(recv(connect,name->string,length,MSG_WAITALL) != length)
            goto clean_nd;
        }

    name->unit_count = length;
    /* Decompress (Should not be needed, but still) */
    if(decompress_data(name,data) == JS_ERROR)
        goto clean_nd;

    /* show_esc_stdout(name); printf("\n"); */ /*DEBUG*/
    /* Convert the header */
    if(read_hdr(data,&header) == JS_ERROR)
        goto clean_nd;

    /* We only answer questions (Thanks to Roy Arends for pointing out this
       security flaw) */
    if(header.qr != 0) {
        goto clean_nd;
        }

    /* If they only have permission to convert (proxy via UDP) the query,
       do so */
    if((perms & 1) != 1) {
        if((perms & 2) == 2) {
            convert_query(connect,&udp_forward_server,4,data,perms);
            return JS_SUCCESS;
            }
        goto clean_nd;
        }

    /* Determine the length of the zone they want an AXFR for */
    length = dlabel_length(data,12);
    if(length == JS_ERROR)
        goto clean_nd;

    /* Get the name of the Zone they want */
    if(js_substr(data,name,12,length) == JS_ERROR)
        goto clean_nd;

    /* Make sure this is a AXFR or IXFR request */
    if(data->unit_count < 14 + length) /* 12 bytes header, 2 bytes type */
        goto clean_nd;
    /* The query must be query 0-255 */
    if(*(data->string + 12 + length) != 0) {
        /* We may need to forward the query to the UDP DNS upstream */
        if((perms & 2) == 2) {
            convert_query(connect,&udp_forward_server,4,data,perms);
            return JS_SUCCESS;
            }
        goto clean_nd;
        }
    /* The query must be SOA, AXFR, or IXFR (hack: IXFR treated like AXFR) */
    switch(*(data->string + 13 + length)) {
        case RR_SOA: /* SOA */
            soa_q = 1;
        case RR_IXFR: /* IXFR */
        case RR_AXFR: /* AXFR */
            break;
        default:
            /* In the case of them having permission to both server
               zones and convert other DNS requests in to UDP requests,
               we need to forward the request when they ask for anything
               besides a SOA, IXFR, or AXFR */
            if((perms & 2) == 2) {
                convert_query(connect,&udp_forward_server,4,data,perms);
                return JS_SUCCESS;
                }
            /* OK, they aren't giving us a query related to serving a zone
               file */
            goto clean_nd;
        }

    /* Create the binzone string */
    if((binzone = js_create(260,1)) == 0)
        goto clean_nd;
    /* Give "filename" the name of the file with the zone file */
    if(js_copy(name,binzone) == JS_ERROR) {
        goto clean_ndb;
        }
    /* Convert the name in to all lowercase (since A-Z never appear as a
       metacharacter in a zone file, we can quickly do this conversion) */
    for(counter = 0; counter < name->unit_count; counter++) {
        if(*(name->string + counter) >= 'A' &&
           *(name->string + counter) <= 'Z') {
              *(name->string + counter) += 32;
              }
        }
    /* Convert the name in to a dotted decimal format that the mararc
       file uses */
    if(hname_translate(name,RR_A) == JS_ERROR)
        goto clean_ndb;
    if(js_substr(name,data,1,name->unit_count - 1) == JS_ERROR)
        goto clean_ndb;
        /* (data is now something like "example.com.") */
    /* See if we have a zone file for the zone they are requesting */
    if(js_qstr2js(name,"csv1") == JS_ERROR)
        goto clean_ndb;
    /* At this point, we disable timeouts (to give time to transfer large
     * zones over slow links) */
    alarm(0);
    if(read_dvar(name,data,name) == JS_ERROR) { /* XXX Covers "no such zone" */
            /* If we don't have a csv1 zone, perhaps we have a csv2 zone;
             * check in csv2_parse_zone_zoneserver */
            if(csv2_parse_zone_zoneserver(data,connect,soa_q,&header) ==
                            JS_SUCCESS) {
                    /* Success; close the connection, etc. */
                    exit(0); /* fork() makes all that easy :) */
            }
            mlog(L_NO_ZONE_HERE); /* "Zone we do not have asked for, disconnecting" */
            goto clean_ndb;
    }

    /* name now has the file with the zone in question */
    /* Create the filename */
    if((filename = js_create(390,1)) == 0)
        goto clean_ndb;
    /* Give "filename" the name of the file with the zone file */
    if(js_copy(name,filename) == JS_ERROR) {
        js_destroy(filename);
        goto clean_ndb;
        }

    /* Copy the name of the zone over to zone */
    if((zone = js_create(390,1)) == 0)
        goto clean_ndb;
    if(js_copy(data,zone) == JS_ERROR) {
        js_destroy(filename); js_destroy(zone);
        goto clean_ndb;
        }
    /* Create the query string */
    if((query = js_create(390,1)) == 0) {
        js_destroy(zone); js_destroy(filename);
        goto clean_ndb;
        }
    if(js_set_encode(query,MARA_LOCALE) == JS_ERROR) {
        js_destroy(zone); js_destroy(query); js_destroy(filename);
        goto clean_ndb;
        }
    /* Create the response string */
    if((response = js_create(512,1)) == 0) {
        js_destroy(zone); js_destroy(query); js_destroy(filename);
        goto clean_ndb;
        }
    if(js_set_encode(response,MARA_LOCALE) == JS_ERROR) {
        js_destroy(zone); js_destroy(query); js_destroy(response);
        js_destroy(filename);
        goto clean_ndb;
        }
    /* Create the soa string */
    if((soa = js_create(390,1)) == 0) {
        js_destroy(zone); js_destroy(query); js_destroy(response);
        js_destroy(filename);
        goto clean_ndb;
        }
    if(js_set_encode(soa,MARA_LOCALE) == JS_ERROR)
        goto clean_ndzqrs;

    /* Open up the zone file */
    if(js_open_read(filename,&desc) == JS_ERROR)
        goto clean_ndzqrs;

    /* Build up the header, which is the same for all the replies */
    header.qr = header.aa = 1;
    header.ancount = 1;
    header.opcode = header.tc = header.ra = header.z = header.rcode =
    header.qdcount = header.nscount = header.arcount = 0;

    /* If they asked for a SOA record, generate a SOA record.
       Since BIND insists that the SOA record have an authority
       section, we have to read the entire zone file to synthesize one */
    if(soa_q == 1) {
        soa_reply_header = header;
        /* Make a 12-byte header so we can start appending answers to
           the header */
        if(make_hdr(&soa_reply_header,response) == JS_ERROR)
            goto clean_ndzqrs;
        /* Add the question to the reply */
        if(js_append(binzone,response) == JS_ERROR)
            goto clean_ndzqrs;
        if(js_adduint16(response,6) == JS_ERROR) /* SOA Query */
            goto clean_ndzqrs;
        if(js_adduint16(response,1) == JS_ERROR) /* IN Class */
            goto clean_ndzqrs;
        soa_reply_header.qdcount = 1;
        /* Start reading the zone file */
        while(!js_buf_eof(&desc)) {
            /* Get the line */
            if(js_buf_getline(&desc,data) <= JS_ERROR)
                goto clean_ndzqrs;
            /* Process the % character and any \ escape sequences */
            if(bs_process(data,name,zone) == JS_ERROR)
                goto clean_ndzqrs;
            /* Get the data from the line in the zone file */
            rr_type = parse_csv1_line(name,query,data,&ttl);
            if(rr_type == JS_ERROR)
                goto clean_ndzqrs;
            if(rr_type == -2) /* Syntax error */
                continue;
            if(rr_type > 0 && rr_type < 65536) { /* Line with RR */
                /* If we have added all of the NS records, add no more */
                if(soa_q == 2 && rr_type != RR_NS)
                    soa_q = 0;
                /* If this is the first SOA record or an authoritative NS
                   record */
                if(soa_q > 0) {
                    /* The "query" also has the Qtype in it */
                    if(js_append(query,response) == JS_ERROR)
                        goto clean_ndzqrs;
                    if(js_adduint16(response,1) == JS_ERROR)  /* Class is 1 */
                        goto clean_ndzqrs;
                    if(js_adduint32(response,ttl) == JS_ERROR)
                        goto clean_ndzqrs;
                    if(js_adduint16(response,data->unit_count) == JS_ERROR)
                        goto clean_ndzqrs;
                    if(js_append(data,response) == JS_ERROR)
                        goto clean_ndzqrs;
                    /* We only add the SOA once */
                    if(soa_q == 1)
                        soa_q = 2; /* Adding name servers */
                    else if(soa_q == 2)
                        soa_reply_header.nscount++;
                    }
                }
            }

        /* Give the response to the client */
        /* Hack to change the header without truncating the string */
        soa_q = response->unit_count;
        if(make_hdr(&soa_reply_header,response) == JS_ERROR)
            goto clean_ndzqrs;
        response->unit_count = soa_q;
        soa_q = 0;
        /* Determine the length of the response to send */
        get[0] = (response->unit_count & 0xff00) >> 8;
        get[1] = response->unit_count & 0xff;
        if(write(connect,get,2) == -1)
            goto clean_ndzqrs;
        if(write(connect,response->string,response->unit_count) == -1)
            goto clean_ndzqrs;

        /* Pretend to get the next query */

        /* Get two bytes for the length */
        if(connect == 1) {
            if(read(0,get,2) != 2)
                goto clean_ndzqrs;
            }
        else {
            if(recv(connect,get,2,MSG_WAITALL) != 2)
                goto clean_ndzqrs;
            }

        /* Determine how long the second query will be */
        length = (get[0] & 0xff) << 8 | (get[1] & 0xff);
        /* Pretend to get the actual query */
        while(length > 0) {
            if(connect == 1) {
                if(read(0,get,1) != 1)
                    goto clean_ndzqrs;
                }
            else {
                if(recv(connect,get,1,MSG_WAITALL) != 1)
                    goto clean_ndzqrs;
                }
            length--;
            }

        /* Close and reopen the zone file so we can read it for the AXFR
           request */
        if(js_close(&desc) == JS_ERROR)
            goto clean_ndzqrs;
        if(js_open_read(filename,&desc) == JS_ERROR)
            goto clean_ndzqrs;

        }

    /* Read all of the lines from the zone file one by one */
    while(!js_buf_eof(&desc)) {
        /* Get the line */
        if(js_buf_getline(&desc,data) <= JS_ERROR)
            goto clean_ndzqrs;
        /* Process the % character and any \ escape sequences */
        if(bs_process(data,name,zone) == JS_ERROR)
            goto clean_ndzqrs;
        /* Get the data from the line in the zone file */
        rr_type = parse_csv1_line(name,query,data,&ttl);
        if(rr_type == JS_ERROR)
            goto clean_ndzqrs;
        if(rr_type == -2) /* Syntax error */
            continue;
        if(rr_type > 0 && rr_type < 65536) { /* Non-blank line */
            /* Make the header */
            if(make_hdr(&header,response) == JS_ERROR)
                goto clean_ndzqrs;
            /* Add this response to the message, in the answer section */
            /* The "query" also has the Qtype in it */
            if(js_append(query,response) == JS_ERROR)
                goto clean_ndzqrs;
            if(js_adduint16(response,1) == JS_ERROR)  /* Class, always 1 */
                goto clean_ndzqrs;
            if(js_adduint32(response,ttl) == JS_ERROR)
                goto clean_ndzqrs;
            if(js_adduint16(response,data->unit_count) == JS_ERROR) {
                goto clean_ndzqrs;
                }
            if(js_append(data,response) == JS_ERROR)
                goto clean_ndzqrs;
            /* Spit out the data over the TCP pipe */
            get[0] = (response->unit_count & 0xff00) >> 8;
            get[1] = response->unit_count & 0xff;
            if(write(connect,get,2) == -1)
                goto clean_ndzqrs;
            if(write(connect,response->string,response->unit_count) == -1)
                goto clean_ndzqrs;
            /* If this is the first SOA record, copy it so we can send it
               at the end */
            if(is_soa == 1 && rr_type == RR_SOA) {
                is_soa = 0;
                if(js_copy(response,soa) == JS_ERROR)
                    goto clean_ndzqrs;
                }
            }
        }
    /* Show them the SOA record again */
    if(is_soa == 0) { /* If we showed them the SOA before */
        get[0] = (soa->unit_count & 0xff00) >> 8;
        get[1] = soa->unit_count & 0xff;
        if(write(connect,get,2) == -1)
            goto clean_ndzqrs;
        if(write(connect,soa->string,soa->unit_count) == -1)
            goto clean_ndzqrs;
        }
    close(connect); /* Close connection after AXFR is done */

    /* Destroy all allocated strings */
    js_destroy(soa);
    js_destroy(response);
    js_destroy(query);
    js_destroy(zone);
    js_destroy(filename);
    js_destroy(binzone);
    js_destroy(name);
    js_destroy(data);
    js_close(&desc); /* Remove memory this sucks up */
    return JS_SUCCESS; /* Return success */

    /* We are using gotos because C does not have decent error handling */
    clean_ndzqrs:
        js_destroy(soa);
        js_destroy(response);
        js_destroy(query);
        js_destroy(zone);
        js_destroy(filename);
    clean_ndb:
        js_destroy(binzone);
    clean_nd:
        js_destroy(name);
        js_destroy(data);
        close(connect); /* Close connection on error */
        js_close(&desc); /* Remove memory this sucks up */
        return JS_ERROR;
    }

/* The core of the DNS Zone server */

int main(int argc, char **argv) {

    js_string *mararc_loc, *errors, *chrootn, *kvar_str, *maxpstr,
              *kvar_query, *bind_address, *incoming, *uncomp, *verbstr;
    unsigned char chroot_zt[255];
    int errorn, sock, maxprocs, counter, connection,
        inetd = 0;
#ifndef DARWIN
    struct rlimit rlim;
#endif
    pid_t pid = 0;
    uid_t uid;
    gid_t gid;
    ipv4pair zonetransfer_acl[512], tcpconvert_acl[512], recursive_acl[512];
    ipv4pair tcpconvert_servers[512];
    int synth_soa_serial;
    js_string *synth_soa_origin;

    /* Kill children processes when we are signaled */
    if(setpgid(0,0) && getpgrp() != getpid()) {
        printf("%s",strerror(errno)); /* harderror() would kill the group which may not be correct yet */
        return 3;
    }
    signal(SIGTERM,handle_term);

    /* Initialize the strings (allocate memory for them, etc.) */
    if((mararc_loc = js_create(256,1)) == 0)
        harderror(L_MLC); /* "Could not create mararc_loc string" */
    if(js_set_encode(mararc_loc,MARA_LOCALE) == JS_ERROR)
        harderror("Could not set locale for mararc_loc string");
    if((errors = js_create(256,1)) == 0)
        harderror(L_EC); /* "Could not create errors string" */
    if(js_set_encode(errors,MARA_LOCALE) == JS_ERROR)
        harderror("Could not set locale for errors string");
    if((kvar_str = js_create(256,1)) == 0)
        harderror(L_KSC); /* "Could not create kvar_str string" */
    if(js_set_encode(kvar_str,MARA_LOCALE) == JS_ERROR)
        harderror(L_KSL); /* "Could not set locale for kvar_str string" */
    if((verbstr = js_create(256,1)) == 0)
        harderror(L_VC); /* "Could not create verbstr string" */
    if(js_set_encode(verbstr,MARA_LOCALE) == JS_ERROR)
        harderror(L_VL); /* "Could not set locale for verbstr string" */
    if((maxpstr = js_create(256,1)) == 0)
        harderror(L_MC); /* "Could not create maxpstr string" */
    if(js_set_encode(maxpstr,MARA_LOCALE) == JS_ERROR)
        harderror(L_ML); /* "Could not set locale for maxpstr string" */
    if((chrootn = js_create(256,1)) == 0)
        harderror(L_CC); /* "Could not create chrootn string" */
    if(js_set_encode(chrootn,MARA_LOCALE) == JS_ERROR)
        harderror(L_CL); /* "Could not set locale for chrootn string" */
    if((kvar_query = js_create(256,1)) == 0)
        harderror(L_KQC); /* "Could not create kvar_query string" */
    if(js_set_encode(kvar_query,MARA_LOCALE) == JS_ERROR)
        harderror(L_KQL); /* "Could not set locale for kvar_query string" */
    if((bind_address = js_create(64,1)) == 0)
        harderror(L_BAC); /* "Could not create bins_address string" */
    if(js_set_encode(bind_address,MARA_LOCALE) == JS_ERROR)
        harderror(L_BAL); /* "Could not set locale for bind_address string" */
    if((incoming = js_create(768,1)) == 0)
        harderror(L_IC); /* "Could not create incoming string" */
    if(js_set_encode(incoming,MARA_LOCALE) == JS_ERROR)
        harderror(L_IL); /* "Could not set locale for incoming string" */
    if((uncomp = js_create(768,1)) == 0)
        harderror(L_UC); /* "Could not create uncomp string" */
    if(js_set_encode(uncomp,MARA_LOCALE) == JS_ERROR)
        harderror(L_UL); /* "Could not set locale for uncomp string" */

    /* First, find the mararc file */
    if(argc == 1) { /* No arguments */
        if(find_mararc(mararc_loc) == JS_ERROR)
            harderror(L_MW); /* "Error locating mararc file" */
        }
    else if(argc==2) { /* maradns -v or maradns --version */
        printf("%s %s\n%s\n",L_THISIS,VERSION,L_RTFM); /* "This is MaraDNS versi
on %s\nFor usage information, type in 'man maradns'" */
        exit(0);
        }
    else if(argc==3) { /* maradns -f /wherever/mararc */
        if(js_qstr2js(mararc_loc,argv[2]) == JS_ERROR)
            harderror(L_GET_MARARC); /* "Could not get mararc from command line" */
        }
    else
        harderror(L_USAGE); /* "Usage: mararc [-f mararc_location]" */

    /* Then parse that file */
    if(read_mararc(mararc_loc,errors,&errorn) == JS_ERROR)
        harderror(L_PARSE_MARARC); /* "Error parsing contents of mararc file" */
    if(errorn != 0) {
        if(errorn != -1)
          /* "Error parsing contents of mararc file on line " */
          printf("%s%d%s",L_PARSE_MARARC_LINE,errorn,LF); /* errorn, "\n" */
        printf("%s",L_ERROR_CODE); /* "Error code: " */
        js_show_stdout(errors);
        printf("%s",LF);
        exit(2);
        }

    /* Initialize the psudo-random-number-generator */
    srng();

    inetd = 0;

    /* Get in to a state of least privledge ASAP */

    /* Limit the maximum number of processes */
    maxprocs = read_numeric_kvar("maxprocs",128);

    /* Determine how csv2 zone files will handle the tilde character */
    csv2_tilde_handling = read_numeric_kvar("csv2_tilde_handling",2);
    if(csv2_tilde_handling < 0 || csv2_tilde_handling > 3) {
        harderror("csv2_tilde_handling "
                  "must have a value between 0 and 3");
        exit(1);
        }

    /* If we have both maxprocs and max_tcp_procs defined, the zone server
       will use max_tcp_procs. */
    if(js_qstr2js(kvar_query,"max_tcp_procs") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    /* See if max_tcp_procs is set */
    if(read_kvar(kvar_query,maxpstr) != 0) {
        maxprocs = js_atoi(maxpstr,0);
        }

#ifndef DARWIN
    rlim.rlim_cur = rlim.rlim_max = maxprocs;

#ifdef RLIMIT_NPROC
    if(setrlimit(RLIMIT_NPROC,&rlim) != 0)
        harderror(L_SETMAX); /* "Unable to set maximum number of processes" */
#endif /* SOLARIS */
#endif /* DARWIN */

    /* Determine the level of error reporting */
    if(js_qstr2js(kvar_query,"verbose_level") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,verbstr) == JS_ERROR)
        verbose = 0;
    else
        verbose = js_atoi(verbstr,0);

    /* Determine if we are root */
#ifndef __CYGWIN__
    if(geteuid() == 0)
#else
    if(1==1)
#endif /* CYGWIN doesn't have root */
    {
        /* Change the root directory */
        if(js_qstr2js(kvar_query,"chroot_dir") == JS_ERROR)
            harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,chrootn) == JS_ERROR)
            harderror(L_CHROOT); /* "Problem getting chroot kvar.\nYou must have chroot_dir set if you start this as root" */
        if(js_js2str(chrootn,(char *)chroot_zt,200) == JS_ERROR)
            harderror(L_CHROOT_NT); /* "Problem making chroot nt string.\nMake sure the chroot directory is 200 chars or less" */
        if(chdir((char *)chroot_zt) != 0)
            harderror(L_NO_CHROOT); /* "Problem changing to chroot dir.\nMake sure chroot_dir points to a valid directory" */
        if(chroot((char *)chroot_zt) != 0)
            harderror(L_CHROOT_ERROR);  /* "Problem changing the root directory." */


        /* Determine which uid and gid to use */
        uid = read_numeric_kvar("maradns_uid",MARADNS_DEFAULT_UID);
        gid = read_numeric_kvar("maradns_gid",MARADNS_DEFAULT_GID);
        if(uid < 10)  /* Security check */
              uid = MARADNS_DEFAULT_UID;

        mlog(L_CHROOT_SUCCESS); /* "Root directory changed" */

        /* Bind to dns_port
           To Do: use capset to give us privledged bind abilities without
                  needing to be root.
        */

        /* Set the dns_port */
        dns_port = read_numeric_kvar("dns_port",53);
        if(dns_port < 1 || dns_port > 65530) {
            harderror("dns_port must be between 1 and 65530");
            exit(1);
        }

        if(inetd != 1) { /* If we are a standalone server */
            ipv4pair *bind_addresses;
            int bind_address_iterate;
            int stream1[2]; /* Used for piping */
            /* pid_t child[70]; */ /* Children's process IDs */

            /* bind_address is now a js_string object in the
             * form "10.1.2.3,10.1.2.4".  Use the make_ip_acl code to
             * make a list of bind addresses from the bind_address string,
             * then fork once for each bind address.  This will
             * be somewhat like the code below that gets the zone transfer
             * ACL list
             * */

            bind_addresses = libtcp_bind_address(1);
            if(bind_addresses == 0 || bind_addresses[0].ip == 0xffffffff) {
                    harderror("Could not make list of bind addresses");
            }
            bind_address_iterate = 0;
            while(bind_address_iterate < 70 &&
                    bind_addresses[bind_address_iterate].ip != 0xffffffff) {
                    /* Spawn a child process that is only bound to this
                     * IP */
                    /* We set things up so the
                     * child's stdout/stderr goes to the parent's
                     * stdout/stderr */
                    if(pipe(stream1) != 0)
                            harderror("Pipe()'s broken");
                    /* if((child[bind_address_iterate] = fork())) * Parent */
                    if((pid = fork())) { /* Parent or error */
                    if(pid < 0)
                        harderror("Could not fork");
                            close(stream1[1]);
                            fcntl(stream1[0],F_SETFL,O_NONBLOCK);
                            /* The following might not be portable */
                            if(stream1[0] != bind_address_iterate + 3)
                                dup2(stream1[0],
                               bind_address_iterate + 3); /* Pipe redirected */
                    } else { /* Child */
                            close(stream1[0]);
                            dup2(stream1[1],1); /* Stdout redirected to pipe */
                            dup2(stream1[1],2); /* Stderr redirection */
                            if(tcpbind(&sock,
                        bind_addresses[bind_address_iterate].ip) == JS_ERROR)
                            harderror(L_BIND); /* "Problem binding to dns_port.\nMost likely, another process is already listening on dns_port" */
                            break;
                    }
                    bind_address_iterate++;
            }
            if(pid) { /* Parent */
                    /* Handle children's output */
                    fd_set child_set;
                    fd_set read_set;
                    char buf[1024];
                    ssize_t readed;
                    setgid(gid);
#ifndef __CYGWIN__
                    if(setuid(uid) != 0) {
                            /* This is an ancient Linux kernel bug */
                            harderror("Parent couldn't drop UID\n");
                    }
#endif
                    FD_ZERO(&child_set);
                    /* Add all child fds */
                    for(counter = 3;
                      counter < bind_address_iterate + 3; counter++) {
                        FD_SET(counter,&child_set);
                    }
                    for(;;) {
                            FD_ZERO(&read_set);
                            /* select on available children */
                            for(counter = 3;
                              counter < bind_address_iterate + 3; counter++) {
                                if(FD_ISSET(counter,&child_set))
                                    FD_SET(counter,&read_set);
                            }
                            if(select(bind_address_iterate + 3,&read_set,
                              NULL,NULL,NULL) > 0) {
                                for(counter = 3;
                                  counter < bind_address_iterate + 3; counter++) {
                                    if(FD_ISSET(counter,&read_set)) {
                                        readed = read(counter,buf,1024);
                                        if(readed > 0) {
                                            write(1,buf,readed);
                                        } else {
                                            /* No longer exists  */
                                            close(counter);
                                            FD_CLR(counter,&child_set);
                                        }
                                    }
                                }
                            } else {
                                break;
                            }
                            waitpid(0,NULL,WNOHANG); /* Catch exited children */
                    }
                    return 0;
            }
            if(libtcp_create_bind_addrs() == JS_ERROR)
                harderror("libtcp_create_synthip_addrs");
            mlog(L_SOCKET_SUCCESS);  /* "Socket opened on TCP dns_port" */
            }

        /* Drop the elevated privileges */
#ifndef __CYGWIN__
        setgid(gid);
        if(setuid(uid) != 0)
            harderror(L_NODROP); /* "Could not drop root uid" */
        if(setuid(0) == 0)
            harderror(L_STILL_ROOT);  /* "We seem to still be root" */
#endif

        if(inetd != 1) /* If we are not called from inetd */
            mlog(L_DROP_SUCCESS); /* "Root privileges dropped" */

        }
    else {
        harderror("inetd is not zero; this is a fatal error.\n"
                  "Make sure to be the root user.\n");
        }

    /* Make a database of IPs permitted to transfer zone file */
    /* Initialize the ACL list */
    for(counter = 0; counter < 512; counter++)
        zonetransfer_acl[counter].ip = 0xffffffff;
    if(js_qstr2js(kvar_query,"zone_transfer_acl") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,kvar_str) == JS_ERROR)
        harderror(L_NO_ACL); /* "Could not read zone_transfer_acl data" */
    if(inetd == 1) {
        harderror("inetd is set.  This is a fatal error.  You should not be seeing this\n");
        }
    else {
        if(make_ip_acl(kvar_str,zonetransfer_acl,500,0) == JS_ERROR) {
            /* harderror(L_ACL_LIST); *//* "Could not make ip ACL list" */
            zonetransfer_acl[0].ip=0xffffffff; /* No zone transfer ACL */
            }
        }

    /* Make a database of IPs permitted to convert TCP queries into UDP
       queries */
    /* Initialize this ACL list */
    for(counter = 0; counter < 512; counter++)
        tcpconvert_acl[counter].ip = 0xffffffff;
    if(js_qstr2js(kvar_query,"tcp_convert_acl") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,kvar_str) == JS_SUCCESS) {
         if(srng_place == -1) {
            printf("I could not get value for random_seed_file.\n");
            printf("You must have this set in your mararc file.\n");
            printf("Please add something like this to the mararc file\n");
            printf("you are using:\n");
            printf("\n\trandom_seed_file = \"/dev/urandom\"\n\n");
            exit(1);
            }
        if(make_ip_acl(kvar_str,tcpconvert_acl,500,0) == JS_ERROR)
            /* XXX better error message and allow blank value */
            harderror("XXX need better error message"); /* "Could not make ip ACL list" */
        }

    /* Make a database of IPs permitted to convert TCP queries into UDP
       queries */
    /* Initialize this ACL list */
    for(counter = 0; counter < 512; counter++)
        recursive_acl[counter].ip = 0xffffffff;
    if(js_qstr2js(kvar_query,"recursive_acl") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,kvar_str) == JS_SUCCESS) {
         if(srng_place == -1) {
            printf("I could not get value for random_seed_file.\n");
            printf("You must have this set in your mararc file.\n");
            printf("Please add something like this to the mararc file\n");
            printf("you are using:\n");
            printf("\n\trandom_seed_file = \"/dev/urandom\"\n\n");
            exit(1);
            }
        if(make_ip_acl(kvar_str,recursive_acl,500,0) == JS_ERROR)
            /* XXX better error message and allow blank value */
            harderror("XXX need better error message"); /* "Could not make ip ACL list" */
        }

    /* Initialize the list of UDP servers (only honor the first one) */
    for(counter = 0; counter < 512; counter++)
        tcpconvert_servers[counter].ip = 0xffffffff;
    if(js_qstr2js(kvar_query,"tcp_convert_server") == JS_ERROR)
        harderror(L_MAKE_KQ); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,kvar_str) == JS_SUCCESS) {
         if(srng_place == -1) {
            printf("I could not get value for random_seed_file.\n");
            printf("You must have this set in your mararc file.\n");
            printf("Please add something like this to the mararc file\n");
            printf("you are using:\n");
            printf("\n\trandom_seed_file = \"/dev/urandom\"\n\n");
            exit(1);
            }
        if(make_ip_acl(kvar_str,tcpconvert_servers,500,0) == JS_ERROR)
            /* XXX better error message and allow blank value */
            harderror("XXX need better error message"); /* "Could not make ip ACL list" */
        }
    udp_forward_server = tcpconvert_servers[0].ip;

    /* Set the synth_soa_origin and synth_soa_serial as needed */
    /* Get the values for the synthetic SOA serial and the synthetic SOA
       origin (called MNAME in RFC1035) */
    synth_soa_serial = read_numeric_kvar("synth_soa_serial",1);
    if(synth_soa_serial < 1 || synth_soa_serial > 2) {
        harderror("Fatal: synth_soa_serial must be 1 or 2\n");
        }
    set_soa_serial(synth_soa_serial);
    verbstr = read_string_kvar("synth_soa_origin");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        synth_soa_origin = js_create(256,1);
        if(synth_soa_origin == 0) {
            harderror("Fatal: can not create synth_soa_origin string");
            }
        if(js_qstr2js(synth_soa_origin,"Z") != JS_SUCCESS) {
            harderror("Fatal: could not make synth_soa_origin string Z");
            }
        if(js_append(verbstr,synth_soa_origin) != JS_SUCCESS) {
            harderror("Fatal: could not append to synth_soa_origin string");
            }
        /* We should see if the origin already has a dot on the end */
        if(js_qappend(".",synth_soa_origin) != JS_SUCCESS) {
            harderror("Fatal: could not append final dot to soa_synth_origin");
            }
        /* Now we make that raw data */
        if(hname_2rfc1035(synth_soa_origin) <= 0) {
            harderror("Fatal: Malformed synth_soa_origin value.\n"
            "Please make sure that synth_soa_origin is a valid hostname\n"
            "*without* a dot at the end.  For example:\n\n"
            "\tsynth_soa_origin = \"example.com\"\n");
            }
        set_soa_origin(synth_soa_origin);
        }

    /* Initialize decompression */
    decomp_init(0);

    if(inetd == 1) {
        harderror("inetd is not zero.  This is a fatal error\nComplain loudly on the MaraDNS mailing list.\n");
        }

    /* Set up a signal handler so we can decrement the number of children
       whenever a child exits */
    signal(SIGCHLD,handle_childs);

    /* Otherwise, listen for data on the TCP socket */
    for(;;) {
        int permissions = 0; /* What the connecter is allowed to do
          0: Nothing
          1: Only transfer zone files
          2: Only forward queries
          3: Both
          4: Nothing
          5: Only transfer zone files
          6: Only forward queries with recusion (caching data from other
             nameservers) enabled
          7: Both zone transfer and forward with recursion enabled
        */
        if(verbose >= 2)
            mlog(L_WAITING); /* "Awaiting data on dns_port" */
        connection = gettcp(&sock,zonetransfer_acl,tcpconvert_acl,
                     recursive_acl,500,&permissions);
        if(connection == JS_ERROR)
            continue;
        if(verbose >= 2)
            mlog(L_GOT); /* "Message received, processing" */

        /* Make sure we don't have more children than we can handle */
        while(num_children > maxprocs)
            sleep(1);

        /* Fork and have the child handle the data */
        while((pid = fork()) == -1) /* Resource starvation handling */
            sleep(1);

        if(!pid) { /* Child */
            /* If they have permissions to serve a zone, or to convert
               a query, do so */
            if((permissions & 1) == 1 || (permissions & 2) == 2)
               serve_zone(connection,permissions);
            exit(0); /* End child */
            }

        /* Parent */
        num_children++;

        /* Hackish way to clean up child processes without needlessly slowing
           the program */
        while(waitpid(0,NULL,WNOHANG) > 0) num_children--;

        /* Make sure to close any lingering open connections */
        close(connection);
        }

    }

