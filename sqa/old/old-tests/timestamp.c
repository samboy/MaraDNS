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

/* This is a stub DNS server that converts A record requests in to
   time stamps; used to make sure the various minimum ttls were working
   correctly. */

/* Include stuff needed to be a UDP server */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifndef DARWIN
#include <sys/resource.h>
#endif
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"
#include "../server/MaraDNS_locale.h"

/* Stubs to handle the various error callers */

void harderror(char *why) {
    printf("Fatal: %s\n",why);
    exit(1);
    }

void sys_harderror(char *why) {
    harderror(why);
    }

int mlog(char *logmessage) {
    return 1;
    }

int zjlog(char *left, js_string *right) {
    return 1;
    }

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, get the query type for the string in
   question.
   Input: js_string object with raw UDP data
   Output: JS_ERROR on error, record type (0-65535) on success */

int get_rtype(js_string *js) {

    int rtype;

    /* Sanity tests */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_count < 3)
        return JS_ERROR;

    /* get the last two bytes */
    rtype = (*(js->string + js->unit_count - 1) & 0xff) |
            (*(js->string + js->unit_count - 2) & 0xff) << 8;

    return rtype;
    }

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, and the desired new record number for
   that data type, convert the record type to the new number.
   Input: js_string object with raw UDP data, the desired new record type
   Output: JS_ERROR on error, JS_SUCCESS on success */

int change_rtype(js_string *js, int newtype) {

    /* Sanity tests */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_count < 3)
        return JS_ERROR;
    if(newtype < 0 || newtype > 65535)
        return JS_ERROR;

    /* Change the last two bytes */
    *(js->string + js->unit_count - 1) = newtype & 0xff;
    *(js->string + js->unit_count - 2) = (newtype & 0xff00) >> 8;

    return JS_SUCCESS;
    }

/* Return a packet indicating that there was an error in the received
   packet
   input: socket number,
          a js_string object that we get the data from the first two
          bytes from, a sockaddr of who to send the error to, the error
          to give them in the RCOADE part of the header
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int udperror(int sock,js_string *raw, struct sockaddr_in *from, int error,
             char *why) {

    q_header header;
    js_string *reply;
    int len_inet = sizeof(struct sockaddr);

    if(raw->unit_count < 2 || raw->max_count < 3)
        return JS_ERROR;

    if((reply = js_create(32,1)) == 0)
        return JS_ERROR;

    /* Fill out the header */
    header.id = ((*(raw->string) & 0xff) << 8) | (*(raw->string + 1) & 0xff);
    header.qr = 1;
    header.opcode = 0;
    header.aa = 0; /* Errors are never authoritative (unless they are
                      NXDOMAINS, which this is not) */
    header.tc = 0;
    header.rd = 0;
    header.ra = 0;
    header.z = 0;
    header.rcode = error;
    header.qdcount = 0;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Make that raw UDP data */
    if(make_hdr(&header,reply) == JS_ERROR)
        return JS_ERROR;

    /* Send them the reply */
    sendto(sock,reply->string,reply->unit_count,0,
            (struct sockaddr *)from,len_inet);

    return JS_SUCCESS;

    }

/* OK, there are a handful of record types which MaraDNS gives special
   treatment to when a TXT record is asked for the host name in question.
   This routine handles these special domain names.
   Input: ID of the query they sent us, socket of the request, a sockaddr
          with their address and port on it, a js_string containing
          the query (dname + type), The host name that is given special
          treatment (in a pre-hname2rfc1035 format), query type to convert,
          2 strings whose data is dependent on the the query_type to
          convert.
*/

int easter_egg(int id,int sock,struct sockaddr_in *client, js_string *query,
               char *hname, uint16 type, char *opt1, char *opt2) {
    js_string *reply, *hname_js, *data; /* The reply, the query, the answer */
    q_header header;
    int result;

    /* Sanity checks */
    if(js_has_sanity(query) == JS_ERROR)
        return JS_ERROR;
    if(hname == 0 || opt1 == 0)
        return JS_ERROR;

    if((reply = js_create(512,1)) == 0)
        return JS_ERROR;
    if((hname_js = js_create(256,1)) == 0) {
        js_destroy(reply);
        return JS_SUCCESS;
        }
    if((data = js_create(256,1)) == 0) {
        js_destroy(reply); js_destroy(hname_js);
        return JS_SUCCESS;
        }

    /* Make sure that this is the query that they asked for */
    hname_js->encoding = query->encoding;

    if(js_qstr2js(hname_js,hname) == JS_ERROR)
        goto cleanup;

    if(hname_2rfc1035(hname_js) <= 0)
        goto cleanup;

    if(js_adduint16(hname_js,type) == JS_ERROR)
        goto cleanup;

    result = js_issame(hname_js,query);
    if(result == JS_ERROR)
        goto cleanup;

    if(result != 1) {
        js_destroy(reply); js_destroy(hname_js); js_destroy(data);
        return 0;
        }

    /* OK, the hostname matches the "easter egg" name, now we form
       the "easter egg" reply */

    /* Get the data from the options */
    /* If we ever support easter eggs for anything besides TXT
       records, this will become a switch statement */
    if(type != RR_TXT) {
        js_destroy(reply); js_destroy(hname_js); js_destroy(data);
        return 0;
        }

    if(opt2 == 0)
        return JS_ERROR;

    /* With TXT records, we take the string in opt1, add the string in
       opt2 to the string, and make that the data.  hname_js is used
       as a "throwaway" string */
    if(js_qstr2js(hname_js,"") == JS_ERROR)
        goto cleanup;
    if(js_qappend(opt1,hname_js) == JS_ERROR)
        goto cleanup;
    if(js_qappend(opt2,hname_js) == JS_ERROR)
        goto cleanup;
    if(js_qstr2js(data,"") == JS_ERROR)
        goto cleanup;
    if(hname_js->unit_count > 255)
        goto cleanup;
    if(js_addbyte(data,hname_js->unit_count) == JS_ERROR)
        goto cleanup;
    if(js_append(hname_js,data) == JS_ERROR)
        goto cleanup;

    /* Build up the header for this reply */
    if(id > 0 && id < 65535)
        header.id = id;
    else
        goto cleanup;

    header.qr = 1; /* Reply */
    header.opcode = 0; /* Normal DNS */
    header.aa = 0; /* DDIP to A translations are never authoritative */
    header.tc = 0; /* A labels are too short to be truncated */
    header.rd = 0; /* Recursion not desired */
    header.ra = 0; /* Recursion not available */
    header.z = 0; /* This must be 0 unless we are EDNS aware (we aren't) */
    header.rcode = 0; /* Success! */
    header.qdcount = 1;
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;

    /* Make a header of the reply */
    if(make_hdr(&header,reply) == JS_ERROR)
        goto cleanup;

    /* Add the question they asked to the reply */
    if(js_append(query,reply) == JS_ERROR)
        goto cleanup;

    /* Add the class (in) to the answer */
    if(js_adduint16(reply,1) == JS_ERROR)
        goto cleanup;

    /* We will now add out manufactured reply */
    if(js_append(query,reply) == JS_ERROR)
        goto cleanup;
    /* Append the class (in) to the answer */
    if(js_adduint16(reply,1) == JS_ERROR)
        goto cleanup;
    /* Append a bogus TTL to the answer */
    if(js_adduint32(reply,770616) == JS_ERROR) /* Was 770616 */
        goto cleanup;
    /* Add the rdlength to the answer */
    if(js_adduint16(reply,data->unit_count) == JS_ERROR)
        goto cleanup;
    /* Add the actual data to the answer */
    if(js_append(data,reply) == JS_ERROR)
        goto cleanup;

    /* Send the reply out */
    sendto(sock,reply->string,reply->unit_count,0,(struct sockaddr *)client,
           sizeof(struct sockaddr));

    /* And, we are done */
    js_destroy(reply);
    js_destroy(hname_js);
    js_destroy(data);
    return JS_SUCCESS;

    /* We use gotos to work around C's lack of error trapping */
    cleanup:
        js_destroy(reply);
        js_destroy(hname_js);
        js_destroy(data);
        return JS_ERROR;

    }

/* Convert a domain-name query in to its lower-case equivalent
   Input: Pointer to the js string object with the query
   Output: JS_ERROR on error, JS_SUCCESS on sucess, 0 on
           success if no change was made to the string */

int fold_case(js_string *js) {
    int counter = 0;
    int ret = 0;

    if(js->max_count <= js->unit_count)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count < 2)
        return JS_ERROR;
    while(counter + 2 < js->unit_count) {
        /* Since A-Z never happen in a domain length label, we can speed
           things up a bit */
        if(*(js->string + counter) >= 'A' && *(js->string + counter) <= 'Z') {
            *(js->string + counter) += 32;
            ret = 1;
            }
        counter++;
        }

    return ret;

    }

/* Make an A record from the current time
   input: Pointer to js_string object with the query
   output: JS_ERROR on fatal error, 0 on non-ddip query,
           JS_SUCCESS if it was a ddip
*/

int timestamp(int id, int sock, struct sockaddr *from, js_string *query) {
    unsigned char ip[4];
    unsigned char length, val;
    int counter, critter, lenl, value;
    js_string *reply;
    q_header header;

    /* Sanity checks */
    if(query->unit_size != 1)
        return JS_ERROR;
    if(query->unit_count >= query->max_count)
        return JS_ERROR;

    if(get_rtype(query) != RR_A && get_rtype(query) != RR_ANY)
        return 0;

    if(query->unit_count < 9) /* The minimum possible length for a
                                 ddip domain label */
        return 0;

    if((reply = js_create(512,1)) == 0)
        return JS_ERROR;

    /* Build up the header for this reply */
    if(id > 0 && id < 65535)
        header.id = id;
    else
        goto cleanup;

    header.qr = 1; /* Reply */
    header.opcode = 0; /* Normal DNS */
    header.aa = 0; /* DDIP to A translations are never authoritative */
    header.tc = 0; /* A labels are too short to be truncated */
    header.rd = 0; /* Recursion not desired */
    header.ra = 0; /* Recursion not available */
    header.z = 0; /* This must be 0 unless we are EDNS aware (we aren't) */
    header.rcode = 0; /* Success! */
    header.qdcount = 1;
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;

    /* Make a header of the reply */
    if(make_hdr(&header,reply) == JS_ERROR)
        goto cleanup;

    /* Add the question they asked to the reply */
    if(js_append(query,reply) == JS_ERROR)
        goto cleanup;

    /* Add the class (in) to the answer */
    if(js_adduint16(reply,1) == JS_ERROR)
        goto cleanup;

    /* Make sure the answer is an A record type */
    if(change_rtype(query,RR_A) == JS_ERROR)
        goto cleanup;

    /* We will now add out manufactured A reply */
    if(js_append(query,reply) == JS_ERROR)
        goto cleanup;
    /* Append the class (in) to the answer */
    if(js_adduint16(reply,1) == JS_ERROR)
        goto cleanup;
    /* Append a bogus TTL to the answer */
    /*if(js_adduint32(reply,19770616) == JS_ERROR)*/
    if(js_adduint32(reply,69) == JS_ERROR)
        goto cleanup;
    /* Add the rdlength to the answer */
    if(js_adduint16(reply,4) == JS_ERROR)
        goto cleanup;
    /* Add the actual 4-byte reply to the answer */
    time((time_t *)&ip); /* Endian dependent, but doesn't matter */
    for(counter = 0; counter < 4; counter++) {
        if(js_addbyte(reply,ip[counter]) == JS_ERROR)
            goto cleanup;
        }

    /* Send the reply out */
    sendto(sock,reply->string,reply->unit_count,0,from,
           sizeof(struct sockaddr));

    /* And, we are done */
    js_destroy(reply);
    return JS_SUCCESS;

    /* We use gotos to work around C's lack of error trapping */
    cleanup:
        js_destroy(reply);
        return JS_ERROR;

    }

/* Process the DNS query that comes in from the 'net
   Input: uncompressed form of incoming UDP query, IP address of where
          this query came from, socket number of this socket
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int proc_query(js_string *raw, struct sockaddr_in *from, int sock) {

    q_header header; /* Header of the question */
    js_string *lookfor; /* What to look for in the big hash */
    js_string *origq; /* Original query asked by the user */
    js_string *lc; /* Lower-case version of query asked by the user */
    rr *nxstore = 0; /* A pointer to the SOA we return when we hit a
                        NXDOMAIN */
    int length, case_folded, result_code = 0, qtype;
    int has_recursive_authority = 0;
    mhash_e spot_data;
    int have_authority = 0; /* Do we have authority for this record?
                               (must be 1 to return a NXDOMAIN) */
    rr *point;
    uint32 ip;
    int desires_recursion = 0; /* Do they desire recursion? */
    char *num_string; /* The string to put the number of thread running
                         in */
    unsigned int mem_usage; /* The amount of memory a maradns process has
                               allocated */

    /* Sanity checks */
    if(js_has_sanity(raw) == JS_ERROR)
        return JS_SUCCESS;
    if(raw->unit_size != 1)
        return JS_SUCCESS;

    /* Get the header */
    if(read_hdr(raw,&header) == JS_ERROR) { /* Something went wrong,
                                               return error "Format error" */
        udperror(sock,raw,from,FORMAT_ERROR,"Couldn't get header");
        return JS_SUCCESS;
        }

    /* We only answer questions (Thanks to Roy Arends for pointing out this
       security flaw) */
    if(header.qr != 0) {
        return JS_SUCCESS;
        }

    /* We only support a qdcount of 1 */
    if(header.qdcount != 1) {
        udperror(sock,raw,from,NOT_IMPLEMENTED,"Qdcount not 1");
        return JS_SUCCESS;
        }

    /* We only support an opcode of 0 (standard query) */
    if(header.opcode != 0) {
        /* Since TinyDNS also returns NOT_IMPLEMENTED here, no need for
           a fingerprint check.  Note that tinydns, unlike MaraDNS, echos
           the question. */
        udperror(sock,raw,from,NOT_IMPLEMENTED,"non-0 opcode");
        return JS_SUCCESS;
        }

    /* Get the question from the stream */
    if(raw->unit_count < 14) {
        udperror(sock,raw,from,FORMAT_ERROR,"bad question hdr");
        return JS_SUCCESS;
        }

    /* Determine the length of the domain label in the question */
    length = dlabel_length(raw,12);
    if(length < 0 || length > 255) {
        udperror(sock,raw,from,FORMAT_ERROR,"bad question length");
        return JS_SUCCESS;
        }

    if(raw->unit_count < 16 + length) { /* 16 because 12 for the header,
                                           and 4 for the type and class */
        udperror(sock,raw,from,FORMAT_ERROR,"question doesn't fit");
        return JS_SUCCESS;
        }

    /* Return "not implemented" if the class is not 1 (Internet class) */
    if(*(raw->string + length + 14) != 0 &&
       *(raw->string + length + 15) != 1) {
        udperror(sock,raw,from,NOT_IMPLEMENTED,"Class not 1");
        return JS_ERROR;
        }

    /* Create the lookfor string, returning error if appropriate */
    if((lookfor = js_create(256,1)) == 0) {
        udperror(sock,raw,from,SERVER_FAIL,"can't create lookfor string");
        return JS_ERROR;
        }
    if((origq = js_create(256,1)) == 0) {
        js_destroy(lookfor);
        udperror(sock,raw,from,SERVER_FAIL,"can't create origq string");
        return JS_ERROR;
        }
    if((lc = js_create(256,1)) == 0) {
        js_destroy(lookfor); js_destroy(origq);
        udperror(sock,raw,from,SERVER_FAIL,"can't create lc string");
        return JS_ERROR;
        }
    if(js_set_encode(lc,JS_US_ASCII) == JS_ERROR) { /* ASCII because we
                                                     only fold the case of
                                                     A-Z */
        goto serv_fail;
        }

    /* Get the query we will look for from their raw query */
    if(js_substr(raw,lookfor,12,length + 2) == JS_ERROR) {
        goto serv_fail;
        }

    /* And copy it over to the "original query" */
    if(js_copy(lookfor,origq) == JS_ERROR) {
        goto serv_fail;
        }

    /* Get the type of query the client desires */
    qtype = get_rtype(origq);
    if(qtype == JS_ERROR) {
        goto serv_fail;
        }

    if(qtype >= 250 && qtype <= 254) { /* IXFR, AXFR, and 2 more */
        goto not_impl;
        }

    /* Return a timestamp */
    result_code = timestamp(header.id,sock,(struct sockaddr *)from,origq);
    if(result_code == JS_SUCCESS) {
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }
    if(result_code == JS_ERROR) {
        goto serv_fail;
        }

    js_destroy(lookfor); js_destroy(origq); js_destroy(lc);

    return JS_SUCCESS;

    /* Work around C's lack of error handling and garbage collection with
       gotos */
    serv_fail:
        js_destroy(lookfor);
        js_destroy(origq);
        js_destroy(lc);
        udperror(sock,raw,from,SERVER_FAIL,"serv_fail in proc_query");
        return JS_ERROR;

    not_impl:
        js_destroy(lookfor);
        js_destroy(origq);
        js_destroy(lc);
        udperror(sock,raw,from,NOT_IMPLEMENTED,"not_impl in proc_query");
        return JS_ERROR;

    }

/* Bind to UDP port 53. (or DNS_PORT if debugging MaraDNS on a system where
                         I do not have root, and theirfore can not bind to
                         a low port number)
   Input:  pointer to socket to bind on, js_string with the dotted-decimal
           ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udpbind(int *sock, js_string *ip_ddip) {
    int len_inet; /* Length */
    struct sockaddr_in dns_udp;
    char ip[64];

    /* Sanity checks */
    if(sock == 0)
        return JS_ERROR;
    if(js_has_sanity(ip_ddip) == JS_ERROR)
        return JS_ERROR;
    if(ip_ddip->unit_size != 1)
        return JS_ERROR;

    /* Create string to hold IP */
    if(js_js2str(ip_ddip,ip,60) == JS_ERROR)
        return JS_ERROR;

    /* Create a raw UDP socket */
    if((*sock = socket(AF_INET,SOCK_DGRAM,0)) == -1) {
        return JS_ERROR;
        }

    /* Create a socket address to use with bind() */
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET;
    /* DNS_PORT is usually 53, but can be another port.  Defined in
       MaraDNS.h */
    dns_udp.sin_port = htons(DNS_PORT);
    if((dns_udp.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
        return JS_ERROR;

    len_inet = sizeof(dns_udp);

    /* Bind to the socket.  Note that we usually have to be root to do this */
    if(bind(*sock,(struct sockaddr *)&dns_udp,len_inet) == -1)
        return JS_ERROR;

    /* We are now bound to UDP port 53. (Or whatever DNS_PORT is) Leave */
    return JS_SUCCESS;
    }

/* Get information from a previously binded UDP socket
   Input:  UDP bound socket, pointer to sockaddr structure that will contain
           the IP of the system connecting to us, pointer to js_string
           object that will have the data in question, maximum allowed
           length of data we receive
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int getudp(int sock,struct sockaddr *client, js_string *data, int max_len) {
    int len_inet, counter;

    /* Sanity checks */
    if(client == 0 || data == 0)
        return JS_ERROR;
    if(js_has_sanity(data) == JS_ERROR)
        return JS_ERROR;
    if(data->unit_size != 1)
        return JS_ERROR;
    if(max_len < 0 || max_len >= data->max_count)
        return JS_ERROR;

    len_inet = sizeof(struct sockaddr);

    counter = recvfrom(sock,data->string,max_len,0,client,&len_inet);

    if(counter < 0)
        return JS_ERROR;

    data->unit_count = counter;

    return JS_SUCCESS;

    }

/* The core of the DNS server */

int main(int argc, char **argv) {

    js_string *mararc_loc, *errors, *chrootn, *uidstr, *maxpstr,
              *kvar_query, *bind_address, *incoming, *uncomp, *verbstr;
    unsigned char chroot_zt[255];
    uid_t uid;
    gid_t gid;
    int errorn, value, sock, maxprocs, counter;
    int cache_size;
    int min_ttl_n = 300, min_ttl_c = 300;
    int max_glueless; /* Maximum allowed glueless level */
    int max_q_total; /* Maximum total queries in attempt to resolve hostname */
    int timeout; /* Maximum time to wait for a remote server when performing
                    a recursive query */
    struct sockaddr client;
    struct sockaddr_in *clin; /* So we can log the IP */
#ifndef DARWIN
    struct rlimit rlim;
#endif

    clin = (struct sockaddr_in *)&client;

    /* Initialize the strings (allocate memory for them, etc.) */
    if((mararc_loc = js_create(256,1)) == 0)
        harderror(L_MLC); /* "Could not create mararc_loc string" */
    if(js_set_encode(mararc_loc,MARA_LOCALE) == JS_ERROR)
        harderror(L_MLL); /* "Could not set locale for mararc_loc string" */
    if((errors = js_create(256,1)) == 0)
        harderror(L_EC); /* "Could not create errors string" */
    if(js_set_encode(errors,MARA_LOCALE) == JS_ERROR)
        harderror(L_EL); /* "Could not set locale for errors string" */
    if((uidstr = js_create(256,1)) == 0)
        harderror(L_UC); /* "Could not create uidstr string" */
    if(js_set_encode(uidstr,MARA_LOCALE) == JS_ERROR)
        harderror(L_UL); /* "Could not set locale for uidstr string" */
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
        harderror(L_UCC); /* "Could not create uncomp string" */
    if(js_set_encode(uncomp,MARA_LOCALE) == JS_ERROR)
        harderror(L_UCL); /* "Could not set locale for uncomp string" */

    /* First, find the mararc file */
    if(argc == 1) { /* No arguments */
        if(find_mararc(mararc_loc) == JS_ERROR)
            harderror(L_LOC_MARARC); /* "Error locating mararc file" */
        }
    else if(argc==3) { /* maradns -f /wherever/mararc */
        if(js_qstr2js(mararc_loc,argv[2]) == JS_ERROR)
            harderror(L_MARARC_ARG); /* "Could not get mararc from command line" */
        }
    else
        harderror(L_USAGE); /* "Usage: mararc [-f mararc_location]" */

    /* Then parse that file */
    if(read_mararc(mararc_loc,errors,&errorn) == JS_ERROR) {
        harderror(L_MARARC_PARSE); /* "Error parsing contents of mararc file" */
        }
    if(errorn != 0) {
        /* Print this out at log level 0 because it is a fatal error */
        if(errorn != -1)
          /* "Error parsing contents of mararc file on line " */
          printf("%s%d%s",L_MARARC_LINE,errorn,L_N); /* errorn, "\n" */
        printf("%s",L_ERROR_CODE); /* "Error code: " */
        js_show_stdout(errors);
        printf("%s",L_N); /* "\n" */
        exit(2);
        }

    /* There are too many greedy lawyers in the US */
    if(js_qstr2js(kvar_query,"hide_disclaimer") == JS_ERROR)
        harderror(L_KVAR_Q); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,verbstr) != JS_SUCCESS) {
        printf("%s","THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR\n");
        printf("%s","IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n");
        printf("%s","OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n");
        printf("%s","IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,\n");
        printf("%s","INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n");
        printf("%s","(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n");
        printf("%s","SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n");
        printf("%s","HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n");
        printf("%s","STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING\n");
        printf("%s","IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n");
        printf("%s","POSSIBILITY OF SUCH DAMAGE.\n");
        printf("\nTo not display this message, add the follwing to your ");
        printf("mararc file:\n\nhide_disclaimer = \"YES\"\n\n");
        }
    /* Get in to a state of least privledge ASAP */

    /* Limit the maximum number of processes */
    if(js_qstr2js(kvar_query,"maxprocs") == JS_ERROR)
        harderror(L_KVAR_Q); /* "Could not create kvar_query" */
    if(read_kvar(kvar_query,maxpstr) == JS_ERROR)
        harderror(L_MAXPROC); /* "Problem getting maxprocs value.\nmaxprocs must be set before starting the MaraDNS server" */
    if((maxprocs = js_atoi(maxpstr,0)) == 0)
        harderror(L_MAXPROC_NUM); /* "Problem converting maxprocs to a number\nThis must be a non-zero number" */

    /* MaraDNS has a known problem with hanging if maxprocs is too high */
    if(maxprocs > 200) {
        maxprocs = 200;
        mlog(L_MAXPROC_MAX); /* "Maxprocs can not be greater than 200\nThere are known problems with MaraDNS hanging using higher numbers" */
        }
#ifndef DARWIN
    rlim.rlim_cur = rlim.rlim_max = maxprocs;

    /* If this OS supports setrlimit and if setrlimit fails, bail (the ENOSYS
       check is there so OSes w/o setrlimit support can still run MaraDNS) */
#ifndef SOLARIS
    if(setrlimit(RLIMIT_NPROC,&rlim) != 0 && errno != ENOSYS)
        sys_harderror(L_MAXPROC_SET); /* "Unable to set maximum number of processes" */
#endif /* SOLARIS */
#endif /* DARWIN */

    /* Anything after this does not need recursion enabled for the
       kvar in question to be read */

    /* Determine if we are root */
    if(geteuid() == 0) {

        /* Change the root directory */
        if(js_qstr2js(kvar_query,"chroot_dir") == JS_ERROR)
            harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,chrootn) == JS_ERROR)
            harderror(L_CHROOT_KVAR); /* "Problem getting chroot kvar.\nYou must have chroot_dir set if you start this as root" */
        if(js_js2str(chrootn,chroot_zt,200) == JS_ERROR)
            harderror(L_CHROOT_NT); /* "Problem making chroot nt string.\nMake sure the chroot directory is 200 chars or less" */
        if(chdir(chroot_zt) != 0)
            sys_harderror(L_CHROOT_CHANGE); /* "Problem changing to chroot dir.\nMake sure chroot_dir points to a valid directory" */
        if(chroot(chroot_zt) != 0)
            sys_harderror(L_CHROOT_DO);  /* "Problem changing the root directory." */

        mlog(L_CHROOT_SUCCESS); /* "Root directory changed" */

        /* Bind to port 53
           To Do: use capset to give us privledged bind abilities without
                  needing to be root.
        */
        if(js_qstr2js(kvar_query,"bind_address") == JS_ERROR)
            harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,bind_address) == JS_ERROR)
            harderror(L_NOBIND); /* "Problem getting chroot kvar.\nYou must have bind_address set to the IP maradns will listen on" */
        if(udpbind(&sock,bind_address) == JS_ERROR)
            sys_harderror(L_BINDFAIL); /* "Problem binding to port 53.\nMost likely, another process is already listening on port 53" */
        zjlog(L_BIND2ADDR,bind_address); /* "Binding to address " */
        mlog(L_BIND_SUCCESS);  /* "Socket opened on UDP port 53" */

        /* Drop the elevated privileges */
        /* First, change the GID */
        if(js_qstr2js(kvar_query,"maradns_gid") == JS_ERROR)
            harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,uidstr) == JS_SUCCESS) {
            gid = js_atoi(uidstr,0);
            /* Drop all supplemtal groups */
            setgroups(1,&gid);
            /* Set the group ID */
            setgid(gid);
            }
        /* Next, change the UID */
        if(js_qstr2js(kvar_query,"maradns_uid") == JS_ERROR)
            harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,uidstr) == JS_ERROR)
            harderror(L_NOUID); /* "Problem getting maradns_uid kvar.\nYou must have maradns_uid set if you start this as root" */
        if((uid = js_atoi(uidstr,0)) < 10)
            harderror(L_BADUID); /* "maradns_uid is less than 10 or not a number.\nThis uid must have a value of 10 or more" */
        if(setuid(uid) != 0)
            sys_harderror(L_NODROP); /* "Could not drop root uid" */
        /* Workaround for known Linux kernel security problem circa
           early 2000 */
        if(setuid(0) == 0)
            sys_harderror(L_STILL_ROOT);  /* "We seem to still be root" */

        mlog(L_DROP_SUCCESS); /* "Root privileges dropped" */

        }
    else {

        /* Bind to port 53 as a non-root user */
        if(js_qstr2js(kvar_query,"bind_address") == JS_ERROR)
            harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        if(read_kvar(kvar_query,bind_address) == JS_ERROR)
            harderror(L_NOBIND); /* "Problem getting chroot kvar.\nYou must have bind_address set to the IP maradns will listen on" */
        if(udpbind(&sock,bind_address) == JS_ERROR)
            sys_harderror(L_BEROOT); /* "Problem binding to port 53.\nYou should run this as root" */
        mlog(L_BIND_SUCCESS);  /* "Socket opened on UDP port 53" */
        }

    /* Flush out any messages that have already appeared */
    fflush(stdout);

    /* Listen for data on the UDP socket */
    for(;;) {
        if(getudp(sock,(struct sockaddr *)&client,incoming,512) == JS_ERROR)
            continue;
        if(decompress_data(incoming,uncomp) == JS_ERROR)
            continue;
        proc_query(uncomp,(struct sockaddr_in *)&client,sock);
        }

    }

