/* Copyright (c) 2002-2022 Sam Trenholme
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

/* This is the core DNS server */

/* Language specific labels */
#include "MaraDNS_locale.h"

/* Include stuff needed to be a UDP server */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "../qual/qual_timestamp.h"
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#ifndef MINGW32
#include <grp.h>
#endif
#include <fcntl.h>
#ifdef __FreeBSD__
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifndef DARWIN
#endif
#ifndef MINGW32
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock.h>
#include <wininet.h>
#endif
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"
#include "../parse/Csv2_database.h"
#include "../parse/Csv2_read.h"
#include "../parse/Csv2_functions.h"
#include "functions_server.h"
#include "timestamp.h"
#include "read_kvars.h"

/* Virutal memory limit */
#ifdef RLIMIT_AS
#define MAX_MEM RLIMIT_AS
#else /* RLIMIT_AS */
#ifdef RLIMIT_VMEM
#define MAX_MEM RLIMIT_VMEM
#endif /* RLIMIT_VMEM */
#endif /* RLIMIT_AS */

/* Our global variables */
mhash *bighash;
int log_level = 1; /* 0: No messages except for fatal errors which stop
                         MaraDNS, 1: Startup and shutdown messages,
                  2: Log queries that generate errors, 3: Log all queries */
int no_fingerprint = 0; /* 0: Have some MaraDNS-specific features, such as
                              DDIP expansion and a special query that
                              tells you the version number of the server.
                           1: Attempts to have as generic an interface as
                              possible. */
int rrany_set = 3; /* (Determined with default_rrany_set in mararc file)
                      3: A request for RR_ANY will only return A and MX
                         records for a given node.
                      15: A request for RR_ANY will return A, MX, NS, and
                         SOA records */
int max_ar_chain = 1; /* Maximum number of records we show of a chain
                         of A records in the additional section of an
                         answer */
int max_chain = 8; /* Total maximum number of records in any chain of
                      records */
int max_total = 20; /* Total maximum number of records we will show */
int debug_delay = 0; /* Delay before sending a reply; only used for
                        debugging MaraDNS */
int default_zonefile_enabled = 0; /* Whether a default zone file is
                                     enabled (whether we are allowing
                                     stars at end of hostnames) */
int no_cname_warnings = 0; /* Whether to supress warnings about dangling
                              CNAMES or not */
int min_visible_ttl = 30; /* The minimum TTL we will show the user */

/* Some variables used to assist in the housekeeping making sure we
   do not display a given RR in the Additional records section twice */
rr *seenlist[256];
int seenlist_where = 0;

int total_count = 0; /* This has to be global to handle udpany's use of it */

int debug_msg_level = 1; /* The level of debug messages to allow */

int reject_aaaa = 0; /* Whether to send a bogus SOA (not there) every time
                        someone asks for an AAAA (works around problems
                        with RH7.2 resolver library) */
int reject_ptr = 0; /* Whether to send a bogus SOA (not there) every time
                       someone asks for a PTR */

rr *ra_data = 0; /* Bogus SOA to give out whenever a SOA request is sent */

/*int rd_value = 0;*/ /* Whether RD is set to 0 or 1 in replies to
                         authoritative queries; disabled because you
                         shouldn't use global variables in threaded
                         code */

int dos_protection_level = 0; /* How many features of MaraDNS we're willing
                                 to give up to make her more immune to
                                 Denial of Service attacks */

int bind_star_handling = 0; /* Handle star records the same way BIND does */

int remote_admin = 0; /* Whether remote administration (currently,
                         changing the verbose_level while MaraDNS is
                         running is the only thing that can be changed
                         remotely) is allowed.  Default off */

int force_auth = 1; /* Whether any non-NS delegation record returned
                     * from the authoritative half is always marked
                     * authoritative */

int dns_port = 53; /* The default port for the server to listen on */

int csv2_tilde_handling = 2; /* How to parse tildes in CSV2 zone files */

int recurse_delegation = 0; /* Whether MaraDNS will recurse when we would
                             * otherwise give out a NS delegation entry */

int dns_records_served = 0; /* The number of DNS records we are serving */

js_string *notthere_ip = 0; /* The Class + TTL (0) + Rdlength (4)
                             * + IP (The IP the user wants) for synthetic
                             * IPs when they mistype a domain name or some
                             * such (Sponsored by XeroBank). */

int recursion_enabled = 0; /* Whether we have recursion */

int rfc8482 = 1; /* Whether we send an RFC8482 reply to ANY queries */

/* A list of who is and who is not allowed to make recursive DNS queries */
ipv4pair recurse_acl[512];
/* A list of the ipv4 IP addresses we bind MaraDNS to (the netmask portion is
   ignored) */
ipv4pair bind_addresses[512];
/* A list which we will use just in case we need a different list of ips
 * in the synthetic NS records than the list of IPs we're bound to (also
 * useful for binding to "0.0.0.0" for people who don't mind the bugs that
 * causes */
ipv4pair csv2_synthip_list[512];
#ifdef AUTHONLY
/* A list of the ips which we can send long packets to */
ipv4pair long_packet[512];
#endif

/* A list of IPs allowed to administrate MaraDNS (See MaraDNS' version
 * number, see how many threads are running, the number of processes running,
 * etc.). */
ipv4pair admin_acl[512];

/* Some global variables so that the user can change the SOA origin (MINFO)
 * and the format of the SOA serial number if needed */
js_string *synth_soa_origin = 0;
int synth_soa_serial = 1;
/* Some routines so we can see the above variables */
js_string *show_synth_soa_origin() {
        return synth_soa_origin;
}
int show_synth_soa_serial() {
        return synth_soa_serial;
}

/* Define log_lock(); and log_unlock(); for authonly use */
#ifdef AUTHONLY
#define log_lock()
#define log_unlock()
#endif /* AUTHONLY */

/* Debug routine that shows an IP in dotted decimal format on the
   standard output.
   Input:  A uint32 ip
   Output: none
*/
void debug_show_ip(uint32 ip) {
    printf("%d.%d.%d.%d",(ip & 0xff000000) >> 24,
                         (ip & 0x00ff0000) >> 16,
                         (ip & 0x0000ff00) >>  8,
                          ip & 0x000000ff);
    }

/* This displays ipv6 ips; thanks Remmy */

#ifdef IPV6
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
#ifndef MINGW32
void debug_show_socket_ipv6(struct sockaddr_in6 *socket) {
        /* Disabled because it currently doesn't work */
        /* printf(" ipv6 "); return; */
        /* This looks broken */
        char hostname[INET6_ADDRSTRLEN];
        printf("%s", inet_ntop(AF_INET6, &socket->sin6_addr, hostname, sizeof(hostname)));
}
#endif /* MINGW32 */
#endif /* __CYGWIN__ */
#endif /* AUTHONLY */

/* Signal handler for SIGPIPE, so we don't terminate */
void handle_sigpipe() {
    if(log_level > 1) {
        log_lock();
        printf("%s%s",L_CAUGHT_PIPE,L_N); /* "Caught SIGPIPE" */
        log_unlock();
        }
    return;
    }

int got_hup_signal = 0;

/* Signal handler for HUP signal */
void handle_hup() {
    got_hup_signal = 1;
    return;
    }

/* Signal handler for other signals */
void handle_signal() {
    if(log_level > 1) {
        log_lock();
        printf("%s%s",L_CAUGHT_SIG,L_N); /* "Caught Signal" */
        log_unlock();
        }
    return;
    }

#ifdef DEBUG
/* Signal handler which tells us about unfreed memory before exiting */
void display_unfreed() {
    if(log_level > 0)
        js_show_leaks();
    exit(64);
    }
#endif /* DEBUG */

/* Print out log messages
   Input: Null-terminated string with the message to log
   Output: JS_SUCCESS on success, JS_ERROR on error
*/

int mlog(char *logmessage) {

    if(log_level == 0)
        return JS_SUCCESS;

    if(logmessage == 0)
        return JS_ERROR;
    log_lock();
    show_timestamp();
    printf("%s%s%s",L_LOG,logmessage,L_N);
          /* "Log: ", logmessage, "\n" */

    /* Unbuffered output */
    fflush(stdout);
    log_unlock();

    return JS_SUCCESS;
    }

/* Print out log messages of js_string messages
   Input: js_string object to log
   Output: JS_SUCCESS on success, JS_ERROR on error
*/

int jlog(js_string *logmessage) {

    int ret;

    if(log_level == 0)
        return JS_SUCCESS;

    log_lock();
    printf("%s",L_LOG); /* "Log: " */
    ret = show_esc_stdout(logmessage);
    printf("%s",L_N); /* "\n" */

    /* Unbuffered output */
    fflush(stdout);
    log_unlock();

    return ret;
    }

/* Print out log message of a Null-terminated string followed by a js_string
   Input: Null-terminated string, js_string
   Output: JS_SUCCESS on success, JS_ERROR on error */

int zjlog(char *left, js_string *right) {
    int ret;
    if(log_level == 0)
        return JS_SUCCESS;
    if(left == 0)
        return JS_ERROR;
    log_lock();
    printf("%s%s",L_LOG,left); /* "Log: ", left */
    ret = show_esc_stdout(right);
    printf("%s",L_N); /* "\n" */

    /* Unbuffered output */
    fflush(stdout);
    log_unlock();

    return ret;
    }

/* Handler to handle fatal errors.
   Input: Pointer to null-terminalted string with fatal error
   Output: MaraDNS exits
*/

void harderror(char *why) {
    printf("%s%s%s",L_FATAL,why,L_N); /* "Fatal Error: ", why, "\n" */

    /* Unbuffered output */
    fflush(stdout);

    exit(3);
    }

/* Handler to handle system fatal errors.
   Input: Pointer to null-terminalted string with fatal error
   Output: MaraDNS exits
*/

void sys_harderror(char *why) {
    printf("%s%s%s",L_FATAL,why,L_N); /* "Fatal Error: ", why, "\n" */
    printf("%s: %s%s",L_SYSERROR,strerror(errno),L_N);
    /* This outputs to stderr, which duende can not catch (I gave up
       trying to catch stderr messages after trying for two days) */
    /*perror(L_SYSERROR);*/ /* "System said: " */

    /* Unbuffered output */
    fflush(stdout);

    exit(3);
    }

/* This function returns an appropriate RA (Recursion available) value.
 * If the user has not set "recursive_acl", this will always return 0.
 * If the argument give to this is 0, return zero.  Otherwise, return 1
 */

int calc_ra_value(int want_ra) {
#ifdef AUTHONLY
        return 0;
#else /* AUTHONLY */
        if(recursion_enabled == 0) {
                return 0;
        }
        return want_ra;
#endif /* AUTHONLY */
}

/* This function prepares the notthere_ip string so that it we can quickly
 * make synthetic IPs.  Basically, the string is most of the DNS header and
 * data for the generated synthetic IP, in this form:
 *
 * Dname: 2-byte compression pointer to question (0xc00c)
 * Class (16-bit): 1 (Internet)
 * TTL: 0 (Not to be cached)
 * Rdlength: 4 (4-byte IP)
 * Rddata: The dotted-decimal IP given to the function converted in to raw
 *         binary form.
 *
 * Input: A js_string containing the dotted-decimal IP we will convert
 * Output: A js_string containing the above raw data
 */

js_string *make_notthere_ip(js_string *ddip) {
        js_string *out = 0;
        js_string *ip = 0;
        out = js_create(19,1);
        if(out == 0) {
                return 0;
        }
        ip = js_create(10,1);
        if(ip == 0) {
                js_destroy(out);
                return 0;
        }
        if(js_adduint16(out,0xc00c) == JS_ERROR || /* Hostname (compressed) */
           js_adduint16(out,1) == JS_ERROR || /* TYPE (A) */
           js_adduint16(out,1) == JS_ERROR || /* CLASS */
           js_adduint16(out,0) == JS_ERROR || /* TTL pt. 1 */
           js_adduint16(out,0) == JS_ERROR || /* TTL pt. 2 */
           js_adduint16(out,4) == JS_ERROR) { /* Rdlength */
                js_destroy(out);
                js_destroy(ip);
                return 0;
        }
        if(ddip_2_ip(ddip,ip,0) == JS_ERROR) {
                js_destroy(out);
                js_destroy(ip);
                return 0;
        }
        if(js_append(ip,out) == JS_ERROR) {
                js_destroy(out);
                js_destroy(ip);
                return 0;
        }
        js_destroy(ip);
        return out;
}

/* Calculate the TTL age given the expire time (absolute time) and
   the ttl (relative time)
   Input: Exprire time, TTL in question
   Output: The TTL we should give, taking TTL aging in to account
 */

uint32 determine_ttl(qual_timestamp expire,uint32 ttl) {
    qual_timestamp now;

    if(expire == 0) {
        return ttl;
        }
    now = qual_get_time();

    /* If this is a record being resurrected from the expired records, we
       make the TTL 29 seconds */
    if(expire < (now - 10)) {
        return 29;
        }

    if(expire - now > min_visible_ttl) {
        return expire - now;
        }
    return min_visible_ttl;
    }

/* Given a JS_STRING object with a DNS query (starting with the header)
 * in it, determine what the RD bit in that header is. */
int get_header_rd(js_string *query) {
        if(js_has_sanity(query) == JS_ERROR) {
                return 0;
        }
        if(query->unit_size != 1) {
                return 0;
        }
        if(query->unit_count < 3 || query->max_count < 3) {
                return 0;
        }
        return *(query->string + 2) & 0x01;
}

/* This function takes a conn *ect (a MaraDNS-specific description of a
 * connection that can be the IP and port of either a ipv4 or ipv6
 * connection), a socket number, and a js_string to send, and sends
 * a message over the 'net */
int mara_send(conn *ect, int sock, js_string *reply) {
        if(ect == 0 || reply == 0) {
                return JS_ERROR;
        }
        if(ect->type == 4) {
                sendto(sock,reply->string,reply->unit_count,0,
                                (struct sockaddr *)ect->d,ect->addrlen);
                return JS_SUCCESS;
#ifdef IPV6
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
        } else if(ect->type == 6) {
                sendto(sock,reply->string,reply->unit_count,0,
                                (struct sockaddr *)ect->d,ect->addrlen);
                return JS_SUCCESS;
#endif /* __CYGWIN__ */
#endif
        } else {
                return JS_ERROR;
        }
}

/* Return a packet indicating that there was an error in the received
   packet
   input: socket number,
          a js_string object that we get the data from the first two
          bytes from, a sockaddr of who to send the error to,
          the question the error-generating query asked, the error
          to give them in the RCODE part of the header,
          the reason for the error, the minimim log_level to log this
          error (with reason) with
   output: JS_ERROR on error, JS_SUCCESS on success

   If error is -111, this means "truncated" (magic number)
*/

int udperror(int sock,js_string *raw, struct sockaddr_in *from,
             js_string *question, int error,
             char *why,int min_log_level, int rd_val, conn *ect,int log_msg) {

    q_header header;
    js_string *reply;
    int len_inet = sizeof(struct sockaddr);

    if(log_level >= min_log_level && log_msg == 1) {
        show_timestamp();
        zjlog(L_BAD_QUERY,raw); /* "Bad query received: " */
        if(ect != 0 && ect->type == 4) {
            struct sockaddr_in *clin = 0;
            clin = (struct sockaddr_in *)(ect->d);
            printf("From IP: ");
            debug_show_ip(ntohl(clin->sin_addr.s_addr));
            printf("\n");
            }
        else if(from != 0) {
            printf("From IP: ");
            debug_show_ip(ntohl(from->sin_addr.s_addr));
            printf("\n");
            }
        }
    if(log_level >= 2) /* Tell them why */
        mlog(why);

    if(raw->unit_count < 2 || raw->max_count < 3)
        return JS_ERROR;

    if((reply = js_create(96,1)) == 0)
        return JS_ERROR;

    /* Fill out the header */
    header.id = ((*(raw->string) & 0xff) << 8) | (*(raw->string + 1) & 0xff);
    header.qr = 1;
    header.opcode = 0;
    header.aa = 0; /* Errors are never authoritative (unless they are
                      NXDOMAINS, which this is not) */

    if(error != -111) {
        header.tc = 0;
    } else {
        header.tc = 1;
    }
    header.rd = rd_val; /* RDBUG udperror */
    header.ra = 0;
    header.z = 0;
    if(error != -111) {
        header.rcode = error;
    } else {
        header.rcode = 0;
    }
    if(question == 0)
        header.qdcount = 0;
    else
        header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Make that raw UDP data */
    if(make_hdr(&header,reply) == JS_ERROR) {
        js_destroy(reply);
        return JS_ERROR;
    }

    /* Append the question, if there is one */
    if(question != 0) {
       if(js_append(question,reply) == JS_ERROR) {
           js_destroy(reply);
           return JS_ERROR;
           }
       if(js_adduint16(reply,1) == JS_ERROR) {
           js_destroy(reply);
           return JS_ERROR;
           }
       }

    /* Send them the reply */
    if(ect == 0) {
        sendto(sock,reply->string,reply->unit_count,0,
            (struct sockaddr *)from,len_inet);
    } else {
        mara_send(ect,sock,reply);
    }
    js_destroy(reply);
    return JS_SUCCESS;

    }

/* If we successfully found a record, add the answer to the A record,
   if applicable, add the NS data too, and add the appropriate
   additional records.
   Input: Where a pointer to the rr in question is, a pointer to the
          string where we add answers, pointer to ns data string, a pointer
          to the string where we add additional records, a pointer to the
          number containing the number of answers, a pointer to the
          number containing the number of authority records, a pointer to
          the number containing the number of additional records, whether
          to add records to the authority (ns) section, the real query name
          (used in the case of star records, otherwise 0.)
   Output: JS_ERROR on error, JS_SUCCESS on success

   NOTE: This routine is only called from udpany and is only used to
         process ANY queries.
*/

int add_answer(rr *where,js_string *most, js_string *ns, js_string *ar,
               uint16 *ancount, uint16 *nscount, uint16 *arcount,
               int add_ns, void **rotate_point, js_string *starwhitis,
               unsigned char max_answers) {

    uint16 first_rr_type;
    rr *ipwhere = 0;
    int in_ns = 0;
    int a_count = 0; /* Number of records displayed for a given chain */
    int ar_count = 0; /* Number of records displayed for a chain in the AR
                         section */
    int rotate_done = 0; /* We only rotate data once per call
                            to this function */
    /* The following are used for round robin rotation */
    rr *rotate_1st = 0, *rotate_2nd = 0, *rotate_last = 0;

    /* Sanity check */
    if(where == 0) {
        goto giveerror;
        }
    if(where->query == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->query) == JS_ERROR) {
        goto giveerror;
        }
    if(where->data == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->data) == JS_ERROR) {
        goto giveerror;
        }
    if(starwhitis != 0 && js_has_sanity(starwhitis) == JS_ERROR) {
            goto giveerror;
    }
    first_rr_type = get_rtype(where->query);

    /* The data must be between 0 and 65535 bytes in length (16-bit
       unsigned value) */
    if(where->data->unit_count < 0 || where->data->unit_count > 65535) {
        goto giveerror;
        }

    /* Initialize some temporary pointers used for round robin rotation */
    rotate_1st = where;
    rotate_2nd = where->next;
    /* We do not round robin if there is but a single record */
    if(rotate_2nd != 0 && first_rr_type != RR_NS &&
       rotate_2nd->rr_type == RR_NS)
        rotate_2nd = 0;

    /* OK, we now add the answers */
    while(where != 0) {
        /* Increment the number of answers -or- ns records */
        if(first_rr_type != RR_NS && where->rr_type == RR_NS &&
                        max_answers == 0) {

            /* Due to the data structure MaraDNS currently uses, the behavior
               is buggy if we round-robin rotate data when we allow more than
               one additional record to be create per answer/authoritative
               record.  */
            if(rotate_2nd != 0 && max_ar_chain == 1 && rotate_done == 0
               && first_rr_type != RR_NS) {
                rotate_done = 1;
                /* If it makes sense to do a round-robin rotation */
                rotate_1st->next = where;
                rotate_last->next = rotate_1st;
                *rotate_point = rotate_2nd;
                }

            a_count = 0; /* The NS chain is different than the AN
                            chain of answers: If we only allow eight
                            answers in a chain, we can still have 16
                            answers: 8 records in the answer section then
                            8 records in the authority section */
            if(add_ns == 1)
                in_ns = 1;
            else
                return JS_SUCCESS;
            }
        /* Add an answer record */
        if(!in_ns && a_count < max_chain && total_count < max_total) {
            a_count++; /* Counter so we don't exceed the maximum number
                          of records allowed to be seen in a chain */
            total_count++;
            /* This allows us to have multiple records for a given RTYPE
               when an ANY query is made */
            if(where->rr_type == RR_NS && first_rr_type != RR_NS &&
               max_answers != 0) {
                in_ns = 1;
                goto max_answers_skip;
                }
            (*ancount)++; /* This goes in the header of the reply */
            /* Append the name for this answer to the answer */
            if(starwhitis == 0 && /* We don't do following if this fails */
                            js_append(where->query,most) == JS_ERROR) {
                goto giveerror;
            }
            else if(starwhitis != 0 &&
                            js_append(starwhitis,most) == JS_ERROR) {
                    goto giveerror;
            }
            /* Append the class (in) to the answer */
            if(js_adduint16(most,1) == JS_ERROR) {
                goto giveerror;
                }
            /* Append the ttl to the answer */
            if(js_adduint32(most,determine_ttl(where->expire,where->ttl))
                == JS_ERROR) {
                goto giveerror;
                }
            /* Add the rdlength to the answer */
            if(js_adduint16(most,where->data->unit_count) == JS_ERROR) {
                goto giveerror;
                }
            /* Add the record itself to the answer */
            if(js_append(where->data,most) == JS_ERROR) {
                goto giveerror;
                }
max_answers_skip:
            if(max_answers == 1) {
                return JS_SUCCESS;
                }
            }
        else if(a_count < max_chain && total_count < max_total &&
                max_answers == 0) {
            a_count++; total_count++; /* The counters that make sure we do
                                         not have more than, say, eight
                                         records for a given answer */
            /* Append the name for this answer to the answer */
            if(js_append(where->query,ns) == JS_ERROR) {
                goto giveerror;
                }
            /* Append the class (in) to the answer */
            if(js_adduint16(ns,1) == JS_ERROR) {
                goto giveerror;
                }
            /* Append the ttl to the answer */
            if(js_adduint32(ns,determine_ttl(where->expire,where->ttl))
                == JS_ERROR) {
                goto giveerror;
                }
            /* Add the rdlength to the answer */
            if(js_adduint16(ns,where->data->unit_count) == JS_ERROR) {
                goto giveerror;
                }
            /* Add the record itself to the answer */
            if(js_append(where->data,ns) == JS_ERROR) {
                goto giveerror;
                }
            (*nscount)++;
            }
        /* If there is an IP, and this is *not* a CNAME record,
           append the IP of the answer to the AR section */
        if(where->ip != 0 && where->rr_type != RR_CNAME && max_answers == 0) {
            ipwhere = where->ip;
            ar_count = 0; /* Reset for each instance of showing AR
                             records */
            while(ipwhere != 0 && ipwhere->rr_type != RR_NS &&
                  ar_count < max_ar_chain && total_count < max_total) {
                ar_count++; /* Counter so we don't exceed maximum number
                               of AN records allowed to be displayed */
                total_count++; /* Similar to ar_count */
                /* We only show a given additional record once */
                if(ipwhere->seen == 1) { /* If we have displayed this RR
                                            already */
                    /* Go to the next link in the linked list */
                    ipwhere = ipwhere->next;
                    continue;
                    }
                /* Increment the number of additional records */
                (*arcount)++;
                /* Append the name for this answer to the ip */
                if(js_append(ipwhere->query,ar) == JS_ERROR) {
                    goto giveerror;
                    }
                /* Append the class (in) to the ip */
                if(js_adduint16(ar,1) == JS_ERROR) {
                    goto giveerror;
                    }
                /* Append the TTL to the ip */
                if(js_adduint32(ar,determine_ttl(ipwhere->expire,ipwhere->ttl))
                   == JS_ERROR) {
                    goto giveerror;
                    }
                /* Add the rdlength to the ip */
                if(js_adduint16(ar,ipwhere->data->unit_count) == JS_ERROR) {
                    goto giveerror;
                    }
                /* Add the record itself to the ip */
                if(js_append(ipwhere->data,ar) == JS_ERROR) {
                    goto giveerror;
                    }
                /* Mark that we have seen this record already */
                if(seenlist_where < 250) {
                    ipwhere->seen = 1;
                    seenlist[seenlist_where] = ipwhere;
                    seenlist_where++;
                    }
                ipwhere = ipwhere->next;
                }
            }

        /* We do not chase CNAME records in an "RR_ALL" query */

        /* Make a note of this node for round-robin rotation purposes */
        rotate_last = where;
        /* Go on to the next record in the linked list */
        where = where->next;
        }

    return JS_SUCCESS;

    /* We use gotos to make up for C's lack of error trapping */
    giveerror:
        return JS_ERROR;

    }

/* If they asked for a RR_ANY record in the authoritative half, see if
   we have a special RR_ANY record in the cache which is a linked list to
   all of the records types for a given domain node.  If so, give them
   an answer; otherwise give them a NXDOMAIN.

   If they ask for an RR_ANY in the recursive half, do the following:

   1. See if MX records exist.  If so, add it to the answer to give.

   2. See if A records record exist.  If so, add it.

   3. If neither A nor MX exist, look for a CNAME record.  If so,
      return just the CNAME record.

   4. Otherwise, return "query denied".

   Input: ID of the iquery they sent us, socket of the request, a sockaddr
          with their address and port number on it, a js_string containing
          the query (dname + type), the rr_set to return (3: A and MX,
          15: A, MX, SOA, and NS), the hash to look for data in, the
          RD value to set in the headers of the reply, the connection
          this is on, whether this is called from the recursive code
          or not.
   Output: JS_ERROR on error, JS_SUCCESS on success, 0 if no records were
           found
*/

int udpany(int id,int sock,struct sockaddr_in *client, js_string *query,
           int rr_set, mhash *bighash, int rd_val, conn *ect, int
           called_from_recursive, js_string *origq) {
    js_string *most, *ns, *ar; /* The answers, the ns records, the ar records*/

    js_string *starwhitis;

    int length_save;
    int len_inet = sizeof(struct sockaddr);
    int found = 0;
    int authoritative = 1;
    rr_list *answer = 0;
    mhash_e spot_data;
    int counter;

    q_header header;
    /* Initialize the js_string objects */
    if((most = js_create(1024,1)) == 0)
        return JS_ERROR;
    if((ar = js_create(1024,1)) == 0) {
        js_destroy(most);
        return JS_ERROR;
        }
    if((ns = js_create(1024,1)) == 0) {
        js_destroy(most); js_destroy(ar);
        return JS_ERROR;
        }

    /* RFC8482 support CODE HERE */
    if(1) {
        header.id = id;
        header.ancount = 1;
        header.nscount = 0;
        header.arcount = 0;
        header.qr = 1;
        header.opcode = 0;
        header.tc = 0;
        header.rd = rd_val; /* RDBUG udpany */
        header.ra = 0;
        header.aa = authoritative; /* Currently always 1 */
        header.z = 0;
        header.rcode = 0; /* No error */
        header.qdcount = 1;
        if(make_hdr(&header,ar) == JS_ERROR) {
               js_destroy(most); js_destroy(ar); js_destroy(ns);
               return JS_ERROR;
           }
        /* Append the question to the answer */
        if(origq == 0) {
            if(js_append(query,ar) == JS_ERROR) {
                  js_destroy(most); js_destroy(ar); js_destroy(ns);
                  return JS_ERROR;
                }
        } else {
            if(js_append(origq,ar) == JS_ERROR) {
                  js_destroy(most); js_destroy(ar); js_destroy(ns);
                  return JS_ERROR;
                }
        }
        /* Append the class (in) to the answer */
        if(js_adduint16(ar,1) == JS_ERROR) {
               js_destroy(most); js_destroy(ar); js_destroy(ns);
               return JS_ERROR;
            }
        /* Append the RFC8482 reply to the answer */
        if(js_adduint16(ar,0xc00c) == JS_ERROR || /* Hostname (compressed) */
           js_adduint16(ar,13) == JS_ERROR || /* TYPE (HINFO) */
           js_adduint16(ar,1) == JS_ERROR || /* CLASS */
           js_adduint16(ar,0) == JS_ERROR || /* TTL pt. 1 */
           js_adduint16(ar,0) == JS_ERROR || /* TTL pt. 2 */
           js_adduint16(ar,9) == JS_ERROR || /* Rdlength */
	   js_adduint16(ar,0x0752) == JS_ERROR || /* len 7, 'R' */
           js_adduint16(ar,0x4643) == JS_ERROR || /* 'FC' */
           js_adduint16(ar,0x3834) == JS_ERROR || /* '84' */
           js_adduint16(ar,0x3832) == JS_ERROR || /* '82' */
           js_addbyte(ar, 0) == JS_ERROR) {
               js_destroy(most); js_destroy(ar); js_destroy(ns);
               return JS_ERROR;
           }
        /* Success! Put out the good data */
        if(ect == 0) {
            sendto(sock,ar->string,ar->unit_count,0,
                (struct sockaddr *)client,len_inet);
        } else {
            mara_send(ect,sock,ar);
        }

        js_destroy(ar);
        js_destroy(ns);
        js_destroy(most);
        return JS_SUCCESS;
    }

    /* Initialize the total number of RRs displayed to the DNS client */
    total_count = 0;

    /* Make the header a placeholder for now */
    header.id = id;
    header.rd = rd_val; /* RDBUG udpany */
    if(make_hdr(&header,most) == JS_ERROR)
        goto giveerror;

    /* Append the question to the answer */
    if(origq == 0) {
        if(js_append(query,most) == JS_ERROR) {
            goto giveerror;
            }
    } else {
        if(js_append(origq,most) == JS_ERROR) {
            goto giveerror;
            }
    }
    /* Append the class (in) to the answer */
    if(js_adduint16(most,1) == JS_ERROR) {
        goto giveerror;
        }

    /* We will increment the ancount, nscount, an arcount, starting at 0 */
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Start synthesizing the reply */
    /* Look for the list of all of the answers */
    spot_data = mhash_get(bighash,query);
    /* If found, use this list for all of the answers */
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
        answer = (rr_list *)spot_data.value;
        for(counter = 0; counter < 100; counter++) {
            if(add_answer(answer->data,most,ns,ar,&(header.ancount),
                   &(header.nscount),&(header.arcount),1,
                   spot_data.point,0,2) == JS_ERROR) {
                goto giveerror;
                }
            if(answer->rr_type != RR_NS) {
                found = 1;
            }
            answer = answer->next;
            if(answer == 0)
                    break;
            }
        goto old_udpany_code_disabled;
        }

    /* OK, no record found, so look for a star record */
    if((starwhitis = js_create(256,1)) == 0) {
        goto giveerror;
        }
    if(js_copy(query,starwhitis) == JS_ERROR) {
        js_destroy(starwhitis);
        goto giveerror;
        }
    if(make_starlabel(starwhitis) == JS_ERROR) {
        js_destroy(starwhitis);
        goto giveerror;
        }

    spot_data = mhash_get(bighash,starwhitis);
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
        int rtype_save;
starwhitis_any_found:
        answer = (rr_list *)spot_data.value;
        found = 1;
        for(counter = 0; counter < 100; counter++) {
            rtype_save = get_rtype(query);
            if(change_rtype(query,answer->data->rr_type) == JS_ERROR) {
                js_destroy(starwhitis);
                goto giveerror;
                }
            if(add_answer(answer->data,most,ns,ar,&(header.ancount),
                   &(header.nscount),&(header.arcount),1,
                   spot_data.point,query,2) == JS_ERROR) {
                js_destroy(starwhitis);
                goto giveerror;
                }
            answer = answer->next;
            if(answer == 0)
                    break;
            }
        if(change_rtype(query,rtype_save) == JS_ERROR) {
            js_destroy(starwhitis);
            goto giveerror;
            }
        js_destroy(starwhitis);
        goto old_udpany_code_disabled;
        }

    counter = 0;
    while(bobbit_starlabel(starwhitis) == JS_SUCCESS) {
        spot_data = mhash_get(bighash,starwhitis);
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
            goto starwhitis_any_found;
            }
        counter++;
        if(counter > 100) {
            break;
            }
        }

    /* Look for ANY records in a possible csv2_default_zonefile */
    if(default_zonefile_enabled == 1) {
        int labels;
        /* Restore original query, since we are now chopping it up at
           the end instead of the beginning of the record. */
        if(js_copy(query,starwhitis) == JS_ERROR) {
            js_destroy(starwhitis);
            goto giveerror;
            }
        counter = 0;
        while((labels = bobbit_starlabel_end(starwhitis)) > 0) {
            /* limit the number of labels */
            if(labels > 120) {
                continue;
                }
            spot_data = mhash_get(bighash,starwhitis);
            if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
                goto starwhitis_any_found;
                }
            counter++;
            if(counter > 120) {
                break;
                }
            }
        }

    js_destroy(starwhitis);
    goto old_udpany_code_disabled;

old_udpany_code_disabled:

    /* Return with exit code of 0 if no answer was found */
    if(header.ancount == 0 || found == 0) {
        js_destroy(ar);
        js_destroy(ns);
        js_destroy(most);
        return 0;
        }

    /* Customize the header */
    /* header.id already set */
    header.qr = 1;
    header.opcode = 0;
    header.tc = 0;
    header.rd = rd_val; /* RDBUG udpany */
    header.ra = 0;
    header.aa = authoritative; /* Currently always 1 */
    header.z = 0;
    header.rcode = 0; /* No error */
    header.qdcount = 1;

    /* OBhack: Tack on the header at the beginning without molesting the
       rest of the string */
    length_save = most->unit_count;
    make_hdr(&header,most);
    most->unit_count = length_save;

    /* Add the ns and ar records to the end */
    if(js_append(ns,most) == JS_ERROR) {
        goto giveerror;
        }
    if(js_append(ar,most) == JS_ERROR) {
        goto giveerror;
        }

    /* Compress "most" and place the compressed data in "ar" */
    if(compress_data(most,ar) == JS_ERROR) {
        js_destroy(ar);
        js_destroy(ns);
        udperror(sock,most,client,0,SERVER_FAIL,"compression failure",2,
                        rd_val,ect,1);
        js_destroy(most);
        return JS_ERROR;
        }

    /* Check to make sure the data fits in under 512 bytes */
    if(ar->unit_count > 512) {

        /* If this is an ipv4 connection and we didn't get a compress error */
        if(ect->type == 4) {
            struct sockaddr_in *dq;
            uint32 ip_test;
            dq = (struct sockaddr_in *)(ect->d);
            ip_test = ntohl(dq->sin_addr.s_addr);
            /* See if we are allowed to send a long packet up to
             * 4096 bytes to this ip address */
            if(check_ipv4_acl(ip_test,long_packet) == 1) {
                if(ar->unit_count < 4096) {
                    goto long_packet_ok;
                    }
                }
            }

        /* We handle truncation by truncating everything except the
           12-byte header */
        header.tc = 1;
        header.ancount = 0;
        make_hdr(&header,ar);
        /* Append the question, if there is one */
        if(query != 0) {
           js_append(query,ar);
           js_adduint16(ar,1);
           }
        }

long_packet_ok:

    /* Success! Put out the good data */
    if(ect == 0) {
        sendto(sock,ar->string,ar->unit_count,0,
            (struct sockaddr *)client,len_inet);
    } else {
        mara_send(ect,sock,ar);
    }

    js_destroy(ar);
    js_destroy(ns);
    js_destroy(most);

    /* Clean up the seenlist_where list (list marking which ARs we gave out) */
    while(seenlist_where > 0) {
        --seenlist_where;
        if(seenlist[seenlist_where] != 0)
            (seenlist[seenlist_where])->seen = 0;
        }


    return JS_SUCCESS;

    /* We use gotos to make up for C's lack of error trapping */
    giveerror:
        js_destroy(ar);
        js_destroy(ns);
        udperror(sock,most,client,0,SERVER_FAIL,"giveerror in udpany",2,
                        rd_val,ect,1);
        js_destroy(most);

        /* Clean up the seenlist_where list
           (list marking which ARs we gave out) */
        while(seenlist_where > 0) {
            --seenlist_where;
            if(seenlist[seenlist_where] != 0)
                (seenlist[seenlist_where])->seen = 0;
            }

        return JS_ERROR;

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

int easter_egg(int id,int sock,conn *ect, js_string *query,
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
        goto cleanup;

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
    header.rd = 0; /* Recursion not desired */ /* RDBUG easter egg */
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
    mara_send(ect,sock,reply);

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

/* Make a synthetic NS record.  This is what the funciton does:
 * Given a dname they wanted, such as "Awww.example.com.", and a number
 * of labels to truncate from the beginning of said dname (such as 1),
 * create a record like "Nexample.com."  */
js_string *make_synth_ns_record(js_string *dname_they_wanted,
                int labels_to_zap) {
        js_string *out = 0;
        int length,point,labels_seen;

        out = js_create(dname_they_wanted->unit_count + 2,1);

        /* Error check */
        if(out == 0) {
                return 0;
        }

        /* Move point forward to where the part we want to copy over
         * begins */
        point = length = 0;
        labels_seen = 0;
        while(labels_seen < labels_to_zap) {
                length = *(dname_they_wanted->string + point);
                if(point + length > dname_they_wanted->unit_count
                                || length > 63) {
                        js_destroy(out);
                        return 0;
                }
                /* printf("point %d length %d\n",point,length); */
                point += length + 1;
                if(point > dname_they_wanted->unit_count) {
                        js_destroy(out);
                        return 0;
                }
                labels_seen++;
        }

        /* Copy over the rest of the source string to 'out' */
        length = 0;
        while(point < dname_they_wanted->unit_count) {
                if(length >= out->max_count) {
                        js_destroy(out);
                        return 0;
                }
                if(point > dname_they_wanted->unit_count) {
                        js_destroy(out);
                        return 0;
                }
                *(out->string + length) =
                        *(dname_they_wanted->string + point);
                length++;
                point++;
        }

        /* Some other prep on the output string */
        out->unit_count = length;

        if(change_rtype(out,RR_NS) == JS_ERROR) {
                js_destroy(out);
                return 0;
        }
        return out;

}

/* If we successfully found a star record, spit out that record on the
   udp packet.
   Input: Where a pointer to the rr in question is, the id of the
          query they sent us, the socket the
          UDP bind is on, the sockaddr of the client who sent us the message,
          a js_string containing the query (dname + type),
          a js_string containing the answer,
          a number that is set to zero if not using a default hostname
          (see the csv2_default_zonefile mararc variable), and the number
          of dlabels before the star otherwise (so the NS record looks
          correct).
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udpstar(rr *where,int id,int sock,struct sockaddr_in *client,
               js_string *query, js_string *answer, int rd_val, int
               endstar, conn *ect) {
    js_string *most, *ar; /* Most of the data then the additional records */

    uint16 first_rr_type;
    int in_ns = 0;
    int length_save;
    int len_inet = sizeof(struct sockaddr);
    js_string *synth_ns_record = 0; /* Used for starwhitis_end stuff */

    q_header header;
    /* Initialize the js_string objects */
    if((most = js_create(1024,1)) == 0)
        return JS_ERROR;
    if((ar = js_create(1024,1)) == 0) {
        js_destroy(most);
        return JS_SUCCESS;
        }

    /* Make the header a placeholder for now */
    init_header(&header);
    header.id = id;
    header.rd = rd_val; /* RDBUG udpstar */
    if(make_hdr(&header,most) == JS_ERROR)
        goto giveerror;

    /* Sanity check */
    if(where == 0) {
        goto giveerror;
        }
    if(where->query == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->query) == JS_ERROR) {
        goto giveerror;
        }
    if(where->data == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->data) == JS_ERROR) {
        goto giveerror;
        }
    if(js_has_sanity(query) == JS_ERROR) {
        goto giveerror;
        }
    first_rr_type = get_rtype(query);

    /* We have to add this header here--authoritative depends on the
       authorative status of the first record we find */
    header.aa = where->authoritative;

    /* The data must be between 0 and 65535 bytes in length (16-bit
       unsigned value) */
    if(where->data->unit_count < 0 || where->data->unit_count > 65535) {
        goto giveerror;
        }

    /* Append the question to the answer */
    if(js_append(query,most) == JS_ERROR) {
        goto giveerror;
        }

    /* Append the class (in) to the answer */
    if(js_adduint16(most,1) == JS_ERROR) {
        goto giveerror;
        }

    /* We will increment the ancount, nscount, an arcount, starting at 0 */
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* OK, we now add the answers */
    while(where != 0) {
        /* Increment the number of answers -or- ns records */
        if(first_rr_type != RR_NS && where->rr_type == RR_NS)
            in_ns = 1;
        if(!in_ns)
            header.ancount++;
        else
            header.nscount++;
        /* Append the name for the user's "canonical" query to the answer */
        if(!in_ns) {
            if(js_append(answer,most) == JS_ERROR) {
                goto giveerror;
                }
            }
        /* (Unless we are telling them the NS records for this RR) */
        else {
            /* If endstar is greater than zero, we need to make
             * a synthetic host name for the NS answer */
            if(endstar > 0 && endstar < 125 && synth_ns_record == 0) {
                synth_ns_record =
                        make_synth_ns_record(answer,endstar - 1);
                if(synth_ns_record == 0) {
                    goto giveerror;
                    }
                }
            if(synth_ns_record == 0) {
                if(js_append(where->query,most) == JS_ERROR) {
                    goto giveerror;
                    }
                } else {
                if(js_append(synth_ns_record,most) == JS_ERROR) {
                    goto giveerror;
                    }
                }
            }
        /* Append the class (in) to the answer */
        if(js_adduint16(most,1) == JS_ERROR) {
            goto giveerror;
            }
        /* Append the ttl to the answer */
        if(js_adduint32(most,determine_ttl(where->expire,where->ttl))
            == JS_ERROR) {
            goto giveerror;
            }
        /* Add the rdlength to the answer */
        if(js_adduint16(most,where->data->unit_count) == JS_ERROR) {
            goto giveerror;
            }
        /* Add the record itself to the answer */
        if(js_append(where->data,most) == JS_ERROR) {
            goto giveerror;
            }
        /* If there is an IP, and this is *not* a CNAME record,
           append the IP of the answer to the AR section */
        if(where->ip != 0 && where->rr_type != RR_CNAME) {
            /* Increment the number of additional records */
            header.arcount++;
            /* Append the name for this answer to the ip */
            if(js_append(where->ip->query,ar) == JS_ERROR) {
                goto giveerror;
                }
            /* Append the class (in) to the ip */
            if(js_adduint16(ar,1) == JS_ERROR) {
                goto giveerror;
                }
            /* Append the TTL to the ip */
            if(js_adduint32(ar,determine_ttl(where->ip->expire,where->ip->ttl))
                == JS_ERROR) {
                goto giveerror;
                }
            /* Add the rdlength to the ip */
            if(js_adduint16(ar,where->ip->data->unit_count) == JS_ERROR) {
                goto giveerror;
                }
            /* Add the record itself to the ip */
            if(js_append(where->ip->data,ar) == JS_ERROR) {
                goto giveerror;
                }
            }
        /* To do: A records attached to CNAMES are added as a second AN
                  record if the originally requested query was not a CNAME
        */
        /* Go on to the next record in the linked list */
        where = where->next;
        }

    /* Customize the header */
    /* header.id already set */
    header.qr = 1;
    header.opcode = 0;
    header.tc = 0; /* To do: truncation handling */
    header.rd = 0; /* RDBUG udpstar */
    header.ra = 0;
    header.z = 0;
    header.rcode = 0; /* No error */
    header.qdcount = 1;

    /* OBhack: Tack on the header at the beginning without molesting the
       rest of the string */
    length_save = most->unit_count;
    make_hdr(&header,most);
    most->unit_count = length_save;

    /* Add the ar records to the end */
    if(js_append(ar,most) == JS_ERROR) {
        goto giveerror;
        }

    /* Compress "most" and place the compressed data in "ar" */
    if(compress_data(most,ar) == JS_ERROR) {
        js_destroy(ar);
        udperror(sock,most,client,0,SERVER_FAIL,"compression failure",2,
                        rd_val,ect,1);
        js_destroy(most);
        if(synth_ns_record != 0) { js_destroy(synth_ns_record); }
        return JS_ERROR;
        }

    /* Check to make sure the data fits in under 512 bytes */
    if(ar->unit_count > 512) {
        /* We handle truncation by truncating everything except the
           12-byte header */
        header.tc = 1;
        make_hdr(&header,ar);
        }

    /* Success! Put out the good data */
    if(ect == 0) {
        sendto(sock,ar->string,ar->unit_count,0,
            (struct sockaddr *)client,len_inet);
    } else {
        mara_send(ect,sock,ar);
    }

    js_destroy(most);
    js_destroy(ar);

    if(synth_ns_record != 0) { js_destroy(synth_ns_record); }

    return JS_SUCCESS;

    /* We use gotos to make up for C's lack of error trapping */
    giveerror:
        if(synth_ns_record != 0) { js_destroy(synth_ns_record); }
        js_destroy(ar);
        udperror(sock,most,client,0,SERVER_FAIL,"giveerror in udpstar",2,
                        rd_val,ect,1);
        js_destroy(most);
        return JS_ERROR;

    }

/* Create a bogus 0-TTL ip answer if we give out these answers instead
 * of SOA answers/NXDOMAINS for non-existant addresses */

int make_notthere_reply(int id, int sock, struct sockaddr_in *client,
                        js_string *query, int rd_val, conn *ect) {
        js_string *most;
        q_header header;
        int len_inet = sizeof(struct sockaddr);

        init_header(&header);
        header.rd = rd_val; /* RDBUG make_notthere_reply */
        header.id = id;
        header.qr = 1;
        header.opcode = 0;
        header.tc = 0;
        header.ra = calc_ra_value(rd_val);
        header.z = 0;
        header.rcode = 0; /* We "found" something */
        /* We return just a single 0-ttl IP */
        header.qdcount = 1; /* Echo the question in the answer */
        header.ancount = 1;
        header.nscount = 0;
        header.arcount = 0;
        if((most = js_create(520,1)) == 0) {
                return JS_ERROR;
        }
        make_hdr(&header,most);
        /* Question */
        js_append(query,most);
        js_adduint16(most,1); /* Class: 1 */
        /* Answer */
        js_append(notthere_ip,most);

        /* Send answer over UDP */
        if(ect == 0) {
                sendto(sock,most->string,most->unit_count,0,
                        (struct sockaddr *)client,len_inet);
        } else {
                mara_send(ect,sock,most);
        }

        js_destroy(most);
        return JS_SUCCESS;
}

/* If we have a NXDOMAIN, deliver that record on the udp packet.
 *        Input: where: A pointer to the rr in question (the SOA record),
 *
 *        id: the id of the query they sent us,
 *
 *        sock: the socket the UDP bind is on,
 *
 *        client: the sockaddr of the client who sent us the message,
 *
 *        query: a js_string containing the query (dname + type),
 *
 *        qtype: if the qtype of the question is different than the
 *        desired qtype of the answer, then specify the qtype of the
 *        original question, otherwise specify 0 for the qtype
 *
 *        rd_val: The value for the "rd" flag in the header
 *
 *        ect: A structure describing from what IP they are connecting from
 *
 *        recursive_call: Whether this is called from the authoritative or
 *                        recursive half of MaraDNS
 *                        0: Called from authoritative half, do not
 *                           make the query the scope of the SOA reply
 *                        1: Called from recursive half, do not make
 *                           the query the scope of the SOA reply
 *                        2: Called from authoritative half, please make
 *                           query the scope of the SOA reply
 *                        3: Called from recursive half, please make
 *                           query the scope of the SOA reply
 *                        4-7: Same as 0-3, but also always return a
 *                             "not there" instead of a NXDOMAIN
 *
 * Output: JS_ERROR on error, JS_SUCCESS on success
 *
 * Note: The qtype for the js_string query changes in this call, and is not
 *       restored.  This may be a bug.
 */

int udpnotfound(rr *where, int id, int sock, struct sockaddr_in *client,
                js_string *query, int qtype, int rd_val, conn *ect,
                int recursive_call) {
    js_string *most, *compressed; /* Most of the data */

    uint16 first_rr_type;
    int length_save = 0, qtype_save = JS_ERROR;
    int len_inet = sizeof(struct sockaddr);

    q_header header;
    int always_not_there = 0;
    if(recursive_call >= 4) {
        recursive_call -= 4;
        always_not_there = 4;
    }

    if(js_has_sanity(query) == JS_ERROR) {
        return JS_ERROR;
        }
    first_rr_type = get_rtype(query);

    /* See if notthere_ip is set, they are using recursion, and
     * that they want an IP */
    if(notthere_ip != 0 && (recursive_call & 1) == 1 && first_rr_type == 1) {
                /* If so, give them a synthetic IP reply */
                return make_notthere_reply(id, sock, client, query, rd_val,
                                           ect);
    }

    /* Initialize the js_string objects */
    if((most = js_create(1024,1)) == 0)
        return JS_ERROR;
    if((compressed = js_create(1024,1)) == 0) {
        js_destroy(most);
        return JS_ERROR;
        }

    /* Make the header a placeholder for now */
    init_header(&header);
    header.rd = rd_val; /* RDBUG udpnotfound */
    header.id = id;
    if(make_hdr(&header,most) == JS_ERROR) {
        js_destroy(most); js_destroy(compressed);
        return JS_ERROR;
        }

    /* Sanity check */
    if(where == 0)
        goto giveerror;
    if(where->query == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->query) == JS_ERROR) {
        goto giveerror;
        }
    if(where->data == 0) {
        goto giveerror;
        }
    if(js_has_sanity(where->data) == JS_ERROR) {
        goto giveerror;
        }


    /* We have to add this header here--authoritative depends on the
       authorative status of the first record we find */
    header.aa = where->authoritative;

    /* The data must be between 0 and 65535 bytes in length (16-bit
       unsigned value) */
    if(where->data->unit_count < 0 || where->data->unit_count > 65535) {
        goto giveerror;
        }

    /* If they specified that the qtype of the quesiton is differnet than
       the qtype of the answer (this is used in the case of RR_ANY), then
       temporarily change the qtype when we give out the answer */
    if(qtype != 0) {
        qtype_save = get_rtype(query);
        if(qtype_save == JS_ERROR)
            goto giveerror;
        if(change_rtype(query,qtype) == JS_ERROR)
            goto giveerror;
        }

    /* Append the question to the answer */
    if(js_append(query,most) == JS_ERROR) {
        change_rtype(query,qtype_save);
        goto giveerror;
        }

    /* Set the qtype of the query */
    if(change_rtype(query,qtype) == JS_ERROR)
        goto giveerror;

    /* Append the class (in) to the answer */
    if(js_adduint16(most,1) == JS_ERROR) {
        goto giveerror;
        }

    /* These three values are zero, one, and zero */
    header.ancount = 0;
    header.nscount = 1;
    header.arcount = 0;

    /* Append the name for this answer to the answer */
    /* In the case of the default zonefile returning negative data,
     * *(where->query->string) will have the value '_'; a character that is
     * illegal to begin a DNS name with.
     * When recursive_call has a value of 2 or 3, this indicates that
     * we narrow the scope of the SOA reply (see notes on recursive_call
     * above) */
    if(*(where->query->string) == '_' || recursive_call == 2
       || recursive_call == 3) {
        qtype_save = get_rtype(query);
        if(change_rtype(query,RR_SOA) == JS_ERROR) {
            goto giveerror;
            }
        if(js_append(query,most) == JS_ERROR) {
            goto giveerror;
            }
        }
    else if(js_append(where->query,most) == JS_ERROR) {
        goto giveerror;
        }
    /* Append the class (in) to the answer */
    if(js_adduint16(most,1) == JS_ERROR) {
        goto giveerror;
        }
    /* Append the ttl to the answer */
    if(js_adduint32(most,determine_ttl(where->expire,where->ttl)) ==
        JS_ERROR) {
        goto giveerror;
        }
    /* Add the rdlength to the answer */
    if(js_adduint16(most,where->data->unit_count) == JS_ERROR) {
        goto giveerror;
        }
    /* Add the record itself to the answer */
    if(js_append(where->data,most) == JS_ERROR) {
        goto giveerror;
        }

    /* Customize the header */
    /* header.id already set */
    header.qr = 1;
    header.opcode = 0;
    header.tc = 0; /* To do: truncation handling */
    header.rd = rd_val; /* RDBUG udpnotfound */
    header.ra = calc_ra_value(rd_val);
    header.z = 0;
    /* Code that verifies that this host does not exist in
       any class.  If so, then we give them a rcode of NXDOMAIN_RCODE.
       Otherwise, we give them a rcode of 0 */
    if(always_not_there == 4) {
        header.rcode = 0; /* "not there" */
    } else if(recursive_call == 1 || recursive_call == 3) {
    /* For the recursive half, we just copy over the rcode from the
       reply the remote server gives us */
        if(where->rcode == 3) {
            header.rcode = 3; /* NXDOMAIN */
        } else {
            header.rcode = 0; /* "not there" */
        }
    } else {
    /* For the authoritative half, see if we have an ANY record
       for this query.  If we do, make the rcode 0 (not there); otherwise
       make the rcode 3 (NXDOMAIN) */
        mhash_e spot_data;
        qtype_save = get_rtype(query);
        if(change_rtype(query,RR_ANY) == JS_ERROR) {
            goto giveerror;
            }
        /* bighash is a global variable; we take advantage of that
           fact here */
        spot_data = mhash_get(bighash,query);
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
            header.rcode = 0; /* "not there" */
        } else {
            header.rcode = 3; /* NXDOMAIN */
        }
    }
    header.qdcount = 1;

    /* OBhack: Tack on the header at the beginning without molesting the
       rest of the string */
    length_save = most->unit_count;
    make_hdr(&header,most);
    most->unit_count = length_save;

    /* Compress "most" and place the compressed data in "compressed" */
    if(compress_data(most,compressed) == JS_ERROR) {
        js_destroy(compressed);
        udperror(sock,most,client,0,SERVER_FAIL,"Compression failure",2,
                        rd_val,ect,1);
        js_destroy(most);
        return JS_ERROR;
        }

    /* Check to make sure the data fits in under 512 bytes */
    if(compressed->unit_count > 512) {
        /* We handle truncation by truncating everything except the
           12-byte header */
        header.tc = 1;
        make_hdr(&header,compressed);
        }

    /* Success! Put out the good data */
    if(ect == 0) {
        sendto(sock,compressed->string,compressed->unit_count,0,
            (struct sockaddr *)client,len_inet);
    } else {
        mara_send(ect,sock,compressed);
    }

    js_destroy(most);
    js_destroy(compressed);

    return JS_SUCCESS;


    /* We use gotos to make up for C's lack of error trapping */
    giveerror:
        js_destroy(compressed);
        udperror(sock,most,client,0,SERVER_FAIL,"giveerror in udpnotfound",2,
                        rd_val,ect,1);
        js_destroy(most);
        return JS_ERROR;

    }

/* Given a domain-label starting with a star record ('_') change this label
   in-place so that the first domain label after the star record is lopped
   off of it.  Eg. '_\003sub\007example\003com\000" becomes
   "_\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           zero-length already
*/

int bobbit_starlabel(js_string *js) {
    int counter = 1;
    unsigned char length;

    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count >= js->max_count)
        return JS_ERROR;
    if(js->unit_count < 2)
        return JS_ERROR;
    if(*(js->string) != '_')
        return JS_ERROR;
    length = *(js->string + 1);

    if(length + 2 > js->unit_count || length > 63)
        return JS_ERROR;
    else if(length == 0)
        return 0;

    length++;

    while(counter < (js->unit_count - length) + 1) {
        *(js->string + counter) = *(js->string + counter + length);
        counter++;
        }

    js->unit_count -= length;

    return JS_SUCCESS;

    }

/* Given a domain-label without a star record ('_'), change the first
   domain label in to a star record ('_') Eg. "\003www\007example\003com\000"
   becomes "_\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           a star record already
*/

int make_starlabel(js_string *js) {
    int counter = 1;
    unsigned char length;

    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count >= js->max_count)
        return JS_ERROR;
    if(js->unit_count < 2)
        return JS_ERROR;
    if(*(js->string) == '_')
        return 0;
    length = *(js->string);
    *(js->string) = '_';

    if(length > js->unit_count || length > 63)
        return JS_ERROR;
    if(length == 0) /* We don't convert a "." domain-label */
        return 0;

    while(counter < js->unit_count - length) {
        *(js->string + counter) = *(js->string + counter + length);
        counter++;
        }

    js->unit_count -= length;

    return JS_SUCCESS;

    }

/* Given a domain-label ending with (or without) a star record ('_'),
   change the label
   in-place so that the first domain label before the star record is lopped
   off of it.  Eg. "\003name\007example\003com\000\000\001" becomes
   "\003name\007example\003com_\000\001", and
   "\003name\007example\003com_\000\001" becomes "\003name\007example_\000\001"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, 0 if the label is
           zero-length already, number of labels including star otherwise
           (130 if we don't know how many labels there are)
*/

int bobbit_starlabel_end(js_string *js) {
    int counter = 1;
    int ret = 0;
    unsigned char toread;
    int length;
    int16 rtype;

    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count >= js->max_count)
        return JS_ERROR;
    if(js->unit_count < 2)
        return JS_ERROR;
    if(js->unit_count == 3) {
        return 0;
    }
    rtype = *(js->string + js->unit_count - 1);
    rtype += *(js->string + js->unit_count - 2) << 8;
    js->unit_count -= 2;
    counter = dlabel_length(js,0);
    counter--;
    if(counter < 0 || counter > js->unit_count)
        return JS_ERROR;

    /* If this is not a starlabel-at-end label yet, convert it */
    if(*(js->string + counter) == '\0') {
        *(js->string + counter) = '_';
        if(js_adduint16(js,rtype) == JS_ERROR) {
            return JS_ERROR;
            }
        return 130;
        }

    /* Otherwise, lop off the last label */
    length = 0;
    toread = *(js->string);
    counter = 0;
    while(length < 256 && toread > 0 && toread != '_') {
        ret++;
        if(toread > 63)
            return JS_ERROR; /* No EDNS nor compressed label support */
        length += toread + 1;
        /* Go to the next jump */
        if(length > js->unit_count || length >= js->max_count)
            return JS_ERROR;
        counter = toread;
        toread = *(js->string + length);
        }
    if(length >= 256) {
        return JS_ERROR;
        }

    counter++;
    if(counter > js->unit_count || counter > length) {
        return JS_ERROR;
        }

    js->unit_count -= counter;
    if(js->unit_count < 1) {
        return JS_ERROR;
        }
    *(js->string + js->unit_count - 1) = '_';

    if(js_adduint16(js,rtype) == JS_ERROR) {
            return JS_ERROR;
        }
    return ret;

    }

/* Given a query, a record type to query, and whether we have
 * already found a record in question, do an ANY lookup for
 * the query in question
 *
 * Note: This is only called from udpany, and only when using the
 *       old ANY handling code (still used by the recursive resolver);
 *       this particular routine can probably be sucessfully pruned at
 *       this point.
 */

int starwhitis_seek_any(js_string *query, int rr_type, int found,
                q_header *head, rr **w, int *a,
                js_string *most, js_string *ns, js_string *ar) {
        js_string *star; /* Star-record converted query */
        mhash_e spot_data;
        int this_rr_found = 0;
        if(found == JS_ERROR) {
                return JS_ERROR;
        }
        if((star = js_create(256,1)) == 0) {
                return JS_ERROR;
        }
        /* Change the query type for the star record */
        if(change_rtype(query,rr_type) == JS_ERROR) {
                js_destroy(star);
                return JS_ERROR;
        }
        /* Copy the query over */
        if(js_copy(query,star) == JS_ERROR) {
                js_destroy(star);
                return JS_ERROR;
        }
        if(make_starlabel(star) == JS_ERROR) {
                js_destroy(star);
                return JS_ERROR;
        }
        /* Look for a record with the same name as the query */
        while(this_rr_found == 0) {
                spot_data = mhash_get(bighash,star);
                /* If found, add the data to our records */
                if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
                        /* If we have already found other records, there
                         * is no need to add NS records to the authority
                         * section of the answer, nor to determine whether
                         * the record should be marked "authoritative" in the
                         * DNS header */
                        if(found == 1) {
                                this_rr_found = 1;
                                if(add_answer(spot_data.value,most,ns,ar,
                                      &(head->ancount), &(head->nscount),
                                      &(head->arcount),0,spot_data.point,
                                      query,0) == JS_ERROR) {
                                        js_destroy(star);
                                        return JS_ERROR;
                                }
                        /* If we have not already found a record, we
                         * use the NS records for the first record
                         * we find to determine what NS and AR
                         * records go in the authority section.
                         * We also use the "authority" bit in the
                         * first answer we find to set the
                         * AA bit in the DNS header */
                        } else {
                                this_rr_found = 1;
                                found = 1;
                                *w = (rr *)spot_data.value;
                                *a = (*w)->authoritative;
                                if(add_answer(spot_data.value,most,ns,ar,
                                        &(head->ancount),&(head->nscount),
                                        &(head->arcount),1,spot_data.point,
                                        query,0) == JS_ERROR) {
                                        js_destroy(star);
                                        return JS_ERROR;
                                }
                        }
                }
                if(bobbit_starlabel(star) <= 0)
                        break;
        }
        js_destroy(star);
        return found;
}

/* Convert a domain-name query in to its lower-case equivalent
   Input: Pointer to the js string object with the query
   Output: JS_ERROR on error, JS_SUCCESS on sucess, 0 on
           success if no change was made to the string */

int fold_case(js_string *js) {
    int counter = 0;
    int ret = 0;

    if(js->max_count <= js->unit_count) {
        return JS_ERROR;
        }
    if(js->unit_size != 1) {
        return JS_ERROR;
        }
    if(js->unit_count < 2) {
        return JS_ERROR;
        }
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

/* Check to see if the IP in question is a ddip (e.g.
   "<03>127<01>0<01>0<03>1<00>"), and, if so, convert it in to
   a bare A record
   input: Pointer to js_string object with the query
   output: JS_ERROR on fatal error, 0 on non-ddip query,
           JS_SUCCESS if it was a ddip
*/

int ddip_check(int id, int sock, conn *ect, js_string *query) {
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

    /* We presently only do ddip translation for A and ANY requests
       (DJB only supports this in Dnscache) */
    if(get_rtype(query) != RR_A && get_rtype(query) != RR_ANY)
        return 0;

    if(query->unit_count < 9) /* The minimum possible length for a
                                 ddip domain label */
        return 0;

    lenl = 0;
    for(counter=0;counter<4;counter++) {
        length = *(query->string + lenl);
        if(length < 1 || length > 3)
            return 0;
        critter = lenl + 1;
        lenl += length + 1;
        if(lenl > query->unit_count)
            return JS_ERROR;
        for(value = 0;critter < lenl;critter++) {
            val = *(query->string + critter);
            if(val > '9' || val < '0')
                return 0;
            value *= 10;
            value += val - '0';
            }
        if(value < 0 || value > 255)
            return 0;
        ip[counter] = value;
        }

    if(*(query->string + lenl) != 0)
        return 0;

    /* OK, it is definitely a ddip label.  Convert the ip in to a DNS reply */

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
    header.rd = 0; /* Recursion not desired */ /* RDBUG ddip_check */
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
    if(js_adduint32(reply,19770616) == JS_ERROR)
        goto cleanup;
    /* Add the rdlength to the answer */
    if(js_adduint16(reply,4) == JS_ERROR)
        goto cleanup;
    /* Add the actual 4-byte reply to the answer */
    for(counter = 0; counter < 4; counter++) {
        if(js_addbyte(reply,ip[counter]) == JS_ERROR)
            goto cleanup;
        }

    /* Send the reply out */
    mara_send(ect,sock,reply);

    /* And, we are done */
    js_destroy(reply);
    return JS_SUCCESS;

    /* We use gotos to work around C's lack of error trapping */
    cleanup:
        js_destroy(reply);
        return JS_ERROR;

    }

/* Determine if a given IP is on a given ipv4pair ACL
 * Input: The ip, the ACL list
 * Output: 0 if they do not have authority, 1 if they do
 */
int check_ipv4_acl(uint32 ip, ipv4pair *list) {
    int counter = 0, ret = 0;
    while(counter < 500 && (list[counter]).ip != 0xffffffff) {
        if((ip & (list[counter]).mask) ==
               ((list[counter]).ip & (list[counter]).mask)) {
            /* They are authorized */
            ret = 1;
            break;
            }
        counter++;
        }
    return ret;
}

/* Determine if a given IP has authority to perform recursive DNS lookups
   Input: IP of where they come from
   Ouput: 0 if they do not have authority, 1 if they do
   Global variables used: The recurse_acl array
*/

int check_recursive_acl(uint32 ip) {
    return check_ipv4_acl(ip,recurse_acl);
    }

/* Look for both the upper and lower case versions of a given query.
   Input: The query, and, to give to udpsuccess:
          The ID of this query
          The socket ID of this query
          Where this ID came from
          The original query (to echo in the question)
   Output: 0 on not found, JS_ERROR on error, JS_SUCCESS on success
 */

int hunt_single_query(js_string *query, int id, int sock,
                      conn *ect, js_string *question, int rd_val) {
    mhash_e spot_data;
    int qtype_o, qtype_q;
    /* js_string *lower; */

    qtype_o = get_rtype(question);
    qtype_q = get_rtype(query);

    if(qtype_o == JS_ERROR || qtype_q == JS_ERROR) {
        return JS_ERROR;
        }


    spot_data = mhash_get(bighash,query);
    /* If found, give back the response */
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
        if(qtype_o == RR_A || qtype_q == RR_CNAME) {
#ifdef AUTHONLY
            udpsuccess(spot_data.value,id,sock,0,question,
                       spot_data.point,1,rd_val,ect,force_auth,0);
#else
            udpsuccess(spot_data.value,id,sock,0,question,
                       spot_data.point,1,rd_val,ect,force_auth,rd_val);
#endif /* AUTHONLY */
            }
        else {
#ifdef AUTHONLY
            udpsuccess(spot_data.value,id,sock,0,question,
                       spot_data.point,0,rd_val,ect,force_auth,0);
#else
            udpsuccess(spot_data.value,id,sock,0,question,
                       spot_data.point,0,rd_val,ect,force_auth,rd_val);
#endif /* AUTHONLY */
             }
        return JS_SUCCESS;
        }

    /* Not found */
    return 0;
    }

/* Check to see if we have a collision that, when we anally follow
 * RFC1034 section 4.3.3, makes it so we stop looking for a star record
 * "above".  In other words, if there is a record b.example.com and a
 * record *.example.com, this makes sure a.b.example.com and
 * c.a.b.example.com do not resolve */
int star_collision(js_string *lookfor, mhash *bighash) {
        js_string *be_anal = 0;
        mhash_e spot_data;
        if(js_length(lookfor) < 2) {
            return 0;
            }
        be_anal = js_create(257,1);
        if(js_copy(lookfor,be_anal) == JS_ERROR) {
            js_destroy(be_anal);
            return JS_ERROR;
            }
        /* This is a very hackey way of removing the first character
         * from the string.  This works, but it's very important to
         * restore the string pointer to its previous position before
         * deallocating the string. */
        be_anal->string++;
        be_anal->unit_count--;
        if(change_rtype(be_anal,RR_ANY) == JS_ERROR) {
            be_anal->string--;
            js_destroy(be_anal);
            return JS_ERROR;
            }
        spot_data = mhash_get(bighash,be_anal);
        if(spot_data.value != 0 &&
              spot_data.datatype == MARA_DNS_LIST) {
            /* There is a RR phohibiting the star record.  Return
             * name error */
            be_anal->string--;
            js_destroy(be_anal);
            return 1;
            }
        be_anal->string--;
        js_destroy(be_anal);
        return 0;
}

/* Process the DNS query that comes in from the 'net
   Input: uncompressed form of incoming UDP query, IP address of where
          this query came from, socket number of this socket
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int proc_query(js_string *raw, conn *ect, int sock) {

    q_header header; /* Header of the question */
    js_string *lookfor = 0; /* What to look for in the big hash */
    js_string *origq = 0; /* Original query asked by the user */
    js_string *lc = 0; /* Lower-case version of query asked by the user */
    rr *nxstore = 0; /* A pointer to the SOA we return when we hit a
                        NXDOMAIN */
    /* int case_folded; */
    int length, result_code = 0, qtype;
#ifndef AUTHONLY
    int has_recursive_authority = 0;
#endif
    mhash_e spot_data;
    int have_authority = 0; /* Do we have authority for this record?
                               (must be 1 to return a NXDOMAIN) */
    rr *point = 0;
    uint32 ip;
    int desires_recursion = 0; /* Do they desire recursion? */
    char *num_string = 0; /* The string to put the number of thread running
                             in */
    unsigned int mem_usage; /* The amount of memory a maradns process has
                               allocated */
    struct sockaddr_in *z; /* Makes certain ugly declarations readable */
    int always_not_there = 0;
    int rd_val = 0;
    int not_impl_datatype = NOT_IMPLEMENTED;


    /* Sanity checks */
    if(js_has_sanity(raw) == JS_ERROR)
        return JS_SUCCESS;
    if(raw->unit_size != 1)
        return JS_SUCCESS;

    /* Get the header */
    if(read_hdr(raw,&header) == JS_ERROR) { /* Something went wrong,
                                               return error "Format error" */
        udperror(sock,raw,0,0,FORMAT_ERROR,"Couldn't get header",2,0,ect,1);
        return JS_SUCCESS;
        }

    /* See if they desire recursion or not */
    desires_recursion = rd_val = header.rd;

    /* We only answer questions (Thanks to Roy Arends for pointing out this
       security flaw) */
    if(header.qr != 0) {
        return JS_SUCCESS;
        }

    /* We only support a qdcount of 1 */
    if(header.qdcount != 1) {
        if(no_fingerprint != 1)
            udperror(sock,raw,0,0,NOT_IMPLEMENTED,"Qdcount not 1",2,
                            desires_recursion,ect,1);
        return JS_SUCCESS;
        }

    /* Get the question from the stream */
    if(raw->unit_count < 14) {
        if(no_fingerprint != 1)
            udperror(sock,raw,0,0,FORMAT_ERROR,"bad question hdr",2,
                            desires_recursion,ect,1);
        return JS_SUCCESS;
        }

    /* Determine the length of the domain label in the question */
    length = dlabel_length(raw,12);
    if(length < 0 || length > 255) {
        if(no_fingerprint != 1)
            udperror(sock,raw,0,0,FORMAT_ERROR,"bad question length",2,
                            desires_recursion,ect,1);
        return JS_SUCCESS;
        }

    if(raw->unit_count < 16 + length) { /* 16 because 12 for the header,
                                           and 4 for the type and class */
        if(no_fingerprint != 1)
            udperror(sock,raw,0,0,FORMAT_ERROR,"question doesn't fit",2,
                            desires_recursion,ect,1);
        return JS_SUCCESS;
        }

    /* Create the lookfor string, returning error if appropriate */
    if((lookfor = js_create(256,1)) == 0) {
        if(no_fingerprint != 1)
            udperror(sock,raw,0,0,SERVER_FAIL,
                     "can't create lookfor string",2,desires_recursion,ect,1);
        return JS_ERROR;
        }
    if((origq = js_create(256,1)) == 0) {
        udperror(sock,raw,0,0,SERVER_FAIL,"can't create origq string",2,
                        desires_recursion,ect,1);
        js_destroy(lookfor);
        return JS_ERROR;
        }

    /* Get the query we will look for from their raw query */
    if(js_substr(raw,lookfor,12,length + 2) == JS_ERROR) {
        goto serv_fail;
        }

    /* We only support an opcode of 0 (standard query)
       (this check is down here so we can echo the question) */
    if(header.opcode != 0) {
        /* Since TinyDNS also returns NOT_IMPLEMENTED here, no need for
           a fingerprint check. */
        udperror(sock,raw,0,lookfor,NOT_IMPLEMENTED,"non-0 opcode",2,
                        desires_recursion,ect,1);
        js_destroy(origq); js_destroy(lookfor);
        return JS_SUCCESS;
        }

    /* Return "not implemented" if the class is not 1 (Internet class) */
    /* Down here so we can echo the question */
    if(*(raw->string + length + 14) != 0 &&
       *(raw->string + length + 15) != 1) {
        if(no_fingerprint != 1) {
            udperror(sock,raw,0,lookfor,NOT_IMPLEMENTED,"Class not 1",2,
                            desires_recursion,ect,1);
            }
        js_destroy(origq); js_destroy(lookfor);
        return JS_ERROR;
        }

    /* Copy the original query over to the "original query" string */
    if(js_copy(lookfor,origq) == JS_ERROR) {
        goto serv_fail;
        }

    /* Convert the query in to lower-case, since DNS is case-insensitive
     * and any attempt to not make it so is buggy */
    fold_case(lookfor);

    /* Get the type of query the client desires */
    qtype = get_rtype(origq);
    if(qtype == JS_ERROR) {
        goto serv_fail;
        }

    /* We may reject AAAA queries */
    if(qtype == 28 && reject_aaaa != 0) {
            udpnotfound(ra_data,header.id,sock,0,origq,0,
                            desires_recursion,ect,2);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
    }

    /* We may reject PTR queries */
    if(qtype == RR_PTR && reject_ptr != 0) {
            udpnotfound(ra_data,header.id,sock,0,origq,0,
                            desires_recursion,ect,2);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
    }

    if(qtype == 253 || qtype == 254 || qtype == 250) { /* MAILB, MAILA, TSIG */
        goto not_impl;
        }

    if(qtype == 251 || qtype == 252) { /* IXFR, AXFR */
        not_impl_datatype = -111;
        goto not_impl;
        }

    /* Set 'ip' to have the ip they are using MaraDNS from */
    z = (struct sockaddr_in *)ect->d;
    ip = htonl((z->sin_addr).s_addr);

#ifndef AUTHONLY
    /* See if they have permission to perform a recursive query */
    has_recursive_authority = check_recursive_acl(ip);
    if(has_recursive_authority == JS_ERROR)
        goto serv_fail;
#endif

    /* We go straight to processing this as a recursive query at a
     * dos_protection_level of 78; this is the default value of
     * dos_protection_level if neither csv1 nor csv2 nor csv2_default_zonefile
     * is set */
    if(dos_protection_level == 78 ) {
            goto recursive_call;
    }
    /* When dos_protection_level is 79, the only authoritative-type thing we
     * do is report the version number of MaraDNS if they ask for it and have
     * the authority to get this information */
    if(dos_protection_level == 79) {
            goto report_version;
    }

    /* We don't process RR_ANY records if dos_protection_level is greater
     * than 13 */
    if(dos_protection_level > 13) {
            goto skip_rrany;
    }

    /* Handle the case of RR_ANY */
    if(qtype == RR_ANY) {
        result_code = udpany(header.id,sock,0,lookfor,rrany_set,bighash,
                        desires_recursion,ect,0,origq);
        if(result_code == JS_SUCCESS) {
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
            }
        else if(result_code == JS_ERROR)
            goto serv_fail;
        /* Otherwise, no RR_ANY information was found.  We will return,
           if appropriate, the expected "no such host" SOA reply or
           NS delegation reply.  Hack: Since there *should not* be
           any elements in the hash proper with "ANY" as the desired
           record type, we go ahead and perform the various normal
           searches. */
        }

skip_rrany:

    /* OK, start the complicated domain look up routine */
    /* Look for upper and lower case versions of the query as
       they asked it */
    if(hunt_single_query(lookfor,header.id,sock,ect,origq,rd_val) != 0) {
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

    /* If dos_protection_level is greater than seven, then we don't look up
     * CNAME records */
    if(dos_protection_level > 7) {
            goto skip_cname;
    }

    /* OK, if not found, maybe there is a CNAME with the same domain label */
    if(change_rtype(lookfor,RR_CNAME) == JS_ERROR) {
        goto serv_fail;
        }
    if(hunt_single_query(lookfor,header.id,sock,ect,origq,rd_val) != 0) {
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

skip_cname:

    /* If dos_protection_level is one or higher, we don't process
     * any of the messages one can get about MaraDNS */

    if(dos_protection_level > 0) {
            goto skip_easter_egg;
    }

    /* Franky's request to have "administrative IPs", finally implemented
     * after almost four years */

    if(check_ipv4_acl(ip,admin_acl) != 1) {
            goto skip_easter_egg;
    }


report_version:

        /* A TXT query to "version.maradns." will
           return the version of MaraDNS being run.  This only
           works if we are not authoritative for "maradns.org", since
           the real "erre-con-erre-cigarro.maradns.org" says
           "MaraDNS version number not available" in the TXT record.
           Note: This is disabled if no_fingerprint is 1 or if
           debug_msg_level is less than one */
        if(origq->unit_count == 19 && *(origq->string) == 7
           && no_fingerprint != 1 && debug_msg_level >= 1) {
            result_code = easter_egg(header.id,sock,ect,origq,
               "Tversion.maradns.",RR_TXT,"MaraDNS version ",
#ifdef VERSION
               VERSION
#else
               "Broken compile, VERSION not defined"
#endif /* VERSION */
            );
            if(result_code == JS_SUCCESS) {
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_SUCCESS;
                }
            if(result_code == JS_ERROR) {
                goto serv_fail;
                }
            }

    /* At dos_protection_level 79, the only authoritative-type thing we do
     * is let them see the version number of MaraDNS (see above) */
    if(dos_protection_level == 79 && debug_msg_level <= 1) {
            goto recursive_call;
    }

        /* A TXT query to "numthreads.maradns." tells us the number of
           threads that MaraDNS is running; this is only enabled if
           no_fingerprint is 0 and if debug_msg_level is 2 or greater
        */
#ifndef AUTHONLY
       if(origq->unit_count == 22 && *(origq->string) == 10
          && no_fingerprint != 1 && debug_msg_level >= 2) {
           /* Allocate a string to put the number of threads running in */
           if((num_string = js_alloc(32,1)) == 0) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_ERROR;
               }
           snprintf(num_string,10,"%d",how_many_threads());
           result_code = easter_egg(header.id,sock,ect,origq,
            "Tnumthreads.maradns.",RR_TXT,"Number threads running: ",
            num_string);
           js_dealloc(num_string);
           if(result_code == JS_SUCCESS) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_SUCCESS;
               }
           if(result_code == JS_ERROR) {
               goto serv_fail;
               }
           }
#endif /* AUTHONLY */

        /* A TXT query to "memusage.maradns." tells us the number of
           threads that MaraDNS is running; this is only enabled if
           no_fingerprint is 0 and if debug_msg_level is 2 or greater
        */
       if(origq->unit_count == 20 && *(origq->string) == 8
          && no_fingerprint != 1 && debug_msg_level >= 2) {
           /* Allocate a string to put the number of threads running in */
           mem_usage = js_tell_memory_allocated();
           if(mem_usage > 0) {
               if((num_string = js_alloc(32,1)) == 0) {
                   js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                   return JS_ERROR;
                   }
               snprintf(num_string,14,"%d",mem_usage);
               result_code = easter_egg(header.id,sock,ect,origq,
                "Tmemusage.maradns.",RR_TXT,"Memory usage, in bytes: ",
                num_string);
               js_dealloc(num_string);
               }
           else {
               result_code = easter_egg(header.id,sock,ect,origq,
                "Tmemusage.maradns.",RR_TXT,"Memory usage unknown; ",
                "try compiling with make debug (note that this will greatly"
                " slow down MaraDNS)");
               }
           if(result_code == JS_SUCCESS) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_SUCCESS;
               }
           if(result_code == JS_ERROR) {
               goto serv_fail;
               }
           }

        /* A TXT query to "timestamp.maradns." tells us the time
           on the system MaraDNS is running on; this is only enabled if
           no_fingerprint is 0 and if debug_msg_level is 2 or greater
        */
       if(origq->unit_count == 21 && *(origq->string) == 9
          && no_fingerprint != 1 && debug_msg_level >= 3) {
           qual_timestamp the_time;
           /* Allocate a string to put the number of threads running in */
           the_time = qual_get_time();
           if(the_time > 0) {
               if((num_string = js_alloc(32,1)) == 0) {
                   js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                   return JS_ERROR;
                   }
               if(sizeof(int) < 8 && the_time > 2147483647U) {
                   strncpy(num_string,"pastY2038",11);
                   }
               else {
                   snprintf(num_string,14,"%d",(int)the_time);
                   }
               result_code = easter_egg(header.id,sock,ect,origq,
                "Ttimestamp.maradns.",RR_TXT,"Timestamp: ",
                num_string);
               js_dealloc(num_string);
               }
           else {
               result_code = easter_egg(header.id,sock,ect,origq,
                "Tmemusage.maradns.",RR_TXT,"Memory usage unknown; ",
                "try compiling with make debug (note that this will greatly"
                " slow down MaraDNS)");
               }
           if(result_code == JS_SUCCESS) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_SUCCESS;
               }
           if(result_code == JS_ERROR) {
               goto serv_fail;
               }
           }

        /* A TXT query to "cache-elements.maradns." tells us the number of
           elements in the DNS cache; this is only enabled if
           no_fingerprint is 0 and if debug_msg_level is 2 or greater
        */
#ifndef AUTHONLY
       if(origq->unit_count == 26 && *(origq->string) == 14
          && no_fingerprint != 1 && debug_msg_level >= 2) {
           /* Allocate a string to put the number of threads running in */
           if((num_string = js_alloc(32,1)) == 0) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_ERROR;
               }
           snprintf(num_string,10,"%d",cache_elements());
           result_code = easter_egg(header.id,sock,ect,origq,
            "Tcache-elements.maradns.",RR_TXT,"Elements in DNS cache: ",
            num_string);
           js_dealloc(num_string);
           if(result_code == JS_SUCCESS) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_SUCCESS;
               }
           if(result_code == JS_ERROR) {
               goto serv_fail;
               }
           }
#endif /* AUTHONLY */

/* A TXT query to [0-9].verbose_level.maradns. (where [0-9] is a number
   between 0 and 9) sets the verbose_level to the number in question.
   This is only allowed if remote_admin is set to one */
       if(origq->unit_count == 27 && *(origq->string) == 1
          && no_fingerprint != 1 && remote_admin == 1) {
           int new_verbose_level;
           char *query_string;
           new_verbose_level = *(origq->string + 1) - '0';
           if(new_verbose_level < 0 || new_verbose_level > 9) {
               goto skip_easter_egg;
               }
           /* Allocate a string to put the verbose_level in */
           if((num_string = js_alloc(4,1)) == 0) {
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_ERROR;
               }
           *num_string = new_verbose_level + '0';
           *(num_string + 1) = 0;
           if((query_string = js_alloc(37,1)) == 0) {
               js_dealloc(num_string);
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_ERROR;
               }
           if(strncpy(query_string,"T0.verbose_level.maradns.",29) == 0) {
               js_dealloc(query_string);
               js_dealloc(num_string);
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_ERROR;
               }
           *(query_string + 1) = '0' + new_verbose_level;
           result_code = easter_egg(header.id,sock,ect,origq,
            query_string,RR_TXT,"Verbose level is now ",num_string);
           js_dealloc(num_string);
           js_dealloc(query_string);
           if(result_code == JS_SUCCESS) {
               log_level = new_verbose_level;
               log_lock();
               printf("Verbose_level remotely set to %d\n",new_verbose_level);
               log_unlock();
#ifndef AUTHONLY
               init_rlog_level(new_verbose_level);
#endif
               js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
               return JS_SUCCESS;
               }
           if(result_code == JS_ERROR) {
               goto serv_fail;
               }
           }

skip_easter_egg:

    /* If dos_protection_level is greater than 11, then we don't
     * look for delegation NS records */
    if(dos_protection_level > 11) {
        goto skip_delegation_ns;
    }

    /* OK, if not found, maybe there is a *nonauthoritative* NS record with
       the same domain label */
    if(change_rtype(lookfor,RR_NS) == JS_ERROR) {
        goto serv_fail;
        }

    spot_data = mhash_get(bighash,lookfor);
    point = spot_data.value;
    /* If the non-authoritative NS was found, return the NS infomation */
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR &&
       point->authoritative == 0) {
        /* It is possible, but unlikely, they want recursion */
#ifndef AUTHONLY
        if(recurse_delegation == 1 && desires_recursion == 1 &&
           has_recursive_authority == 1) {
                /* Recursion only works for IPV4 */
                if(ect->type != 4) {
                        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                        return JS_ERROR;
                }
                /* Launch the thread that will process the request; we
                 * copy ect->d over */
                z = (struct sockaddr_in *)ect->d;
                launch_thread(header.id,sock,*z,origq);
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_SUCCESS;
                }
#endif
        /* We return a NS server delegation */
        udpsuccess(spot_data.value,header.id,sock,0,origq,spot_data.point,
                        0,desires_recursion,ect,0,0);
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

    /* See if it is a dotted-decimal IP */
    if(no_fingerprint != 1) {
        result_code = ddip_check(header.id,sock,ect,origq);
        if(result_code == JS_SUCCESS) {
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
            }
        if(result_code == JS_ERROR) {
            goto serv_fail;
            }
        }

    /* Look for a NS record at the same level or above.  E.G., if they
       ask for somthing.below.sub.example.com. and we have knowledge
       that sub.example.com is a NS record, act as appropriate.  Send
       them the NS record -or- go recursive if the NS record is
       non-authoritative (we're not handling the zone), otherwise return
       a "host not there" if the NS record is authoritative
     */

    nxstore = NULL;

    if(
#ifndef AUTHONLY
       has_recursive_authority != 1 ||
#endif
       desires_recursion != 1 || recurse_delegation != 1) {
      do {
        spot_data = mhash_get(bighash,lookfor);
        point = spot_data.value;
        /* We stop going up the tree if we have found an authoritative NS
           record */
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR &&
           point->authoritative != 0) {
            have_authority = 1;
            /* Look for a SOA record of the same type to prepare for
               a NXDOMAIN reply */
            if(change_rtype(lookfor,RR_SOA) == JS_ERROR) {
                goto serv_fail;
                }
            spot_data = mhash_get(bighash,lookfor);
            if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
                nxstore = spot_data.value;
                }
            break;
            }
        /* Return the NS record we found "up the tree", if appropriate */
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
            /* We return a NS server delegation */
            udpsuccess(spot_data.value,header.id,sock,0,origq,
                       spot_data.point,0,desires_recursion,ect,0,0);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
            }
        } while(bobbit_label(lookfor) > 0);
    }

skip_delegation_ns:

    /* Skip search for star levels at the beginning of hostnames if
     * dos_protection_level is greater than 17 */
    if(dos_protection_level > 17) {
            goto skip_starwhitis;
    }

    /* Remmy's issue: If we have any recordtype for a given record, we don't
     * look for a star record with the same name.  This emulates BIND's
     * behavior for star records and strictly follows RFC1034 section
     * 4.3.3 */
    if(bind_star_handling >= 1) {
        if(js_copy(origq,lookfor) == JS_ERROR)
            goto serv_fail;
        if(fold_case(lookfor) == JS_ERROR)
            goto serv_fail;
        /* Look for an ANY record with the same name and
           goto skip_starwhitis if found */
        if(change_rtype(lookfor,RR_ANY) == JS_ERROR) {
            goto serv_fail;
        }
        spot_data = mhash_get(bighash,lookfor);
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
            always_not_there = 4;
            goto skip_starwhitis;
            }
        }

    /* Maybe it is a star record they are looking for */

    /* We need to restore "lookfor" because we shredded both
       strings looking for a NS sub-delegation */
    if(js_copy(origq,lookfor) == JS_ERROR) {
        goto serv_fail;
        }
    if(fold_case(lookfor) == JS_ERROR) {
        goto serv_fail;
        }
    /* Convert lookfor in to a star label */
    if(make_starlabel(lookfor) == JS_ERROR) {
        goto serv_fail;
        }

    /* Look for the star record in the big hash */
    spot_data = mhash_get(bighash,lookfor);
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
        udpstar(spot_data.value,header.id,sock,0,origq,origq,
                        desires_recursion,0,ect);
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

    /* When bind_star_handling is set, we never incorrectly return a
     * NXDOMAIN if there is a star record with the given name */
    if(bind_star_handling >= 1) {
        int rtype_saver;
        rtype_saver = get_rtype(lookfor);
        if(change_rtype(lookfor,RR_ANY) == JS_ERROR) {
            goto serv_fail;
        }
        spot_data = mhash_get(bighash,lookfor);
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
            always_not_there = 4;
            }
        if(change_rtype(lookfor,rtype_saver) == JS_ERROR) {
            goto serv_fail;
            }
        }

    /* Anally strict RFC 1034 section 4.3.3 compliance.  If you
     * have b.example.com and *.example.com, a.b.example.com does
     * *not* match the star record */
    if(bind_star_handling == 2) {
        int r;
        r = star_collision(lookfor,bighash);
        if(r == -1) {
            goto serv_fail;
        } else if(r == 1) {
            udpnotfound(nxstore,header.id,sock,0,origq,0,desires_recursion,
                        ect,always_not_there);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
        }
    }

    /* OK, maybe there is a star record "above".  In other words,
       handle the case when they ask for foo.bar.example.com and we have
       a record for *.example.com */
    while(bobbit_starlabel(lookfor) > 0) {
        int rtype_saver = 1;

        if(bind_star_handling >= 1) {
            rtype_saver = get_rtype(lookfor);
        }
        spot_data = mhash_get(bighash,lookfor);
        point = spot_data.value;
        if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {

            /* We found the record */
            udpstar(spot_data.value,header.id,sock,0,origq,origq,
                            desires_recursion,0,ect);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
            }
        else {
            /* Make sure we don't incorrectly return a NXDOMAIN */
            if(bind_star_handling >= 1) {
                if(change_rtype(lookfor,RR_ANY) == JS_ERROR) {
                    goto serv_fail;
                }
                spot_data = mhash_get(bighash,lookfor);
                if(spot_data.value != 0 &&
                     spot_data.datatype == MARA_DNS_LIST) {
                    always_not_there = 4;
                } else

        /* If bind_star_handling is really high, look for any collision
         * that breaks RFC1034 section 4.3.3 compliance */
        if(bind_star_handling == 2) {
            int r;
            r = star_collision(lookfor,bighash);
            if(r == -1) {
                goto serv_fail;
            } else if(r == 1) {
                udpnotfound(nxstore,header.id,sock,0,origq,0,desires_recursion,
                        ect,(always_not_there & 3));
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_SUCCESS;
            }
          }

                if(change_rtype(lookfor,rtype_saver) == JS_ERROR) {
                    goto serv_fail;
                }
              }
            }


        }

    /* Perhaps they have a star record which points to a CNAME (yes,
       some people actually do this) */

    /* All CNAME lookups are disabled when the dos_protection_level
     * is greater then seven */
    if(dos_protection_level > 7) {
            goto skip_starwhitis;
    }

    /* We need to restore "lookfor" because, again, we shredded
       both strings looking for a star label that was not a CNAME */
    if(js_copy(origq,lookfor) == JS_ERROR)
        goto serv_fail;
    if(fold_case(lookfor) == JS_ERROR)
        goto serv_fail;
    /* First, we make it a star label */
    if(make_starlabel(lookfor) == JS_ERROR)
        goto serv_fail;
    /* Then we make it a CNAME rtype */
    if(change_rtype(lookfor,RR_CNAME) == JS_ERROR)
        goto serv_fail;

    /* Look for the star CNAME record in the big hash */
    spot_data = mhash_get(bighash,lookfor);
    if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
        /* We have to make a form of origq that is a cname */
        if(js_copy(origq,lookfor) == JS_ERROR)
            goto serv_fail;
        if(change_rtype(lookfor,RR_CNAME) == JS_ERROR)
            goto serv_fail;
        udpstar(spot_data.value,header.id,sock,0,origq,lookfor,
                        desires_recursion,0,ect);
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

    /* Look for a star record "above" when it is a CNAME */
    while(bobbit_starlabel(lookfor) > 0) {
        spot_data = mhash_get(bighash,lookfor);

        /* Optional strict RFC1034 section 4.3.3 compliance */
        if(bind_star_handling >= 1) {
            int rtype_saver;
            rtype_saver = get_rtype(lookfor);
            if(change_rtype(lookfor,RR_ANY) == JS_ERROR) {
                goto serv_fail;
            }
            spot_data = mhash_get(bighash,lookfor);
            if(spot_data.value != 0 &&
                 spot_data.datatype == MARA_DNS_LIST) {
                goto skip_starwhitis;
            }
            if(change_rtype(lookfor,rtype_saver) == JS_ERROR) {
                goto serv_fail;
            }
        }

        if(spot_data.value != 0 && spot_data.datatype == MARA_DNSRR) {
            if(js_copy(origq,lookfor) == JS_ERROR)
                goto serv_fail;
            if(change_rtype(lookfor,RR_CNAME) == JS_ERROR)
                goto serv_fail;
            udpstar(spot_data.value,header.id,sock,0,origq,lookfor,
                            desires_recursion,0,ect);
            js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
            return JS_SUCCESS;
            }
        }

    /* Perhaps they have something which ends in a star record;
       look for it.  starwhitis_end */

skip_starwhitis:

    /* If they have enabled stars at the end of hostnames */
    if(default_zonefile_enabled == 1) {
        int labels;
        /* Again, restore the original query */
        if(js_copy(origq,lookfor) == JS_ERROR)
            goto serv_fail;
        /* Now, start lopping off the dlabels from the *end* of the hostname */
        while((labels = bobbit_starlabel_end(lookfor)) > 0) {
            /* I like to know just how many labels we really have;
             * this will not break any real-world use (It only breaks
             * cases where they ask for "www.example.com" and we have
             * "www.example.com.*"; this will also break cases like
             * "a.b.c.d.e.[...].y.z.[...].a.b.c.d[...and so on...].z. Where
             * the domain name was very long with very short labels.  Again,
             * not in the real world ) */
            int store_rtype;
            if(labels > 120)
                    continue;
            spot_data = mhash_get(bighash,lookfor);
            point = spot_data.value;
            if(point != 0 && spot_data.datatype == MARA_DNSRR) {
                udpstar(point,header.id,sock,0,origq,origq,
                                desires_recursion,labels,ect);
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_SUCCESS;
                }

            /* If we failed, see if we return "not there" or NXDOMAIN */
            store_rtype = get_rtype(lookfor);
            if(store_rtype == JS_ERROR) {
                goto serv_fail;
                }
            if(change_rtype(lookfor,RR_ANY) == JS_ERROR) {
                goto serv_fail;
                }
            spot_data = mhash_get(bighash,lookfor);
            if(change_rtype(lookfor,store_rtype) == JS_ERROR) {
                goto serv_fail;
                }
            if(spot_data.value != 0 && spot_data.datatype == MARA_DNS_LIST) {
                always_not_there = 4;
                }

            }
        /* OK, if we didn't find anything, give out a
         * NXDOMAIN or "Not there" reply. */

        /* Find the SOA record for the default zonefile */
        if(change_rtype(lookfor,RR_SOA) == JS_ERROR) {
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_ERROR;
                }
        spot_data = mhash_get(bighash,lookfor);
        point = spot_data.value;
        if(point == 0 || spot_data.datatype != MARA_DNSRR) {
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_ERROR;
                }
        udpnotfound(point,header.id,sock,0,origq,0,desires_recursion,ect,
                    always_not_there);
        js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
        return JS_SUCCESS;
        }

recursive_call:

    /* If we do not have authority for this record... */
    if(have_authority == 0 && default_zonefile_enabled != 1) {
        /* Ask other DNS servers for RRs which we do not have authoity
           for.  */

        /* Launch a separate thread to recursivly determine the
           host name in question */
#ifndef AUTHONLY
        if(has_recursive_authority == 1 && desires_recursion == 1) {
            /* Recursion only works for IPV4 */
            if(ect->type != 4) {
                js_destroy(lookfor); js_destroy(origq); js_destroy(lc);
                return JS_ERROR;
                }
            /* Launch the thread that will process the request; we
             * copy ect->d over */
            z = ect->d;
            launch_thread(header.id,sock,*z,origq);
            }
        else
#endif
            udperror(sock,raw,0,0,REFUSED,
            "I'm sorry Dave (recurse attempt)",3,desires_recursion,ect,1);
        js_destroy(lookfor);
        js_destroy(origq);
        js_destroy(lc);
        return JS_SUCCESS;
        }

    /* Currently, MaraDNS will not support star records for NS
       subdelegation.  Code in ParseCsv1.c warns the user of this fact. */

    udpnotfound(nxstore,header.id,sock,0,origq,0,desires_recursion,ect,
                always_not_there);
    js_destroy(lookfor); js_destroy(origq); js_destroy(lc);

    return JS_SUCCESS;

    /* Work around C's lack of error handling and garbage collection with
       gotos */
    serv_fail:
        js_destroy(origq);
        if(lc != 0) {
            js_destroy(lc);
            }
        if(no_fingerprint != 1)
            udperror(sock,raw,0,lookfor,SERVER_FAIL,
                     "serv_fail in proc_query",2,desires_recursion,ect,1);
        js_destroy(lookfor);
        return JS_ERROR;

    not_impl:
        js_destroy(origq);
        js_destroy(lc);
        if(no_fingerprint != 1)
            udperror(sock,raw,0,lookfor,not_impl_datatype,
                     "not_impl in proc_query",2,desires_recursion,ect,1);
        js_destroy(lookfor);
        return JS_ERROR;

    }

/* Bind to IPV4 UDP port 53. (or DNS_PORT if debugging MaraDNS on a
                              system where I do not have root, and
                              theirfore can not bind to a low port number)

   Input:  pointer to socket to bind on, js_string with the dotted-decimal
           ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udp_ipv4_bind(int *sockets, ipv4pair *addresses) {
    int len_inet; /* Length */
    struct sockaddr_in dns_udp;
    int counter;

    /* Sanity checks */
    if(sockets == 0)
        return JS_ERROR;

    counter = 0;

    /* Create a socket address to use with bind() */
    while(counter < 500 && addresses[counter].ip != 0xffffffff) {
        /* Create a raw UDP socket */
        if((sockets[counter] = socket(AF_INET,SOCK_DGRAM,0)) == -1) {
            return JS_ERROR;
            }

        memset(&dns_udp,0,sizeof(dns_udp));
        dns_udp.sin_family = AF_INET;
        /* DNS_PORT is usually 53, but can be another port.  Defined in
           MaraDNS.h */
        dns_udp.sin_port = htons(dns_port);
        if((dns_udp.sin_addr.s_addr = htonl(addresses[counter].ip))
           == INADDR_NONE)
            return JS_ERROR;

        len_inet = sizeof(dns_udp);

        /* Bind to the socket.  Note that we usually have to be root to
           do this */
        if(bind(sockets[counter],(struct sockaddr *)&dns_udp,len_inet) == -1)
            return JS_ERROR;

        counter++;
        }

    /* We are now bound to UDP port 53. (Or whatever DNS_PORT is) Leave */
    return JS_SUCCESS;
    }

/* We don't allow both recursive and ipv6 support, since the recursive
 * resolver is ipv4-only */

#ifdef IPV6
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
/* Bind to IPV6 UDP port 53. (or DNS_PORT if debugging MaraDNS on a system
                         where I do not have root, and theirfore can not
                         bind to a low port number)
   Input:  pointer to socket to bind on, js_string with the dotted-decimal
           ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udp_ipv6_bind(int *sock, int splace, js_string *ipv6_address) {
    int len_inet; /* Length */
    struct sockaddr_in6 dns_udp;
    int counter;
    char ascii_ipv6[128];

    if(js_js2str(ipv6_address,ascii_ipv6,100) == JS_ERROR) {
            return JS_ERROR;
    }
    if(splace >= 501) {
            return JS_ERROR;
    }

    /* Sanity checks */
    if(sock == 0)
        return JS_ERROR;

    counter = 0;

    if((sock[splace] = socket(AF_INET6,SOCK_DGRAM,0)) == -1) {
            return JS_ERROR;
            }

    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin6_family = AF_INET6;
    /* DNS_PORT is usually 53, but can be another port.  Defined in
       MaraDNS.h */
    dns_udp.sin6_port = htons(dns_port);
    inet_pton(AF_INET6,ascii_ipv6,&(dns_udp.sin6_addr));

   /* if((dns_udp.sin6_addr = htonl(addresses[counter].ip))
         == INADDR_NONE)
            return JS_ERROR; */

    len_inet = sizeof(dns_udp);

    /* Bind to the socket.  Note that we usually have to be root to
       do this */
    if(bind(sock[splace],(struct sockaddr *)&dns_udp,len_inet) == -1)
            return JS_ERROR;

    /* We are now bound to UDP port 53. (Or whatever DNS_PORT is) Leave */
    return JS_SUCCESS;
    }
#endif /* __CYGWIN__ */
#endif /* IPV6 */

/* Return a list of addresses we are bound to
 * Input: None
 * Output: bind_addresses */
ipv4pair *get_bind_addr_list() {
        return bind_addresses;
}

/* Return a list of addresses to synthesize for people who want different
 * synthetic NS IPs than the IPs MaraDNS is bound to; this will return
 * the bind_address list if the synthip list is not set */
ipv4pair *get_synthip_list() {
        if(csv2_synthip_list[0].ip == 0xffffffff) {
                return bind_addresses;
        }
        return csv2_synthip_list;
}

/* Get information from a previously binded UDP socket
   Input:  list of UDP bound sockets, list of addresses we are bound to,
           pointer to sockaddr structure that will contain
           the IP of the system connecting to us, pointer to js_string
           object that will have the data in question, maximum allowed
           length of data we receive
   Output: JS_ERROR on error, socket we got packet from on success
*/

int getudp(int *sock,ipv4pair *addr,conn *ect,
           js_string *data, int max_len, int have_ipv6_address) {
    int len_inet, counter, len;
    fd_set rx_fd;
    int select_output;
    int max_socket;
    struct timeval timeout;
    struct sockaddr_in *ipv4_client;
#ifdef IPV6
/* Cugwin doesn't support ipv6 yet */
#ifndef __CYGWIN__
    struct sockaddr_in6 *ipv6_client;
#endif /* __CYGWIN__ */
#endif

    /* Sanity checks */
    if(ect == 0 || data == 0)
        return JS_ERROR;
    if(js_has_sanity(data) == JS_ERROR)
        return JS_ERROR;
    if(data->unit_size != 1)
        return JS_ERROR;
    if(max_len < 0 || max_len >= data->max_count)
        return JS_ERROR;

    FD_ZERO(&rx_fd);
    counter = 0;
    max_socket = 0;
    while(counter < 500 && addr[counter].ip != 0xffffffff) {
        FD_SET(sock[counter],&rx_fd);
        if((sock[counter] + 1) > max_socket) {
            max_socket = sock[counter] + 1;
            }
        counter++;
        }
#ifdef IPV6
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
    if(have_ipv6_address == 1) {
        FD_SET(sock[counter],&rx_fd);
        if((sock[counter] + 1) > max_socket) {
            max_socket = sock[counter] + 1;
            }
        }
#endif /* __CYGWIN__ */
#endif
    if(max_socket == 0) /* No sockets */ {
        return JS_ERROR;
        }

    timeout.tv_sec = 1; /* Check for HUP signal every second */
    timeout.tv_usec = 0;

    /* OK, wait for activity on any of those sockets */
    select_output = select(max_socket,&rx_fd,NULL,NULL,&timeout);

    if(select_output <= 0) { /* 0: Timeout; less than 0: error */
        return JS_ERROR;
        }

    /* Figure out which socket gave us something */
    counter = 0;
    while(counter < 500 && addr[counter].ip != 0xffffffff) {
        if(FD_ISSET(sock[counter],&rx_fd)) {
            len_inet = sizeof(struct sockaddr_in);
            ect->addrlen = len_inet;

            ipv4_client = js_alloc(1,sizeof(struct sockaddr_in));
            if(ipv4_client == 0)
                    return JS_ERROR;

#ifdef SELECT_PROBLEM
            fcntl(sock[counter], F_SETFL, O_NONBLOCK);
#endif
            len = recvfrom(sock[counter],data->string,max_len,0,
                           (struct sockaddr *)ipv4_client,
                           (socklen_t *)&(ect->addrlen));
            if(len < 0) {
                js_dealloc(ipv4_client);
                return JS_ERROR;
                }
            ect->type = 4;
            ect->d = ipv4_client;

            data->unit_count = len;

            return sock[counter];
            }
        counter++;
        }
#ifdef IPV6
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
    if(have_ipv6_address == 1) {
        if(FD_ISSET(sock[counter],&rx_fd)) {
            socklen_t stupid_gcc_warning; /* To get rid of gcc warning */
            len_inet = sizeof(struct sockaddr_in6);
            ect->addrlen = len_inet;
            ipv6_client = js_alloc(1,sizeof(struct sockaddr_in6));
            if(ipv6_client == 0)
                    return JS_ERROR;

#ifdef SELECT_PROBLEM
            fcntl(sock[counter], F_SETFL, O_NONBLOCK);
#endif
            stupid_gcc_warning = ect->addrlen;
            len = recvfrom(sock[counter],data->string,max_len,0,
                           (struct sockaddr *)ipv6_client,
                           &stupid_gcc_warning);
            ect->addrlen = stupid_gcc_warning;

            if(len < 0) {
                js_dealloc(ipv6_client);
                return JS_ERROR;
                }

            ect->type = 6;
            ect->d = ipv6_client;

            data->unit_count = len;

            return sock[counter];
            }
        }
#endif /* __CYGWIN__ */
#endif /* IPV6 */

    /* "JS_ERROR" means "nobody talked to us in the last second" */
    ect->type = 0;
    ect->d = 0;
    return JS_ERROR;

    }

/* Function that initialized the ra_data (bogus reply to send if MaraDNS
 * is set up to reject aaaa or ptr queries, and the DNS client sends a
 * aaaa/ptr query */

rr *init_ra_data() {
        js_string *rq; /* Query */
        js_string *rv; /* Value */
        rr *lra_data;
        /* Allocate memory */
        rq = js_create(256,1);
        rv = js_create(256,1);
        if(rq == 0 || rv == 0) {
                harderror("reject_aaaa error 1");
        }
        if((lra_data = js_alloc(1,sizeof(rr))) == 0) {
                harderror("reject_aaaa error 2");
        }

        /* Clear out all of ra_data fields */
        init_rr(lra_data);
        /* The following porbably isn't necessary */
        lra_data->expire = lra_data->ttl = lra_data->authoritative = 0;
        lra_data->rr_type = 0; lra_data->next = lra_data->ip = 0;
        lra_data->query = lra_data->data = 0; lra_data->seen = 0;
        lra_data->zap = 0; lra_data->ptr = 0;

        /* Set up query ("." type SOA) */
        js_addbyte(rq,0);
        js_adduint16(rq,RR_SOA);

        /* Set up value (SOA: It ain't there) */
        /* SOA field 1: SOA origin (make '.') */
        js_addbyte(rv,0);
        /* SOA field 2: SOA Mname (email address of person in charge; make
         * 'm@m.m') */
        js_addbyte(rv,1); js_addbyte(rv,'m'); /* m@ ... */
        js_addbyte(rv,1); js_addbyte(rv,'m'); /* ... m. ... */
        js_addbyte(rv,1); js_addbyte(rv,'m'); /* ... m ... */
        js_addbyte(rv,0); /* Final 'dot' */
        /* SOA field 3: Serial (make 1) */
        js_adduint16(rv,0); js_adduint16(rv,1);
        /* SOA field 4: Refresh (make 60) */
        js_adduint16(rv,0); js_adduint16(rv,60);
        /* SOA field 5: Retry (make 60) */
        js_adduint16(rv,0); js_adduint16(rv,60);
        /* SOA field 6: Expire (make 60) */
        js_adduint16(rv,0); js_adduint16(rv,60);
        /* SOA field 7: TTL (make 60) */
        js_adduint16(rv,0); js_adduint16(rv,60);

        /* OK, strings set up; add to ra_data */
        lra_data->expire = 0;
        lra_data->ttl = 60;
        lra_data->authoritative = 1;
        lra_data->rr_type = RR_SOA;
        lra_data->data = rv;
        lra_data->query = rq;
        return lra_data;
}

/* The core of the DNS server */

int main(int argc, char **argv) {

    js_string *mararc_loc = 0, *errors = 0,
              *bind_address = 0, *ipv6_bind_address = 0,
              *csv2_synthip_address = 0,
              *ipv4_bind_address = 0, *incoming = 0,
              *uncomp = 0, *verbstr = 0;
#ifndef MINGW32
    unsigned char chroot_zt[255];
#ifndef __CYGWIN__
    uid_t uid;
#endif
    gid_t gid;
#endif
    int errorn, value, maxprocs, counter;
    int sock[514];
    int cache_size;
    int timestamp_type = 5; /* Type of timestamp */
#ifndef AUTHONLY
    int min_ttl_n = 300;
    int min_ttl_c = 300;
    int verbose_query = 0;
    int max_glueless; /* Maximum allowed glueless level */
    int max_q_total; /* Maximum total queries in attempt to resolve hostname */
    int timeout; /* Maximum time to wait for a remote server when performing
                    a recursive query */
    int handle_noreply = 1; /* How tohandle a recursive query when you don't
                             * get a remote reply at all */
    int retry_cycles = 2; /* Number of times to try and contact all of the
                           * name servers for a given domain */
    int thread_overhead = THREAD_OVERHEAD; /* The amount of memory we need
                                            * to allow to be allocated for
                                            * threads */
#else
    int thread_overhead = 0; /* No memory needed for threads */
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
#ifdef IPV6
    struct sockaddr_in6 *clin6;
#endif
#endif /* __CYGWIN__ */
#endif
    struct sockaddr client;
    struct sockaddr_in *clin = 0; /* So we can log the IP */
#ifndef MINGW32
    struct rlimit rlim;
#endif /* MINGW32 */
    int have_ipv6_address = 0;
    int default_dos_level = 78; /* 78: Recursive-only; 0: default when
                                 * there is one or more zonefiles */

#ifdef MINGW32
    /* Windows-specific initialization of socket */
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2,2);
    WSAStartup( wVersionRequested, &wsaData);
#endif /* MINGW32 */

#ifndef AUTHONLY
    int recurse_min_bind_port = 15000;
    int recurse_number_ports = 4096;
#endif

    /* First order of business: Initialize the hash */
    if(mhash_set_add_constant(
#ifdef MINGW32
        "secret.txt"
#else
        "/dev/urandom"
#endif
                ) != 1) {
        printf(
#ifdef MINGW32
        "Fatal error opening secret.txt"
#else
        "Fatal error opening /dev/urandom"
#endif
                        );
                        return 32;
        }

    memset(&client,0,sizeof(client)); /* Initialize ya variables */
    clin = (struct sockaddr_in *)&client;
#ifdef AUTHONLY
/* Cygwin doesn't have ipv6 yet */
#ifndef __CYGWIN__
#ifdef IPV6
    clin6 = (struct sockaddr_in6 *)&client;
#endif
#endif /* __CYGWIN__ */
#endif

    /* Initialize the strings (allocate memory for them, etc.) */
    if((mararc_loc = js_create(256,1)) == 0)
        harderror(L_MLC); /* "Could not create mararc_loc string" */
    if(js_set_encode(mararc_loc,MARA_LOCALE) == JS_ERROR)
        harderror(L_MLL); /* "Could not set locale for mararc_loc string" */

    if((errors = js_create(256,1)) == 0)
        harderror(L_EC); /* "Could not create errors string" */
    if(js_set_encode(errors,MARA_LOCALE) == JS_ERROR)
        harderror(L_EL); /* "Could not set locale for errors string" */

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
    else if(argc==2) { /* maradns -v or maradns --version */
        printf("%s %s\n%s %s\n%s\n",L_THISIS,VERSION,L_COMPILED,
               COMPILED,L_RTFM); /* "This is MaraDNS version blah blah blah */
        exit(0);
        }
    else if(argc==3) { /* maradns -f /wherever/mararc */
        if(js_qstr2js(mararc_loc,argv[2]) == JS_ERROR)
            harderror(L_MARARC_ARG); /* "Could not get mararc from command line" */
        }
    else
        harderror(L_USAGE); /* "Usage: maradns [-f mararc_location]" */

    /* Then parse that file */
    if(read_mararc(mararc_loc,errors,&errorn) == JS_ERROR) {
        harderror(L_MARARC_PARSE); /* "Error parsing contents of mararc file" */
        }
    js_destroy(mararc_loc);
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
    verbstr = read_string_kvar("hide_disclaimer");
    if(verbstr == 0 || js_length(verbstr) != 3) {
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
    js_destroy(verbstr);
    verbstr = 0;
    /* Get in to a state of least privledge ASAP */

    /* Limit the maximum number of processes */
    maxprocs = read_numeric_kvar("maxprocs",64);
    if(maxprocs == 0) {
        maxprocs = 64;
        }

    if(maxprocs > 5000) {
        maxprocs = 5000;
        mlog(L_MAXPROC_MAX); /* "Maxprocs can not be greater than 5000" */
        }
#ifndef MINGW32
#ifndef DARWIN
    rlim.rlim_cur = rlim.rlim_max = maxprocs;

    /* If this OS supports setrlimit and if setrlimit fails, bail (the ENOSYS
       check is there so OSes w/o setrlimit support can still run MaraDNS) */
#ifdef RLIMIT_NPROC
    if(setrlimit(RLIMIT_NPROC,&rlim) != 0 && errno != ENOSYS)
        sys_harderror(L_MAXPROC_SET); /* "Unable to set maximum number of processes" */
#endif /* RLIMIT_NPROC */
#endif /* DARWIN */
#endif /* MINGW32 */

    /* Determine how many elements the cache can have */
    cache_size = read_numeric_kvar("maximum_cache_elements",1024);
    if(cache_size < 32 || cache_size > 268435455) /* 2^28 - 1 */ {
        mlog(L_INVALID_CACHESIZE);
        cache_size = 1024;
        }

    /* Determine the level of error reporting */
    log_level = read_numeric_kvar("verbose_level",1);
#ifndef AUTHONLY
    init_rlog_level(log_level);
#endif

    /* If they want a synthetic IP given when the recursive resolver would
     * otherwise give a SOA "not there" record (or when it's impossible to
     * contact an upstream_server if handle_noreply is appropriately set),
     * prepare most of the synthetic answer we will give them. */
    verbstr = read_string_kvar("notthere_ip");
    if(verbstr != 0) {
        notthere_ip = make_notthere_ip(verbstr);
        js_destroy(verbstr);
    }
    verbstr = 0;

    /* Determine if we will handle star records the way BIND does:
       . If a non-A record for foo.example.com exists
       . And an A record for *.example.com exists
       . And the user asks for the A record for "foo.example.com"
       . Return "not there" instead of the A record attached to "*.example.com"

     If this is 0, we return the A record attached to "*.example.com"
     If this is 1, we return "not there" (since at least one RR for
     foo.example.com exists)
     If this is any other value, exit with a fatal error
     */
     bind_star_handling = read_numeric_kvar("bind_star_handling",1);
     if(bind_star_handling < 0 || bind_star_handling > 2) {
         harderror("bind_star_handling must have a value of 0, 1, or 2");
     }

     /* remote_admin: Whether we allow remote administration.  Currently,
        the only remote administration allowed is to change the
        verbose_level while MaraDNS is running.  I am allowing this
        under limited circumstances (your IP *must* be on the
        admin_acl list for this to work) because this will help
        debug some wonkeyness which happens when MaraDNS is very heavily
        loaded (1200 queries a second in large datacenters).  I personally
        think the wonkeyness is because the underlying kernel is overloaded,
        but this will allow more comprehensive debugging */
     remote_admin = read_numeric_kvar("remote_admin",0);
     if(remote_admin < 0 || remote_admin > 1) {
         harderror("remote_admin must have a value of 0 or 1");
     }

    /* Set the timestamp type */
    timestamp_type = read_numeric_kvar("timestamp_type",5);
    set_timestamp(timestamp_type);

    /* Get the minttl values from the kvar database (if there) */
#ifndef AUTHONLY
    min_ttl_n = read_numeric_kvar("min_ttl",300);
    min_ttl_c = read_numeric_kvar("min_ttl_cname",min_ttl_n);
#endif
    min_visible_ttl = read_numeric_kvar("min_visible_ttl",30);
    if(min_visible_ttl < 5)
        min_visible_ttl = 5;

#ifndef AUTHONLY
    handle_noreply = read_numeric_kvar("handle_noreply",1);
    if(handle_noreply < 0 || handle_noreply > 2) {
        harderror("handle_noreply must have a value between 0 and 2");
    }
    init_handle_noreply(handle_noreply);

    retry_cycles = read_numeric_kvar("retry_cycles",2);
    if(retry_cycles < 1 || retry_cycles > 31) {
        harderror("retry_cycles must have a value between 1 and 31");
        }
    init_retry_cycles(retry_cycles);

    recurse_min_bind_port = read_numeric_kvar("recurse_min_bind_port",15000);
    if(recurse_min_bind_port < 1024) {
        harderror("recurse_min_bind_port must have a minimum value of 1024");
    }
    recurse_number_ports = read_numeric_kvar("recurse_number_ports",4096);
    if(recurse_number_ports < 256 || recurse_number_ports > 32768) {
  harderror("recurse_number_ports must have a value between 256 and 32768");
        }
    /* I learned this trick during an interview at Google */
    if((recurse_number_ports & (recurse_number_ports - 1)) != 0) {
        harderror("recurse_number_ports must be a power of two");
    }
    if(recurse_min_bind_port + recurse_number_ports >= 65535) {
        harderror(
"recurse_min_bind_port + recurse_number_ports too large for 16-bit portnum");
        }
    set_port_range(recurse_min_bind_port,recurse_number_ports);
#endif /* AUTHONLY */

    /* Set the values */
#ifndef AUTHONLY
    set_min_ttl(min_ttl_n,min_ttl_c);
#endif

    /* Determine if we should make a "best faith" effort to have
       no MaraDNS-specific features */
    no_fingerprint = read_numeric_kvar("no_fingerprint",0);
    /* We may set up a bogus "not there" reply */
    reject_aaaa = read_numeric_kvar("reject_aaaa",0);
    reject_ptr = read_numeric_kvar("reject_ptr",0);
    if(reject_aaaa != 0 || reject_ptr != 0) {
            ra_data = init_ra_data();
    }

    /* Determine if we should return NS and SOA records when given a RR_ANY
       query */
    rrany_set = read_numeric_kvar("default_rrany_set",3);

    /* There are 3 user-customizable parameters which determine the maximum
       number of records we spit out for various chains of records */
    /* Maximum number of A records we show for a given host name in the
       additional section */
    max_ar_chain = read_numeric_kvar("max_ar_chain",1);
    /* Maximum number of records we show for any non-A chain in the answer
       or additional section */
    max_chain = read_numeric_kvar("max_chain",8);
    /* Maximum number of records we show total */
    max_total = read_numeric_kvar("max_total",20);
    /* Whether to supress dangling CNAME warnings */
    no_cname_warnings = read_numeric_kvar("no_cname_warnings",0);

#ifndef AUTHONLY
    verbose_query = read_numeric_kvar("verbose_query",0);
#endif

    /* Set the dns_port */
    dns_port = read_numeric_kvar("dns_port",53);
    if(dns_port < 1 || dns_port > 65530) {
        harderror("dns_port must be between 1 and 65530");
        exit(1);
    }

    /* Get the values for the synthetic SOA serial and the synthetic SOA
       origin (called MNAME in RFC1035) */
    synth_soa_serial = read_numeric_kvar("synth_soa_serial",1);
    if(synth_soa_serial < 1 || synth_soa_serial > 2) {
        harderror("Fatal: synth_soa_serial must be 1 or 2\n");
        }
#ifdef MINGW32
    /* Mingw32 doesn't have gmtime_r, so this has to puke.  Just ignore
     * that stupid dnsreport.com warning if you're using the win32 port */
    if(synth_soa_serial == 2) {
     harderror("Fatal: synth_soa_serial can not be 2 with the Windows port\n");
    }
#endif /* MINGW32 */

    verbstr = read_string_kvar("synth_soa_origin");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        synth_soa_origin = js_create(256,1);
        if(synth_soa_origin == 0) {
            harderror("Fatal: can not create synth_soa_origin string");
            }
        if(js_qstr2js(synth_soa_origin,"Z") != JS_SUCCESS) {
            harderror("Fatal: could not make synth_soa_origin string Z");
            }
        if(js_append(verbstr,synth_soa_origin) == JS_ERROR) {
            harderror("Fatal: could not append to synth_soa_origin string");
            }
        /* We should see if the origin already has a dot on the end */
        if(js_qappend(".",synth_soa_origin) == JS_ERROR) {
            harderror("Fatal: could not append final dot to soa_synth_origin");
            }
        /* Now we make that raw data */
        if(hname_2rfc1035(synth_soa_origin) <= 0) {
            harderror("Fatal: Malformed synth_soa_origin value.\n"
            "Please make sure that synth_soa_origin is a valid hostname\n"
            "*without* a dot at the end.  For example:\n\n"
            "\tsynth_soa_origin = \"example.com\"\n");
            }
        }


#ifdef AUTHONLY
    /* Determine the list of ipv4 ips that we send long packets to */
    for(counter = 0; counter < 511; counter++)
        long_packet[counter].ip = 0xffffffff;
    verbstr = read_string_kvar("long_packet_ipv4");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        if(make_ip_acl(verbstr,long_packet,500,0) == JS_ERROR)
            harderror("Could not make long packet list");
    }
    if(verbstr != 0) {
        js_destroy(verbstr);
        verbstr = 0;
    }
#endif

#ifndef AUTHONLY
    /* Determine what the ACL is for recursive queries */
    /* Initialize the ACL list */
    for(counter = 0; counter < 511; counter++)
        recurse_acl[counter].ip = 0xffffffff;
    /* Read in the ACL list from the mararc file */
    verbstr = read_string_kvar("recursive_acl");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        recursion_enabled = 1;
        /* If recursive ACL is set, then we set all the variables
           which use recursion */
        if(make_ip_acl(verbstr,recurse_acl,500,0) == JS_ERROR)
            harderror(L_ACL_LIST_RECURSE); /* "Could not make ip ACL list" */

        /* Determine what the maximum glueless level is */
        max_glueless = read_numeric_kvar("max_glueless_level",10);
        if(max_glueless == 0)
            harderror(L_INVALID_MAXGLUE); /* max_glueless_level needs to be a number, and be greater than zero */

        /* Determine the total numer of queries to perform in a recursive
           query */
        max_q_total = read_numeric_kvar("max_queries_total",32);
        if(max_q_total == 0)
            harderror(L_INVALID_MAXQTOTAL); /* max_queries_total needs to be a number, and be greater than zero */

        /* Determine the maximum time to wait for a remote server (in
           seconds) */
        timeout = read_numeric_kvar("timeout_seconds",2);
        if(timeout < 1)
            harderror(L_INVALID_TIMEOUT); /* timeout_seconds needs to be a number, and be greater than zero */

        /* Load the "seed" data in to the DNS cache */
        counter = init_cache(cache_size,maxprocs,max_glueless,max_q_total,
                             timeout,verbose_query);
        thread_overhead += maxprocs * PER_THREAD_MEM;
        if(counter < 0) {
            switch(counter) {
                case -7:
                    /* In MaraDNS 1.2, we now use a built-in list of the
                     * ICANN root servers if the root_servers variable
                     * is not set */
                    harderror(L_SETROOTNS); /* root_servers["."] must be set in the mararc file; e.g. root_servers["."] = "198.41.0.4" */
                case -11:
                    harderror(L_BADROOTNS); /* root_servers["."] in the mararc file is invalid.; Example good value: root_servers["."] = "198.41.0.4" */
                case -14:
                    harderror(L_CHOOSEONE); /* Both root_servers and upstream_servers are set in the mararc file... please choose one  */
                default:
                    printf(L_ERROR_VALUE); /* "Error value (for software devlopers): " */
                    printf("%d\n",counter);
                    harderror(L_INITCACHE_FAIL); /* Init_cache() failed */
                }
            }

    /* Read in the list of spam-friendly DNS servers, which we will
       refuse to get data from */
    if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
    verbstr = read_string_kvar("spammers");

    /* If there is a spam-friendly list, read it in */
    if(verbstr != 0 && js_length(verbstr) > 0) {
        if(init_spammers(verbstr) == JS_ERROR)
            harderror(L_INIT_SPAMMERS); /* "Could not make spammers list" */
        }
    /* Otherwise, make sure the spammers list is an empty list */
    else {
        if(init_spammers(0) == JS_ERROR)
            harderror(L_INIT_SPAMMERS); /* "Could not make spammers list" */
        }

    if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
    /* BEGIN RNG USING CODE */
    /* Determine which file to read the key from */
    verbstr = read_string_kvar("random_seed_file");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        counter = init_rng(verbstr,0);
        if(counter < 0) {
            switch(counter) {
                case -2:
                    sys_harderror(L_OPENSEED_FAIL); /* Could not open the random_seed_file */
                case -3:
                    harderror(L_NEED16BYTES); /* The random_seed_file needs to be 16 bytes or longer */
                default:
                    harderror(L_INITCRYPTO_FAIL); /* "Init_crypto() failed" */
                }
            }
        }
    else if((recurse_acl[0]).ip != 0xffffffff) {
        /* Default random_seed_file value: /dev/urandom */
        if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
        verbstr = js_create(256,1);
        if(js_qstr2js(verbstr,"/dev/urandom") == JS_ERROR)
             harderror(L_KVAR_Q);
        counter = init_rng(verbstr,0);
        if(counter < 0) {
            switch(counter) {
                case -2:
                    sys_harderror(
"MaraDNS was unable to open up the file /dev/urandom\n"
"MaraDNS needs a random seed for security purposes.  Please create a file \n"
"with 16 or more bytes of random data in it, and have your mararc file point\n"
"to this random seed as follows:\n\n"
"\trandom_seed_file = \"filename\"\n\nWhere filename is the name of the file\n"
"with 16 or more bytes of random data.\n");
                case -3:
                    harderror("The file /dev/urandom is not 16 bytes long.\n"
"This is very unusual.\n\n"
"MaraDNS needs a random seed for security purposes.  Please create a file \n"
"with 16 or more bytes of random data in it, and have your mararc file point\n"
"to this random seed as follows:\n\n"
"\trandom_seed_file = \"filename\"\n\nWhere filename is the name of the file\n"
"with 16 or more bytes of random data.\n");
                default:
                    harderror(L_INITCRYPTO_FAIL); /* "Init_crypto() failed" */
                }
            }
        }
    /* END RNG USING CODE */
    } else { /* We can lower the cap of maximum memory usable */
        thread_overhead = 0; }
#else /* AUTHONLY */
    /* Die right away so an admin isn't scratching their head wondering why
     * Mara isn't able to recursively resolve hostname */
    if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
    verbstr = read_string_kvar("recursive_acl");
    if(verbstr != 0 && js_length(verbstr) > 0) {
            harderror("No recursion in MaraDNS 2; use Deadwood");
    }
#endif /* AUTHONLY */

    /* Set up the list of IPs allowed to look at (and possibly change)
     * MaraDNS' internal information */
    for(counter = 0; counter < 511; counter++)
        admin_acl[counter].ip = 0xffffffff;
    if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
    verbstr = read_string_kvar("admin_acl");
    if(verbstr != 0 && js_length(verbstr) > 0) {
        if(make_ip_acl(verbstr,admin_acl,500,0) == JS_ERROR)
            harderror("Could not make admin_acl list");
        }
    default_dos_level = 78; /* 78: Recursive-only; 0: default when
                             * there is one or more zonefiles */
    if(admin_acl[0].ip != 0xffffffff) {
        default_dos_level = 79; /* 79: Only check for Tversion.maradns. */
        }

    /* Anything after this does not need recursion enabled for the
       kvar in question to be read */

    /* Determine whether to wait before sending a reply (used only
       for debugging) */
    debug_delay = read_numeric_kvar("debug_response_delay",0);

    /* Set the debug_msg_level to the Debug message level they want */
    debug_msg_level = read_numeric_kvar("debug_msg_level",1);

#ifndef MINGW32
    /* Determine if we are root */
#ifndef __CYGWIN__
    if(geteuid() == 0) {
#endif

        if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
        verbstr = read_string_kvar("chroot_dir");
        if(verbstr == 0) {
            harderror(L_CHROOT_KVAR);
            }
        if(js_length(verbstr) <= 0)
            harderror(L_CHROOT_KVAR); /* "Problem getting chroot kvar.\nYou must have chroot_dir set if you start this as root" */
        if(js_js2str(verbstr,(char *)chroot_zt,200) == JS_ERROR)
            harderror(L_CHROOT_NT); /* "Problem making chroot nt string.\nMake sure the chroot directory is 200 chars or less" */
        if(chdir((char *)chroot_zt) != 0)
            sys_harderror(L_CHROOT_CHANGE); /* "Problem changing to chroot dir.\nMake sure chroot_dir points to a valid directory" */
#if ! (defined __CYGWIN__ || defined QNX)
        if(chroot((char *)chroot_zt) != 0)
            sys_harderror(L_CHROOT_DO);  /* "Problem changing the root directory." */
#endif

        mlog(L_CHROOT_SUCCESS); /* "Root directory changed" */
#else
    if(1 == 1) {
#endif /* MINGW32 */

        /* Bind to port 53
           To Do: use capset to give us privledged bind abilities without
                  needing to be root.
        */
        bind_address = read_string_kvar("bind_address");
        csv2_synthip_address = read_string_kvar("csv2_synthip_list");
        ipv4_bind_address = read_string_kvar("ipv4_bind_addresses");
        /* If there is no bind address set, have MaraDNS return an error */
        if(js_length(ipv4_bind_address) < 1 && js_length(bind_address) < 1) {
            harderror("The mararc variable ipv4_bind_addresses must be set.\n"
"This is the IP or list of IPs that your MaraDNS DNS server will have.\n"
"This can be a single IP, such as:\n\n"
"\tipv4_bind_addresses = \"127.0.0.1\"\n"
"\nOr a list of IPs, such as:\n\n"
"\tipv4_bind_addresses = \"127.0.0.1,10.7.14.86\"\n");
            }
        if(js_length(ipv4_bind_address) >= 1 &&
           js_length(bind_address) >=1) {
  harderror("Both bind_address and ipv4_bind_addresses can not be set.");
            }
        for(counter = 0; counter < 512 ; counter++) {
            bind_addresses[counter].ip = 0xffffffff;
            csv2_synthip_list[counter].ip = 0xffffffff;
            sock[counter] = 0;
            }
        if(js_length(bind_address) >=1) {
            if(make_ip_acl(bind_address,bind_addresses,500,0) == JS_ERROR)
                harderror("Can not make ip acl for the bind addresses"
"\nMake sure you have a correctly formatted value for the bind_address in your"
"\nmararc file");
            } else {
            if(make_ip_acl(ipv4_bind_address,bind_addresses,500,0) == JS_ERROR)
                harderror("Can not make ip acl for the ipv4 bind addresses\n"
"Make sure you have a correctly formatted value for the ipv4_bind_address in"
"\nyour mararc file");
            }

        if(js_length(csv2_synthip_address) >= 1) {
            if(make_ip_acl(csv2_synthip_address,csv2_synthip_list,500,0) ==
                            JS_ERROR)
                harderror("Looks like there is a malformed csv2_synthip_list");
            }

        if(udp_ipv4_bind(sock,bind_addresses) == JS_ERROR)
            sys_harderror(L_BINDFAIL); /* "Problem binding to port 53.\nMost likely, another process is already listening on port 53" */
        if(js_length(bind_address) >=1) {
            zjlog(L_BIND2ADDR,bind_address); /* "Binding to address " */
        } else {
            zjlog(L_BIND2ADDR,ipv4_bind_address); /* "Binding to address " */
        }
        mlog(L_BIND_SUCCESS);  /* "Socket opened on UDP port 53" */
        js_destroy(bind_address);
        js_destroy(csv2_synthip_address);
        js_destroy(ipv4_bind_address);

        ipv6_bind_address = read_string_kvar("ipv6_bind_address");
#ifndef IPV6
        /* If there is an ipv6 bind address, have MaraDNS return an error */
        if(js_length(ipv6_bind_address) >= 1) {
                harderror("maradns must be compiled as ipv6 to have ipv6 support\n"
                "./configure --ipv6 ; make will compile maradns thusly\n"
                );
        }
#else
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
        if(js_length(ipv6_bind_address) >= 1) {
                for(counter = 0; counter < 502; counter++) {
                        if(sock[counter] == 0)
                            break;
                }
                if(counter >= 501) {
                        harderror("We are bound to too many ipv4 addresses");
                }
                if(udp_ipv6_bind(sock,counter,ipv6_bind_address) == JS_ERROR) {
                        sys_harderror("Binding to a ipv6 socket failed");
                }
                have_ipv6_address = 1;
        }
#else
        if(js_length(ipv6_bind_address) >= 1) {
                printf("Cygwin doesn't have ipv6 support\n");
                exit(1);
        }
#endif /* __CYGWIN__ */
#endif /* IPV6 */

#ifndef MINGW32
        /* Drop the elevated privileges */
        /* First, change the GID */
        gid = read_numeric_kvar("maradns_gid",MARADNS_DEFAULT_GID);
#ifndef __CYGWIN__
        /* Drop all supplemental groups */
        setgroups(1,&gid);
#endif /* __CYGWIN__ */
        /* Set the group ID */
        setgid(gid);

#ifndef __CYGWIN__
        /* Next, change the UID */
        uid = read_numeric_kvar("maradns_uid",MARADNS_DEFAULT_UID);
        if(uid < 10)
            harderror(L_BADUID); /* "maradns_uid is less than 10 or not a number.\nThis uid must have a value of 10 or more" */
        if(setuid(uid) != 0)
            sys_harderror(L_NODROP); /* "Could not drop root uid" */
        /* Workaround for known Linux kernel security problem circa
           early 2000 */
        if(setuid(0) == 0)
            sys_harderror(L_STILL_ROOT);  /* "We seem to still be root" */

        mlog(L_DROP_SUCCESS); /* "Root privileges dropped" */
#endif /* __CYGWIN__ */
#endif /* MINGW32 */

#ifndef __CYGWIN__
        }
    else {
#else
    if(1 == 2) {
#endif /* __CYGWIN__ */
#ifndef ALLOW_NON_ROOT
        harderror("Running MaraDNS 2.0 as a non-root server support disabled");
#else
        /* Bind to port 53 as a non-root user */
        bind_address = read_string_kvar("bind_address");
        ipv4_bind_address = read_string_kvar("ipv4_bind_addresses");

        if(js_length(ipv4_bind_address) < 1 && js_length(bind_address) < 1) {
         harderror("The mararc variable ipv4_bind_addresses must be set.");
        }

        if(js_length(ipv4_bind_address) >= 1 && js_length(bind_address) >=1) {
       harderror("Both bind_address and ipv4_bind_addresses can not be set.");
        }

        for(counter = 0; counter < 512 ; counter++)
                bind_addresses[counter].ip = 0xffffffff;

        if(js_length(bind_address) >=1) {
            if(make_ip_acl(bind_address,bind_addresses,500,0) == JS_ERROR) {
                harderror("Looks like bind_address may have a bad value");
            }
        } else {
          if(make_ip_acl(ipv4_bind_address,bind_addresses,500,0) == JS_ERROR) {
              harderror("Looks like ipv4_bind_addresses may have a bad value");
            }
        }

        if(udp_ipv4_bind(sock,bind_addresses) == JS_ERROR)
                sys_harderror(L_BEROOT); /* "Problem binding to port 53.\nYou should run this as root" */

        mlog(L_BIND_SUCCESS);  /* "Socket opened on UDP port 53" */
#endif /* ALLOW_NON_ROOT */
        }

    csv2_tilde_handling = read_numeric_kvar("csv2_tilde_handling",2);

    /* Make sure that if csv2_tilde_handling is set, it has a value 0-3 */
    if(csv2_tilde_handling < 0 || csv2_tilde_handling > 3) {
        harderror("csv2_tilde_handling "
                  "must have a value between 0 and 3");
        exit(1);
        }

    recurse_delegation = read_numeric_kvar("recurse_delegation",0);

    /* Make sure that if recurse_delegation is set, it has a value 0-1 */
    if(recurse_delegation < 0 || recurse_delegation > 1) {
        harderror("recurse_delegation "
                  "must have a value between 0 and 1");
        exit(1);
        }

#ifndef AUTHONLY
    /* Set the upstream port */
    set_upstream_port(read_numeric_kvar("upstream_port",53));
#endif

    /* Create the big hash */
    bighash = 0;
    bighash = mhash_create(8);
    if(bighash == 0)
        harderror(L_NOBIGHASH); /* "Could not create big hash" */

    /* populate_main uses qual timestamps for the csv2 zone files */
    qual_set_time();
    value = populate_main(bighash,errors,recursion_enabled);
    if(dns_records_served > 0) {
        printf("MaraDNS proudly serves you %d DNS records\n",
               dns_records_served);
        }

    /* Limit the amount of memory we can use */
#ifdef MAX_MEM
    /* Limit the maximum amount of memory we can allocate, in
     * bytes */
    maxprocs = read_numeric_kvar("max_mem",
               2097072 + thread_overhead +
               ((cache_size + dns_records_served) * 3072));
    if(maxprocs < 262144 && maxprocs > 0) { maxprocs = 262144; }
    if(maxprocs > 0) {
      rlim.rlim_cur = rlim.rlim_max = maxprocs;
      if(setrlimit(MAX_MEM,&rlim) != 0) {
        if(errno == ENOSYS) {
            printf(
      "WARNING: Your system does not allow setting memory allocation limits!");
            }
        else {
#ifdef __CYGWIN__
            printf(
      "WARNING: Your system does not allow setting memory allocation limits!");
#else /* __CYGWIN__ */
            harderror("Unable to set memory allocation limits");
#endif
            }
       } else {
            printf("MaraDNS maximum memory allocation set to %d bytes\n",
                   maxprocs);
            }
     }
#else /* MAX_MEM */
     printf(
      "WARNING: Your system does not allow setting memory allocation limits!");
#endif /* MAX_MEM */

    /* If we have one or more elements in the cache, we will need to look
     * through the cache for elements (default_dos_level, in this context,
     * allows us to save time when doing just recursive queries by not
     * bothering with cache lookups) */
    if(value == JS_SUCCESS) {
        default_dos_level = 0;
    }

    if(value == JS_ERROR)
        harderror(L_NOPOPULATE); /* "Error running populate_main program" */
    else if(value == -2) {
        js_show_stdout(errors);
        printf("%s",L_N); /* "\n" */
        harderror(L_POPULATE_FATAL); /* "This error in populate hash is fatal" */
        }

    if(verbstr != 0) { js_destroy(verbstr); verbstr = 0; }
    verbstr = read_string_kvar("csv2_default_zonefile");
    if(verbstr !=0 && js_length(verbstr) > 0) {
            js_string *zone;
            int q;
            if(recursion_enabled == 1) {
                    harderror("Default zonefile not permitted when recursion is enabled");
            }
            if((zone = js_create(12,1)) == 0) {
                    harderror("Unable to create zone js_string");
            }
            if(js_qstr2js(zone,"*") == JS_ERROR) {
                    harderror("Unable to create zone string");
            }
            q = csv2_parse_zone_bighash(zone,verbstr,bighash,1);
            if(q < 0) {
                   printf("Error parsing csv2 default zonefile %d\n",q);
            }
            printf("Csv2 default zonefile parsed\n");
            default_zonefile_enabled = 1;
            default_dos_level = 0;
    }

    /* Set the dos_protection_level to see if we disable some features
     * to protect us from a denial of service attack. */
    dos_protection_level =
        read_numeric_kvar("dos_protection_level",default_dos_level);

    mlog(L_RRS_LOADED);  /* "All RRs have been loaded" */

    /* Right now, all we do after getting a HUP signal is exit with a code
       of 8.  The static DNS database is too tangley for me to figure out
       how to clear all of the memory it uses quickly; there is too much
       chance of having a memory leak with this, so I don't feel comfortable
       doing the right thing after getting a HUP signal until Franky comes
       back to help make sure HUP handling is memory-leak free */
#ifndef MINGW32
    signal(SIGHUP,handle_hup); /* All this does is change the got_hup_signal
                                  global variable */
#ifdef DEBUG
    signal(SIGTERM,display_unfreed);
    signal(SIGINT,display_unfreed);
#endif /* DEBUG */
#endif /* MINGW32 */

    /* Initialize the new decompression code */
    /* Disabled until I can get the bugs worked out */
    decomp_init(log_level);

    /* Flush out any messages that have already appeared */
    fflush(stdout);

    if(log_level >= 3)
        mlog(L_DATAWAIT); /* "Awaiting data on port 53" */
    /* Listen for data on the UDP socket */
    for(;;) {
        int sock_num;
        conn ect; /* The space is not a typo */
        ect.type = 0;
        ect.d = (void *)0;
        ect.addrlen = 0;
        /* Make sure we never got a HUP signal */
        if(got_hup_signal != 0) {
            printf("HUP signal sent to MaraDNS process\n");
            printf("Exiting with return value of 8\n");
            exit(8);
            }
        /* Update the timestamp; this needs to be run once a second */
        qual_set_time();
        if(log_level >= 50) /* This happens once a second */
            mlog(L_DATAWAIT); /* "Awaiting data on port 53" */
        sock_num = getudp(sock,bind_addresses,&ect,incoming,512,
                          have_ipv6_address);
        if(sock_num == JS_ERROR)
            continue;
        if(log_level >= 3)
            mlog(L_GOTDATA);     /* "Message received, processing" */
        if(decompress_data(incoming,uncomp) == JS_ERROR) {
            if(log_level >= 4) {
                if(ect.type == 4) {
                    clin = (struct sockaddr_in *)(ect.d);
                }
#ifdef IPV6
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
                else {
                    clin6 = (struct sockaddr_in6 *)(ect.d);
                }
#endif /* __CYGWIN__ */
#endif
                log_lock();
                show_timestamp();
                printf("%s ","Query from");
                if(ect.type == 4) {
                    debug_show_ip(ntohl(clin->sin_addr.s_addr));
                } else {
#ifdef IPV6
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
                    debug_show_socket_ipv6(clin6);
#endif /* __CYGWIN__ */
#else
                    printf(" UNKNOWN ");
#endif
                }
                printf("has decompression error: ");
                show_esc_stdout(incoming);
                printf("\n");
                log_unlock();
                }
            if(ect.d != 0) {
                js_dealloc(ect.d);
                }
            continue;
            }
        if(log_level >= 5) {
            log_lock();
            show_timestamp();
            printf("Decompressed packet: ");
            show_esc_stdout(uncomp);
            printf("\n");
            log_unlock();
            }
        if(log_level >= 3 && uncomp->unit_count > 12) {
            /* Show them the query */
            counter = dlabel_length(uncomp,12);
            value = js_readuint16(uncomp,12+counter);
            if(js_substr(uncomp,incoming,12,counter) != JS_ERROR) {
                clin = (struct sockaddr_in *)(ect.d);
#ifdef IPV6
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
                clin6 = (struct sockaddr_in6 *)(ect.d);
#endif /* __CYGWIN__ */
#endif
                hname_translate(incoming,value);
                /* Yes, I know, put these in the "to localize" header file */
                log_lock();
                show_timestamp();
                printf("%s: ","Query from");
                if(ect.type == 4) {
                    debug_show_ip(ntohl(clin->sin_addr.s_addr));
                } else {
#ifdef IPV6
/* Cygwin doesn't have ipv6 support yet */
#ifndef __CYGWIN__
                    debug_show_socket_ipv6(clin6);
#endif /* __CYGWIN__ */
#else
                    printf(" UNKNOWN ");
#endif
                }
                printf(" ");
                js_show_stdout(incoming);
                printf("\n");
                log_unlock();
                }
            }
        /* Delay the processing the request, as needed */
#ifndef MINGW32
        if(debug_delay > 0)
            sleep(debug_delay);
#endif
        /* Process the query */
        proc_query(uncomp,&ect,sock_num);
        /* Free the memory used by the ect structure */
        if(ect.d != 0) {
                js_dealloc(ect.d);
            }
        }

    /* We should never end up here */

    exit(7); /* Exit code 7: Broke out of loop somehow */

    }

