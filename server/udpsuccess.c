/* Copyright (c) 2002-2013 Sam Trenholme
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

#ifndef MINGW32
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock.h>
#include <wininet.h>
#endif

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "../dns/functions_dns.h"
#include "functions_server.h"

extern int total_count;
extern int max_ar_chain;
extern int max_chain;
extern int max_total;
extern rr *seenlist[256];
extern int seenlist_where;
extern ipv4pair long_packet[512];
extern int calc_ra_value(); /* Make -Wall happy */

/* If we successfully found a record, spit out that record on the
   udp packet.
   Input: Where a pointer to the rr in question is, the id of the
          query they sent us, the socket the
          UDP bind is on, the sockaddr of the client who sent us the message,
          a js_string containing the query (dname + type), whether to show
          an A record along with a CNAME record (this is no longer used),
          rd_val (which to set the RD flag in the headers), ect: A
          description of the connection to send the reply to,
          force_authoritative: A boolean.  If 0, the value of the
          authoritative bit is determined by looking at the data in where.
          If 1, the record is always marked in the DNS headers as
          "authoritative".
          The value to give the "RA" bit.
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udpsuccess(rr *where, int id, int sock, struct sockaddr_in *client,
               js_string *query, void **rotate_point, int show_cname_a,
               int rd_val, conn *ect, int force_authoritative,int ra_value) {
    js_string *most = 0; /* Most of the data */
    js_string *ar = 0; /* Then the additional records */

    uint16 first_rr_type;
    int in_ns = 0;
    int ns_delegation = 0;
    int length_save;
    int len_inet = sizeof(struct sockaddr);
    rr *ipwhere = 0;
    /* The following are used for round robin rotation */
    rr *rotate_1st = 0, *rotate_2nd = 0, *rotate_last = 0;
    /* Counters in ensure that we don't give out more than the maximum
       number of A, AN (A), chain, or total records */
    int a_count = 0, an_count = 0;
    fila *zap_point;
    /* These two variables are added to handle PTR records */
    int seen_ptr_record = 0;
    rr *top = where;
    int is_auth = 0;
    int compress_error_happened = 0;

    q_header header;

    /* Initialize the total count */
    total_count = 0;
    /* Initialize the js_string objects */
    if((most = js_create(1024,1)) == 0)
        return JS_ERROR;
#ifdef AUTHONLY
    if((ar = js_create(5000,1)) == 0) {
        js_destroy(most);
        return JS_ERROR;
        }
#else
    if((ar = js_create(600,1)) == 0) {
        js_destroy(most);
        return JS_ERROR;
        }
#endif

    /* Make the header a placeholder for now */
    init_header(&header);
    header.id = id;
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

    /* Somewhat hacky way to determine that this is a NS delegation */
    ns_delegation = 0;
    if(first_rr_type != RR_NS && where->rr_type == RR_NS) {
        ns_delegation = 1;
        }

    /* With the cache, this may be a rtype of RR_ANY.  We need to handle
       this special case */

    /* We have to add this header here--authoritative depends on the
       authorative status of the first record we find */
    if(force_authoritative != 1) {
        header.aa = where->authoritative;
        }
    else {
        header.aa = 1;
        }
    is_auth = where->authoritative;

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
        if(first_rr_type != RR_NS && where->rr_type == RR_NS && in_ns == 0) {
            /* Due to the data structure MaraDNS currently uses, the behavior
               is buggy if we round-robin rotate data when we allow more than
               one additional record to be create per answer/authoritative
               record.  */
            if(rotate_2nd != 0 && max_ar_chain == 1 && rotate_last != 0 &&
               first_rr_type != RR_NS) {
                /* If it makes sense to do a round-robin rotation, do so.
                 * Make rotate_1st, which was the first record, the last
                 * record; make rotate_2nd, which was the second record,
                 * the first record; and make rotate_last, which is the last
                 * record in the chain, have its next record be the first
                 * record */
                rotate_1st->next = where;
                rotate_last->next = rotate_1st;
                *rotate_point = rotate_2nd;
                rotate_2nd = 0; /* Make sure we can not rotate again */
                }
            in_ns = 1;
            a_count = 0; /* The NS chain is different than the AN
                            chain of answers: If we only allow eight
                            answers in a chain, we can still have 16
                            answers: 8 records in the answer section then
                            8 records in the authority section */
            }
        if(a_count < max_chain && total_count < max_total && (in_ns == 0
           || is_auth == 1 || ns_delegation == 1)) {
            a_count++;
            total_count++;
            if(!in_ns) {
                header.ancount++;
                }
            else {
                header.nscount++;
                }
            /* Append the name for this answer to the answer */
            if(js_append(where->query,most) == JS_ERROR)
                goto giveerror;
            /* Append the class (in) to the answer */
            if(js_adduint16(most,1) == JS_ERROR)
                goto giveerror;
            /* Append the ttl to the answer */
            if(js_adduint32(most,determine_ttl(where->expire,where->ttl))
               == JS_ERROR)
                goto giveerror;
            /* Add the rdlength to the answer */
            if(js_adduint16(most,where->data->unit_count) == JS_ERROR)
                goto giveerror;
            /* Add the record itself to the answer */
            if(js_append(where->data,most) == JS_ERROR)
                goto giveerror;
            /* If there is an IP, and this is *not* a CNAME record,
               append the IP of the answer to the AR section */
            if(where->ip != 0 && where->rr_type != RR_CNAME) {
                /* Reset the number of an records we have seen */
                an_count = 0;
                ipwhere = where->ip;
                while(ipwhere != 0 && ipwhere->rr_type != RR_NS) {
                    /* We only show a given additional record once */
                    if(ipwhere->seen == 1) { /* If we have displayed this RR
                                                already */
                        /* Go to the next link in the linked list */
                        ipwhere = ipwhere->next;
                        continue;
                        }
                    /* Stop showing records if we have exceeded our limit */
                    if(an_count >= max_ar_chain || total_count >= max_total)
                        break;
                    an_count++;
                    total_count++;
                    /* Increment the number of additional records */
                    header.arcount++;
                    /* Append the name for this answer to the ip */
                    if(js_append(ipwhere->query,ar) == JS_ERROR)
                        goto giveerror;
                    /* Append the class (in) to the ip */
                    if(js_adduint16(ar,1) == JS_ERROR)
                        goto giveerror;
                    /* Append the TTL to the ip */
                    if(js_adduint32(ar,
                      determine_ttl(ipwhere->expire,ipwhere->ttl)) == JS_ERROR)
                        goto giveerror;
                    /* Add the rdlength to the ip */
                    if(js_adduint16(ar,ipwhere->data->unit_count) == JS_ERROR)
                        goto giveerror;
                    /* Add the record itself to the ip */
                    if(js_append(ipwhere->data,ar) == JS_ERROR)
                        goto giveerror;
                    /* Mark that we have seen this record already */
                    if(seenlist_where < 250) {
                        ipwhere->seen = 1;
                        seenlist[seenlist_where] = ipwhere;
                        seenlist_where++;
                        }
                    /* Go to the next link in the linked list */
                    ipwhere = ipwhere->next;
                    }
                }
#ifdef IPV6
              if(where->ip6 != 0 && where->rr_type != RR_CNAME) {
                /* Reset the number of an records we have seen */
                an_count = 0;
                ipwhere = where->ip6;
                while(ipwhere != 0 && ipwhere->rr_type != RR_NS) {
                    /* We only show a given additional record once */
                    if(ipwhere->seen == 1) { /* If we have displayed this RR
                                                already */
                        /* Go to the next link in the linked list */
                        ipwhere = ipwhere->next;
                        continue;
                        }
                    /* Stop showing records if we have exceeded our limit */
                    if(an_count >= max_ar_chain || total_count >= max_total)
                        break;
                    an_count++;
                    total_count++;
                    /* Increment the number of additional records */
                    header.arcount++;
                    /* Append the name for this answer to the ip */
                    if(js_append(ipwhere->query,ar) == JS_ERROR)
                        goto giveerror;
                    /* Append the class (in) to the ip */
                    if(js_adduint16(ar,1) == JS_ERROR)
                        goto giveerror;
                    /* Append the TTL to the ip */
                    if(js_adduint32(ar,
                      determine_ttl(ipwhere->expire,ipwhere->ttl)) == JS_ERROR)
                        goto giveerror;
                    /* Add the rdlength to the ip */
                    if(js_adduint16(ar,ipwhere->data->unit_count) == JS_ERROR)
                        goto giveerror;
                    /* Add the record itself to the ip */
                    if(js_append(ipwhere->data,ar) == JS_ERROR)
                        goto giveerror;
                    /* Mark that we have seen this record already */
                    if(seenlist_where < 250) {
                        ipwhere->seen = 1;
                        seenlist[seenlist_where] = ipwhere;
                        seenlist_where++;
                        }
                    /* Go to the next link in the linked list */
                    ipwhere = ipwhere->next;
                    }
                }
#endif
            /* This code is only used by the recursive code; the
             * authoritative code now uses where->list to attach
             * a CNAME record to its corresponding rddata
             * If there is an IP, and this is a CNAME record, and
             * show_cname_a is set to one (argument to this function)
             * append the IP in question to the answer section */
            if(where->ip != 0 && where->rr_type == RR_CNAME
               && show_cname_a == RR_A && where->list == 0) {
                /* Reset the number of an records we have seen */
                an_count = 0;
                ipwhere = where->ip;
                while(ipwhere != 0 && ipwhere->rr_type != RR_NS) {
                    /* We only show a given additional record once */
                    if(ipwhere->seen == 1) { /* If we have displayed this RR
                                                already */
                        /* Go to the next link in the linked list */
                        ipwhere = ipwhere->next;
                        continue;
                        }
                    /* If the IP in question is 255.255.255.255, we do
                       not show the data in question */
                    if(ipwhere->rr_type == RR_A &&
                       ipwhere->data->unit_count == 4 &&
                       *(ipwhere->data->string) == 0xff &&
                       *(ipwhere->data->string + 1) == 0xff &&
                       *(ipwhere->data->string + 2) == 0xff &&
                       *(ipwhere->data->string + 3) == 0xff) {
                        ipwhere = ipwhere->next;
                        continue;
                        }
                    /* Stop showing records if we have exceeded our limit */
                    if(an_count >= max_ar_chain || total_count >= max_total)
                        break;
                    an_count++;
                    total_count++;
                    /* Increment the number of answer records */
                    header.ancount++;
                    /* Append the name for this answer to the ip */
                    if(js_append(ipwhere->query,most) == JS_ERROR)
                        goto giveerror;
                    /* Append the class (in) to the ip */
                    if(js_adduint16(most,1) == JS_ERROR)
                        goto giveerror;
                    /* Append the TTL to the ip */
                    if(js_adduint32(most,
                      determine_ttl(ipwhere->expire,ipwhere->ttl)) == JS_ERROR)
                        goto giveerror;
                    /* Add the rdlength to the ip */
                    if(js_adduint16(most,ipwhere->data->unit_count)
                       == JS_ERROR)
                        goto giveerror;
                    /* Add the record itself to the ip */
                    if(js_append(ipwhere->data,most) == JS_ERROR)
                        goto giveerror;
                    /* Mark that we have seen this record already */
                    if(seenlist_where < 250) {
                        ipwhere->seen = 1;
                        seenlist[seenlist_where] = ipwhere;
                        seenlist_where++;
                        }
                    /* Go to the next link in the linked list */
                    ipwhere = ipwhere->next;
                    }
                }
            /* Again, this code is only used by the recursive half.
             * The authoritative half now has a way of showing the record
             * that correspods to any RR type attached to a CNAME record.
             *
             * If there is an PTR, and this is a CNAME record, and
             * show_cname_a is set to one (argument to this function)
             * append the IP in question to the answer section */
            else if(top->ptr != 0 && top->rr_type == RR_CNAME
               && show_cname_a == RR_PTR && seen_ptr_record == 0
               && where->list == 0) {
                    /* Mark that we have seen this record already */
                    seen_ptr_record = 1;
                    /* Increment the total number of answers seen */
                    total_count++;
                    /* Increment the number of answer records */
                    header.ancount++;
                    /* Append the name for this answer to the ip */
                    if(js_append(top->data,most) == JS_ERROR)
                        goto giveerror;
                    /* Append the type for this query */
                    if(js_adduint16(most,RR_PTR) == JS_ERROR)
                        goto giveerror;
                    /* Append the class (in) to the ip */
                    if(js_adduint16(most,1) == JS_ERROR)
                        goto giveerror;
                    /* Append the TTL to the ip */
                    if(js_adduint32(most,
                      determine_ttl(top->expire,top->ttl)) == JS_ERROR)
                        goto giveerror;
                    /* Add the rdlength to the ip */
                    if(js_adduint16(most,top->ptr->unit_count)
                       == JS_ERROR)
                        goto giveerror;
                    /* Add the record itself to the ip */
                    if(js_append(top->ptr,most) == JS_ERROR)
                        goto giveerror;
               }
            /* This code is currently only used by the authoritative half;
             * bascially, if we see a CNAME record we see if we have a list
             * which lists all record types for the host name the CNAME
             * is pointing to.  We used this list to add, in the answer
             * section, the answer the person is looking for. */
            else if(where->rr_type == RR_CNAME && where->list != 0) {
               struct rr_list *any_list = 0;
               uint16 this_rr_type = 0;
               int counter = 0;
               /* Start at the top of list of RRs */
               any_list = where->list;
               this_rr_type = first_rr_type; /* The rtype they want */
               /* We go down the list until we find the desired rr_type */
               for(counter = 0; counter < 1000; counter++) {
                   if(any_list->rr_type == this_rr_type) {
                       break;
                       }
                   if(any_list->next == 0) {
                       break;
                       }
                   any_list = any_list->next;
                   }
               /* If we found the desired record type... */
               if(any_list->rr_type == this_rr_type && any_list->data != 0) {
                   rr *answer;
                   int counter = 0;
                   answer = any_list->data;
                   while(answer != 0 && answer->rr_type == this_rr_type &&
                         counter < 100) {
                       /* Then we add this information to the AN section of
                        * the answer */
                       /* Increase the number of answers in the header */
                       header.ancount++;
                       /* RFC 1035 section 3.2.1 header */
                       /* Name + Type */
                       if(js_append(answer->query,most) == JS_ERROR)
                           goto giveerror;
                       /* Class */
                       if(js_adduint16(most,1) == JS_ERROR)
                           goto giveerror;
                       /* TTL */
                       /* Since this currently only returns authoritative
                        * data, answer->expire should always be zero and
                        * determine_ttl is a redundant call.  However, we'll
                        * keep it that way just in case things change in
                        * the future */
                       if(js_adduint32(most,determine_ttl(answer->expire,
                              answer->ttl)) == JS_ERROR)
                           goto giveerror;
                       /* Rdlength */
                       if(answer->data == 0)
                           goto giveerror;
                       if(answer->data->unit_count < 0 ||
                          answer->data->unit_count > 65535)
                           goto giveerror;
                       if(js_adduint16(most,answer->data->unit_count) ==
                           JS_ERROR)
                           goto giveerror;
                       /* rdata */
                       if(js_append(answer->data,most) == JS_ERROR)
                           goto giveerror;
                       counter++;
                       answer = answer->next;
                       }
                   }
               }
            }
        /* Go on to the next record in the linked list */
        rotate_last = where;
        where = where->next;
        /* If it makes sense to do a round-robin rotation, do so */
        if(where == 0 && rotate_2nd != 0 && max_ar_chain == 1 &&
           first_rr_type != RR_NS) {
            /* For records in the cache, we need to make sure that
               the custodian properly points to the first record
               in the chain or we will leak memory */
            if(rotate_1st->zap != 0) {
                zap_point = rotate_1st->zap;
                rotate_1st->zap = 0;
                rotate_2nd->zap = zap_point;
                zap_point->record = rotate_2nd;
                }
            rotate_1st->next = 0;
            rotate_last->next = rotate_1st;
            *rotate_point = rotate_2nd;
            rotate_2nd = 0; /* Make sure we can not rotate again */
            }
        }

    /* Customize the header */
    /* header.id already set */
    header.qr = 1;
    header.opcode = 0;
    header.tc = 0;
    header.rd = rd_val; /* RDBUG udpsuccess */
    header.ra = calc_ra_value(ra_value);
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

    compress_error_happened = 0;
    if(compress_data(most,ar) == JS_ERROR) {
        compress_error_happened = 1;
    }

    /* Check to make sure the data fits in under 512 bytes (4096 bytes
     * if it's a long_packet_ipv4 address) truncate if not */
    if(ar->unit_count > 512 || compress_error_happened == 1) {
        int x;
#ifdef AUTHONLY

        /* If this is an ipv4 connection and we didn't get a compress error */
        if(ect->type == 4 && compress_error_happened == 0) {
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
#endif

        for(x = 0; x < 20; x++) {
                compress_error_happened = 0;
                /* OK, try to squeeze the packet in by removing records */
                if(squeeze_to_fit(most) == 0) {
                        goto giveerror;
                }
                if(most->unit_count > 12) {
                        if(compress_data(most,ar) == JS_ERROR) {
                                compress_error_happened = 1;
                        }
                        if(ar->unit_count <= 512 &&
                            compress_error_happened == 0) {
                                break;
                        }
                } else if(most->unit_count == 12) {
                        if(js_copy(most,ar) == JS_ERROR) {
                                goto giveerror;
                        }
                } else {
                        goto giveerror;
                }
            }
        }

#ifdef AUTHONLY
long_packet_ok:
#endif

    if(compress_error_happened == 1) {
        goto giveerror;
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

    /* Clean up the seenlist_where list */
    while(seenlist_where > 0) {
        seenlist_where--;
        if(seenlist[seenlist_where] != 0)
            (seenlist[seenlist_where])->seen = 0;
        }

    return JS_SUCCESS;

    /* We use gotos to make up for C's lack of error trapping */
    giveerror:
        js_destroy(ar);
        udperror(sock,most,client,0,SERVER_FAIL,"giveerror in udpsuccess",2,
                        rd_val,ect,1);
        js_destroy(most);

        /* Clean up the seenlist_where list */
        while(seenlist_where > 0) {
            seenlist_where--;
            if(seenlist[seenlist_where] != 0)
                (seenlist[seenlist_where])->seen = 0;
            }
        return JS_ERROR;

    }
