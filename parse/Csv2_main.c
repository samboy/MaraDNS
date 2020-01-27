/* Copyright (c) 2004-2015 Sam Trenholme
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef MINGW32
#include <sys/socket.h>
#else
#include <winsock.h>
#endif
#include "../libs/JsStr.h"
#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "Csv2_database.h"
#include "Csv2_read.h"
#include "Csv2_functions.h"
#include "functions_parse.h"
#include "../dns/functions_dns.h"

/* We have to do this this way because it is declared in two different
 * places, depending on what program is calling these parsing functions */
extern ipv4pair *get_synthip_list();

/* The main function for parsing a csv2_zone for putting stuff
 * in the big hash */
int csv2_parse_main_bighash(mhash *main_table,int32 starwhitis) {
        /* Get a listing of all of the csv2 hash elements */
        mhash *csv2s; /* List of CSV2 files to read */
        js_string *zone; /* Tempory string with the zone we are looking at */
        js_string *filename; /* filename of the file we want to see */
        ipv4pair *iplist; /* List of bound addresses */
        int x;

        csv2s = (mhash *)dvar_raw(dq_keyword2n("csv2"));

        /* If there are no csv2 elements, just return */
        if(csv2s == 0) {
                return 0;
        }

        /* OK, the string has been at least initialized.  Make sure
         * we have no "0.0.0.0" bind addresses */
        iplist = get_synthip_list();
        for(x = 0 ; x < 500 ; x++ ) {
                if(iplist[x].ip == 0xffffffff) {
                        break;
                }
                if(iplist[x].ip == 0) {
                        printf("You can not have both csv2 zone files and "
                                        "have MaraDNS bind to 0.0.0.0\n"
                                        "MaraDNS now supports binding to "
                                        "multiple IPs; please use this "
                                        "feature.\n");
                        exit(1);
                }
        }

        /* Allocate the zone string */
        if((zone = js_create(MAX_ZONE_SIZE,1)) == 0) {
                return -1;
        }

        /* Point to the first key in the hash */

        /* Handle the case of csv2 = {} and nothing else in the mararc file */
        if(mhash_firstkey(csv2s,zone) == 0) {
                js_destroy(zone);
                return 0;
        }

        /* Parse all of the zone files */
        do {
                filename = mhash_get_js(csv2s,zone);
                if(zone != 0) { /* If we're pointing to live data */
                        js_string *t;
                        /* Make sure the zone name is sane */
                        if((t = csv2_zone_to_udpzone(zone)) != 0) {
                                csv2_parse_zone_bighash(zone,filename,
                                                main_table,starwhitis);
                                js_destroy(t);
                        } else {
                                printf("Bad zone name ");
                                show_esc_stdout(zone);
                                printf(" (don't forget the trailing dot!)\n");
                        }
                }
        } while(mhash_nextkey(csv2s,zone) != 0);

        js_destroy(zone);
        return 0;

}

/* A function that copies a header over; this is used so that we may echo
 * most of the bits from the header */
q_header *csv2_copy_header(q_header *in) {
        q_header *out;
        if((out = js_alloc(sizeof(q_header),1)) == 0) {
                return 0;
        }
        /* We can get away with a simple memcpy, since q_header has no
         * strings */
        if(memcpy(out,in,sizeof(q_header)) == 0) {
                js_dealloc(out);
                return 0;
        }
        return out;
}

/* convert an Alabel (such as "example.com.") in to its appropriate Blabel
 * form ("\007example\003com\000").  Input: The Alabel.
 * Output: The corresponding Blabel */

js_string *csv2_alabel_to_blabel(js_string *alabel) {
        return csv2_zone_to_udpzone(alabel);
}

/* Given a js_string to add a record to, and a pointer to a csv2_rr
 * structure, append this rr in RFC21035 format to the DNS reply.
 * Output: JS_ERROR on error, JS_SUCCESS on success
 */
int csv2_append_rr(js_string *reply, csv2_rr *point) {
        if(point == 0) {
                return JS_ERROR;
        }
        if(js_append(point->query,reply) == JS_ERROR) {
                return JS_ERROR;
        }
        if(js_adduint16(reply,point->rtype) == JS_ERROR) {
                return JS_ERROR;
        }
        /* Class of '01 (IP-based internet) */
        if(js_adduint16(reply,1) == JS_ERROR) {
                return JS_ERROR;
        }
        /* ttl */
        js_adduint32(reply,point->ttl);
        if(js_adduint16(reply,point->data->unit_count) == JS_ERROR) {
                return JS_ERROR;
        }
        if(js_append(point->data,reply) == JS_ERROR) {
                return JS_ERROR;
        }
        return JS_SUCCESS;
}

/* Given a state with a chain of RRs, a TCP connection, the header of
 * their request, the name of the zone they requested (in Alabel format),
 * the type of data they are outputting (a SOA, a AXFR of whatever is in
 * the state's buffer, or a single AXFR of the initial SOA again), and the
 * SOA in case of outputting the first SOA again, make the information
 * available over the TCP connection.
 *
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int csv2_tcp_spit_data(csv2_add_state *state, int connect, q_header *header,
                js_string *zone, int type, csv2_rr *soa) {
        q_header *h_copy;
        unsigned char len[3];
        js_string *reply, *zone_name;
        csv2_rr *point;

        h_copy = csv2_copy_header(header);

        /* Change the things in the header that make a question an
         * answer */

        h_copy->qr = 1; /* It is a response to a query */
        /* Opcode is copied from query, so not changed */
        h_copy->aa = 1; /* It's in our zone file, we have authority for
                         * it */
        h_copy->tc = 0; /* We don't need to truncate when going over
                         * TCP */
        /* RD is copied from the query (yes, copying this shouldn't
         * be mandatory, the value of this doesn't matter, but the
         * author of dietlibc is anal about this, so be it; people
         * should listen to DJB when he points out this field
         * doesn't matter in a reply) so not changed */
        h_copy->ra = 0; /* This is a "useless bit of flippery" and
                           is just set to zero, even though recursion is
                           available on TCP connections when we forward a
                           TCP query to a recursive DNS server. */
        h_copy->z = 0; /* This is only valid as 0 in RFC1035 */
        h_copy->rcode = 0; /* It's a valid reply */
        h_copy->qdcount = 1; /* We echo the question they ask, since
                                DNS clients expect the question to be
                                echoed */
        h_copy->ancount = 1; /* The answer */
        h_copy->nscount = 0; /* But, really, the number of NS records in
                                our RR chain; we increment this. */
        h_copy->arcount = 0; /* BIND, thankully, doesn't insist on ARs for
                                the SOA reply */

        /* Determine the number of NS records to put in the header */
        point = state->buffer;

        if(point == 0 && type != 3 && type != 4) {
                js_dealloc(h_copy);
                return JS_ERROR;
        }

        if(type != 3 && type != 4) { /* type 3: SOA at end of AXFR */
                point = point->next;
        }

        if(type == 1) { /* type 1: SOA and any NSes in the authority section */
                while(point != 0) {
                        if(point->rtype != RR_NS) /* Hacky; we should also
                                                     see if the query is not
                                                     for the zone name */
                                break;
                        h_copy->nscount++;
                        if(h_copy->nscount > 1000) {
                                js_dealloc(h_copy);
                                return JS_ERROR;
                        }
                        point = point->next;
                }
        }

        /* Create a reply to send to the user */
        if((reply = js_create(2048,1)) == 0) {
                js_dealloc(h_copy);
                return JS_ERROR;
        }

        /* Put the header in that reply */
        if(make_hdr(h_copy,reply) == JS_ERROR) {
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }

        /* If this is a SOA reply, put in the SOA question */
        if(type == 1) {
                /* Put the question in to the reply */
                if((zone_name = csv2_alabel_to_blabel(zone)) == 0) {
                        js_dealloc(h_copy);
                        js_destroy(reply);
                        return JS_ERROR;
                }
                if(js_append(zone_name,reply) == JS_ERROR) {
                        js_dealloc(h_copy);
                        js_destroy(reply);
                        return JS_ERROR;
                }
                if(js_adduint16(reply,RR_SOA) == JS_ERROR) {
                        js_dealloc(h_copy);
                        js_destroy(reply);
                        return JS_ERROR;
                }
                js_destroy(zone_name);
        } else if(type == 2 || type == 3 || type == RR_AXFR || type == 4) {
                csv2_rr *point;
                if(type == 2 || type == RR_AXFR) {
                        point = state->buffer;
                }
                else {
                        point = soa;
                }
                /* Newer versions of Dig whine if the initial question is
                 * not an AXFR RR type */
                if(type != RR_AXFR && type != 4) {
                    if(js_append(point->query,reply) == JS_ERROR) {
                        js_dealloc(h_copy);
                        js_destroy(reply);
                        return JS_ERROR;
                    }
                    if(js_adduint16(reply,point->rtype) == JS_ERROR) {
                        js_dealloc(h_copy);
                        js_destroy(reply);
                        return JS_ERROR;
                    }
                } else {
                    if(js_append(soa->query,reply) == JS_ERROR) {
                        js_dealloc(h_copy); js_destroy(reply); return JS_ERROR;
                    }
                    if(js_adduint16(reply,RR_AXFR) == JS_ERROR) {
                        js_dealloc(h_copy); js_destroy(reply); return JS_ERROR;
                }}
        } else { /* Shouldn't get here... */
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }

        /* Internet class: Class 1 */
        if(js_adduint16(reply,1) == JS_ERROR) {
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }

        /* Put the answer in to the reply */
        if(type == 1 || type == 2 || type == RR_AXFR) {
                point = state->buffer;
        }
        else if(type == 3 || type == 4) {
                point = soa;
        }
        if(csv2_append_rr(reply,point) == JS_ERROR) {
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }

        /* Put the NS answers in to the reply (only if needed) */
        if(type == 1) {
                point = point->next;
                while(point != 0) {
                        if(point->rtype != RR_NS) { /* Hacky; we should also
                                                       see if the query is not
                                                       for the zone name */
                                break;
                        }
                        if(csv2_append_rr(reply,point) == JS_ERROR) {
                                js_dealloc(h_copy);
                                js_destroy(reply);
                                return JS_ERROR;
                        }
                        point = point->next;
                }
        }

        /* Make len have the length of the reply */
        len[0] = (reply->unit_count & 0xff00) >> 8;
        len[1] = reply->unit_count & 0xff;

        /* Now that the reply has been formulated, chug it down the
         * TCP pipe */
        if(write(connect,len,2) == -1) {
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }
        if(write(connect,reply->string,reply->unit_count) == -1) {
                js_dealloc(h_copy);
                js_destroy(reply);
                return JS_ERROR;
        }

        js_dealloc(h_copy);
        js_destroy(reply);
        return JS_SUCCESS;

}

/* Spit out the SOA record (as a SOA record) over a TCP connection */
int csv2_tcp_spit_soa(csv2_add_state *state, int connect, q_header *header,
                                js_string *zone) {
        return csv2_tcp_spit_data(state,connect,header,zone,1,0);
}

/* Send out all of the zones in a given state's buffer to TCP; clearing
 * the buffer in the process */
int csv2_tcp_spit_buffer(csv2_add_state *state, int connect, q_header *header,
                js_string *zone, csv2_rr *soa) {
        if(state->add_method != 2) { /* We only do this for the zoneserver */
                return JS_ERROR;
        }
        while(state->buffer != 0) {
                if(csv2_tcp_spit_data(state,connect,header,zone,RR_AXFR,soa)
                                == JS_ERROR) {
                        return JS_ERROR;
                }
                csv2_pop_buffer(state);
        }
        return JS_SUCCESS;
}


/* The function we call from the zoneserver; this lets us put the contents
 * of the zone in question available over the TCP socket specified by
 * the calling program (zoneserver)
 * Input: The name of the zone (example.com., etc.) in Alabel format
 *        The name of the file with the zone
 *        The tcp connection socket (connect)
 *        Whether the zone transfer client asked for an SOA recrd (soa_q)
 * Output: JS_SUCCESS if we were able to send the zone over the connection
 *         socket
 */

int csv2_parse_zone_zoneserver(js_string *zone,
                int connect, int soa_q, q_header *header) {
        csv2_add_state *state;
        int x;
        /* q_header *head; */
        csv2_read *stream;
        csv2_rr *soa_save;
        js_string *dvar_name, *filename;

        /* Set up the state we are in */
        if((state = csv2_init_add_state(zone)) == 0) {
                return 0;
        }

        /* Set up the state so that it processes zone server data */
        if(csv2_set_add_method(state,2) == JS_ERROR) {
                csv2_close_state(state);
                return 0;
        }

        /* Get the filename from the mararc parameters (called "dvars"
         * here; short for "dictionary variable") */
        if((filename = js_create(256,1)) == 0) {
                csv2_close_state(state);
                return 0;
        }
        if((dvar_name = js_create(6,1)) == 0) {
                js_destroy(filename);
                csv2_close_state(state);
                return 0;
        }
        if(js_qstr2js(dvar_name,"csv2") == JS_ERROR) {
                js_destroy(filename);
                js_destroy(dvar_name);
                csv2_close_state(state);
                return 0;
        }
        if(read_dvar(dvar_name,zone,filename) == JS_ERROR) {
                js_destroy(filename);
                js_destroy(dvar_name);
                csv2_close_state(state);
                return 0;
        }

        /* Set the timestamp for the SOA serial number if the
         * zone file doesn't have a SOA record; this is based
         * on the last modification time (mtime) for the file */
        if(csv2_set_soa_serial(state,filename) == JS_ERROR) {
                printf("Error running stat() on ");
                show_esc_stdout(filename);
                printf("\n");
        }

        /* Open up the file for reading */
        stream = csv2_open(filename);
        if(stream == 0) {
                printf("Error opening ");
                show_esc_stdout(filename);
                printf("\n");
                csv2_zap_add_state(state);
                return 0;
        }

        /* Read all of the records in the zone until we hit a non-soa
         * or non-authoritative record; this puts such records in
         * the state's buffer of records */
        for(x = 0; x < 29; x++) {
                if(state->in_ns != 1) {
                        break;
                }
                if(csv2_read_rr(state, stream,0) < 0) {
                        break;
                }
        }

        /* If they asked for a SOA record, spit that out on the connection
         * and wait for the next connection */
        if(soa_q == 1) {
                int length;
                unsigned char get[3];
                if(csv2_tcp_spit_soa(state, connect, header, zone)
                                == JS_ERROR) {
                        csv2_zap_add_state(state);
                        return JS_ERROR;
                }
                /* Determine how long the next query will be */
                if(connect == 1) { /* STDIN for inetd hack */
                        if(read(0,get,2) != 1) {
                                csv2_zap_add_state(state);
                                return JS_ERROR;
                        }
                } else {
                        if(recv(connect,get,2,0) != 2) {
                                csv2_zap_add_state(state);
                                return JS_ERROR;
                        }
                }
                length = (get[0] & 0xff) << 8 | (get[1] & 0xff);
                /* Pretend to get the next, actual, query */
                while(length > 0) {
                        if(connect == 1) { /* STDIN; for inetd hack */
                                if(read(0,get,1) != 1) {
                                        csv2_zap_add_state(state);
                                        return JS_ERROR;
                                }
                        } else {
                                if(recv(connect,get,1,MSG_WAITALL) != 1) {
                                        csv2_zap_add_state(state);
                                        return JS_ERROR;
                                }
                        }
                        length--;
                }
        }

        /* OK, at this point we convert the csv2 zone file we are reading
         * and make it become TCP packets */

        /* First, save the inital SOA record so we can tack it on to the
         * end of the zone transfer */
        soa_save = copy_csv2_rr(state->buffer);

        /* Second, flush the buffer out */
        if(csv2_tcp_spit_buffer(state,connect,header,zone,soa_save)
                        == JS_ERROR) {
                js_dealloc(soa_save);
                csv2_zap_add_state(state);
                return JS_ERROR;
        }

        /* Then continually fill up and empty out the buffer */
        for(x = 0 ; x < 100000 ; x++) {
                int c, q;

                q = 0;
                for(c = 0 ; c < 20 ; c++) {
                        q = csv2_read_rr(state, stream, 0);
                        if(q < 0) {
                                break;
                        }
                }

                if(csv2_tcp_spit_buffer(state,connect,header,zone,soa_save) ==
                                JS_ERROR) {
                        js_dealloc(soa_save);
                        csv2_zap_add_state(state);
                        return JS_ERROR;
                }

                if(q < 0) { /* And so we avoid a goto by an extra variable */
                        break;
                }

        }

        /* Finally, give them the first SOA record again */
        if(csv2_tcp_spit_data(state,connect,header,zone,4,soa_save)
                        == JS_ERROR) {
                js_dealloc(soa_save);
                csv2_zap_add_state(state);
                return JS_ERROR;
        }
        csv2_zap_add_state(state);
        return JS_SUCCESS;

}

/* Parse a single zone, when we want to put data in the big hash */
int csv2_parse_zone_bighash(js_string *zone, js_string *filename,
                mhash *bighash, int32 starwhitis) {
        csv2_add_state *state; /* State of adding record to database */

        /* No stars in zone names; yes some people who do not RTFM try
         * this then whine when things don't work */
        int nostar;
        for(nostar = 0; nostar < (zone->unit_size * zone->unit_count);
                        nostar++) {
                if(*(zone->string + nostar) == '*' && zone->unit_count > 1) {
                        printf("Illegal zone name: ");
                        for(nostar = 0; nostar <
                            (zone->unit_size * zone->unit_count); nostar++) {
                                printf("%c",*(zone->string + nostar));
                        }
                        printf("\nThis is a fatal error.\n");
                        exit(1);
                }
        }

        if((state = csv2_init_add_state(zone)) == 0) {
                return 0;
        }
        if(csv2_set_bighash(state,bighash) == JS_ERROR) {
                csv2_close_state(state);
                return 0;
        }
        if(starwhitis == 0) {
                if(csv2_set_add_method(state,1) == JS_ERROR) {
                        csv2_close_state(state);
                        return 0;
                }
        } else if(starwhitis == 1) {
                if(csv2_set_add_method(state,3) == JS_ERROR) {
                        csv2_close_state(state);
                        return 0;
                }
        } else {
                printf("FATAL: Illegal value %d for starwhitis\n",(int)starwhitis);
                exit(1);
        }

        return csv2_parse_zone(filename,state,starwhitis);
}

/* Parse a single zone */
int csv2_parse_zone(js_string *filename, csv2_add_state *state,
                int32 starwhitis) {
        csv2_read *stream;
        int x;

        printf("Processing zone ");
        show_esc_stdout(state->zone);
        printf(" right now.\n");
        printf("Filename: ");
        show_esc_stdout(filename);
        printf("\n");

        /* Set the timestamp for the SOA serial number if the
         * zone file doesn't have a SOA record; this is based
         * on the last modification time (mtime) for the file */
        if(csv2_set_soa_serial(state,filename) == JS_ERROR) {
                printf("Error running stat() on ");
                show_esc_stdout(filename);
                printf("\n");
        }

        stream = csv2_open(filename);
        if(stream == 0) {
                printf("Error opening ");
                show_esc_stdout(filename);
                printf("\n");
                csv2_zap_add_state(state);
                return 0;
        }

        /* If you have more than 100000 records in a single zone, please
         * reconsider your zone management */
        for(x = 0; x < 100000; x++) {
                if(csv2_read_rr(state,stream,starwhitis) < 0) {
                        break;
                }
        }
        csv2_close(stream);
        /* If needed, add the SOA record to the zone; this is for
         * zones with only SOA and NS records */
        if(state->in_ns == 1) {
                csv2_add_soa(state);
        }
        csv2_zap_add_state(state);
        return 0;
}

