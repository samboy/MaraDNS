/* Copyright (c) 2004-2011 Sam Trenholme
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

#include "../libs/JsStr.h"
#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "Csv2_database.h"
#include "Csv2_read.h"
#include "Csv2_functions.h"
#include "../dns/functions_dns.h"

/* The following includes are for running stat() */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define WITH_FQDN6

/* Some function prototypes so that the overly anal GCC doesn't
 * generate warnings */
js_string *csv2_copy_js(js_string *s);
int csv2_set_soa(csv2_add_state *state, js_string *query,
                js_string *data, int32 ttl);
int csv2_add_rr_w(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data);
/* We have to do this this way because it is declared in two different
 * places, depending on what program is calling these parsing functions */
extern ipv4pair *get_synthip_list();
extern js_string *show_synth_soa_origin();
extern int show_synth_soa_serial();

/* OK, a word on queries.  Because of the history of MaraDNS' development,
 * there are four ways of internally storing hostnames.  The four ways
 * are:
 *
 * - As an ASCII/UTF-8 label:  "example.com."  We will call this Alabel
 * - As an ASCII/UTF-8 lable with a one-character prefix:  "Aexample.com."
 *   We will call this PAlabel
 * - As a raw binary label: "\007example\003com\000" We will call this
 *   this a Blabel
 * - As a raw binary label with a two-byte rtype suffx:
 *   "\007example\003com\000\000\001" We will call this SBlabel
 */

/* Function to initialize the csv2_add_state for a new zone; this would
 * be in the constructor if we were coding in C++
 * Input: The zone in Alabel format.
 * Output: The initialized csv2 add state
 */

csv2_add_state *csv2_init_add_state(js_string *zone) {
        js_string *nzone, *norigin;
        csv2_add_state *new;
        if(zone->unit_size != 1) {
                return 0;
        }
        if((new = js_alloc(1,sizeof(csv2_add_state))) == 0) {
                return 0;
        }
        if((nzone = js_create(zone->unit_count + 1,1)) == 0) {
                js_dealloc(new);
                return 0;
        }
        if((norigin = js_create(zone->unit_count + 1,1)) == 0) {
                js_dealloc(new);
                return 0;
        }
        if(js_copy(zone,nzone) == JS_ERROR) {
                js_destroy(nzone);
                js_dealloc(new);
                return 0;
        }
        if(js_copy(zone,norigin) == JS_ERROR) {
                js_destroy(nzone);
                js_dealloc(new);
                return 0;
        }
        new->buffer = 0;
        new->zone = nzone; /* This is the "origin" */
        new->origin = norigin; /* This is the "origin" */
        new->ostack = 0; /* A pointer to a "stack" or origin values we can
                          * push or pop */
        new->ostack_height = 0;
        new->rrnum = 0;
        new->bighash = 0;
        new->add_method = 0;
        new->soa_serial = 1;
        new->default_ttl = 86400;
        new->in_ns = 1;
        new->zone_nses_added = 0;
        return new;
}

void csv2_zap_add_state(csv2_add_state *x) {
        int a = 0;
        csv2_origin *v, *q;
        csv2_rr *y, *z;

        /* Get rid of the origin stack */
        v = x->ostack;
        while(v != 0 && a < 10000) {
                js_destroy(v->origin);
                q = v->next;
                js_dealloc(v);
                v = q;
                a++;
        }
        a = 0;

        /* Get rid of the buffer of rrs */
        y = x->buffer;
        while(y != 0 && a < 10000) {
                js_destroy(y->query);
                js_destroy(y->data);
                z = y->next;
                js_dealloc(y);
                y = z;
                a++;
        }
        a = 0;

        /* Get rid of the zone string */
        if(x->zone != 0) {
                js_destroy(x->zone);
                x->zone = 0;
        }
        /* ...the origin string */
        if(x->origin != 0) {
                js_destroy(x->origin);
                x->origin = 0;
        }

        /* And now, finally, get rid of this object, I mean structure */
        js_dealloc(x);
}

/* Function to clean up the memory used by a given csv2_add_state; if this
 * were object-oriented, this function would be the deconstructor for the
 * csv2_add_state */

/* Function to set the big hash we point to
 * Input: Pointer to hash
 * Output: JS_ERROR on error; JS_SUCCESS on success */
int csv2_set_bighash(csv2_add_state *state, mhash *bighash) {
        if(state == 0) {
                return JS_ERROR;
        }
        state->bighash = bighash;
        return JS_SUCCESS;
}

/* Function to set the method we use to process sucessfully parsed
 * records.  Input: numeric method process
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int csv2_set_add_method(csv2_add_state *state, int method) {
        if(state == 0) {
                return JS_ERROR;
        }
        state->add_method = method;
        return JS_SUCCESS;
}

/* Function that closes out the state for processing parsed records;
 * JS_ERROR on error, JS_SUCCESS on success */
int csv2_close_state(csv2_add_state *state) {
        csv2_zap_add_state(state);
        return JS_SUCCESS;
}

/* Function that uses stat() to determine the timestamp to put in the
 * SOA serial for when we synthesize the SOA record;
 * JS_ERROR on error, JS_SUCCESS on success */
int csv2_set_soa_serial(csv2_add_state *state, js_string *filename) {
        char name[256];
        struct stat buf;
        time_t t;
        qual_timestamp q;
        if(js_js2str(filename,name,200) == JS_ERROR) {
                return JS_ERROR;
        }
        if(stat(name,&buf) == -1) {
                return JS_ERROR;
        }
        t = buf.st_mtime;
        /* Y2038 workaround */
        if(t < 290805600) {
            t += 2147483648U;
            }
        if(show_synth_soa_serial() != 2) {
            q = t; /* Type conversion */
            q -= 290805600;
            q /= 6; /* Since the SOA serial is a 32-bit value, this
                       division pushes Y2038-type problems far in to the
                       future */
        } else {
            struct tm bd;
#ifndef MINGW32
            if(gmtime_r(&t,&bd) == NULL) {
               return 1979032815;
               }
#else
            return 2005032801;
#endif
            q = bd.tm_year + 1900;
            q *= 100;
            q += bd.tm_mon + 1;
            q *= 100;
            q += bd.tm_mday;
            q *= 100;
            q += bd.tm_hour;
        }
        state->soa_serial = q; /* Type conversion */
        return JS_SUCCESS;
}

/* Function that converts an ASCII zone file in to a udpzone,
 * returning the new zone as a string on stdout
 * This converts an Alabel to a Blabel */
js_string *csv2_zone_to_udpzone(js_string *zone) {
        js_string *udpzone;
        /* Convert the ASCII-esque zone string in to a udpzone string;
         * modelled after the code in MaraBigHash.c in the function
         * populate_main */
        if((udpzone = js_create(128,1)) == 0) {
                return 0;
        }
        if(js_qstr2js(udpzone,"A") == JS_ERROR) {
                js_destroy(udpzone);
                return 0;
        }
        if(js_append(zone,udpzone) == JS_ERROR) {
                js_destroy(udpzone);
                return 0;
        }
        if(hname_2rfc1035_starwhitis(udpzone,1) == JS_ERROR) {
                js_destroy(udpzone);
                /* We should have better error handling of this.
                 * Or we should check to make sure the zone name is
                 * sane elsewhere */
                return 0;
        }
        return udpzone;
}

/* Function that just shows the rr we would have added; this is mainly
 * for debugging purposes
 * Input: The csv2_add_state, the query (Blabel),
 * the rtype, the ttl, and the data.
 * Output: JS_ERROR on error, JS_SUCCESS on success
 */

int csv2_add_rr_debug(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data) {
        if(state == 0) {
                return JS_ERROR;
        }
        printf("Name: ");
        show_esc_stdout(query);
        printf("\nrtype: %d\nttl %d\n",rtype,(int)ttl);
        printf("rddata: "); show_esc_stdout(data); printf("\n\n");
        return JS_SUCCESS;
}

/* Function to add an rr to the big hash;
 * Input: The csv2_add_state,
 * the query (Blabel), the rtype, the ttl, and the data.
 * Output: JS_ERROR on error; JS_SUCCESS on success
 */

int csv2_add_rr_bighash(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data, int32 starwhitis) {
        js_string *cquery;
        js_string *udpzone;

        /* Sanity checks */
        if(state->bighash == 0) {
                return JS_ERROR;
        }
        if(state->zone == 0) {
                return JS_ERROR;
        }
        if(state->origin == 0) {
                return JS_ERROR;
        }
        if(js_has_sanity(query) == JS_ERROR) {
                return JS_ERROR;
        }
        if(query->unit_size != 1) {
                return JS_ERROR;
        }
        if(js_has_sanity(data) == JS_ERROR) {
                return JS_ERROR;
        }
        if(data->unit_size != 1) {
                return JS_ERROR;
        }
        /* ttl also needs a sane value */
        if(ttl < 60) {
                ttl = 60;
        }
        if(ttl > 63072000) { /* 2 years */
                ttl = 63072000;
        }

        /* Combine query and rtype into a "cquery", since this is
         * how the authoritative code expects to see records */
        if((cquery = js_create(query->unit_count + 3,1)) == 0) {
                return JS_ERROR;
        }
        if(js_copy(query,cquery) == JS_ERROR) {
                js_destroy(cquery);
                return JS_ERROR;
        }
        if(js_adduint16(cquery,rtype) == JS_ERROR) {
                js_destroy(cquery);
                return JS_ERROR;
        }

        if((udpzone = csv2_zone_to_udpzone(state->zone)) == 0) {
                js_destroy(cquery);
                return JS_ERROR;
        }
        /* add_rr_to_bighash expects the "udpzone" to actually be
         * a NS query for the zone */
        if(js_adduint16(udpzone,2) == JS_ERROR) {
                js_destroy(cquery);
                js_destroy(udpzone);
                return JS_ERROR;
        }

        /* Add the record in question to the big hash */
        add_rr_to_bighash(state->bighash,cquery,data,ttl,udpzone,0);
        js_destroy(udpzone);
        js_destroy(cquery);
        return JS_SUCCESS;
}

/* Function to process an rr for the zone server;
 * Input: The csv2_add_state,
 * the query (Blabel), the rtype, the ttl, and the data.
 * Output: JS_ERROR on error; JS_SUCCESS on success
 */

int csv2_add_rr_zoneserver(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data) {

        int ret;
        js_string *cquery;

        /* When this function is called with the RTYPE being SOA, we know
         * that we are no longer going to add NS records to the state */
        if(rtype == RR_SOA) {
                return JS_SUCCESS;
        }

        /* In the case of the query being a star record, we convert
         * MaraDNS' special format for star labels in to a
         * "\x01*" label */
        if(query->unit_count >= 1 && *(query->string) == '_') {
                if((cquery = js_create(query->unit_count + 2,1)) == 0) {
                        return JS_ERROR;
                }

                /* First character will be "\001" */
                if(js_qstr2js(cquery,"\001") == JS_ERROR) {
                        js_destroy(cquery);
                        return JS_ERROR;
                }

                /* Append the query */
                if(js_append(query,cquery) == JS_ERROR) {
                        js_destroy(cquery);
                        return JS_ERROR;
                }

                /* Make the star character a '*' instead of a '_' */
                if(cquery->unit_count < 2) {
                        js_destroy(cquery);
                        return JS_ERROR;
                }
                *(cquery->string + 1) = '*';

                ret = csv2_push_buffer(state, cquery, rtype, ttl, data);
                js_destroy(cquery);
        } else {
                ret = csv2_push_buffer(state, query, rtype, ttl, data);
        }
        return ret;
}

/* Create a synthetic query
 * Input: the csv2_add_state
 * Output: A query (from the state's zone name) suitable for passing
 *         csv2_add_rr_w (in binary rfc1035/1983 format--Blabel) */
js_string *csv2_synth_query(csv2_add_state *state) {

        js_string *query;

        /* Create the query string: '%' */
        if((query = js_create(256,1)) == 0) {
                return 0;
        }
        if(js_qstr2js(query,"Z") == JS_ERROR) {
                js_destroy(query);
                return 0;
        }
        if(js_append(state->zone,query) == JS_ERROR) {
                js_destroy(query);
                return 0;
        }
        if(hname_2rfc1035(query) == JS_ERROR) {
                js_destroy(query);
                return 0;
        }
        return query;
}

/* If needed, synthesize a soa record for this zone */
int csv2_synthesize_soa(csv2_add_state *state) {
        js_string *query, *email, *data;
        int ret;

        /* Create the query string */
        if((query = csv2_synth_query(state)) == 0) {
                return JS_ERROR;
        }

        /* Create the data:
         * '% hostmaster@% {tstamp} 7200 3600 604800 1800' */
        /* field 1 (SOA origin / MNAME): % */
        if((data = js_create(256,1)) == 0) {
                js_destroy(query);
                return JS_ERROR;
        }
        if(show_synth_soa_origin() == 0) { /* If no soa origin set, use the
                                              domain name */
            if(js_copy(query,data) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
            }
        } else { /* Otherwise use soa origin value */
            if(js_copy(show_synth_soa_origin(),data) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
                }
        }

        /* field 2 (Rname: email of person in charge of domain):
             hostmaster@% */
        if((email = js_create(256,1)) == 0) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }
        if(js_qappend("Zhostmaster.",email) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                js_destroy(email);
                return JS_ERROR;
        }
        if(js_append(state->zone,email) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                js_destroy(email);
                return JS_ERROR;
        }
        if(hname_2rfc1035(email) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                js_destroy(email);
                return JS_ERROR;
        }
        if(js_append(email,data) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                js_destroy(email);
                return JS_ERROR;
        }
        js_destroy(email);

        /* field 3 (serial): {tstamp} */
        if(js_adduint32(data,state->soa_serial) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }

        /* field 4 (refresh): 7200 */
        if(js_adduint32(data,7200) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }

        /* field 5 (retry): 3600 */
        if(js_adduint32(data,3600) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }

        /* field 6 (expire): 604800 */
        if(js_adduint32(data,604800) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }

        /* field 7 (minimum): 3600 */
        if(js_adduint32(data,3600) == JS_ERROR) {
                js_destroy(query);
                js_destroy(data);
                return JS_ERROR;
        }

        ret = csv2_set_soa(state, query, data, 86400);
        js_destroy(query);
        js_destroy(data);
        return ret;
}

/* Make a single synthetic A record, given a certain IP.
 * Input: The state (since we store the record), the ip address, whether
 *        we actually make the record (1) or just the blabel (0)
 * Output: The Blabel with the record in question.
 */
js_string *csv2_synth_ip(csv2_add_state *state, uint32 ip,
                int actually_make_record) {
        /* Create the string that stores the synth Blabel name */
        js_string *name;
        js_string *rddata;
        int c;
        int32 q;

        /* Create the string that stores the synthetic NS data */
        if((name = js_create(20 + state->zone->unit_count,1)) == 0) {
                return 0;
        }
        if(js_qstr2js(name,"Zsynth-ip-") == 0) {
                js_destroy(name);
                return 0;
        }
        q = ip;
        for(c = 0 ; c < 8 ; c++) {
                int32 x;
                x = q;
                x >>= 28;
                x &= 0xf;
                if(x < 10) {
                        if(js_addbyte(name,'0' + x) == JS_ERROR) {
                                js_destroy(name);
                                return 0;
                        }
                } else {
                        if(js_addbyte(name,'a' + (x - 10)) == JS_ERROR) {
                                js_destroy(name);
                                return 0;
                        }
                }
                q <<= 4;
        }
        if(js_qappend(".",name) == JS_ERROR) {
                js_destroy(name);
                return 0;
        }
        if(js_append(state->zone,name) == JS_ERROR) {
                js_destroy(name);
                return 0;
        }
        if(hname_2rfc1035(name) == JS_ERROR) {
                js_destroy(name);
                return 0;
        }

        /* Sometimes, we just want the name without actually creating
         * the IP record */
        if(actually_make_record != 1) {
                return name;
        }

        /* Now, create an A record pointing to the information and
         * store that record in the method specified to store the
         * record */
        if((rddata = js_create(5,1)) == 0) {
                js_destroy(name);
                return 0;
        }
        for(c = 3 ; c >= 0 ; c--) {
                *(rddata->string + c) = ip & 0xff;
                ip >>= 8;
        }
        rddata->unit_count = 4;
        if(csv2_add_rr_w(state,name,RR_A,86400,rddata) == JS_ERROR) {
                js_destroy(name);
                js_destroy(rddata);
                return 0;
        }
        js_destroy(rddata);

        return name;

}

/* Make a single synthetic NS record */
int csv2_make_synth_ns(csv2_add_state *state, uint32 ip) {
        /* We create two records: 1) The synth NS record
         * 2) The synth A record */
        /* int c;
           uint32 q; */
        js_string *query, *data;

        /* Create the string that stores the synthetic query string */
        if((query = csv2_synth_query(state)) == 0) {
                return JS_ERROR;
        }

        /* Create an IP that stores the data in question */
        if((data = csv2_synth_ip(state, ip, 0)) == 0) {
                js_destroy(query);
                return JS_ERROR;
        }

        /* Store that data */
        csv2_add_rr_w(state, query, RR_NS, 86400, data);
        js_destroy(query);
        js_destroy(data);
        return JS_SUCCESS;
}

/* tell us if we are looking at a private IP (rfc1918 or localhost)
 * 0: No, we're not looking at one
 * 1: Yes, we're are looking at one */
int csv2_is_private_ip(uint32 ip) {
        return (((ip & 0xff000000) == 0x7f000000) || /* localhost */
                ((ip & 0xff000000) == 0x0a000000) || /* rfc1918 */
                ((ip & 0xfff00000) == 0xac100000) || /* rfc1918 */
                ((ip & 0xffff0000) == 0xc0a80000));  /* rfc1918 */
}

/* tell us if we are looking at a localhost IP
 * 0: Nope
 * 1: yep */
int csv2_is_localhost_ip(uint32 ip) {
        return ((ip & 0xff000000) == 0x7f000000);
}

/* If needed, synthesize NS records for this zone; this code
 * assumes that people without NS records are on ipv4 addresses */
int csv2_synthesize_ns(csv2_add_state *state) {
        /* Find out what IPs this machine is bound to */
        ipv4pair *iplist;
        int c;
        int public_ips = 0;
        int non_localhost_ips = 0;
        js_string *tmp;

        iplist = get_synthip_list();

        /* Make sure we do not have any "0.0.0.0" addresses in
         * this list; if we do, we need to abort and *not*
         * synthesize NS records */
        for(c = 0 ; c < 500 ; c++) {
                if(iplist[c].ip == 0xffffffff) {
                        break;
                }
                if(iplist[c].ip == 0) {
                        printf("Warning: No NS records can be syntesized\n");
                        return JS_ERROR;
                }
        }

        /* Next: see if we have any public ips */
        for(c = 0 ; c < 500 ; c++) {
                if(iplist[c].ip == 0xffffffff) {
                        break;
                }
                if(!csv2_is_private_ip(iplist[c].ip)) {
                        public_ips = 1;
                        non_localhost_ips = 1;
                }
        }

        /* Next: see if we have any non-localhost ips */
        if(public_ips != 1) {
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        if(!csv2_is_localhost_ip(iplist[c].ip)) {
                                non_localhost_ips = 1;
                        }
                }
        }

        /* Now, synthesize ns records */
        if(public_ips == 1) {
                /* Synthesize the NS records */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        if(!csv2_is_private_ip(iplist[c].ip)) {
                                csv2_make_synth_ns(state,iplist[c].ip);
                        }
                }
                /* Now, synthesize the IPs */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        if(!csv2_is_private_ip(iplist[c].ip)) {
                                tmp = csv2_synth_ip(state,iplist[c].ip,1);
                                js_destroy(tmp);
                        }
                }
        }
        else if(non_localhost_ips == 1) {
                /* Synthesize the NS records */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        if(!csv2_is_localhost_ip(iplist[c].ip)) {
                                csv2_make_synth_ns(state,iplist[c].ip);
                        }
                }
                /* Now, synthesize the IPs */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        if(!csv2_is_localhost_ip(iplist[c].ip)) {
                                tmp = csv2_synth_ip(state,iplist[c].ip,1);
                                js_destroy(tmp);
                        }
                }
        }
        else {
                /* Syntheisze the NS records */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        csv2_make_synth_ns(state,iplist[c].ip);
                }
                /* Now, synthesize the IPs */
                for(c = 0; c < 500 ; c++) {
                        if(iplist[c].ip == 0xffffffff) {
                                break;
                        }
                        tmp = csv2_synth_ip(state,iplist[c].ip,1);
                        js_destroy(tmp);
                }
        }

        return JS_SUCCESS;
}

/* Create a copy of a csv2_rr; this will *not* copy the entire
 * chain, but only the record at the top of the chain */
csv2_rr *copy_csv2_rr(csv2_rr *source) {
        csv2_rr *new;
        js_string *q, *d;

        if((q = csv2_copy_js(source->query)) == 0) {
                return 0;
        }
        if((d = csv2_copy_js(source->data)) == 0) {
                js_destroy(q);
                return 0;
        }

        /* Create the new entry to add */
        if((new = js_alloc(sizeof(csv2_rr),1)) == 0) {
                js_destroy(q);
                js_destroy(d);
                return 0;
        }
        new->query = q;
        new->data = d;
        new->rtype = source->rtype;
        new->ttl = source->ttl;
        new->next = 0;

        return new;
}

/* Push an RR to the state's buffer
 * Input: The query, rtype, etc. of what we will add.
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int csv2_push_buffer(csv2_add_state *state, js_string *query, int rtype,
                int32 ttl, js_string *data) {
        js_string *q, *d;
        csv2_rr *new;
        csv2_rr *point;
        int x;

        if((q = csv2_copy_js(query)) == 0) {
                return JS_ERROR;
        }
        if((d = csv2_copy_js(data)) == 0) {
                js_destroy(q);
                return JS_ERROR;
        }

        /* Create the new entry to add */
        if((new = js_alloc(sizeof(csv2_rr),1)) == 0) {
                js_destroy(q);
                js_destroy(d);
                return JS_ERROR;
        }
        new->query = q;
        new->data = d;
        new->rtype = rtype;
        new->ttl = ttl;
        new->next = 0;

        /* Add said entry to the linked list; this is O(N)
         * inefficient */
        if(state->buffer == 0) {
                state->buffer = new;
        }
        point = state->buffer;

        /* We only allow 64 things in the buffer because it gets slower and
         * slower to add things to the end */
        if(state->buffer != new) {
                for(x = 0; x < 64 ; x++) {
                        if(point->next == 0) {
                                break;
                        }
                        point = point->next;
                }
        }

        /* Error if there are too many things in the buffer */
        if(state->buffer != new && point->next != 0) {
                js_destroy(q);
                js_destroy(d);
                js_dealloc(new);
                return JS_ERROR;
        }

        if(state->buffer != new) {
                point->next = new;
        }
        return JS_SUCCESS;
}


/* Get the soa in a state.
 * Input: The raw js_string query and data; the ttl
 * Output: JS_ERROR on error; JS_SUCCESS on success */

int csv2_set_soa(csv2_add_state *state, js_string *query, js_string *data,
                int32 ttl) {

        return csv2_push_buffer(state, query, RR_SOA, ttl, data);
}

/* Check to see if the query is the same as the zone in state
 * Input: the state, a query
 * Output: 1 if they are the same, 0 otherwise */
int csv2_is_zonetop(csv2_add_state *state, js_string *query) {
        js_string *q;

        if((q = csv2_zone_to_udpzone(state->zone)) == 0) {
                return 0;
        }
        if(js_issame(q,query) == 1) {
                js_destroy(q);
                return 1;
        }
        js_destroy(q);
        return 0;
}

/* Pop the top record from the state's buffer of records, adding it to
 * the cache (or doing whatever processing we're doing) */
int csv2_pop_buffer(csv2_add_state *state) {
        csv2_rr *save;
        int ret;
        if(state->buffer == 0) {
                return 0;
        }

        save = state->buffer->next;
        /* We do nothing except erase the record when the method is
         * 2 (zone server), since the zone server processes a record by
         * tacking it on to the end of the buffer */
        if(state->add_method != 2) {
                ret = csv2_add_rr_w(state, state->buffer->query,
                                state->buffer->rtype, state->buffer->ttl,
                                state->buffer->data);
        } else {
                ret = JS_SUCCESS;
        }
        if(ret != JS_ERROR) {
                js_destroy(state->buffer->query); /* This is copied in
                                                     csv2_add_rr_w */
                js_destroy(state->buffer->data); /* We finally copy this in
                                                  * mhash_put_rr/mhash_add_rr */
                js_dealloc(state->buffer);
                state->buffer = save;
        }
        return ret;
}

/* Add the SOA record in the state to the zone in question */
int csv2_add_soa(csv2_add_state *state) {
        if(state->in_ns != 1) {
                return JS_ERROR;
        }
        if(state->buffer == 0 || state->buffer->rtype != RR_SOA) {
                return JS_ERROR;
        }
        state->in_ns = 0;
        return csv2_pop_buffer(state);
}

/* Routine that simply makes a copy of a js_string object,
 * returning the copy of that object. */
js_string *csv2_copy_js(js_string *s) {
        js_string *c;
        if(s->unit_size != 1) {
                return 0;
        }
        if((c = js_create(s->unit_count + 1,1)) == 0) {
                return 0;
        }
        if(js_copy(s,c) == JS_ERROR) {
                js_destroy(c);
                return 0;
        }
        return c;
}

/* Wrapper to make sure all of the authoritative
 * stuff for the zone is setup (regardless of whether said authoritative
 * data is in the actual zone file) before adding the SOA record */
int csv2_add_rr(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data) {

        /* Check to see if the first record is a SOA record */
        state->rrnum++;
        if(state->rrnum == 1 && rtype != RR_SOA && state->add_method != 3) {
                /* Synthesize a soa record if it isn't */
                csv2_synthesize_soa(state);
        }
        else if(state->rrnum == 1 && rtype != RR_SOA &&
                        state->add_method == 3) { /* Error */
                printf("Please put an SOA record in the default zone file\n");
                return JS_ERROR;
        }
        else if(state->rrnum == 1) { /* Set initial SOA record from zone */
                return csv2_set_soa(state, query, data, ttl);
        }
        else if(rtype == RR_SOA) {
                /* We only allow a single SOA record at the top of the
                 * zone */
                printf("Warning: Only one SOA per zone file.\n"
                        "This SOA must be the first record in the zone.\n"
                                "Other SOA records are ignored\n");
                return JS_ERROR;
        }

        /* We check to see if the zone has authoritative NS records
         * in it near the top.  If it does, then we note this, so
         * that we don't need to synthesize NS records for this
         * domain */
        if(state->zone_nses_added == 0 && state->in_ns == 1 &&
                        rtype == RR_NS && csv2_is_zonetop(state,query)) {
                state->zone_nses_added = 1;
        }

        /* We give out a warning if they put authoritative NS records
         * for the domain anywhere except the domain top */
        if(state->in_ns == 0 && rtype == RR_NS &&
                        csv2_is_zonetop(state,query)) {
                printf("Warning: Authoritative NSes must be "
                                "immediately after SOA\n"
                                "Or the first records in the zone\n"
                                "Otherwise, the record is ignored\n");
                return JS_ERROR;
        } else
        /* We do not allow delegation NS records in the default zonefile */
        if(state->in_ns == 0 && rtype == RR_NS && state->add_method == 3) {
                printf("Warning: Delegation NS records are not permitted "
                       "in\nthe default zonefile.  This record is ignored\n");
                return JS_ERROR;
        } else
        /* We also do not permit CNAME records in the default zonefile */
        if(rtype == RR_CNAME && state->add_method == 3) {
                printf("Warning: CNAME records are not permitted "
                       "in the\ndefault zonefile.  This record is ignored\n");
                return JS_ERROR;
        }

        /* Once we are past all of the authority records (the SOA
         * and all NSes for this zone), we add the SOA record.
         * We do it this way so that the SOA record has NS records in
         * its authority section */

        if(state->in_ns == 1 && (rtype != RR_NS ||
                                !csv2_is_zonetop(state,query))) {
                /* If no authoritative NS records exist for this
                 * domain, then we synthesize NS records for this
                 * domain */
                if(state->zone_nses_added == 0 &&
                                state->add_method != 3) {
                        csv2_synthesize_ns(state);
                }
                if(state->zone_nses_added == 0 &&
                                state->add_method == 3) {
                        printf(
                        "Please include NS records in a default zone file\n");
                        return JS_ERROR;
                }
                if(state->add_method != 2) {
                        csv2_add_soa(state);
                }
                state->in_ns = 0;
        }

        return csv2_add_rr_w(state, query, rtype, ttl, data);

}

/* Given a binary js_string object with an IP in it (e.g. "127.0.0.1"
   is, in hexadecimal "7f000001" in the input), create the corresponding
   ptr label as a Blabel ("\x011\x010\x010\x03127\x07in-addr\x04arpa\x00"
   in the "7f000001" case). */

js_string *csv2_make_ptr_query(js_string *binary_ip) {
        js_string *ptr_label;
        int len = 0;
        int counter = 0;

        /* Sanity check */
        if(js_length(binary_ip) != 4)
                return 0;

        ptr_label = js_create(31,1); /* Maximum possible length for this */
        if(ptr_label == 0) {
                return 0;
        }

        /* This for loop handles the "d.c.b.a" part of
           "d.c.b.a.in-addr.arpa." */
        for(counter = 3; counter >= 0; counter--) {
                char a;
                int b;
                int c = 1;
                int d;
                a = (*(binary_ip->string + counter));

                /* The following sillyness is because some versions of
                   GCC on some ports of linux don't have "unsigned char" */
                b = a;
                b &= 0xff;

                if(b < 0) {
                        b += 128;
                }
                if(b > 99) {
                        c++; /* Not the programming language */
                }
                if(b > 9) {
                        c++;
                }
                if(len <= 30)
                        *(ptr_label->string + len) = c;
                d = c;
                while(c > 0) {
                        if(len + c <= 30)
                                *(ptr_label->string + len + c) = '0' + b % 10;
                        b /= 10;
                        c--;
                }
                len++;
                len += d;
        }

        /* Reset the length of the string */
        if(len < ptr_label->max_count)
                ptr_label->unit_count = len;

        /* And now, end it off with "in-addr.arpa." */
        js_qappend(".in-addr.arpa.",ptr_label);
        if(len <= 30) {
                *(ptr_label->string + len) = 7; /* "in-addr" length */
        }
        len += 8;
        if(len <= 30) {
                *(ptr_label->string + len) = 4; /* "arpa" length */
        }
        len += 5;
        if(len <= 30) {
                *(ptr_label->string + len) = 0; /* null to end dlabel */
        }

        return ptr_label;
}

/* Given a binary js_string object with an IP in it (e.g. "127.0.0.1"
   is, in hexadecimal "7f000001" in the input), create the corresponding
   ptr label as a Blabel ("\x011\x010\x010\x03127\x07in-addr\x04arpa\x00"
   in the "7f000001" case). */

#ifdef WITH_FQDN6
js_string *csv2_make_ptr6_query(js_string *binary_ip) {
        js_string *ptr_label;
        int len = 0;
        int counter = 0;

        /* Sanity check */
        if(js_length(binary_ip) != 16)
                return 0;

        ptr_label = js_create(256,1); /* Maximum possible length for this */
        if(ptr_label == 0) {
                return 0;
        }

        for(counter = 15; counter >= 0; counter--) {
                char a;
                int b;

                a = (*(binary_ip->string + counter));

                /* low nibble */
                *(ptr_label->string + len) = 1;
                len++;
                b = a & 0x0f;
                if ( b > 9 ) b += 'a' - 10;
                else         b += '0';
                *(ptr_label->string + len) = b;
                len++;

                /* high nibble */
                *(ptr_label->string + len) = 1;
                len++;
                b = (a >> 4) & 0x0f;
                if ( b > 9 ) b += 'a' - 10;
                else         b += '0';
                *(ptr_label->string + len) = b;
                len++;
        }

        if(len <= 250) {
                *(ptr_label->string + len)   =  3;  /* "ipv6" length */
                *(ptr_label->string + len+1) = 'i'; /* "ipv6 */
                *(ptr_label->string + len+2) = 'p';
                *(ptr_label->string + len+3) = '6';
                len += 4;
        }

        if(len <= 250) {
                *(ptr_label->string + len) = 4;     /* "arpa" length */
                *(ptr_label->string + len+1) = 'a'; /* "ipv6 */
                *(ptr_label->string + len+2) = 'r';
                *(ptr_label->string + len+3) = 'p';
                *(ptr_label->string + len+4) = 'a';
                len += 5;
        }
        if(len <= 255) {
                *(ptr_label->string + len) = 0; /* null to end dlabel */
                len++;
        }
        ptr_label->unit_size=1;
        ptr_label->unit_count=len;
        return ptr_label;
}
#endif

/* Function to add an rr in general */
/* Note: "query" is a Blabel */
int csv2_add_rr_w(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data) {
        js_string *cquery;
        int ret = -1, counter = -1;
        if(state == 0) {
                return JS_ERROR;
        }

        /* cquery is a lower-case copy of query */
        if((cquery = js_create(query->unit_count + 1,1)) == 0) {
                return JS_ERROR;
        }
        if(js_copy(query,cquery) == JS_ERROR) {
                js_destroy(cquery);
                return JS_ERROR;
        }

        /* Make cquery lower-case */
        counter = 0;
        if(cquery->unit_count < 0) {
                js_destroy(cquery);
                return JS_ERROR;
        }
        /* A-Z, nicely enough, never happen in a domain length label,
          so we can very quickly make this label lower-case */
        while(counter < cquery->unit_count) {
                if(*(cquery->string + counter) >= 'A' &&
                   *(cquery->string + counter) <= 'Z') {
                        *(cquery->string + counter) += 32;
                }
                counter++;
        }

        /* The "magic" rtype of 65765 means that we add this as an
           A record, then add a PTR record (which is created from the
           A record) as needed; this is spelled "FQDN4" in the zone file */
        if(rtype == 65765 && state->add_method != 3) {
            js_string *pq;
            rtype = 1;
            pq = csv2_make_ptr_query(data);
            /* This can not infinitely recurse because we change the
             * rtype from the magic 65765 rtype */
            csv2_add_rr_w(state,pq,RR_PTR,ttl,cquery);
            js_destroy(pq);
        } else if(rtype == 65765 && state->add_method == 3) {
            printf("Warning: FQDN4 records are not permitted "
                   "in the\ndefault zonefile.  This record is ignored.\n");
            js_destroy(cquery);
            return JS_ERROR;
            }
#ifdef WITH_FQDN6
        if(rtype == 65766 && state->add_method != 3) {
                js_string *pq;
                rtype = RR_AAAA;
                pq = csv2_make_ptr6_query(data);
                /* This can not infinitely recurse because we change the
                * rtype from the magic 65766 rtype */
                csv2_add_rr_w(state,pq,RR_PTR,ttl,cquery);
                js_destroy(pq);
        } else if(rtype == 65766 && state->add_method == 3) {
                printf("Warning: FQDN6 records are not permitted "
                       "in the\ndefault zonefile.  This record is ignored.\n");
                js_destroy(cquery);
                return JS_ERROR;
        }
#endif
        ret = JS_ERROR; /* This should be set to another value */
        switch(state->add_method) {
                case 1: /* Adding records to MaraDNS-1 style "bighash" */
                        ret = csv2_add_rr_bighash(state, cquery, rtype,
                                        ttl, data, 0);
                        break;
                case 2: /* The zone servers way of processing records */
                        ret = csv2_add_rr_zoneserver(state, cquery, rtype,
                                        ttl, data);
                        break;
                case 3: /* Identical to case one, as it turns out; this
                           last argument is ignored.  However, this
                           is when we are adding records to the
                           "csv2_default_zonefile" */
                        ret = csv2_add_rr_bighash(state, cquery, rtype,
                                        ttl, data, 1);
                        break;
                default:
                        ret = csv2_add_rr_debug(state, cquery, rtype,
                                        ttl, data);
        }
        js_destroy(cquery);
        return ret;
}

