/* Copyright (c) 2002-2004 Sam Trenholme
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

#include "../MaraDns.h"
#include "../server/read_kvars.h"

/* This is added so we get no warnings when compiled with -Wall */
extern int make_ip_acl(js_string *in, ipv4pair *out, int max, int depth);

/* Stuff needed so that tcp stuff compiles w/o MaraDNS.c */

int log_level = 1;

ipv4pair *bind_addr_list = 0;
ipv4pair *synthip_addr_list = 0;

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

/* Not in MaraDNS.c: Routines for setting synth_soa_origin and
 * synth_soa_serial */
void set_soa_origin(js_string *in) {
        synth_soa_origin = in;
}
void set_soa_serial(int in) {
        synth_soa_serial = in;
}

/* Obtain a bind address from the kvars.
 * This is used to determine the IPs the zoneserver will bind to
 * Input: type: 1: the bind address
 *              2: the address to synthesize for NS records
 * Output: an ipv4pair containing the bind address. */
ipv4pair *libtcp_bind_address(int type) {
        js_string *bind_address = 0, *ipv4_bind_address = 0,
                  *synthip = 0, *q = 0;

        ipv4pair *out = 0;

        int c;

        bind_address = read_string_kvar("bind_address");
        ipv4_bind_address = read_string_kvar("ipv4_bind_addresses");
        if(type == 2)
                synthip = read_string_kvar("csv2_synthip_list");

        if((out = js_alloc(sizeof(ipv4pair),512)) == 0) {
                js_destroy(bind_address);
                js_destroy(ipv4_bind_address);
                js_destroy(synthip);
                return 0;
        }

        for(c = 0 ; c < 512 ; c++) {
                out[c].ip = 0xffffffff;
        }

        q = bind_address;

        if(js_length(ipv4_bind_address) > 0) {
                q = ipv4_bind_address;
        }
        if(type == 2 && js_length(synthip) > 0) {
                q = synthip;
        }

        if(make_ip_acl(q,out,500,0) == JS_ERROR) {
                js_destroy(bind_address);
                js_destroy(ipv4_bind_address);
                js_destroy(synthip);
                js_dealloc(out);
                return 0;
        }

        js_destroy(bind_address);
        js_destroy(ipv4_bind_address);
        js_destroy(synthip);
        return out;

}

/* Create a bind address list
 * Input: None
 * Output: JS_SUCCESS on success; JS_ERROR on error */

int libtcp_create_bind_addrs() {
        bind_addr_list = libtcp_bind_address(1);
        synthip_addr_list = libtcp_bind_address(2);
        if(bind_addr_list == 0) {
                return JS_ERROR;
        }
        if(synthip_addr_list == 0) {
                return JS_ERROR;
        }
        return JS_SUCCESS;
}

/* Show them the bind address list
 * Input: None
 * Output: The bind address list
 */

/* TO DO: remove this from MaraDNS.c and have MaraDNS.c call this routine */

ipv4pair *get_bind_addr_list() {
        return bind_addr_list;
}

ipv4pair *get_synthip_list() {
        return synthip_addr_list;
}

/* Convert a domain-name query in to its lower-case equivalent
 * Input: Pointer to the js string object with the query
 * Output: JS_ERROR on error, JS_SUCCESS on sucess, 0 on
 * success if no change was made to the string */

/* TO DO: remove this from MaraDNS.c and have MaraDNS.c call this routine */

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
                /* Since A-Z never happen in a domain length label, we can
                 * speed things up a bit */
                if(*(js->string + counter) >= 'A' &&
                                *(js->string + counter) <= 'Z') {
                        *(js->string + counter) += 32;
                        ret = 1;
                }
                counter++;
        }

        return ret;
}

