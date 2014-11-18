/* Copyright (c) 2002-2006 Sam Trenholme
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


/* Parse a mararc file */

#include "../MaraDns.h"
#include "../libs/MaraHash.h"
#include "ParseCsv1_en.h"
#include <stdlib.h>
#ifndef MINGW32
#include <pwd.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include "functions_parse.h"

/* Convert a dotted-decimal IP (in a js_string object) followed by
   a netmask in to a raw IP and netmask, using a ipv4pair object.
   The input data is in the form 10.69.69.69/24 or 10.69.69.69/255.255.0.0
   The output will be a binary IP and netmask, in network order.
   input: pointer to dotted decimal data, pointer to ipv4pair object to
          place raw IP in to, offset from top to start looking
   output: JS_ERROR on error, pointer to first non-ip byte on SUCCESS
           (-2 if no non-ip byte was found)
*/

int ddip_ip_mask(js_string *ddip, ipv4pair *ips, int offset) {
    int qr, counter,firstoffset,slashp;
    int ret;

    unsigned char ip_byte;

    static js_string *dotq = 0;
    static js_string *numdotq = 0;
    static js_string *slashq = 0;
    static uint32 masks[33] = {
    0x00000000,
    0x80000000,
    0xc0000000,
    0xe0000000,
    0xf0000000,
    0xf8000000,
    0xfc000000,
    0xfe000000,
    0xff000000,
    0xff800000,
    0xffc00000,
    0xffe00000,
    0xfff00000,
    0xfff80000,
    0xfffc0000,
    0xfffe0000,
    0xffff0000,
    0xffff8000,
    0xffffc000,
    0xffffe000,
    0xfffff000,
    0xfffff800,
    0xfffffc00,
    0xfffffe00,
    0xffffff00,
    0xffffff80,
    0xffffffc0,
    0xffffffe0,
    0xfffffff0,
    0xfffffff8,
    0xfffffffc,
    0xfffffffe,
    0xffffffff };

    char dot = '.';
    char slash = '/';

    /* Sanity checks */
    if(mara_goodjs(ddip) == JS_ERROR)
        return JS_ERROR;
    if(ips == 0)
        return JS_ERROR;

    /* Allocate string if this is the first time we are running this */
    if(dotq == 0) {
        if((dotq = js_create(7,1)) == 0)
            return JS_ERROR;
        /* Place a dot in that string */
        if(js_str2js(dotq,&dot,1,1) == JS_ERROR) {
            js_destroy(dotq);
            dotq = 0;
            return JS_ERROR;
            }
        }
    if(numdotq == 0) {
        if((numdotq = js_create(211,1)) == 0)
            return JS_ERROR;
        if(js_set_encode(numdotq,JS_8859_1) == JS_ERROR) {
            js_destroy(numdotq);
            numdotq = 0;
            return JS_ERROR;
            }
        /* Place numbers in that string */
        if(js_numbers(numdotq) == 0) {
            js_destroy(numdotq);
            numdotq = 0;
            return JS_ERROR;
            }
        /* Add the dot to that regex */
        if(js_append(dotq,numdotq) == JS_ERROR) {
            js_destroy(numdotq);
            numdotq = 0;
            return JS_ERROR;
            }
        }
    if(slashq == 0) {
        if((slashq = js_create(7,1)) == 0)
            return JS_ERROR;
        /* Place a slash in that string */
        if(js_str2js(slashq,&slash,1,1) == JS_ERROR) {
            js_destroy(slashq);
            slashq = 0;
            return JS_ERROR;
            }
        }

    /* Keep track of where we begin looking in the string */
    firstoffset = offset;

    /* See the first non number/dot after the offset */
    ret = js_notmatch_offset(numdotq,ddip,offset);
    /* If it returned an error, or the character at the offset is not
       a number nor a dot, return an error */
    if(ret == JS_ERROR || ret == offset)
        return JS_ERROR;

    /* Begin the ddip (dotted decimal IP) to raw binary ip conversion */
    if(js_length(ddip) < offset + 1)
        return JS_ERROR;

    ips->ip = 0;

    for(counter = 0; counter < 4; counter++) {
        if(offset == -2)
            return JS_ERROR;

        qr = js_atoi(ddip,offset);

        if(qr < 0 || qr > 255)
            return JS_ERROR;

        ip_byte = qr;

        /* Add the byte in question to the ipv4pair object */
        ips->ip |= (ip_byte & 0xff) << (24 - 8 * counter);

        /* Return error if there was a non-number/dot in the IP */
        if(counter == 4 && ret < offset)
            return JS_ERROR;

        offset = js_match_offset(dotq,ddip,offset + 1);
        if(offset == JS_ERROR)
            return JS_ERROR;

        offset++;
        }

    /* If no slash immediately after, assumes the netmask is 255.255.255.255 */
    if(js_match_offset(slashq,ddip,firstoffset) != ret ||
       js_match_offset(slashq,ddip,firstoffset) == -2) {
        ips->mask = 0xffffffff;
        return ret;
        }
    slashp = ret;

    /* There are two possible formats we have to deal with:
       10.69.69.69/255.255.255.0 and 10.69.69.69/24.  */
    ret = js_match_offset(dotq,ddip,slashp + 1);
    if(ret == JS_ERROR)
        return JS_ERROR;
    offset = js_notmatch_offset(numdotq,ddip,slashp + 1);
    if(offset == JS_ERROR)
        return JS_ERROR;
    /* If it is in a 10.69.69.69/24 form */
    if(ret == -2 || (offset < ret && offset != -2)) {
        ret = js_atoi(ddip,slashp + 1);
        if(ret < 0 || ret > 32)
            return JS_ERROR;
        ips->mask = masks[ret];
        if(offset + 1 < ddip->unit_count)
            return offset + 1;
        else
            return -2;
        }
    else {
        offset = slashp + 1;
        ips->mask = 0;
        for(counter = 0; counter < 4; counter++) {
            if(offset == -2)
                return JS_ERROR;

            qr = js_atoi(ddip,offset);

            if(qr < 0 || qr > 255)
                return JS_ERROR;

            ip_byte = qr;

            /* Add the byte in question to the ipv4pair object */
            ips->mask |= (ip_byte & 0xff) << (24 - 8 * counter);

            if(counter != 3) {
                offset = js_match_offset(dotq,ddip,offset + 1);
                if(offset == JS_ERROR)
                    return JS_ERROR;
                }
            else
                return js_notmatch_offset(numdotq,ddip,offset + 1);

            offset++;
            }
        return JS_ERROR; /* We should never get here */
        }

    return JS_ERROR; /* We should never get here */
    }

/* Make a list of ip addresses and netmasks that are allowed to connect to
   the zone server.

   Input: Pointer to object containing a list of either ip/netmask
          pairs (10.1.1.1/24 or 10.1.1.1/255.255.255.0 form) or
          an alias (e.g. ipv4_alias["foo"] = "10.1.1.1/24"
                         ipv4_alias["bar"] = "10.2.2.2/24"
                    followed by zone_transfer_acl = "foo,bar"),
          Pointer to list of ipv4pair objects (ip, mask),
          maximum number of ipv4objects allowed in "out"
          array,
          pointer to where from beginning of string to put the
          next ipv4object (allows recursion),
          recursion depth (stops loops)

   Output: JS_SUCCESS on success, JS_ERROR on error
*/

int make_ip_acl(js_string *in, ipv4pair *out, int max, int depth) {

    js_string *sub = 0, *delimq = 0, *value = 0;
    int start, next, index = 0;
    char delim = ',';

    /* Sanity checks */
    if(depth > 32)
        return JS_ERROR;
    if(js_has_sanity(in) == JS_ERROR)
        return JS_ERROR;
    if(in->unit_size != 1)
        return JS_ERROR;
    if(out == 0)
        return JS_ERROR;

    /* Create the "sub" string */
    if((sub = js_create(256,1)) == 0)
        return JS_ERROR;
    if(js_set_encode(sub,MARA_LOCALE) == JS_ERROR)
        return JS_ERROR;
    if((value = js_create(512,1)) == 0)
        return JS_ERROR;
    if(js_set_encode(value,MARA_LOCALE) == JS_ERROR)
        return JS_ERROR;
    if((delimq = js_create(7,1)) == 0) {
        js_destroy(sub);
        return JS_ERROR;
        }
    if(js_str2js(delimq,&delim,1,1) == JS_ERROR) {
        js_destroy(sub); js_destroy(value); js_destroy(delimq);
        return JS_ERROR;
        }

    next = -1;
    do {
        start = next + 1;
        /* Look for the next comma */
        next = js_match_offset(delimq,in,start);
        if(next == JS_ERROR) {
            js_destroy(sub); js_destroy(delimq); js_destroy(value);
            return JS_ERROR;
            }
        /* If there is no next comma */
        if(next == -2) {
            int nx = in->unit_count - 1;
            /* If there is leading space, skip past it; hackey code */
            while(start < nx && *(in->string + start) == ' ') {
                start++;
                }
            /* Hacky code to lop off trailing whitespace */
            while(nx > start && (*(in->string + nx) == ' ' ||
                                  *(in->string + start) == '\t')) {
                if(nx >= 0) {
                    nx--;
                    }
                else {
                    js_destroy(sub); js_destroy(delimq); js_destroy(value);
                    return JS_ERROR;
                    }
                }
            /* Make the string "sub" go to the end of the string */
            if(js_substr(in,sub,start,(nx + 1) - start) == JS_ERROR) {
                js_destroy(sub); js_destroy(delimq); js_destroy(value);
                return JS_ERROR;
                }
            }
        else {
            int nx = next;
            /* If there is leading space, skip past it; hackey code */
            while(start < nx && (*(in->string + start) == ' ' ||
                                    *(in->string + start) == '\t')) {
                start++;
                }
            /* Hacky code to lop off trailing whitespace */
            while((nx > start) && ((*(in->string + nx) == ' ') ||
                                  (*(in->string + start) == '\t') ||
                                 (*(in->string + nx) == ','))) {
                if(nx >= 0) {
                    nx--;
                    }
                else {
                    js_destroy(sub); js_destroy(delimq); js_destroy(value);
                    return JS_ERROR;
                    }
                }
            /* Make the string "sub" go to the next comma */
            if(js_substr(in,sub,start,(nx + 1) - start) == JS_ERROR) {
                js_destroy(sub); js_destroy(delimq); js_destroy(value);
                return JS_ERROR;
                }
            }
        /* See if an alias for the value exists */
        if(js_qstr2js(value,"ipv4_alias") == JS_ERROR) {
            js_destroy(sub); js_destroy(delimq); js_destroy(value);
            return JS_ERROR;
            }
        /* If so, recurse */
        if(read_dvar(value,sub,value) != JS_ERROR) {
            if(make_ip_acl(value,out,max,depth + 1) == JS_ERROR) {
                js_destroy(sub); js_destroy(delimq); js_destroy(value);
                return JS_ERROR;
                }
            }
        /* Otherwise, add the ip/netmask to the out array */
        else {
            /* Find the end of the array */
            while(index < max && (out[index]).ip != 0xffffffff)
                index++;
            /* Error if we are out of bounds */
            if(index >= max) {
                js_destroy(sub); js_destroy(delimq); js_destroy(value);
                return JS_ERROR;
                }
            /* Run ddip_ip_mask to convert the actual ip/mask pair */
            if(ddip_ip_mask(sub,&(out[index]),0) == JS_ERROR) {
                js_destroy(sub); js_destroy(delimq); js_destroy(value);
                return JS_ERROR;
                }
            }
        } while(next != -2);

    js_destroy(sub);
    js_destroy(delimq);
    js_destroy(value);
    return JS_SUCCESS;
    }

