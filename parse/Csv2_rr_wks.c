/* Copyright (c) 2004-2007 Sam Trenholme
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

/* This file includes code to process WKS and other obscure record types */

#include "../libs/JsStr.h"
#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "../dns/functions_dns.h"
#include "Csv2_database.h"
#include "Csv2_read.h"
#include "Csv2_functions.h"
#include "functions_parse.h"

/* Some limits on the contents of a WKS record */
/* The maximum number of open ports we may have */
#define CSV2_WKS_PORTS_MAX 10
/* The highest port number we allow */
#define CSV2_WKS_HIGHPORT 1024

/* Functions specifically designed to parse obscure records */

/* This function is designed to tell us if the character in question is
 * a wks delimiter (comma, tab, or space) */
int csv2_is_wks(int32 in) {
        return (in == ',' || in == '\t' || in == ' ');
}

/* Match on [0-9a-zA-Z\-\_\.] */
int csv2_is_alphanum_ordot(int32 in) {
        return (csv2_is_alphanum(in) || in == '.');
}

/* Match on [0-9\-] */
int csv2_is_signed_num(int32 in) {
        return ((in >= '0' && in <= '9') || in == '-');
}

/* Get an WKS record from the stream (ignoring any leading whitespace) and
 * return a js_string object with the raw rddata for the WKS record */
js_string *csv2_get_wks(csv2_read *stream) {
        js_string *ddip; /* The 32-bit IP address */
        js_string *out;
        int protocol;
        int ports[CSV2_WKS_PORTS_MAX + 3];
        int portindex = 0;
        int hiport = 0;
        int32 look;
        int x, num;

        if(csv2_get_1st(stream,csv2_is_number,0) != JS_SUCCESS) {
                return 0;
        }

        /* Address */
        if((ddip = process_ipv4_ddip(stream)) == 0) {
                return 0;
        }

        /* Protocol */
        protocol = csv2_get_num(stream);
        if(protocol < 0) {
                js_destroy(ddip);
                return 0;
        }

        if(csv2_get_1st(stream,csv2_is_number,0) != JS_SUCCESS) {
                js_destroy(ddip);
                return 0;
        }

        /* Read the port numbers, putting them in the ports
         * array */
        /* Allow the tilde to end a list */
        if(stream->tilde_handling == 103) {
                csv2_allow_tilde(stream);
        }
        look = csv2_justread(stream);
        num = 0;
        for(x = 0; x < 1000; x++) {
                if(stream->tilde_handling != 103) {
                        /* This is one of the few places where we treat a
                         * newline differently than a space or tab; a newline
                         * (or EOF) ends the WKS list of ports */
                        if(look == -2 || look == '\n' || look == '\r') {
                                break;
                        }
                        /* Comments also end the WKS list of ports */
                        else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                break;
                        }
                } else { /* If we use the tilde as a record separator,
                          * no need to use hacks to determine when we
                          * are at the end of the record */
                        if(look == '~') {
                                break;
                        } else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                look = csv2_read_unicode(stream);
                                continue;
                        }
                }
                /* Numbers are processed one byte at a time */
                if(csv2_is_number(look)) {
                        num *= 10; /* Decimal */
                        num += look - '0'; /* Random thought: It would have
                                            * made hexadecimal processing
                                            * easier if the ASCII code after
                                            * '9' was 'A' (or 'a') */
                        /* Bounds checking; TCP only has 16-bit port numbers */
                        if(num > 100000) {
                                js_destroy(ddip);
                                return 0;
                        }
                }
                /* If it's a space, tab, or comma... (or newline
                 * if we use the tilde to separate records) */
                else if(csv2_is_wks(look) || (stream->tilde_handling == 103
                        && (look == '\r' || look == '\n'))) {
                        /* Take the number we've been processing and add it
                         * to the list of ports */
                        if(portindex >= CSV2_WKS_PORTS_MAX) {
                                js_destroy(ddip);
                                return 0;
                        }
                        ports[portindex] = num;
                        portindex++;
                        if(num > hiport) {
                                hiport = num;
                        }
                        if(num > CSV2_WKS_HIGHPORT) {
                                js_destroy(ddip);
                                return 0;
                        }
                        num = 0;
                }
                /* Any other character is an error */
                else {
                        js_destroy(ddip);
                        return 0;
                }
                look = csv2_read_unicode(stream);
        }

        /* Convert the last number we read in to a port number to put
         * in the ports array, if needed.  Note that this code doesn't
         * allow the last port number to be zero.  This is a feature.
         * (no one uses WKS anymore so I don't think it's worth the bother
         * to fix) */
        if(num > 0 && num < CSV2_WKS_HIGHPORT) {
                if(portindex >= CSV2_WKS_PORTS_MAX) {
                        js_destroy(ddip);
                        return 0;
                }
                ports[portindex] = num;
                if(num > hiport) {
                        hiport = num;
                }
        }

        /* Create the string with the raw binary WKS data */
        if((out = js_create((hiport >> 3) + 6,1)) == 0) {
                js_destroy(ddip);
                return 0;
        }

        /* Zero out the string */
        for(x = 0; x < (hiport >> 3) + 6; x++) {
                *(out->string + x) = 0;
        }

        /* Make the first four bytes of the string the IP given by the
         * user */
        if(ddip_2_ip(ddip,out,0) == JS_ERROR) {
                js_destroy(ddip);
                js_destroy(out);
                return 0;
        }

        /* Set the length of the string as needed */
        out->unit_count = 6 + (hiport >> 3);

        /* Bounds checking, as needed in C (ugh) */
        if(out->max_count < out->unit_count) {
                js_destroy(ddip);
                js_destroy(out);
                return 0;
        }

        /* Set the protocol number */
        *(out->string + 4) = protocol & 0xff;

        /* And set the port numbers */
        for(x = 0; x < portindex; x++) {
                int pn, q, mask;
                pn = ports[x];
                q = pn >> 3;
                mask = 128 >> (pn % 8);
                if(q >= out->unit_count) {
                        js_destroy(ddip);
                        js_destroy(out);
                        return 0;
                }
                *(out->string + q + 5) |= mask;
        }

        js_destroy(ddip);
        return out;
}

/* This processes obscure RFC1035 mail-related records where the record
 * data is one or more email addresses (MG, MR, and MINFO) */

js_string *csv2_get_mbox(csv2_read *stream, js_string *zone, int count) {
        js_string *name;
        js_string *out;
        int c;

        if((out = js_create(512,1)) == 0) {
                return 0;
        }

        for(c = 0; c < count; c++) {
                /* Mailbox label */
                if(csv2_get_1st(stream,csv2_is_alphanum_ordot,0) !=
                    JS_SUCCESS) {
                        js_destroy(out);
                        return 0;
                }
                if((name = process_mbox(stream)) == 0) {
                        js_destroy(out);
                        return 0;
                }
                if(csv2_convert_percent(name,zone) == 0) {
                        js_destroy(name);
                        js_destroy(out);
                        return 0;
                }
                if(email_2rfc1035(name) == JS_ERROR) {
                        js_destroy(name);
                        js_destroy(out);
                        return 0;
                }
                if(js_append(name,out) == JS_ERROR) {
                        js_destroy(name);
                        js_destroy(out);
                        return 0;
                }
                js_destroy(name);
        }
        return out;
}

/* This processes RRs that use hexadecimal numbers (NSAP, possibly others) */

js_string *csv2_get_hex(csv2_read *stream) {
        js_string *out;
        int32 look;
        int place;

        /* Get the two-byte "0x" prefix; return an error if this prefix
         * is not present */
        if(csv2_get_1st(stream,csv2_is_number,0) != JS_SUCCESS) {
                return 0;
        }
        if(csv2_justread(stream) != '0') {
                return 0;
        }
        if(csv2_read_unicode(stream) != 'x') {
                return 0;
        }

        look = -1;
        place = 0;

        out = js_create(256,1);
        if(out == 0) {
                return 0;
        }

        while(look != -2 && !csv2_is_delimiter(look)) {
                int lnybble, rnybble, chr;
                int x;

                look = csv2_read_unicode(stream);
                x = 0;
                /* Get the left nybble */
                while(look == '.' && x < 10000) {
                        look = csv2_read_unicode(stream);
                        x++;
                }
                if(look >= '0' && look <= '9') {
                        lnybble = look - '0';
                }
                else if(look >= 'a' && look <= 'f') {
                        lnybble = look - 'a';
                }
                else if(look >= 'A' && look <= 'F') {
                        lnybble = look - 'A';
                }
                else if(look == -2 || csv2_is_delimiter(look)) {
                        break;
                }
                else {
                        csv2_error(stream,"Unexpected char");
                        js_destroy(out);
                        return 0;
                }
                look = csv2_read_unicode(stream);
                /* Get the right nybble */
                if(look == '.') {
                        csv2_error(stream,"Dot not at byte boundary");
                        js_destroy(out);
                        return 0;
                }
                if(look >= '0' && look <= '9') {
                        rnybble = look - '0';
                }
                else if(look >= 'a' && look <= 'f') {
                        rnybble = look - 'a';
                }
                else if(look >= 'A' && look <= 'F') {
                        rnybble = look - 'A';
                }
                else if(look == -2 || csv2_is_delimiter(look)) {
                        csv2_error(stream,"Record must end on byte boundary");
                        js_destroy(out);
                        return 0;
                }
                else {
                        csv2_error(stream,"Unexpected char");
                        js_destroy(out);
                        return 0;
                }
                chr = (((lnybble & 0xf) << 4) | (rnybble & 0xf)) & 0xff;
                if(place + 7 > out->max_count) {
                        js_destroy(out);
                        return 0;
                }
                out->unit_count = place + 1;
                *(out->string + place) = chr;
                place++;
        }

        return out;
}

/* This gets an integer from the data stream; we use the multiply factor to
 * allow semi-decimal fractions; If the multiply factor is 0, then the number
 * is a standard integer.  If the factor is 1, we can have precisely one
 * number after the decimal; 1.1 becomes "11", 6.0 becomes "60", and 32.6
 * becomes "326".  If the factor is two 1.23 becomes "123" */

int32 csv2_get_int(csv2_read *stream, int mulfactor) {
        int out = 0;
        int32 look;
        int x;
        int decimal = 0;
        int sign = 1;

        if(mulfactor == 3) {
                mulfactor = 1000;
        } else if(mulfactor == 2) {
                mulfactor = 100;
        } else if(mulfactor == 1) {
                mulfactor = 10;
        } else if(mulfactor == 0) {
                mulfactor = 1;
        } else {
                return 0;
        }

        look = csv2_justread(stream);
        if(look == '-') {
                sign = -1;
                look = csv2_read_unicode(stream);
        }

        for(x = 0; x < 100; x++) {
                if(!csv2_is_number_or_dot(look)) {
                        return out * mulfactor * sign;
                }
                else if(csv2_is_number(look)) {
                        out *= 10;
                        out += look - '0';
                }
                else if(look == '.') {
                        decimal = 0;
                        out *= mulfactor;
                        look = csv2_read_unicode(stream);
                        while(csv2_is_number(look) && mulfactor > 1) {
                                mulfactor /= 10;
                                decimal += (look - '0') * mulfactor;
                                look = csv2_read_unicode(stream);
                        }
                        return (out + decimal) * sign;
                }
                look = csv2_read_unicode(stream);
        }
        return 0;

}

/* This processes the latitude and longitude in a LOC RR */
uint32 csv2_get_lon_lat(csv2_read *stream, char r1, char r2, char r3,
                        char r4) {
        uint32 out;
        int degrees = 0;
        int mins = 0;
        int secs = 0;
        int32 look;

        if(csv2_get_1st(stream,csv2_is_number,0) != JS_SUCCESS) {
                return 0;
        }

        degrees = csv2_get_int(stream,0);

        if(csv2_get_1st(stream,csv2_is_alphanum,0) != JS_SUCCESS) {
                return 0;
        }

        look = csv2_justread(stream);
        if(look == r1 || look == r2 || look == r3 || look == r4) {
                goto process;
        } else if(csv2_is_number(look)) {
                mins = csv2_get_int(stream,0);
        } else {
                return 0;
        }

        if(csv2_get_1st(stream,csv2_is_alphanum,0) != JS_SUCCESS) {
                return 0;
        }

        look = csv2_justread(stream);
        if(look == r1 || look == r2 || look == r3 || look == r4) {
                goto process;
        } else if(csv2_is_number(look)) {
                secs = csv2_get_int(stream,3);
        } else {
                return 0;
        }

        if(csv2_get_1st(stream,csv2_is_alphanum,0) != JS_SUCCESS) {
                return 0;
        }
        look = csv2_justread(stream);

process:

        if(look != r1 && look != r2 && look != r3 && look != r4) {
                return 0;
        }

        out = 2147483648U;

        if(look == r1 || look == r2) {
                out += (degrees * 3600000 + mins * 60000 + secs);
        } else {
                out -= (degrees * 3600000 + mins * 60000 + secs);
        }

        /* Advance the ticker, otherwise the next csv2_get_1st will think
         * we're on the N/S/E/W character */
        csv2_read_unicode(stream);

        return out;

}

/* This processes the rather complicated LOC RR */
js_string *csv2_get_loc(csv2_read *stream) {
        uint32 lat = 0;
        uint32 lon = 0;
        uint32 alt = 0;
        int size = -1;
        int hpre = -1;
        int vpre = -1;
        int32 look;
        int32 get;
        int x;

        js_string *out;

        /* Get the latitude and longitude */
        lat = csv2_get_lon_lat(stream,'N','n','S','s');
        lon = csv2_get_lon_lat(stream,'E','e','W','w');

        /* Get the altitude */
        if(csv2_get_1st(stream,csv2_is_signed_num,0) == 0) {
                return 0;
        }
        get = csv2_get_int(stream,2);
        get += 10000000;
        if(get < 0) {
                return 0;
        }
        alt = get;
        look = csv2_read_unicode(stream);
        if(look == 'm') {
                look = csv2_read_unicode(stream);
        }

        /* (optionally) get the size, horizontal precision, and vertical
         * precision */
        get = -2;

        /* Allow the tilde to end a list */
        if(stream->tilde_handling == 103) {
                csv2_allow_tilde(stream);
        }

        for(x = 0; x < 1000; x++) {
                if(csv2_is_wks(look) || look == '\r' || look == '\n' ||
                   look == -2 || csv2_is_hash(look)) {
                        int q = 1;
                        int v = 0;
                        if(get != -2) {
                                if(get == -1) {
                                        get = 1;
                                }
                                while(get >= 10 && q < 10) {
                                        q++;
                                        get /= 10;
                                }
                                q++;
                                v = (get & 0xf) << 4;
                                v |= q & 0xf;
                                if(size == -1) {
                                        size = v;
                                }
                                else if(hpre == -1) {
                                        hpre = v;
                                }
                                else if(vpre == -1) {
                                        vpre = v;
                                }
                                else {
                                        printf("here\n");
                                        return 0;
                                }
                                get = -2;
                        }
                }
                /* If we are not using the ~ to separate records */
                if(stream->tilde_handling != 103) {
                        if(look == -2 || look == '\n' || look == '\r') {
                                break;
                        }
                        else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                break;
                        }
                } else { /* When we use the tilde to separate records, we
                          * don't need hacks to determine when we are at the
                          * end of a record */
                        if(look == '~') {
                                break;
                        } else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                look = csv2_read_unicode(stream);
                                continue;
                        }
                }
                /* Numbers are processed one character at a time */
                if(csv2_is_number(look)) {
                        if(get < 0) {
                                get = 0;
                        }
                        get *= 10;
                        get += look - '0';
                }
                /* Error if not space, 'm', or, optionally, newline
                 * if we're using tildes (~) to separate records */
                else if(!csv2_is_wks(look) && look != 'm' &&
                        !(stream->tilde_handling == 103 &&
                        (look == '\r' || look == '\n'))) {
                        return 0; /* Error */
                }
                look = csv2_read_unicode(stream);
        }

        if(size == -1) {
                size = 0x12;
        }
        if(hpre == -1) {
                hpre = 0x16;
        }
        if(vpre == -1) {
                vpre = 0x13;
        }

        if((out = js_create(18,1)) == 0) {
                return 0;
        }
        *(out->string) = 0;
        /* Set the size and both precisions */
        *(out->string + 1) = size & 0xff;
        *(out->string + 2) = hpre & 0xff;
        *(out->string + 3) = vpre & 0xff;
        /* Latitude */
        *(out->string + 4) = (lat >> 24) & 0xff;
        *(out->string + 5) = (lat >> 16) & 0xff;
        *(out->string + 6) = (lat >>  8) & 0xff;
        *(out->string + 7) = lat & 0xff;
        /* Longitude */
        *(out->string + 8) = (lon >> 24) & 0xff;
        *(out->string + 9) = (lon >> 16) & 0xff;
        *(out->string + 10) = (lon >>  8) & 0xff;
        *(out->string + 11) = lon & 0xff;
        /* Altitude */
        *(out->string + 12) = (alt >> 24) & 0xff;
        *(out->string + 13) = (alt >> 16) & 0xff;
        *(out->string + 14) = (alt >>  8) & 0xff;
        *(out->string + 15) = alt & 0xff;
        out->unit_count = 16;
        return out;

}

/* This processes the somewhat complicated NAPTR RR (RFC3403, etc.) */

js_string *csv2_get_naptr(csv2_read *stream) {
        /* New coding style practices.  All variables, when feasible,
         * are initialized when declared */
        js_string *out = 0;
        js_string *name = 0;
        js_string *zone = 0;
        int num = 0;
        int c = 0;

        out = js_create(256,1);
        if(out == 0) {
                return 0;
        }

        /* RFC3403 section 4.1 */
        /* Get the "order" and "preference" (both numbers) */
        for(c = 1; c <= 2; c++) {
                if((num = csv2_get_num(stream)) < 0) {
                        js_destroy(out);
                        return 0;
                }
                if(js_adduint16(out,num) == JS_ERROR) {
                        js_destroy(out);
                        return 0;
                }
        }

        /* Get "flags", "services", and "regexp" (three TXT-type fields) */
        name = csv2_get_string(stream,3,1);
        if(name == 0) {
                js_destroy(out);
                return 0;
        }

        /* Append those three fields to the outputted name */
        if(js_append(name,out) == JS_ERROR) {
                js_destroy(name);
                js_destroy(out);
                return 0;
        }

        js_destroy(name);

        /* Get "replacement" (Domain name) */
        if(csv2_get_1st(stream,csv2_is_dchar,0) != JS_SUCCESS) {
                js_destroy(out);
                return 0;
        }

        zone = js_create(256,1); /* csv2_get_hostname expects zone to
                                  * be valid js_string, so we just allocate
                                  * an empty string */
        if(zone == 0) {
                js_destroy(out);
                return 0;
        }

        name = csv2_get_hostname(stream,zone,3);

        js_destroy(zone);

        if(name == 0) {
                js_destroy(out);
                return 0;
        }

        /* Append the "replacment" to the outputted string */
        if(js_append(name,out) == JS_ERROR) {
                js_destroy(name);
                js_destroy(out);
                return 0;
        }

        js_destroy(name);
        return out;
}

