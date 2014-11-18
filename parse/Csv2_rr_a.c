/* Copyright (c) 2004 Sam Trenholme
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
#include "functions_parse.h"

/* Functions specifically designed to parse A records */

/* This function is designed to tell us if the character in question is
 * a number or dot.  */
int csv2_is_number_or_dot(int32 in) {
        return (csv2_is_number(in) || in == '.');
}

/* Get, from the input stream, an ipv4 DDIP IP: "10.2.19.83" or what not,
 * and put that in an output string */

js_string *process_ipv4_ddip(csv2_read *stream) {
        js_string *o;
        int32 look;
        int num_nums = 1;
        int x;

        o = process_1stchar(stream,csv2_is_number,0);
        if(o == 0) {
                return 0;
        }

        for(x = 0;x < 10000; x++) {
                look = csv2_read_unicode(stream);
                if(look == FATAL_CSV2_READ) {
                        js_destroy(o);
                        return 0;
                }
                if(look == '#' && num_nums == 4) {
                        process_comment(stream);
                        return o;
                }
                else if(look == '.' && num_nums < 4) {
                        num_nums++;
                        if(csv2_append_utf8(o,'.') < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                else if(look == '.') {
                        csv2_error(stream,"Too many numbers in ipv4 ddip");
                        js_destroy(o);
                        return 0;
                }
                else if(csv2_is_number(look)) {
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                else if(csv2_is_delimiter(look) && num_nums ==4) {
                        return o;
                }
                else {
                        csv2_error(stream,"Unexpected character in ddip");
                        js_destroy(o);
                        return 0;
                }
        }
        /* We shouldn't get here */
        js_destroy(o);
        return 0;
}

/* Get an A record from the stream (ignoring any leading whitespace) and
 * return a js_string object with the raw rddata for the A record */
js_string *csv2_get_a(csv2_read *stream) {
        js_string *ddip;
        js_string *out;

        if(csv2_get_1st(stream,csv2_is_number,0) != JS_SUCCESS) {
                return 0;
        }

        if((ddip = process_ipv4_ddip(stream)) == 0) {
                return 0;
        }

        if((out = js_create(7,1)) == 0) {
                js_destroy(ddip);
                return 0;
        }

        if(ddip_2_ip(ddip,out,0) == JS_ERROR) {
                js_destroy(ddip);
                js_destroy(out);
                return 0;
        }

        js_destroy(ddip);
        return out;
}

