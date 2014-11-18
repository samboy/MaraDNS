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

/* Yes, yes, yes.   I concede that RFC2822 3.4 allows just about any
 * character before the @ in an email address.  I understand that I
 * only allow a subset of that.  This is MaraDNS.  This is not some
 * platonic ideal of perfection.
 *
 * Return true if this is our idea of what an OK character before an @
 * in an email address is.
 */

int csv2_b4_at(int32 in) {
        /* [0-9a-zA-Z\-\_\+\%\!\^\=] */
        return (csv2_is_alphanum(in) || in == '+' || in == '%' ||
                        in == '!' || in == '^' || in == '=');
}

/* Process an address in the form 'a@foo.bar.baz.' or 'a.foo.bar.baz.',
 * or even (thanks to Yarin for the idea) 'a\.b\.c@foo.bar.baz.' */

js_string *process_mbox(csv2_read *stream) {
        js_string *o;
        int32 look;
        int x;

        o = process_1stchar(stream,csv2_is_alphanum_ordot,"Z");
        if(o == 0) {
                return 0;
        }

        /* First, the stuff before the @ */
        for(x = 0; x < 10000; x++) {
                look = csv2_read_unicode(stream);
                /* Special code to handle empty email addresses (just a '.')
                 * RFC1183 requires these to be supported */
                if(x == 0 && o->unit_count >= 2 && *(o->string + 1) == '.') {
                        if(csv2_is_delimiter(look)) {
                                return o;
                        }
                        csv2_error(stream,
          ". can only be at start of label that is just a . by itself");
                        js_destroy(o);
                        return 0;
                }
                if(look == FATAL_CSV2_READ) {
                        js_destroy(o);
                        return 0;
                }
                if(look == '@' || look == '.') {
                        if(csv2_append_utf8(o, look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                        if(look == '.') {
                                look = csv2_read_unicode(stream);
                                if(csv2_is_text(look)) {
                                  if(csv2_append_utf8(o, look) < 0) {
                                    csv2_error(stream,
                                        "Error appending character");
                                    js_destroy(o);
                                    return 0;
                                    }
                                } else {
                                   csv2_error(stream,
                                        "Strange character after dot");
                                   js_destroy(o);
                                   return 0;
                                }
                        }
                        break;
                }
                if(look == '\\') {
                        look = csv2_read_unicode(stream);
                        if(look != '.') {
                                csv2_error(stream,
                                        "Illegal character after \\");
                                js_destroy(o);
                                return 0;
                        }
                        if(csv2_append_utf8(o, '.') < 0) {
                                csv2_error(stream,"Error appending dot");
                                js_destroy(o);
                                return 0;
                        }
                        look = csv2_read_unicode(stream);
                }
                if(csv2_b4_at(look)) {
                        if(csv2_append_utf8(o, look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                else {
                        csv2_error(stream,"Unexpected character before @"
                                       " in mbox "
                                "Yes, I know RFC2822 3.4 probably allows "
                                "the character in question to be there. "
                                "This is MaraDNS, not some platonic ideal.");
                        js_destroy(o);
                        return 0;
                }
        }

        /* OK, the stuff after the [@.]  Now just use the stuff
         * that process_dname uses */
        return js_append_dname(o, stream, 0);

}

/* Get a SOA record from the stream (ignoring any leading whitespace)
 * return a js_string object with the raw rddata for the SOA record */

js_string *csv2_get_soa(csv2_read *stream, js_string *zone,
        csv2_add_state *state) {
        js_string *name;
        js_string *out;
        int c;

        if((out = js_create(512,1)) == 0) {
                return 0;
        }

        /* Normal domain name label */
        if(csv2_get_1st(stream,csv2_is_dchar,0) != JS_SUCCESS) {
                return 0;
        }
        if((name = csv2_get_hostname(stream,zone,3)) == 0) {
                js_destroy(out);
                return 0;
        }
        if(js_append(name,out) == JS_ERROR) {
                js_destroy(name);
                js_destroy(out);
                return 0;
        }
        js_destroy(name);

        /* Mbox label */
        name = csv2_get_mbox(stream,zone,1);
        if(js_append(name,out) == JS_ERROR) {
                js_destroy(name);
                js_destroy(out);
                return 0;
        }
        js_destroy(name);

        /* The five remaining fields (serial, refresh, retry, expire, min) */
        for(c = 0 ; c < 5 ; c++) {
                int32 num;
                num = csv2_get_num(stream);
                /* Special case: They put in '/serial' for the serial
                 * number */
                if(num == -2 && c == 0) {
                        if(js_adduint32(out,state->soa_serial) == JS_ERROR) {
                                js_destroy(out);
                                return 0;
                        }
                } else if(num < 0) {
                        js_destroy(out);
                        return 0;
                } else if(js_adduint32(out,num) == JS_ERROR) {
                        js_destroy(out);
                        return 0;
                }
        }
        return out;
}

