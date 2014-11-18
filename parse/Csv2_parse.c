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

/* Stuff for processing dnames */
#define DOT_STATE 0
#define NON_DOT_STATE 1
#define STARWHITIS_STATE 2
#define STARWHITIS_END_STATE 3

#define WITH_FQDN6

/* This function is designed to tell us if a given character is one
 * in a list that we give it
 *
 * Input: The character in question; the list of ASCII characters this
 * character may be
 *
 * Output: 0 if the character is not on the list, 1 if it is
 */

int csv2_see_char(int32 in, char *list) {
        int counter = 0;
        if(list == 0) {
                return 0;
        }
        while(*list != 0 && ++counter < 128) {
                if(*list == in) {
                        return 1;
                }
                list++;
        }
        return 0;
}

/* This function is designed to tell us if the character in question
 * is a number
 */

int csv2_is_number(int32 in) {
        return (in >= '0' && in <= '9');
}

/* This function is designed to tell us if the character in question
 * is a number or slash */

int csv2_is_number_orslash(int32 in) {
        return (in >= '0' && in <= '9') || in == '/';
}

/* This function is designed to tell us if the character in question is
 * an uppercase letter */

int csv2_is_upper(int32 in) {
        return (in >= 'A' && in <= 'Z');
}

/* This function is designed to tell us if the character in question is
 * a lowercase letter */

int csv2_is_lower(int32 in) {
        return (in >= 'a' && in <= 'z');
}

/* This function is designed to tell us if the character in question is
 * a possible part of a legal utf-8 sequence */

int csv2_is_hibit(int32 in) {
        return(in >= 128 && in <=253);
}

/* This function is designed to tell us if the character in question is
 * a delimiter */

int csv2_is_delimiter(int in) {
        return(in == '\r' || in == '\n' || in == '\t' || in == ' ' ||
                        in == '|');
}

/* This function is designed to tell us if the character *isn't* a
 * delimiter */
int csv2_isnt_delimiter(int in) {
        return !csv2_is_delimiter(in);
}

/* Determine how many UTF-8 characters to put after this character.
 * If this is zero, it is an ASCII character; 1 indicates that this
 * is part of the octet sequence after the initial UTF-8 character;
 * 2 indicates it is the first octet of a 2-octet sequence, 3 1st of 3,
 * and up until 6.
 */

int csv2_utf8_length(int in) {
        if(in >= 254) {
                return -2; /* Invalid character */
        }
        if(in < 0) {
                return -1; /* Bad input */
        }
        if(in < 128 && in > 0) {
                return 0;
        }
        if(in >= 0x80 && in < 0xc0) {
                return 1;
        }
        if(in >= 0xc0 && in < 0xe0) {
                return 2;
        }
        if(in >= 0xe0 && in < 0xf0) {
                return 3;
        }
        if(in >= 0xf0 && in < 0xf8) {
                return 4;
        }
        if(in >= 0xf8 && in < 0xfc) {
                return 5;
        }
        if(in >= 0xfc && in < 0xfe) {
                return 6;
        }
        return -1; /* We should never get here */
}

/* Determine the value of a given UTF-8 stream; given a file stream
 * that is pointing to the second character in a UTF-8 sequence (having
 * just read the first character), we determine the value of the
 * UTF-8 sequence in question.
 *
 * Input: Stream we are reading from.
 * Output: The value of the character represented by the UTF-8 sequence.
 */

int32 csv2_get_utf8(csv2_read *stream) {
        int32 in, out;
        int len, count;
        in = csv2_justread(stream);
        len = csv2_utf8_length(in);

        /* Error checking */
        if(len < 2) {
                csv2_error(stream,"Invalid UTF-8 sequence");
                return FATAL_CSV2_READ;
        }

        /* Make the first byte the left-most bits of the output
         * number */
        out = in;
        if(len == 2) {
                out &= 0x1f;
        } else if(len == 3) {
                out &= 0x0f;
        } else if(len == 4) {
                out &= 0x07;
        } else if(len == 5) {
                out &= 0x03;
        } else if(len == 6) {
                out &= 0x01;
        } else {
                csv2_error(stream,"Fatal error parsing UTF-8");
                return FATAL_CSV2_READ;
        }

        count = len;

        while(len > 1) {
                out <<= 6;
                in = csv2_readchar(stream);
                if(in == -2) {
                        csv2_error(stream,"EOF in middle of UTF-8 sequence");
                        return FATAL_CSV2_READ;
                }
                if(in < 0x80 || in >= 0xc0) {
                        csv2_error(stream,"Invalid char in UTF-8 sequence");
                        return FATAL_CSV2_READ;
                }
                in &= 0x3f;
                out |= in;
                len--;
        }

        /* We make sure a given character is represented by the shortest
         * possible UTF-8 sequence that can represent that character */
        if(out < 0x80) {
                csv2_error(stream,"UTF-8 sequence too long");
                return FATAL_CSV2_READ;
        }
        if(out < 0x800 && count > 2) {
                csv2_error(stream,"UTF-8 sequence too long");
                return FATAL_CSV2_READ;
        }
        if(out < 0x10000 && count > 3) {
                csv2_error(stream,"UTF-8 sequence too long");
                return FATAL_CSV2_READ;
        }
        if(out < 0x200000 && count > 4) {
                csv2_error(stream,"UTF-8 sequence too long");
                return FATAL_CSV2_READ;
        }
        if(out < 0x4000000 && count > 5) {
                csv2_error(stream,"UTF-8 sequence too long");
                return FATAL_CSV2_READ;
        }

        csv2_set_unicode(stream,out);
        return out;
}

/* Read a single unicode character from a UTF-8 input stream;
 * this will return FATAL_CSV2_READ if the stream in question has
 * non-UTF-8 characters in it.
 *
 * Input: The stream we are reading
 * Output: The unicode character; FATAL_CSV2_READ if we find an
 *         invalid UTF-8 sequence
 */

int32 csv2_read_unicode(csv2_read *stream) {
        int32 out;
        out = csv2_readchar(stream);
        if(out < 0) {
                return out;
        }
        if(out > 0x7f) {
                return csv2_get_utf8(stream);
        }
        return out;
}

/* Append a single unicode character to the end of a JS-STRING object
 * which represents the string in question in UTF-8 format.  This is
 * easy when the character in question is ASCII; not so easy when
 * the character is not ASCII.
 *
 * Input: The js_string object we want to modify; the unicode character
 *        we want to put at the end of the js_string object.
 * Output: JS_ERROR on error, JS_SUCCESS on success
 */

int csv2_append_utf8(js_string *toappend, int32 in) {
        if(js_has_sanity(toappend) == JS_ERROR) {
                return JS_ERROR;
        }

        if(toappend->unit_size != 1) {
                return JS_ERROR;
        }

        if(in < 0) {
                return JS_ERROR;
        }

        /* Doing ASCII characters is easy... */
        if(in < 0x80) {
                if(toappend->unit_count + 1 > toappend->max_count) {
                        return JS_ERROR;
                }
                *(toappend->string + toappend->unit_count) = in;
                toappend->unit_count++;
                return JS_SUCCESS;
        }

        /* UNICODE is not so easy... */
        else {
                int temp[6];
                int counter, place;
                int32 shift;
                shift = in;
                counter = 5;
                while(counter >= 0 && shift > 0) {
                        temp[counter] = shift & 0x3f; /* Right 6 bits */
                        shift >>= 6;
                        counter--;
                }
                counter++;
                place = counter;
                if(counter == 0)
                        temp[counter] |= 0xfc;
                else if(counter == 1)
                        temp[counter] |= 0xf8;
                else if(counter == 2)
                        temp[counter] |= 0xf0;
                else if(counter == 3)
                        temp[counter] |= 0xe0;
                else if(counter == 4)
                        temp[counter] |= 0xc0;
                else
                        return JS_ERROR;
                for(counter++; counter < 6; counter++)
                        temp[counter] |= 0x80;
                counter = place;
                while(counter < 6) {
                        if(toappend->unit_count + 1 > toappend->max_count) {
                                return JS_ERROR;
                        }
                        *(toappend->string + toappend->unit_count) =
                                temp[counter];
                        toappend->unit_count++;
                        counter++;
                }
        }
        return JS_SUCCESS;
}

/* process_comment: Process a comment that we find in the input stream */
void process_comment(csv2_read *stream) {
        int in, q, z;
        q = 1;

        z = stream->chars_allowed;
        csv2_allow_tilde(stream);
        do {
                in = csv2_readchar(stream);
                /* Tildes are allowed (and ignored) in comments */
                if(in == '~') {
                        (stream->tilde_seen)--;
                }
                q++;
                if(q > 5000) {
                        csv2_error(stream,"Comment too long");
                        return;
                }
        } while(in != '\n' && in != '\r' && in != -2 /* EOF */);
        stream->chars_allowed = z;
}

/* Handler for processing things before the beginning of a RR; this
 * is used for tilde verification, etc. */
int csv2_tilde_processing(csv2_read *stream) {
        /* See how many tildes we have seen (if we were, indeed, before
         * a RR, and not at the beginning of the file before the first
         * RR) */
        int permitted = 0; /* Number of tildes expected before RR:
                            * 0: No tildes
                            * 1: One tilde
                            * -2: Zero or one tilde */
        int seen; /* Number of tildes seen */
        seen = csv2_tilde_seen(stream);

        if(stream->tilde_handling > 100) {
                switch(stream->tilde_handling) {
                        case 101:
                                permitted = 0;
                                break;
                        case 102:
                                permitted = -2;
                                break;
                        case 103:
                                permitted = 1;
                                break;
                }
                if(seen > 1) {
                        csv2_error(stream,"A maximum of one tilde is allowed "
                        "between records.\nIf you need tildes, set "
                        "csv2_tilde_handling to 0");
                        return JS_ERROR;
                }
                if(permitted != -2 && seen != permitted) {
                        if(permitted == 0) {
                                csv2_error(stream,"No tildes allowed "
                                           "between RRs");
                        } else if (permitted == 1) {
                                csv2_error(stream,"You must have one tilde "
                                           "(~) between RRs");
                        }
                        return JS_ERROR;
                }
                if(permitted == -2) {
                        if(seen == 1) {
                                stream->tilde_handling = 103; /* Mandatory ~ */
                        } else {
                                stream->tilde_handling = 101; /* No tildes */
                        }
                }
                /* No tilde anywhere else in the RR */
                csv2_forbid_tilde(stream);
        }
        /* If this is the first record, increment
         * tilde_handling by 100 to mark that we have
         * now seen the first record (tildes are not
         * separating records until after the first
         * one) */
        else if(stream->tilde_handling > 0 && stream->tilde_handling < 20) {
                stream->tilde_handling += 100;
        }
        return JS_SUCCESS;
}

/* csv2_get_1st: Read whitespace, process comments,
 * Output: error on unacceptable
 * errors, -2 on EOF,
 * Input: stream: The stream we are reading,
 * is_ok: what helper function we use to see what
 * is an acceptable first character,
 * options: 0 default
 *          1 We are before a dlabel (probably after a record)
 *          2 We must have at last one whitespace character between this
 *            item and the last item we looked at */
int csv2_get_1st(csv2_read *stream, int (*is_ok)(int32 in), int options) {
        int32 in;
        int x;
        int lastin = 0;
        int pipe_already_seen = 0;

        in = csv2_justread(stream);
        if(in > 127) {
                in = csv2_get_unicode(stream);
        }
        if(in > 127) {
                in = csv2_get_unicode(stream);
        }

        /* We handle the case of already being at an OK character */
        if(options != 1 && is_ok(in)) {
                return JS_SUCCESS;
        }
        /* We're OK if we're at the beginning of a file and options is 1
         * (before the first RR) */
        if(options == 1 && in == -328 && is_ok(in)) {
                return csv2_tilde_processing(stream);
        }

        if(options == 2 && is_ok(in)) {
                csv2_error(stream,
        "At least one whitespace character or | must be before this field");
                return FATAL_CSV2_READ;
        }

        /* Allow hostnames to start with '.' */
        if(options == 1 && in == '.') {
                return csv2_tilde_processing(stream);
        }

        /* If this character is not OK (is not a character we're looking for)
         * and is not a delimiter (whitespace, comment, or |), then it's an
         * error */
        if(in != -328 && !csv2_is_delimiter(in) && !(in == '~' &&
           stream->tilde_handling == 103)) {
                csv2_error(stream,"Unexpected character");
                return FATAL_CSV2_READ;
        }

        if(in == '|') {
                pipe_already_seen = 1;
        }

        /* OK, if we are before a RR, we either allow or not allow a
         * tilde based on the tilde_handling value */
        if(options == 1) {
                switch(stream->tilde_handling) {
                        case 101: /* No tildes anywhere */
                                csv2_forbid_tilde(stream);
                                break;
                        case 102: /* Maybe allow tildes */
                        case 103: /* Mandate tildes */
                                csv2_allow_tilde(stream);
                                break;
                }
        /* Reset the count of the number of tildes we have seen */
        csv2_reset_tilde_seen(stream);
        /* If the current character is a tilde, increment the count */
        if(in == '~') {
                stream->tilde_seen++;
                }
        }

        for(x = 0; x < 10000; x++) {
                lastin = in;
                in = csv2_read_unicode(stream);
                if(in == FATAL_CSV2_READ) {
                        return JS_ERROR;
                }
                if(in == -2) {
                        return -2;
                }
                /* # for comments */
                if(in == '#') {
                        process_comment(stream);
                        in = '\n';
                }
                else if(options != 1 && is_ok(in)) {
                        return JS_SUCCESS;
                }
                else if(options == 1 && (lastin == '\r' || lastin == '\n'
                        || lastin == -328 /* Beginning of file */) &&
                                is_ok(in)) {
                        return csv2_tilde_processing(stream);
                }
                else if(options == 1 && is_ok(in)) {
                        csv2_error(stream,
                           "Host name must be at the beginning of a line");
                        return FATAL_CSV2_READ;
                }
                /* Allow hostnames to start with '.' */
                else if(options == 1 && in == '.') {
                        return csv2_tilde_processing(stream);
                }
                else if(in == '|') {
                   if(pipe_already_seen == 1) {
                        csv2_error(stream,
                   "Only one pipe (|) character is allowed between fields");
                        return FATAL_CSV2_READ;
                   } else {
                        pipe_already_seen = 1;
                   }
                }
                /* ~ is allowed before a hostname */
                else if(in == '~' && options == 1 &&
                        stream->tilde_handling > 100) {
                        continue;
                }
                /* Everything else besides delimiters is a syntax error */
                else if(!csv2_is_delimiter(in)) {
                        csv2_error(stream,"Unexpected character");
                        return FATAL_CSV2_READ;
                }
                if(in == -2) {
                        if(options == 1) {
                                return csv2_tilde_processing(stream);
                        }
                        return JS_SUCCESS;
                }
        }
        return JS_ERROR;
}

/* process_1stchar: Given a function that determines if a given
 * character is OK, and a pointer to a stream we are reading from,
 * create a string that has "pre" (if set) followed by the first
 * character of the string we will make */

js_string *process_1stchar(csv2_read *stream, int (*is_ok)(int32 in),
                char *pre) {
        js_string *o;
        int32 look;

        /* Make sure we're already starting to look at an OK thing */
        look = csv2_justread(stream);
        if(look >= 0xc0 && look < 0xfe) {
                look = csv2_get_utf8(stream);
        }
        else if(look >= 0x80) {
                look = csv2_get_unicode(stream);
        }

        if(look == FATAL_CSV2_READ) {
                return 0;
        }
        if(!is_ok(look)) {
                csv2_error(stream,"Unexpected character");
                return 0; /* This means that all errors in this
                             routine have to be fatal */
        }

        /* Create the output string */
        o = js_create(256,1);
        if(o == 0) {
                return 0;
        }
        if(js_set_encode(o,JS_US_ASCII) == JS_ERROR) {
                js_destroy(o);
                return 0;
        }

        /* If "pre" is set, make that string the beginning of o */
        if(pre != 0 && js_qstr2js(o,pre) != JS_SUCCESS) {
                csv2_error(stream,"Error prepending pre");
                js_destroy(o);
                return 0;
        }

        /* Append the just read character to this output string */
        if(csv2_append_utf8(o, look) < 0) {
                csv2_error(stream,"Error appending character");
                js_destroy(o);
                return 0;
        }

        return o;
}

/* process_something: Given a function which determines if a given
 * character is OK, and a pointer to a stream that we are reading from,
 * return a newly created js_string object that stores the list of
 * somethings in question. */

js_string *process_something(csv2_read *stream, int (*is_ok)(int32 in)) {
        js_string *o;
        int32 look;

        /* Get 1st character; we use a sub function so process_dname
         * can use the same code */
        o = process_1stchar(stream,is_ok,0);
        if(o == 0) {
                return 0;
        }

        do {
                look = csv2_read_unicode(stream);
                if(look == FATAL_CSV2_READ) {
                        js_destroy(o);
                        return 0;
                }
                if(look == '#') { /* Comments in zone files */
                        process_comment(stream);
                        return o;
                }
                if(!is_ok(look) && !csv2_is_delimiter(look)) {
                        csv2_error(stream,"Unexpected character");
                        js_destroy(o);
                        return 0;
                }
                if(is_ok(look) && csv2_append_utf8(o, look) < 0) {
                        csv2_error(stream,"Error appending character");
                        js_destroy(o);
                        return 0;
                }
        } while(is_ok(look));

        return o;
}

/* Determine if the letter in question is an ASCII letter */
int csv2_is_alpha(int32 in) {
        return (csv2_is_lower(in) || csv2_is_upper(in));
}

/* Match on [0-9a-zA-Z\-\_] */
int csv2_is_alphanum(int32 in) {
        return (csv2_is_alpha(in) || csv2_is_number(in) ||
                        in == '-' || in == '_');
}

/* Match on [0-9a-zA-Z\-\_\+] */
int csv2_is_alphanum_orplus(int32 in) {
        return (csv2_is_alphanum(in) || in == '+');
}

/* Match on [0-9a-zA-Z\-\_] or anything utf-8 */
int csv2_is_text(int32 in) {
        return (csv2_is_alphanum(in) || in > 0x7f);
}

/* Match on [0-9a-zA-z\-\_\/] or anything utf-8 */
int csv2_is_dname(int32 in) {
        return (csv2_is_alphanum(in) || in == '/' || in > 0x7f);
}

/* Match on [0-9a-zA-Z\-\_\%] or anything utf-8 */
int csv2_is_dchar(int32 in) {
        return (csv2_is_text(in) || in == '%');
}

/* Match on [0-9a-zA-Z\-\_\.] or anything utf-8 */
int csv2_is_fchar(int32 in) {
        return (csv2_is_text(in) || in == '.');
}

/* Match on [0-9a-zA-Z\-\_\*\%] or anything utf-8 */
int csv2_is_starwhitis(int32 in) {
        return (csv2_is_text(in) || in == '*' || in == '%');
}

/* Match on [0-9a-zA-Z\-\_\*\%\/] or anything utf-8 */
int csv2_is_starwhitis_orslash(int32 in) {
        return (csv2_is_text(in) || in == '*' || in == '%' || in == '/');
}

/* Match on [0-9a-zA-Z\-\_\*\%] or anything utf-8 */
int csv2_is_starwhitis_ordot(int32 in) {
        return (csv2_is_text(in) || in == '*' || in == '%' || in == '.');
}

/* Process number: Process a number that is coming in on the input stream
 * Input: The stream we want to get the number from (we've already seen
 *        the first digit of said number)
 * Output: A pointer to a string object with the number in question
 */

js_string *process_number(csv2_read *stream) {
        return process_something(stream,csv2_is_number);
}

/* Process textlabel: Process a text label which has
 * [0-9a-zA-Z\-\_] or utf8 in it.
 */

js_string *process_textlabel(csv2_read *stream) {
        return process_something(stream,csv2_is_text);
}

/* Process dname label: Process that brilliant idea Paul had back in
 * 1983 to store raw over-the-wire domain names as sets of <length><data>
 * pairs until <length> is zero.  Well, 1983 was /mostly/ a good year;
 * well, except for "True" by Spandau Ballet and anything Air Supply
 * released that year.
 *
 * Anyway, this processes a csv2 dname label and makes it a js_string
 * object.  In the form "this.that.foo."; we use other functions to
 * make this a raw dname label.
 */

js_string *process_dname(csv2_read *stream, int starwhitis) {
        js_string *o;
        js_string *ret;

        /* Get 1st character; we use a sub function so we can use the
         * same code as process_something */
        o = process_1stchar(stream,csv2_is_starwhitis_ordot,"Z");
        if(o == 0 || o->string == 0) {
                return 0;
        }

        ret = js_append_dname(o, stream, starwhitis);
        if(ret == 0) {
                return 0;
        }

        if(o->unit_count > 1 && *(o->string + 1) == '.' && o->unit_count != 2){
                csv2_error(stream,"Dot can only be at beginning of hostname"
                           " for root ('.') hostname");
                return 0;
        }

        if(o->unit_count == 2 && *(o->string + 1) == '.') {
                return o;
        }
        return ret;

}

/* We make this a separate function so that process_mbox in Csv2.rr_soa
 * can use the same code; starwhitis is whether the label in question
 * can have star labels:
 *
 * 1: yes, but only at the beginning of hostnames;
 * 0: no, not at all, and, additionally, we're already somewhere in the
 * middle of the dname;
 * 2: yes, either at the beginning or end of hostnames;
 * 3: stars not allowed, and we're at the beginning of a hostname
 * 4: neither stars nor percents allowed, and we're at the beginning of the
 *    hostname
 * 5: neither stars nor percents allowed, and we're already somewhere in
 *    the middle of the dname */
js_string *js_append_dname(js_string *o, csv2_read *stream, int starwhitis) {
        int x;
        int32 look;
        int state = NON_DOT_STATE;
        look = csv2_justread(stream);

        /* See if we have a %; this means we read no more */
        if((look == '%' && starwhitis != 4 && starwhitis != 5) ||
           look == '.') {
                if(csv2_read_unicode(stream) == FATAL_CSV2_READ) {
                        js_destroy(o);
                        return 0;
                }
                return o;
        } else if(look == '%' && (starwhitis == 4 || starwhitis == 5)) {
                csv2_error(stream,"'\%' character not allowed");
                js_destroy(o);
                return 0;
        }

        /* The value of starwhitis determines which state we start up
         * in. */
        /* Note that this function is called when the
         * first character of a hostname is already read and added to
         * the output string */
        if(starwhitis != 0 && starwhitis != 5) {
                if(csv2_is_dname(look)) {
                        state = NON_DOT_STATE;
                }
                else if(look == '*') {
                        if(starwhitis == 0 || starwhitis == 3  ||
                                        starwhitis == 4 || starwhitis == 5) {
                                csv2_error(stream,"'*' character not allowed");
                                js_destroy(o);
                                return 0;
                                }
                        state = STARWHITIS_STATE;
                }
                else {
                        csv2_error(stream,"Unexpected character");
                        js_destroy(o);
                        return 0;
                }
        } else {
                state = DOT_STATE;
        }

        /* Now, put the rest of the string in to here */
        for(x = 0;x < 10000; x++) {
                look = csv2_read_unicode(stream);
                if(look == FATAL_CSV2_READ) {
                        js_destroy(o);
                        return 0;
                }
                /* Deterministic state machine.
                 * NON_DOT_STATE: This is the state we are in when reading
                 * in a hostname, such as 'www', in 'www.example.com'
                 */
                if(look == '.' && state == NON_DOT_STATE) {
                        state = DOT_STATE;
                        /* Perhaps we should have this code append
                         * something besides a '.', so we can have dots
                         * in host names */
                        if(csv2_append_utf8(o,'.') < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                else if(state == NON_DOT_STATE && csv2_is_dname(look)) {
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                /* DOT_STATE: We have just seen a dot and are now looking
                 * at the character immediately after a dot. */
                /* '#' immediately after a dot terminates the string
                 * x > 0 is here so that '#' can't be the first character
                 * in a hostname */
                else if(look == '#' && state == DOT_STATE && x > 0) {
                        process_comment(stream);
                        return o;
                }
                /* % terminates a string when placed after a dot */
                else if(state == DOT_STATE && look == '%' &&
                                starwhitis != 4 && starwhitis != 5) {
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                        /* Advance input tape; this is because we want
                         * the state machine to be on a delimiter (or
                         * not be on a delimter and return a syntax error)
                         * next time we run csv2_get_1st */
                        if(csv2_read_unicode(stream) == FATAL_CSV2_READ) {
                                js_destroy(o);
                                return 0;
                        }
                        return o;
                }
                /* text character after dot (or at beginning of string)
                 * means we process that text label in the hostname
                 * until we see a dot again */
                else if(state == DOT_STATE && csv2_is_dname(look)) {
                        state = NON_DOT_STATE;
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                /* '*' after a dot is *only* allowed when we allow stars
                 * at end of hostnames, and then must be the last character
                 * in a hostname */
                else if(state == DOT_STATE && starwhitis == 2 &&
                                look == '*') {
                        state = STARWHITIS_END_STATE;
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                /* Whitespace after dot in hostname ends hostname */
                else if(state == DOT_STATE && csv2_is_delimiter(look)) {
                        return o;
                }
                /* STARWHITIS_STATE: The state we are in *after* seeing
                 * a '*' at the beginning of a record; only a dot is
                 * allowed here (actually, the end of a record is also allowed
                 * if we allow stars at end of hostnames) */
                else if(state == STARWHITIS_STATE && look == '.') {
                        state = DOT_STATE;
                        if(csv2_append_utf8(o,look) < 0) {
                                csv2_error(stream,"Error appending character");
                                js_destroy(o);
                                return 0;
                        }
                }
                /* '*' by itself as hostname */
                else if(state == STARWHITIS_STATE && csv2_is_delimiter(look)
                                && starwhitis == 2) {
                        return o;
                }
                /* STARWHITIS_END_STATE: The state we are in after we see a
                 * star at the *end* of a hostname; we only accept
                 * whitespace and comments here because this '*'
                 * is to be the end of the hostname */
                else if(state == STARWHITIS_END_STATE &&
                                csv2_is_delimiter(look)) {
                        return o;
                }
                /* We could have a comment right after a star */
                else if(look == '#' && state == STARWHITIS_END_STATE) {
                        process_comment(stream);
                        return o;
                }
                else if(csv2_is_delimiter(look)) {
                        csv2_error(stream,"Improper termination of label\n"
"Label must end with '.' or '%' (A '*' is allowed in csv2_default_zonefile)");
                        js_destroy(o);
                        return 0;
                }
                else {
                        csv2_error(stream,"Unexpected character");
                        js_destroy(o);
                        return 0;
                }
        }
        js_destroy(o);
        return 0; /* Shouldn't get here */
}

/* Process a % symbol that is at the end of a js_string object,
 * converting it into psub if it is there */
js_string *csv2_convert_percent(js_string *in, js_string *psub) {

        if(in->unit_size != 1) {
                return 0;
        }

        /* Process the % symbol */
        if(in->unit_count >= 1 &&
                        *(in->string + in->unit_count - 1) == '%') {
                in->unit_count--;
                if(js_append(psub,in) == JS_ERROR) {
                        return 0;
                }
        }

        return in;
}


/* A function that gets the host name we are adding a record for;
 * it returns the hostname in raw dname format; we run this
 * function *after* getting the first character for the hostname
 * because we may hit an EOF before getting the hostname
 *
 * Starwhitis: not 2: Stars *not* allowed at ends of hostnames
 *             2: Stars allowed at the ends of hostnames
 */

js_string *csv2_get_hostname(csv2_read *stream, js_string *zonename,
                int starwhitis) {
        js_string *out;
        if((out = process_dname(stream,starwhitis)) == 0) {
                return 0;
        }

        /* Convert a percent if needed */
        if(csv2_convert_percent(out,zonename) == 0) {
                js_destroy(out);
                return 0;
        }

        /* If * are allowed at the ends of hostname */
        if(starwhitis == 2) {
                if(hname_2rfc1035_starwhitis(out,1) < 0) {
                        js_destroy(out);
                        return 0;
                }
        } else {
                if(hname_2rfc1035_starwhitis(out,0) < 0) {
                        js_destroy(out);
                        return 0;
                }
        }

        /* Process star records.
         * TO DO: Also allow stars at end of host names;
         * check recursion and what not */
        if(starrecord_to_meta(out,0) == JS_ERROR) {
                js_destroy(out);
                return 0;
        }

        return out;
}

/* A function that converts a js_string with a rtype in it into a rtype
 * number.  -2 to -10 mean "load again" (-2 "IN", -3 "RAW",
 * -4 to -11 reserved for changing perm masks);
 * -1 means fatal error or unknown rtype; positive is the rtype */

int csv2_numeric_rtype(js_string *text_rtype) {

        /* these labels are case-insensitive */
        js_set_encode(text_rtype,JS_US_ASCII);
        if(js_tolower(text_rtype) == JS_ERROR) {
                return -1;
        }

        if(js_qissame("in",text_rtype) == 1) {
                return -2;
        }
        if(js_qissame("raw",text_rtype) == 1) {
                return -3;
        }
        if(js_qissame("a",text_rtype) == 1) {
                return RR_A;
        }
        if(js_qissame("ns",text_rtype) == 1) {
                return RR_NS;
        }
        if(js_qissame("cname",text_rtype) == 1) {
                return RR_CNAME;
        }
        if(js_qissame("soa",text_rtype) == 1) {
                return RR_SOA;
        }
        if(js_qissame("ptr",text_rtype) == 1) {
                return RR_PTR;
        }
        if(js_qissame("mx",text_rtype) == 1) {
                return RR_MX;
        }
        if(js_qissame("aaaa",text_rtype) == 1) {
                return RR_AAAA;
        }
        if(js_qissame("srv",text_rtype) == 1) {
                return RR_SRV;
        }
        if(js_qissame("txt",text_rtype) == 1) {
                return RR_TXT;
        }
        if(js_qissame("spf",text_rtype) == 1) {
                return RR_SPF;
        }
        if(js_qissame("fqdn4",text_rtype) == 1) {
                return 65765;
        }
#ifdef WITH_FQDN6
        if(js_qissame("fqdn6",text_rtype) == 1) {
                return 65766;
        }
#endif
        /* Obscure RR types follow */
        /* Obscure RFC1035 RR types */
        if(js_qissame("hinfo",text_rtype) == 1) {
                return RR_HINFO;
        }
        if(js_qissame("wks",text_rtype) == 1) {
                return RR_WKS;
        }
        if(js_qissame("mb",text_rtype) == 1) {
                return RR_MB;
        }
        if(js_qissame("md",text_rtype) == 1) {
                return RR_MD;
        }
        if(js_qissame("mf",text_rtype) == 1) {
                return RR_MF;
        }
        if(js_qissame("mg",text_rtype) == 1) {
                return RR_MG;
        }
        if(js_qissame("mr",text_rtype) == 1) {
                return RR_MR;
        }
        if(js_qissame("minfo",text_rtype) == 1) {
                return RR_MINFO;
        }
        /* Obscure RFC1183 data types follow */
        if(js_qissame("afsdb",text_rtype) == 1) {
                return RR_AFSDB;
        }
        if(js_qissame("rp",text_rtype) == 1) {
                return RR_RP;
        }
        if(js_qissame("x25",text_rtype) == 1) {
                return RR_X25;
        }
        if(js_qissame("isdn",text_rtype) == 1) {
                return RR_ISDN;
        }
        if(js_qissame("rt",text_rtype) == 1) {
                return RR_RT;
        }
        /* Obscure RFC1706 RRs follow */
        if(js_qissame("nsap",text_rtype) == 1) {
                return RR_NSAP;
        }
        if(js_qissame("nsap-ptr",text_rtype) == 1) {
                return RR_NSAP_PTR;
        }
        /* Obscure RFC2163 RR */
        if(js_qissame("px",text_rtype) == 1) {
                return RR_PX;
        }
        /* Obscure RFC1712 RR */
        if(js_qissame("gpos",text_rtype) == 1) {
                return RR_GPOS;
        }
        /* Almost obscure RFC1876 RR */
        if(js_qissame("loc",text_rtype) == 1) {
                return RR_LOC;
        }
        /* Maybe not obscure RFC3403 RR */
        if(js_qissame("naptr",text_rtype) == 1) {
                return RR_NAPTR;
        }
        return -1;
}

/* Get the rtype for the record in question; return a -1 on error */
int32 csv2_get_rtype(csv2_read *stream) {
        js_string *r;
        int32 ret;
        /* Go ahead 'til we hit a rtype */
        do {
                if(csv2_get_1st(stream,csv2_is_alpha,0) != JS_SUCCESS) {
                        return -1;
                }
                if((r = process_textlabel(stream)) == 0) {
                        return -1;
                }
                ret = csv2_numeric_rtype(r);
                js_destroy(r);
                /* RAW data specifies the numeric rtype */
                if(ret == -3) {
                        if(csv2_get_1st(stream, csv2_is_number,0) < 0) {
                                csv2_error(stream,
                                        "RAW rr not followed by number");
                                return -1;
                        }
                        ret = csv2_get_num(stream);
                        if(ret < 0) {
                                return -1;
                        }
                        ret += 100000;
                        return ret;
                }
                if(ret == -1 || ret == 0) {
                        return -1;
                }
                /* We really should have some way of setting perms for
                 * a rtype between -4 and -11.  CODE HERE */
        } while(ret <= -2 && ret >= -11);
        return ret;
}

/* Get a number from the stream; return a -1 on error, -2 if they
 * specified '/serial' */
int32 csv2_get_num(csv2_read *stream) {
        js_string *num;
        int32 ret;

        if(csv2_get_1st(stream,csv2_is_number_orslash,0) != JS_SUCCESS) {
                return -1;
        }

        /* '/serial' gets special treatment and returns -2 */
        if(csv2_justread(stream) == '/') {
                if(csv2_read_unicode(stream) != 's') {
                        return -1;
                }
                if(csv2_read_unicode(stream) != 'e') {
                        return -1;
                }
                if(csv2_read_unicode(stream) != 'r') {
                        return -1;
                }
                if(csv2_read_unicode(stream) != 'i') {
                        return -1;
                }
                if(csv2_read_unicode(stream) != 'a') {
                        return -1;
                }
                if(csv2_read_unicode(stream) != 'l') {
                        return -1;
                }
                if(!csv2_is_delimiter(csv2_read_unicode(stream))) {
                        return -1;
                }
                return -2;
        }

        if((num = process_number(stream)) == 0) {
                return -1;
        }
        /* The numeral 0 needs special treatment */
        if(*(num->string) == '0' && num->unit_count == 1) {
                js_destroy(num);
                return 0;
        }
        if((ret = js_atoi(num,0)) == 0) {
                js_destroy(num);
                return -1;
        }
        js_destroy(num);
        return ret;
}

/* Your generic swiss-army-knife "get a stream of characters from the
 * file and make a js_string out of it function"; bascially, we use
 * a pointer to the is_ok function to determine what characters we put
 * in the output string, then we get that string from the stream (skipping
 * whitespace, etc.) */

js_string *csv2_get_something(csv2_read *stream, int (*is_ok)(int32 in)) {
        js_string *o;

        if(csv2_get_1st(stream,is_ok,0) != JS_SUCCESS) {
                return 0;
        }

        if((o = process_something(stream,is_ok)) == 0) {
                return 0;
        }

        return o;
}

/* We can use the above function to get things like filenames */
js_string *csv2_get_filename(csv2_read *stream) {
        return csv2_get_something(stream,csv2_is_fchar);
}

/* Get a record that is in DNAME form; 0 is error;
 * this function is currently *not* called anywhere
 */

js_string *csv2_get_dname(csv2_read *stream) {
        /* js_string *num;
        int32 ret; */

        if(csv2_get_1st(stream,csv2_is_text,0) != JS_SUCCESS) {
                return 0;
        }

        return csv2_get_hostname(stream,0,1);
}

/* Get a mx record; 0 is error.  Pref makes this record more flexible;
 * if this number is 0 or higher, instead of reading the pref from the
 * zone file, the pref is set to the value given the function.  If pref
 * is -1, this is treated as a normal MX record.  Is pref is -2, we read
 * two instead of one host label (for the obscure PX record) */

js_string *csv2_get_mx(csv2_read *stream, js_string *zone, int pref) {
        js_string *out;
        int num;
        int hlabels = 1;

        /* Get the priority */
        if(pref < 0) {
                if((num = csv2_get_num(stream)) < 0) {
                        return 0;
                }
        } else {
                num = pref;
        }
        if((out = js_create(256,1)) == 0) {
                return 0;
        }
        if(js_adduint16(out,num) == JS_ERROR) {
                js_destroy(out);
                return 0;
        }

        if(pref == -2) {
                hlabels = 2;
        }

        /* And the MX host name */
        while(hlabels > 0) {
                js_string *name;
                if(csv2_get_1st(stream,csv2_is_dchar,0) != JS_SUCCESS) {
                        js_destroy(out);
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
                hlabels--;
        }

        return out;

}

/* Get an srv record; 0 is error */

js_string *csv2_get_srv(csv2_read *stream, js_string *zone) {
        js_string *out;
        js_string *name;
        int num, c;

        if((out = js_create(256,1)) == 0) {
                return 0;
        }

        /* Get the priority, weight, and port number */
        for(c = 1 ; c <= 3; c++) {
                if((num = csv2_get_num(stream)) < 0) {
                        js_destroy(out);
                        return 0;
                }
                if(js_adduint16(out,num) == JS_ERROR) {
                        js_destroy(out);
                        return 0;
                }
        }

        /* Get the SRV host name */
        if(csv2_get_1st(stream,csv2_is_dchar,0) != JS_SUCCESS) {
                js_destroy(out);
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
        return out;

}

/* Get a record from the csv2 zone file.  Run csv2_add_rr on the data
 * (which will put in on stdout, in the cache, or what not)
 * return code: -2: EOF; we're done.  -1: Fatal error; puke;
 * JS_SUCCESS: A record has been sucessfully read. */

int csv2_read_rr(csv2_add_state *state, csv2_read *stream, int32 starwhitis) {
        js_string *name = 0, *rddata = 0;
        js_string *zone = 0;
        int32 ttl = 86400;
        int32 rtype;
        int q;
        int slash_command = 0;

        /* Sanity checks */
        if(state->bighash == 0 && state->add_method == 1) {
                return JS_ERROR;
        }
        if(state->zone == 0) {
                return JS_ERROR;
        }
        if(state->origin == 0) {
                return JS_ERROR;
        }

        zone = state->origin;

        /* We read look for the beginning of the host name; this is made
         * more complicated that the "host name" may actually be a
         * special command, such as on that changes the origin (hostname
         * to substitute '%' with) or TTL */

        do {
                slash_command = 0;

                /* The host name must be at the begining of a line
                 * (or the file) */
                q = csv2_get_1st(stream, csv2_is_starwhitis_orslash,1);

                if(q == -2) {
                        return -2;
                }

                if(q == JS_ERROR) {
                        return -1;
                }

                /* Process the slash commands (/origin, /ttl, /opush, /opop,
                 * and /read) */
                if(csv2_justread(stream) == '/') {
                        int32 look, cmd;
                        slash_command = 1;
                        look = csv2_read_unicode(stream);
                        if(look == 't') {
                                cmd = 1; /* ttl */
                        } else if(look == 'o') {
                                cmd = 2; /* origin */
                        } else if(look == 'r') {
                                cmd = 5; /* read */
                        } else {
                                csv2_error(stream,"Invalid slash command");
                                return -1; /* error */
                        }

                        look = csv2_read_unicode(stream);
                        if(cmd == 2 && look == 'p') { /* opush/opop */
                                cmd = 3; /* opush */
                        } else if((cmd == 1 && look != 't') || (cmd == 2 &&
                            look != 'r') || (cmd == 5 && look != 'e')) {
                                csv2_error(stream,"Invalid slash command");
                                return -1;
                        }

                        look = csv2_read_unicode(stream);
                        if(cmd == 3 && look == 'o') {
                                cmd = 4; /* opop */
                        } else if((cmd == 1 && look != 'l') || (cmd == 2 &&
                            look != 'i') || (cmd == 3 && look != 'u') ||
                            (cmd == 5 && look != 'a')) {
                                csv2_error(stream,"Invalid slash command");
                                return -1;
                        }

                        look = csv2_read_unicode(stream);
                        if(cmd == 1 && csv2_is_delimiter(look)) {
                                int newttl;
                                newttl = csv2_get_num(stream);
                                if(newttl < 0) {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                state->default_ttl = newttl;
                        } else if(cmd == 2 && look == 'g') {
                                js_string *n;
                                if(csv2_read_unicode(stream) != 'i') {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                if(csv2_read_unicode(stream) != 'n') {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                look = csv2_read_unicode(stream);
                                if(!csv2_is_delimiter(look)) {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                if(csv2_get_1st(stream,csv2_is_dchar,0) !=
                                    JS_SUCCESS) {
                                        csv2_error(stream,
                                        "Invalid argument for /origin");
                                        return -1;
                                }
                                n = process_1stchar(stream,
                                        csv2_is_starwhitis,0);
                                if(n == 0) {
                                        csv2_error(stream,
                                        "Error processing /origin");
                                        return -1;
                                }
                                n = js_append_dname(n, stream, 3);
                                if(n == 0) {
                                        csv2_error(stream,
                                        "Invalid argument for /origin");
                                        return -1;
                                }
                                if(csv2_convert_percent(n,state->origin)
                                    == 0) {
                                        csv2_error(stream,
                                        "Problem running convert_percent");
                                        return -1;
                                }
                                js_destroy(state->origin);
                                state->origin = n;
                                zone = n;
                        } else if(cmd == 3 && look == 's') {
                                js_string *n;
                                csv2_origin *c, *o;
                                if(csv2_read_unicode(stream) != 'h') {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                look = csv2_read_unicode(stream);
                                if(!csv2_is_delimiter(look)) {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                if(csv2_get_1st(stream,csv2_is_dchar,0) !=
                                    JS_SUCCESS) {
                                        csv2_error(stream,
                                        "Invalid argument for /opush");
                                        return -1;
                                }
                                n = process_1stchar(stream,
                                        csv2_is_starwhitis,0);
                                if(n == 0) {
                                        csv2_error(stream,
                                        "Error processing /opush");
                                        return -1;
                                }
                                n = js_append_dname(n, stream, 3);
                                if(n == 0) {
                                        csv2_error(stream,
                                        "Invalid argument for /opush");
                                        return -1;
                                }
                                if(csv2_convert_percent(n,state->origin)
                                    == 0) {
                                        csv2_error(stream,
                                        "Problem running convert_percent");
                                        return -1;
                                }
                                /* Now, see if there is room on the stack */
                                if(state->ostack_height > 7 ||
                                   state->ostack_height < 0) {
                                        csv2_error(stream,
                                        "origin stack too high");
                                        return -1;
                                }
                                /* OK, there is room; push the current
                                 * origin on the stack and replace it with
                                 * the new value */
                                state->ostack_height++;
                                o = state->ostack;
                                c = js_alloc(1,sizeof(csv2_origin));
                                if(c == 0) {
                                        csv2_error(stream,
                                        "js_alloc error");
                                        return -1;
                                }
                                c->origin = state->origin;
                                c->next = o;
                                state->ostack = c;
                                state->origin = n;
                                zone = state->origin;
                        } else if(cmd == 4 && look == 'p') {
                                csv2_origin *o;
                                look = csv2_read_unicode(stream);
                                if(!csv2_is_delimiter(look)) {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                if(state->ostack_height < 1 ||
                                   state->ostack_height > 8) {
                                       csv2_error(stream,
                                           "origin stack too low");
                                        return -1;
                                }
                                if(state->ostack == 0) {
                                        csv2_error(stream,
                                            "origin stack empty");
                                        return -1;
                                }
                                /* OK, pop the top value from the origin
                                 * stack and make it the origin value */
                                o = state->ostack;
                                js_destroy(state->origin);
                                state->ostack = o->next;
                                state->origin = o->origin;
                                zone = state->origin;
                                js_dealloc(o);
                        } else if(cmd == 5 && look == 'd') {
                                js_string *filename;
                                int rc = 0, fc = 0;
                                look = csv2_read_unicode(stream);
                                if(!csv2_is_delimiter(look)) {
                                        csv2_error(stream,
                                            "Invalid slash command");
                                        return -1;
                                }
                                filename = csv2_get_filename(stream);
                                /* Hack: Ignore everything until the
                                 * next ~ or \n */
                                csv2_allow_tilde(stream);
                                for(rc = 0; rc < 10000; rc++) {
                                        fc = csv2_readchar(stream);
                                        if(fc == '~' || fc == '\n') {
                                                break;
                                        }
                                }
                                csv2_push_file(stream,filename);
                                js_destroy(filename);
                        } else {
                                csv2_error(stream,"Invalid slash command");
                                return -1;
                        }

                }

        } while(slash_command == 1);

        /* If star records are allowed at the end of
         * hostnames, we make the third argument of csv2_get_hostname have
         * a value of 2.  Otherwise, the third argument has a value of 1.
         */
        if(starwhitis == 0) /* DEFAULT */ {
                if((name = csv2_get_hostname(stream,zone,1)) == 0) {
                        csv2_error(stream,"Problem getting hostname");
                        return -1;
                }
        } else if(starwhitis == 1) /* default_zone */ {
                if((name = csv2_get_hostname(stream,zone,2)) == 0) {
                        csv2_error(stream,"Problem getting hostname");
                        return -1;
                }
        } else {
                csv2_error(stream,
                                "Bad starwhitis value passed to csv2_read_rr");
                return -1;
        }

        /* Go through whitespace until we hit a number or
         * letter. */
        if(csv2_get_1st(stream, csv2_is_alphanum_orplus,0) < 0) {
                js_destroy(name);
                csv2_error(stream, "Unexpected character");
                return -1;
        }

        ttl = state->default_ttl;
        /* If we saw a +, process this field as a TTL */
        if(csv2_justread(stream) == '+') {
                if(csv2_read_unicode(stream) < 0) {
                        js_destroy(name);
                        csv2_error(stream, "Unexpected char around +");
                        return -1;
                }
                if((ttl = csv2_get_num(stream)) < 0) {
                        js_destroy(name);
                        csv2_error(stream,"Problem getting TTL");
                        return -1;
                }
                /* Move on to the next field */
                if(csv2_get_1st(stream, csv2_is_alphanum,0) < 0) {
                        js_destroy(name);
                        csv2_error(stream, "Unexpected character");
                        return -1;
                }
        }

        /* rtype or IP rdata; if the first character is a letter
         * it is a rtype; if the first character is a number, it
         * is an ip (we make the rtype A) */
        if(csv2_is_alpha(csv2_justread(stream))) {
                if((rtype = csv2_get_rtype(stream)) == -1) {
                        js_destroy(name);
                        csv2_error(stream,"Unknown Rtype");
                        return -1;
                }
        }
        /* We process the second field as an IP for an A record if the
         * first character is a number */
        else if(csv2_is_number(csv2_justread(stream))) {
                rtype = RR_A;
                rddata = csv2_get_a(stream);

                csv2_add_rr(state, name, rtype, ttl, rddata);

                js_destroy(name);
                js_destroy(rddata);
                return JS_SUCCESS;
        }
        else { /* Shouldn't get here, but... */
                js_destroy(name);
                csv2_error(stream,"Unexpected char (shouldn't get here)");
                return -1;
        }


        /* Now, do rtype-specific processing; this is long because
         * we handle each rtype on a case-by-case basis */
        switch(rtype) {
                case RR_A:
                        rddata = csv2_get_a(stream);
                        break;
                case RR_AAAA:
                        rddata = csv2_get_aaaa(stream);
                        break;
                case RR_SOA:
                        rddata = csv2_get_soa(stream,zone,state);
                        break;
                case RR_MX:
                case RR_AFSDB:
                case RR_RT:
                        rddata = csv2_get_mx(stream,zone,-1);
                        break;
                case RR_SRV:
                        rddata = csv2_get_srv(stream,zone);
                        break;
                case RR_TXT:
                case RR_X25:
                case RR_ISDN:
                case RR_SPF:
                        if(stream->tilde_handling == 2 ||
                           stream->tilde_handling == 102) {
                            csv2_error(stream,"I'm sorry, that record can "
                            "not be the first record unless "
                            "csv2_tilde_handling is set.");
                            break;
                        }
                        rddata = csv2_get_txt(stream,0);
                        break;
                case RR_MG:
                case RR_MR:
                        rddata = csv2_get_mbox(stream,zone,1);
                        break;
                case RR_MINFO:
                case RR_RP:
                        rddata = csv2_get_mbox(stream,zone,2);
                        break;
                case RR_NS:
                case RR_CNAME:
                case RR_PTR:
                case RR_NSAP_PTR:
                case RR_MB:
                        if(csv2_get_1st(stream,csv2_is_dchar,0) !=
                                        JS_SUCCESS) {
                                return -1;
                        }
                        rddata = csv2_get_hostname(stream,zone,3);
                        break;
                case 65765: /* FQDN4: This is an A record where we
                             * automagically also make the corresponding
                             * PTR record */
                        rddata = csv2_get_a(stream);
                        break;
#ifdef WITH_FQDN6
                case 65766: /* FQDN6: This is an AAAA record where we
                                  * automagically also make the corresponding
                                  * PTR record */
                        rddata = csv2_get_aaaa(stream);
                        break;
#endif
                /* Obscure RRs follow */
                case RR_HINFO:
                        rddata = csv2_get_txt(stream,2);
                        break;
                case RR_WKS:
                        if(stream->tilde_handling == 2 ||
                           stream->tilde_handling == 102) {
                            csv2_error(stream,"I'm sorry, that record can "
                            "not be the first record unless "
                            "csv2_tilde_handling is set.");
                            break;
                        }
                        rddata = csv2_get_wks(stream);
                        break;
                case RR_MD:
                        /* As per RFC1035 3.3.4; handle this as an MX with
                         * priority 0 */
                        rddata = csv2_get_mx(stream,zone,0);
                        rtype = RR_MX;
                        break;
                case RR_MF:
                        /* As per RFC1035 3.3.5; handle this as an MX with
                         * priority 10 */
                        rddata = csv2_get_mx(stream,zone,10);
                        rtype = RR_MX;
                        break;
                case RR_NSAP:
                        rddata = csv2_get_hex(stream);
                        break;
                case RR_PX:
                        rddata = csv2_get_mx(stream,zone,-2);
                        break;
                case RR_GPOS:
                        rddata = csv2_get_txt(stream,3);
                        break;
                case RR_LOC:
                        if(stream->tilde_handling == 2 ||
                           stream->tilde_handling == 102) {
                            csv2_error(stream,"I'm sorry, that record can "
                            "not be the first record unless "
                            "csv2_tilde_handling is set.");
                            break;
                        }
                        rddata = csv2_get_loc(stream);
                        break;
                case RR_NAPTR:
                        rddata = csv2_get_naptr(stream);
                        break;
                default:
                        /* RAW rtype */
                        if(rtype >= 100000 && rtype <= 165535) {
                                rtype -= 100000;
                                if(rtype == RR_ANY) {
                                        csv2_error(stream,
                                  "ANY (255) record type isn't for data");
                                } else if(rtype == RR_IXFR) {
                                        csv2_error(stream,
                                  "IXFR (251) record type isn't for data");
                                } else if(rtype == RR_AXFR) {
                                        csv2_error(stream,
                                  "AXFR (252) record type isn't for data");
                                } else if(rtype == RR_MAILB) {
                                        csv2_error(stream,
                                  "MAILB record type isn't for data");
                                } else if(rtype == RR_MAILA) {
                                        csv2_error(stream,
                                  "MAILA record type isn't for data");
                                } else if(rtype == RR_A6) {
                                        csv2_error(stream,
                                  "MaraDNS doesn't allow A6 records");
                                } else if(rtype == RR_DNAME) {
                                        csv2_error(stream,
                                  "MaraDNS doesn't allow DNAME records");
                                } else if(rtype == RR_OPT) {
                                        csv2_error(stream,
                                  "OPT record type isn't for zone files");
                                } else {
                                    rddata = csv2_get_raw(stream);
                                }
                        } else {
                                csv2_error(stream,"Unsupported RTYPE");
                        }
                }

        if(rddata == 0) {
                csv2_error(stream,"Problem getting rddata");
                js_destroy(name);
                return -1;
        }

        csv2_add_rr(state, name, rtype, ttl, rddata);

        js_destroy(name);
        js_destroy(rddata);
        return JS_SUCCESS;
}

