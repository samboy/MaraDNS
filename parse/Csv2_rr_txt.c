/* Copyright (c) 2004-2007,2011 Sam Trenholme
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

#include <stdlib.h>
#include "../libs/JsStr.h"
#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "Csv2_database.h"
#include "Csv2_read.h"
#include "Csv2_functions.h"
#include "../dns/functions_dns.h"

/* Some defines for the various states that we will be in */

/* TXT_GET_STATE: A state when we are getting a text character outside of
                  quotes */
#define TXT_GET_STATE 1

/* TXT_QUOTE_STATE: Whenever we are in quoted text, we are in this state */
#define TXT_QUOTE_STATE 2

/* TXT_BSLASH_STATE1: Whenever we are right after a backslash, we are in this
                      state */
#define TXT_BSLASH_STATE1 3

/* TXT_BSLASH_STATE2: If we see a whitespace right after a backslash, we end
                      up in this state */
#define TXT_BSLASH_STATE2 4

/* TXT_OCTAL_STATE1: We're in this state when in the second number of an
                     octal (\123) sequence */
#define TXT_OCTAL_STATE1 5

/* TXT_OCTAL_STATE2: We're in this state in the third number of an octal
                     sequence */
#define TXT_OCTAL_STATE2 6

/* TXT_HEX_STATE1: We're in this state in the first number of a hex (\xE4 or
                   \xe4) sequence */
#define TXT_HEX_STATE1 7

/* TXT_HEX_STATE2: We're in this state in the second number of a hex
                   sequence */
#define TXT_HEX_STATE2 8

/* TXT_EXIT_STATE: We're done with the record; do any last processing and
                   leave the state machine */
#define TXT_EXIT_STATE 9

/* TXT_BETWEEN_CHUNKS_STATE: We're using ~ to separate records, and have
 * just ended a chunk in a TXT record */
#define TXT_BETWEEN_CHUNKS_STATE 10

/* This returns true on [0-9a-zA-Z\-\_\+\%\!\^\=\;\\\'], false otherwise */
int csv2_is_txtchar(int32 in) {
        return (in >= '0' && in <= '9') ||
               (in >= 'a' && in <= 'z') ||
               (in >= 'A' && in <= 'Z') ||
               in == '-'                ||
               in == '_'                ||
               in == '+'                ||
               in == '%'                ||
               in == '!'                ||
               in == '^'                ||
               in == '='                ||
               in == ';'                ||
               in == '\\'               ||
               in == '\'';
}

/* This returns true on [0-9a-zA-Z\-\_\+\%\!\^\=], false otherwise */
int csv2_is_txt_bchar(int32 in) {
        return (in >= '0' && in <= '9') ||
               (in >= 'a' && in <= 'z') ||
               (in >= 'A' && in <= 'Z') ||
               in == '-'                ||
               in == '_'                ||
               in == '+'                ||
               in == '%'                ||
               in == '!'                ||
               in == '^'                ||
               in == '=';
}

/* This returns true for /any/ character *except* ' (single quote) */
int csv2_isnt_quote(int32 in) {
        return in != '\'';
}

/* This returns true for [\'] (single quote) */
int csv2_is_quote(int32 in) {
        return in == '\'';
}

/* This returns true for [\|] (pipe) */
int csv2_is_pipe(int32 in) {
        return in == '|';
}

/* This returns true for [0-3] */
int csv2_is_0123(int32 in) {
        return (in >= '0' && in <= '3');
}

/* This returns true for [x] */
int csv2_is_x(int32 in) {
        return in == 'x';
}

/* This returns true for [\#] */
int csv2_is_hash(int32 in) {
        return in == '#';
}

/* This returns true for [0-7] */
int csv2_is_octal(int32 in) {
        return (in >= '0' && in <= '7');
}

/* This returns true for [\\] */
int csv2_is_bslash(int32 in) {
        return in == '\\';
}

/* This returns true for [\;] */
int csv2_is_semicolon(int32 in) {
        return in == ';';
}

/* Get a TXT record from the stream.
 * Input: A pointer to the stream we are reading
 * Output: A js_string object with the raw rddata we want */
js_string *csv2_get_txt(csv2_read *stream, int numchunks) {
        return csv2_get_string(stream,numchunks,0);
}

/* Get a RAW record from the stream.
 * Input: A pointer to the stream we are reading
 * Output: A js_string object with the raw rddata we want */
js_string *csv2_get_raw(csv2_read *stream) {
        return csv2_get_string(stream,-1,0);
}

/* Append a Unicode character to a stream, returning the length of the
 * character we appended.  Input: the string to add the char to, the
 * char (unicode thing) to add.  This will add it as Unicode. This
 * will also increment the variable *len given as an argument to this .
 * Output is 0 is an error (we also destroy the string we're adding to)
 */

int csv2_txt_append(js_string *out, int32 chr, int *len) {
        if(csv2_append_utf8(out, chr) == JS_ERROR) {
                js_destroy(out);
                return 0;
        }
        if(chr < 0x80) {
                /* Ugh *len++ increments len, not what len points to */
                *len += 1;
        } else if(chr < 0x800) {
                *len += 2;
        } else if(chr < 0x10000) {
                *len += 3;
        } else if(chr < 0x200000) {
                *len += 4;
        } else { printf("Whoo!  Unicode is huge!\n"); exit(1); }
        return 1;
}

/* Finalize a TXT record.  This is called at the end of TXT record to
 * set the last chunk and to make sure we have the correct number of
 * TXT chunks for this RR */
js_string *csv2_finalize_txt(csv2_read *stream,int numchunks,
                                       int chunkcount,int txt_len_place,
                                       int txt_len, js_string *out) {

        /* TXT length */
        if(numchunks != -1) {
                if(txt_len_place < 0 || txt_len_place > out->max_count) {
                        js_destroy(out);
                        return 0;
                }
                if(txt_len > 255) {
                        csv2_error(stream, "Single TXT chunk too long");
                        js_destroy(out);
                        return 0;
                }
                *(out->string + txt_len_place) = txt_len;
                chunkcount++;
        }
        /* This if only affects HINFO and other obscure RRs */
        if(numchunks > 0 && chunkcount != numchunks) {
                csv2_error(stream, "Incorrect number of chunks for this RR");
                js_destroy(out);
                return 0;
        }
        /* End of TXT record */
        return out;
}

/* Get a string from the stream; we have this so that processing
 * RAW data and processing TXT records can use the same code
 * Input: A pointer to a stream we are reading; number of chunks (0 if any
   one or more chunks are allowed; -1 if we're not using chunks)
 * Output: A js_string object with the raw rddata we want; 0 on error */

js_string *csv2_get_string(csv2_read *stream, int numchunks, int post_txt) {
        int state;
        int out_num = 0; /* Used for octal and hext sequences (\123 or \xE4) */
        int txt_len_place = -1; /* Where we put binary length in TXT records */
        int txt_len; /* How long this TXT chunk is in a TXT record */
        int chunkcount = 0;
        int x; /* counter used to make sure a txt record is not too long */
        int32 look;
        js_string *out;

        if(stream->tilde_handling == 103) {
                csv2_allow_tilde(stream);
        }

        if(csv2_get_1st(stream,csv2_is_txtchar,0) != JS_SUCCESS) {
                return 0;
        }

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

        /* This is the longest a TXT string or raw RR can be */
        if((out = js_create(1513,1)) == 0) {
                return 0;
        }

        if(js_set_encode(out,JS_US_ASCII) == JS_ERROR) {
                js_destroy(out);
                return 0;
        }

        /* If this is a TXT record instead of a raw binary stream, make
         * the first character be one we put the length in */
        if(numchunks != -1) {
                txt_len_place = out->unit_count; /* 0 */
                txt_len = 0;
                chunkcount = 0;
                if(csv2_append_utf8(out, 0) == JS_ERROR) {
                        js_destroy(out);
                        return 0;
                }
        }

        /* Our initial state depends on the character we just saw */
        /* [0-9a-zA-Z\-\_\+\%\!\^\=] */
        if(csv2_is_txt_bchar(look)) {
                /* Append the just read character to this output string */
                if(csv2_txt_append(out, look, &txt_len) != 1) {
                        csv2_error(stream,"Error appending character");
                        return 0;
                }
                state = TXT_GET_STATE;
        }

        /* [\\] */
        else if(csv2_is_bslash(look)) {
                state = TXT_BSLASH_STATE1;
        }

        /* [\'] */
        else if(csv2_is_quote(look)) {
                state = TXT_QUOTE_STATE;
        }

        /* [\;] if we allow one or more chunks (non-RAW record) */
        else if(csv2_is_semicolon(look) && numchunks != -1) {
                if(txt_len_place < 0 || txt_len_place > out->max_count) {
                        js_destroy(out);
                        return 0;
                }
                if(txt_len > 255) {
                        csv2_error(stream, "Single TXT chunk too long");
                        js_destroy(out);
                        return 0;
                }
                *(out->string + txt_len_place) = txt_len;
                txt_len_place = out->unit_count; /* 1 */
                txt_len = 0;
                chunkcount++;
                if(csv2_append_utf8(out, 0) == JS_ERROR) {
                        js_destroy(out);
                        return 0;
                }
                state = TXT_GET_STATE;
        } else if(csv2_is_semicolon(look)) {
                csv2_error(stream, "No non-quoted ; in non-TXT records");
                js_destroy(out);
                return 0;
        }
        else {
                csv2_error(stream, "Unexpected char at beginning of rdata");
                js_destroy(out);
                return 0;
        }

        for(x = 0; x < 10000; x++) {
                look = csv2_read_unicode(stream);

                /* EOF outside */
                if(look == -2 && state != TXT_GET_STATE &&
                   state != TXT_BETWEEN_CHUNKS_STATE) {
                        csv2_error(stream,"Unterminated RR");
                        js_destroy(out);
                        return 0;
                }

                if(state == TXT_GET_STATE) {
                        /* [0-9a-zA-Z\-\_\+\%\!\^\=] */
                        if(csv2_is_txt_bchar(look)) {
                                if(csv2_txt_append(out, look, &txt_len) != 1) {
                                        return 0;
                                }
                        }
                        else if((csv2_is_delimiter(look) &&
                                 stream->tilde_handling != 103) ||
                             (look == '~' && stream->tilde_handling == 103 &&
                                post_txt == 0) ||
                             (csv2_is_delimiter(look) &&
                                 numchunks == -1) ||
                             (csv2_is_delimiter(look) && post_txt == 1) ||
                                        look == -2 /* EOF */) {
                                return csv2_finalize_txt(stream,numchunks,
                                       chunkcount,txt_len_place,txt_len,out);
                        }
                        /* [\\] */
                        else if(csv2_is_bslash(look)) {
                                state = TXT_BSLASH_STATE1;
                        }
                        /* [\'] */
                        else if(csv2_is_quote(look)) {
                                state = TXT_QUOTE_STATE;
                        }
                        /* [\;]: New TXT field, only if non-RAW RR */
                        else if(look == ';' && numchunks != -1) {
                                if(txt_len_place < 0 ||
                                    txt_len_place > out->max_count) {
                                        js_destroy(out);
                                        return 0;
                                }
                                if(txt_len > 255) {
                                        csv2_error(stream,
                                        "Single TXT chunk too long");
                                        js_destroy(out);
                                        return 0;
                                }
                                *(out->string + txt_len_place) = txt_len;
                                chunkcount++;
                                txt_len_place = out->unit_count; /* 1 */
                                txt_len = 0;
                                if(csv2_append_utf8(out, 0) == JS_ERROR) {
                                        js_destroy(out);
                                        return 0;
                                }
                                state = TXT_GET_STATE;
                        }
                        else if(stream->tilde_handling == 103 &&
                                csv2_is_delimiter(look) && look != '|') {
                                state = TXT_BETWEEN_CHUNKS_STATE;
                        }
                        /* [\#]: Comment */
                        else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                if(stream->tilde_handling != 103) {
                                    return csv2_finalize_txt(stream,numchunks,
                                       chunkcount,txt_len_place,txt_len,out);
                                    }
                        }
                        /* Syntax error */
                        else {
                                if(numchunks != -1) {
                                        csv2_error(stream,
                                                "Syntax error in TXT/SPF RR");
                                        js_destroy(out);
                                        return 0;
                                }
                                else if(numchunks == -1) {
                                        csv2_error(stream,
                                                "Syntax error in RAW");
                                        js_destroy(out);
                                        return 0;
                                }
                                else {
                                        csv2_error(stream,
                                            "Something weird in csv2_rr_txt");
                                        js_destroy(out);
                                        return 0;
                                }
                        }
                }
                else if(state == TXT_QUOTE_STATE) {
                        /* Somewhat broken: We can't have non-utf-8 in
                         * quoted text; this should be fixed */
                        if(csv2_is_quote(look)) {
                                state = TXT_GET_STATE;
                        } else if(stream->tilde_handling == 103) {
                                if(look == '#') {
                                        csv2_error(stream,
                           "The # character is not allowed in TXT records\n"
                           "Please use the '\\x23' escape sequence instead.\n"
                           "man csv2_txt for more information");
                                        return 0;
                                } else if(look == '|') {
                                        csv2_error(stream,
                           "The | character is not allowed in TXT records\n"
                           "Please use the '\\x7c' escape sequence instead.\n"
                           "man csv2_txt for more information");
                                        return 0;
                                } else if(look == '~') {
                                        csv2_error(stream,
                           "The ~ character is not allowed in TXT records\n"
                           "Please use the '\\x7e' escape sequence instead.\n"
                           "man csv2_txt for more information");
                                        return 0;
                                } else if(look == 127) {
                                        csv2_error(stream,
                           "The DEL character is not allowed in TXT records\n"
                           "Please use the '\\x7f' escape sequence instead.\n"
                           "man csv2_txt for more information");
                                } else if(look < ' ') {
                                        csv2_error(stream,
   "Control characters (including newlines) are not allowed in TXT records\n"
                        "Please use the appropriate escape sequence instead.\n"
                           "man csv2_txt for more information");
                                        return 0;
                                } else if(csv2_txt_append(out, look, &txt_len)
                                       != 1) {
                                        return 0;
                                }
                        } else {
                                if(csv2_txt_append(out, look, &txt_len) != 1) {
                                        return 0;
                                }
                        }
                }
                else if(state == TXT_BSLASH_STATE1) {
                        /* [\'] */
                        if(csv2_is_quote(look)) {
                                if(csv2_txt_append(out, look, &txt_len) != 1) {
                                        return 0;
                                }
                                state = TXT_GET_STATE;
                        }
                        /* [\|] */
                        else if(csv2_is_pipe(look)) {
                                csv2_error(stream,
                                  "Please don't backslash | characters");
                                js_destroy(out);
                                return 0;
                        }
                        /* [\#] */
                        else if(csv2_is_hash(look)) {
                                /* Change from 1.1.23 behavior: We can
                                 * now put comments directly after
                                 * backslashes */
                                process_comment(stream);
                                state = TXT_BSLASH_STATE2;
                        }
                        /* Delimiter [\r\n\t\ \|] */
                        else if(csv2_is_delimiter(look)) {
                                state = TXT_BSLASH_STATE2;
                        }
                        /* [0-3]: Beginning of octal number */
                        else if(csv2_is_0123(look)) {
                                state = TXT_OCTAL_STATE1;
                                out_num = look - '0';
                        }
                        /* [x]: Beginning of hex number */
                        else if(csv2_is_x(look)) {
                                state = TXT_HEX_STATE1;
                                out_num = 0;
                        }
                        else {
                                csv2_error(stream,
                                        "Invalid character after backslash");
                                js_destroy(out);
                                return 0;
                        }
                }
                else if(state == TXT_BSLASH_STATE2) {
                        /* [0-9a-zA-Z\-\_\+\%\!\^\=] */
                        if(csv2_is_txt_bchar(look)) {
                                if(csv2_txt_append(out, look, &txt_len) != 1) {
                                        js_destroy(out);
                                        return 0;
                                }
                                state = TXT_GET_STATE;
                        }
                        /* [\'] */
                        else if(csv2_is_quote(look)) {
                                state = TXT_QUOTE_STATE;
                        }
                        /* [\|] */
                        else if(csv2_is_pipe(look)) {
                                csv2_error(stream,
        "Please don't have a pipe be after a backslash and whitespace");
                                js_destroy(out);
                                return 0;
                        }
                        /* [\#] */
                        else if(csv2_is_hash(look)) {
                                process_comment(stream);
                                /* We assume that, when placing a backslash
                                 * before a comment and a space, that
                                 * what they want to do is put a comment
                                 * in the middle of a TXT/RAW record.  This
                                 * is a slight behavior change from
                                 * undocumented behavior 1.1.23's parser
                                 * has. */
                                /* return out; */
                        }
                        /* delimiter */
                        else if(csv2_is_delimiter(look)) {
                                state = TXT_BSLASH_STATE2;
                        }
                        else if(csv2_is_bslash(look)) {
                                state = TXT_BSLASH_STATE1;
                        }
                        else {
                                csv2_error(stream,
        "Invalid character after backslash and white space");
                                js_destroy(out);
                                return(0);
                        }
                }
                else if(state == TXT_OCTAL_STATE1) {
                        if(csv2_is_octal(look)) {
                                out_num *= 8;
                                out_num += look - '0';
                                state = TXT_OCTAL_STATE2;
                        }
                        else {
                                csv2_error(stream,"Invalid octal digit");
                                js_destroy(out);
                                return(0);
                        }
                }
                else if(state == TXT_OCTAL_STATE2) {
                        if(csv2_is_octal(look)) {
                                out_num *= 8;
                                out_num += look - '0';
                                if(js_addbyte(out, out_num) == JS_ERROR) {
                                        js_destroy(out);
                                        return 0;
                                }
                                txt_len++;
                                out_num = 0;
                                state = TXT_GET_STATE;
                        }
                        else {
                                csv2_error(stream,"Invalid octal digit");
                                js_destroy(out);
                                return(0);
                        }
                }
                else if(state == TXT_HEX_STATE1) {
                        if(csv2_is_hex(look)) {
                                out_num = 0;
                                if(csv2_is_number(look)) {
                                        out_num += look - '0';
                                }
                                else if(csv2_is_upper(look)) {
                                        out_num += look + 10 - 'A';
                                }
                                else if(csv2_is_lower(look)) {
                                        out_num += look + 10 - 'a';
                                }
                                state = TXT_HEX_STATE2;
                        }
                        else {
                                csv2_error(stream,"Invalid hex digit");
                                js_destroy(out);
                                return (0);
                        }
                }
                else if(state == TXT_HEX_STATE2) {
                        if(csv2_is_hex(look)) {
                                out_num *= 16;
                                if(csv2_is_number(look)) {
                                        out_num += look - '0';
                                }
                                else if(csv2_is_upper(look)) {
                                        out_num += look + 10 - 'A';
                                }
                                else if(csv2_is_lower(look)) {
                                        out_num += look + 10 - 'a';
                                }
                                if(js_addbyte(out, out_num) == JS_ERROR) {
                                        js_destroy(out);
                                        return 0;
                                }
                                txt_len++;
                                out_num = 0;
                                state = TXT_GET_STATE;
                        }
                        else {
                                csv2_error(stream,"Invalid hex digit");
                                js_destroy(out);
                                return (0);
                        }
                }
                else if(state == TXT_BETWEEN_CHUNKS_STATE) {
                        /* [\#] */
                        if(csv2_is_hash(look)) {
                                process_comment(stream);
                        /* [\~] or EOF */
                        } else if(look == '~' || look == -2 /* EOF */) {
                                return csv2_finalize_txt(stream,numchunks,
                                chunkcount,txt_len_place,txt_len,out);
                        /* [\\\'] */
                        } else if(look == '\'' || look == '\\') {
                                if(txt_len_place < 0 ||
                                    txt_len_place > out->max_count) {
                                        js_destroy(out);
                                        return 0;
                                }
                                if(txt_len > 255) {
                                        csv2_error(stream,
                                        "Single TXT chunk too long");
                                        js_destroy(out);
                                        return 0;
                                }
                                *(out->string + txt_len_place) = txt_len;
                                chunkcount++;
                                txt_len_place = out->unit_count; /* 1 */
                                txt_len = 0;
                                if(csv2_append_utf8(out, 0) == JS_ERROR) {
                                        js_destroy(out);
                                        return 0;
                                }
                                if(look == '\'') {
                                        state = TXT_QUOTE_STATE;
                                } else if(look == '\\') {
                                        state = TXT_BSLASH_STATE1;
                                } else {
                                        printf(
                                "Fatal error in BETWEEN_CHUNK state!\n");
                                        exit(1);
                                }
                        /* [\|] */
                        } else if(look == '|') {
                                csv2_error(stream,
                                "Pipes are not allowed between TXT chunks");
                                js_destroy(out);
                                return 0;
                        } else if(!csv2_is_delimiter(look)) {
                                csv2_error(stream,
"Invalid character between chunks; this might be caused by a TXT RR not\n"
"terminated by a ~ character");
                                js_destroy(out);
                                return 0;
                        }

                }
        }

        /* We should never get here */
        csv2_error(stream,"RR too long");
        js_destroy(out);
        return 0;
}

