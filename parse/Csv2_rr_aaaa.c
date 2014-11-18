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
#include "Parse_ipv6_functions.h"

/* This stuff just looks for what looks like a legitmate ipv6-syntax
 * AAAA record */

int csv2_is_hex(int32 in) {
        return (csv2_is_number(in) || (in >= 'a' && in <= 'f') ||
                        (in >= 'A' && in <= 'F'));
}

int csv2_is_hex_or_colon(int32 in) {
        return (csv2_is_hex(in) || in == ':');
}

/* We'll do this the easy way; ip6_to_raw knows when the string has too
 * many colons. */

js_string *process_aaaa(csv2_read *stream) {
        return process_something(stream,csv2_is_hex_or_colon);
}

/* Get an AAAA record from the stream and return the raw RDDATA; ignore
 * any leading whitespace and convert the ipv6 query in to raw RDDATA
 */

js_string *csv2_get_aaaa(csv2_read *stream) {
        js_string *ip6hex;
        js_string *out;

        if(csv2_get_1st(stream,csv2_is_hex_or_colon,0) != JS_SUCCESS) {
                return 0;
        }

        if((ip6hex = process_aaaa(stream)) == 0) {
                return 0;
        }

        if((out = ip6_to_raw(ip6hex)) == 0) {
                js_destroy(ip6hex);
                csv2_error(stream,"Invalid IPv6 address");
                return 0;
        }

        js_destroy(ip6hex);
        return out;

}

