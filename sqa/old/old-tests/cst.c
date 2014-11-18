/* Copyright (c) 2002,2003 Sam Trenholme
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

/* This file attempts to compress a DNS packet which the compressor
   has a problem with; the offending packet in question is one that
   comes from news.com.com
 */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"

main() {
    js_string *to_compress;
    js_string *compressed;

    to_compress = js_create(1024,1);
    compressed  = js_create(1024,1);

    js_str2js(to_compress,
    "\321\366\200\000\000\001\000\002\000\000\000\000\004news\003com\003com\000\000\001\000\001\004news\003com\003com\000\000\005\000\001\000\000\001,\000\015\003www\003com\003com\000\003www\003com\003com\000\000\001\000\001\000\000\001,\000\004@|\355\207"
    ,94,1);

    printf("Compression result: %d\n",compress_data(to_compress,compressed));
    }

