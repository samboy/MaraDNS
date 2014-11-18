/* Copyright (c) 2004-2006 Sam Trenholme
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

#ifndef CSV2_DATABASE_DEFINED
#define CSV2_DATABASE_DEFINED

/* A structure storing the state of adding records to whatever
 * database we are using; this allows us to, for example,
 * temporarily store the SOA record while we get the authoritative
 * NS records for the domain (so that the SOA record has NS records) */

typedef struct csv2_rr {
        js_string *query; /* In blabel format */
        int rtype;
        int32 ttl;
        js_string *data;
        struct csv2_rr *next;
} csv2_rr;

typedef struct csv2_origin {
        js_string *origin;
        struct csv2_origin *next;
} csv2_origin;

typedef struct csv2_add_state {
        csv2_rr *buffer;
        js_string *zone; /* This is the zone that is used for determining
                          * whether a given name is authoritative or not,
                          * in ASCII "name.com." format */
        js_string *origin; /* This is what is used to substitute '%', also
                            * in ASCII "name.com." format */
        csv2_origin *ostack;
        int ostack_height;
        int rrnum;
        int add_method;
        int32 soa_serial; /* Serial number synthetic SOA will have */
        int32 default_ttl; /* Default TTL for RRs */
        int in_ns;
        int zone_nses_added;
        mhash *bighash;
} csv2_add_state;

#endif /* CSV2_DATABASE_DEFINED */

