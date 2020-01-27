/* Copyright (c) 2002-2019 Sam Trenholme
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
#include "ParseMaraRc_en.h"
#include <stdlib.h>
#ifndef MINGW32
#include <pwd.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

/* Keywords that are non-dictionary strings in Mara's rc file */

#define KEYCOUNT 55

char *keywords[KEYCOUNT] = {
        "bind_address", /* IPv4 Addresses to bind to (old name) */
        "ipv4_bind_addresses", /* IPv4 Addresses to bind to (new name) */
        "ipv6_bind_address", /* IPv6 Address (singular) to bind to */
        "csv2_synthip_list", /* List of IPs we synthesize when not supplied in
                              * csv2 zone files */
        "chroot_dir",   /* Directory to chroot to */
        "debug_response_delay", /* Seconds to delay in sending a reply
                                   (useful for debugging purposes) */
        "debug_msg_level", /* The level of debug messages to allow.
                              0: None; 1: version number with
                              Terre-con-erre-cigarro.maradns.org.
                              2: 1 & number of threads currently running
                                with Tnumthreads.maradns.org. */
        "default_rrany_set", /* What kind of records do we return when someone
                                sends us an ANY query.  Note:  This only
                                changes MaraDNS' behavior as an authoritative
                                nameserver */
        "hide_disclaimer", /* Whether to hide the disclaimer */
        "maradns_uid",  /* UID that MaraDNS will run as */
        "maradns_gid",  /* GID that MaraDNS will run as (optional) */
        "max_ar_chain", /* Maximum number of records in a chain of
                           records in the AR section.  Note:  This has
                           to be one or round-robin rotates are disabled */
        "max_chain", /* Maximum number of records in a chain of records for
                        a given host name */
        "max_glueless_level", /* Maximum glueless level allowed when
                                 performing recursive lookups.  The
                                 default value is 6 */
        "max_queries_total", /* Maximum total number of queries allowed
                                when chasing down a host name.  Default
                                is 32 */
        "max_tcp_procs", /* Maximum number of tcp processes */
        "max_total", /* Maximum number of records total */
        "maximum_cache_elements", /* Maximum number of elements in the cache */
        "maxprocs",     /* Maximum number of udp threads or tcp processes */
        "min_ttl_cname", /* Minimum TTL for CNAME records */
        "min_ttl", /* Minimum TTL for authoritative records */
        "min_visible_ttl", /* Minimum TTL that MaraDNS will report */
        "no_fingerprint", /* Do we remove certain distinctive traits that
                             MaraDNS has; e.g. a TXT query of
                             erre-con-erre-cigarro.maradns.org. tells us
                             the version number of the MaraDNS server */
        "random_seed_file", /* File with a seed for the random number
                               generator.  Note:  This has to be truly
                               random for it to be a secure random
                               number generator.  */
        "recursive_acl", /* ACL of IPs allowed to perform recursive queries */
        "spammers", /* List of IPs of spam-friendly DNS servers.  MaraDNS will
                       refuse to query any DNS server on this list */
        "timeout_seconds", /* The amount of time we wait for a foreign
                              DNS server to respond before we give up and
                              try the next DNS server. */
        "timestamp_type", /* People get religious about what is
                             the True Timestamp Format (TM); as a
                             result we need to allow the user to
                             choose this or the mailing list will
                             have a heated discussion about what
                             format to use every month or so */
        "verbose_level", /* How verbose error messages are */
        "tcp_convert_acl", /* Who is allowed to use the zoneserver to forward
                              requests to a UDP DNS server */
        "tcp_convert_server", /* The ip of the UDP dns server or zoneserver
                                 forwards requests to */
        "tcp_convert_recursion", /* Whether or not to ask for recursion when
                                    sending requests to the UDP DNS server */
        "reject_aaaa", /* Send a bogus SOA whenever an AAAA request is sent
                          to the server */
        "reject_ptr", /* Send a bogus SOA whenever a PTR request is sent
                         to the server */
        "verbose_query", /* Whether to output every query the recursive DNS
                            server makes */
        "csv2_default_zonefile", /* Default ("*" character allowed at end of
                                    hostname) zonefile */
        "dos_protection_level", /* How much stuff we disable in MaraDNS
                                   to protect her from a DOS attack */
        "no_cname_warnings", /* Whether to supress warnings about dangling
                                CNAME records */
        "long_packet_ipv4", /* The ipv4 addresses that we send long packets
                               to */
        "synth_soa_origin", /* The origin to put in a synthetic SOA record */
        "synth_soa_serial", /* The format for the serial in a synthetic SOA
                               record */
        "bind_star_handling", /* Whether or not to handle star records the
                                 way BIND does */
        "admin_acl", /* List of IPs allowed to administrate MaraDNS */
        "remote_admin", /* Whether verbose_level can be remotely
                         * set while MaraDNS is running */
        "handle_noreply", /* How to handle the case of none of the remote
                           * servers replying at all */
        "retry_cycles", /* The number of times we try to contact all of
                         * the remote DNS servers to resolve a given name */
        "csv2_tilde_handling", /* How to handle tildes in CSV2 zone files */
        "dns_port", /* What port to bind MaraDNS to */
        "upstream_port", /* What port to contact when contacting other
                            DNS servers */
        "recurse_delegation", /* They might just want to recurse in the
                               * case when the server would otherwise give
                               * out a delegation NS record.  This is by
                               * default disabled, since turning this on
                               * confuses people */
        "recurse_min_bind_port", /* The lowest numbered port the recursive
                                  * resolver will bind to */
        "recurse_number_ports", /* The number of ports the recursive resolver
                                 * is allowed to bind to */
        "max_mem", /* The maximum amount of memory we allow MaraDNS to
                    * allocate, in bytes */
        "notthere_ip", /* The IP to give users when they try to recursively
                        * query a host that is not there or isn't responding
                        */
        "zone_transfer_acl" /* ACL of IPs allowed to perform zone transfers */
        };

/* mara_goodjs: Determine if a given js_string object is a valid string
                for use in the Kiwi internals
   input: Pointer to js_string object to test
   ouput: JS_ERROR if bad, JS_SUCCESS if good */
int mara_goodjs(js_string *test) {
    if(js_has_sanity(test) == JS_ERROR)
        return JS_ERROR;
    /* Yes, I know, data abstraction violation */
    if(test->unit_size != 1)
        return JS_ERROR;
    return JS_SUCCESS;
    }

/* is_numeric_js: Determine if a given js_string object is really
 * a number.  0 if it isn't, 1 if it is, JS_ERROR on error */

int is_numeric_js(js_string *test) {
        int counter;
        if(!mara_goodjs(test)) {
                return JS_ERROR;
        }
        if(test->unit_count > test->max_count) {
                return JS_ERROR;
        }
        if(test->unit_count == 0)
                return 0;
        for(counter = 0; counter < test->unit_count; counter++) {
                if(*(test->string + counter) < '0' ||
                                *(test->string + counter) > '9')
                        return 0;
        }
        return 1;
}

js_string *kvar[KEYCOUNT];

/* keyword2num: Convert a keyword (like "kiwi_maillog") to a number
                (10, in this case)
   input: A js_string object with the keyword
   output: The number of the keyword (starting at 0), JS_ERROR on error,
           -2 on no match
   global vars used: keywords[]
*/
int keyword2num(js_string *keyword) {
    int counter = 0;
    js_string *name;

    if(mara_goodjs(keyword) == JS_ERROR)
        return JS_ERROR;

    if((name = js_create(256,1)) == 0)
        return JS_ERROR;

    js_set_encode(name,MARA_LOCALE);

    while(counter<KEYCOUNT) {
        if(js_qstr2js(name,keywords[counter]) == JS_ERROR) {
            js_destroy(name);
            return JS_ERROR;
            }
        js_set_encode(name,MARA_LOCALE);
        /* HACK: We don't use encode, so just make both the same */
        js_set_encode(keyword,MARA_LOCALE);
        if(js_issame(keyword,name)) {
            js_destroy(name);
            return counter;
            }
        counter++;
        }

    js_destroy(name);
    return -2;
    }

/* num2keyword: convert a number in to a keyword
   input: A number to make the keyword, the place to store the keyword
   output: JS_ERROR if it is out of range or any other error, JS_SUCCESS
           otherwise
   global vars used: keywords[]
*/
int num2keyword(int num, js_string *keyword) {
    if(mara_goodjs(keyword) == JS_ERROR)
        return JS_ERROR;

    if(num < 0 || num >=KEYCOUNT)
        return JS_ERROR;

    return js_qstr2js(keyword,keywords[num]);
    }

/* init_kvars: Initialize the Kiwi variables that the Kiwi program will
               use in its operation
   input: none
   output: JS_SUCCESS or JS_ERROR, depending on error/success
   global vars used: js_string kvar[KEYCOUNT] */
int init_kvars() {
    int counter;
    for(counter = 0;counter < KEYCOUNT;counter++) {
        if((kvar[counter] = js_create(256,1)) == 0)
            return JS_ERROR;
        js_set_encode(kvar[counter],MARA_LOCALE);
        }
    return JS_SUCCESS;
    }

/* read_kvar: Put the value of the Kiwi variable with the name name in
              the value value.
   input: name, value
   output: JS_SUCCESS if set, JS_ERROR if fatal error, or
           0 if the variable has not been set in the user's mararc
           (or is zero-length)
   global vars used: kvar[], keywords[]
*/

int read_kvar(js_string *name, js_string *value) {

    int num;

    /* Sanity checks */
    if(mara_goodjs(name) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(value) == JS_ERROR)
        return JS_ERROR;

    /* Get the number for this value */
    num = keyword2num(name);
    if(num == JS_ERROR)
        return JS_ERROR;

    /* Return not found if not found */
    if(num == -2)
        return num;

    /* Copy over the value */
    if((js_copy(kvar[num],value)) == JS_ERROR)
        return JS_ERROR;

    /* If the string is zero-length, return a 0 */
    if(js_length(kvar[num]) == 0)
        return 0;

    return JS_SUCCESS;

    }

/* write_kvar: Set the value of the Kiwi variable with the name name with
               the value value.
   input: name, value
   output: JS_SUCCESS or JS_ERROR, depending on error/success
   global vars used: kvar[], keywords[]
*/
int write_kvar(js_string *name, js_string *value, int is_plus) {

    int num;
    num = keyword2num(name);

    /* Sanity checks */
    if(mara_goodjs(name) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(value) == JS_ERROR)
        return JS_ERROR;
    if(num == JS_ERROR)
        return JS_ERROR;

    /* Return not found if not found */
    if(num == -2)
        return num;

    /* Copy over the value */
    if(is_plus != 1) {
        if(js_copy(value,kvar[num]) == JS_ERROR)
                return JS_ERROR;
    } else { /* += parsing */
            /* Make sure it is there; this is not perfect */
            if(is_numeric_js(kvar[num]) == 1) {
                    return -5; /* Sorry, += only supported for strings */
            }
            if(js_length(kvar[num]) == 0) {
                    return -4; /* One needs to declare += string first */
            }
            if(js_append(value,kvar[num]) == JS_ERROR) {
                    return JS_ERROR;
            }
    }

    return JS_SUCCESS;

    }

/* Keywords that are dictionaries in the MaraDNS rc file */

#define DKEYCOUNT 6

char *dkeywords[DKEYCOUNT] = {
        "csv1", "csv2",
        "root_servers",
        "upstream_servers",
        "ipv4_alias",
        "future" };

mhash *dvar[DKEYCOUNT];

/* dvar_raw: Point to the hash that dvar[arg] points to
   input: index of dvar to look at
   ouput: pointer to mhash object on success, 0 on failure
*/

/*
 * See https://github.com/samboy/MaraDNS/issues/19
 * Non-exploitable buffer overflow
 * (non-expoitable because index is always, in MaraDNS code, set
 *  by code which never makes index be DKEYCOUNT)
 */
mhash *dvar_raw(int index) {
    if(index < 0 || index >= DKEYCOUNT)
        return 0;
    return dvar[index];
    }

/* dq_keyword2n: Convert a null-terminated string (like "csv1")
 * to a number (0, in this case)
 * input: A null-terminated string with the keyword
 * Output: The number of the keyword (starting at 0), JS_ERROR on error,
 * -2 on no match
 */

int dq_keyword2n(char *in) {
        int counter;
        for(counter = 0; counter < DKEYCOUNT; counter++) {
                if(!strncmp(in,dkeywords[counter],128))
                        return counter;
        }
        return -2;
}

/* dkeyword2num: Convert a keyword (like "csv2") to a number
                (1, in this case)
   input: A js_string object with the keyword
   output: The number of the keyword (starting at 0), JS_ERROR on error,
           -2 on no match
   global vars used: keywords[]
*/
int dkeyword2num(js_string *keyword) {
    int counter = 0;
    js_string *name;

    if(mara_goodjs(keyword) == JS_ERROR)
        return JS_ERROR;

    if((name = js_create(256,1)) == 0)
        return JS_ERROR;

    js_set_encode(name,MARA_LOCALE);

    while(counter < DKEYCOUNT) {
        if(js_qstr2js(name,dkeywords[counter]) == JS_ERROR) {
            js_destroy(name);
            return JS_ERROR;
            }
        if(js_issame(keyword,name)) {
            js_destroy(name);
            return counter;
            }
        counter++;
        }

    js_destroy(name);
    return -2;
    }

/* num2dkeyword: convert a number in to a keyword
   input: A number to make the keyword, the place to store the keyword
   output: JS_ERROR if it is out of range or any other error, JS_SUCCESS
           otherwise
   global vars used: keywords[]
*/
int num2dkeyword(int num, js_string *keyword) {
    if(mara_goodjs(keyword) == JS_ERROR)
        return JS_ERROR;

    if(num < 0 || num >= DKEYCOUNT)
        return JS_ERROR;

    return js_qstr2js(keyword,dkeywords[num]);
    }

/* init_dvars: Initialize the Kiwi variables that the Kiwi program will
               use in its operation
   input: none
   output: JS_SUCCESS (OK, Jaakko, we don't check for any error condition)
   global vars used: js_string dvar[DKEYCOUNT] */
int init_dvars() {
    int counter;
    /* Since we will init these in the rc file, set them to 0 */
    for(counter = 0;counter < DKEYCOUNT;counter++)
        dvar[counter] = 0;

    return JS_SUCCESS;
    }

/* new_dvar: Create a new mhash object for a given dvar object.
   input: name of keyword we will use.
   output: JS_ERROR on error (already created, etc.)
           JS_SUCCESS on success
*/
int new_dvar(js_string *name) {
    int num;
    num = dkeyword2num(name);
    if(num < 0 || num >= DKEYCOUNT || dvar[num] != 0)
        return JS_ERROR;
    if((dvar[num] = mhash_create(7)) == 0)
        return JS_ERROR;

    return JS_SUCCESS;
    }

/* read_dvar: Put the value of the Kiwi variable with the name name in
              the value value.
   input: name, key, value
   output: JS_SUCCESS or JS_ERROR, depending on error/success
   global vars used: dvar[], keywords[]
*/
int read_dvar(js_string *name, js_string *key, js_string *value) {

    int num;
    js_string *place;
    num = dkeyword2num(name);

    /* Sanity checks */
    if(mara_goodjs(name) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(key) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(value) == JS_ERROR)
        return JS_ERROR;
    if(num == JS_ERROR)
        return JS_ERROR;
    if(dvar[num] == 0 || num < 0 || num > DKEYCOUNT)
        return JS_ERROR;

    /* Return not found if not found */
    if(num == -2)
        return num;

    /* Find out where the actual value is */
    place = mhash_get_js(dvar[num],key);
    /* This is a little klunky; there really needs to be a special
       "yes, the hash is there, but I can't find the element you are
        seeking" error code.  However, other MaraDNS code depends on
        this buggy behavior, so I am not changing this quite yet */
    if(place == 0)
        return JS_ERROR;

    /* Copy over the value */
    if((js_copy(place,value)) == JS_ERROR)
        return JS_ERROR;

    return JS_SUCCESS;

    }

/* write_dvar: Set the value of the Kiwi variable with the name name with
               the value value.
   input: name, key, value
   output: JS_ERROR on error, 1 on most sucessful adds, 2 if the add
           caused the hash table to grow, -2 if the hash was not found
           (unused in mararc file), -3 if there is already a hash element
           there, -4 for "Can't do += to something not there",
           -5 for "Sorry, += only supported for strings",
           -6 if dictionary has not been initialized
   global vars used: dvar[], keywords[]
*/
int write_dvar(js_string *name, js_string *key, js_string *value,
                int is_plus) {

    int num;

    num = dkeyword2num(name);

    /* Sanity checks */
    if(mara_goodjs(name) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(key) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(value) == JS_ERROR)
        return JS_ERROR;
    if(num == JS_ERROR)
        return JS_ERROR;
    if(dvar[num] == 0)
        return -6;
    if(num < 0 || num > DKEYCOUNT)
        return JS_ERROR;

    /* Return not found if not found */
    if(num == -2)
        return num;

    /* If num is 0 (csv1), 1 (csv2), 2 (root_servers), or 3 (upstream_servers),
     * then we make the key all lower-case */
    if(num <= 3) {
        int y,z;
        y = 0;
        for(z = 0; z < key->unit_count; z++) {
            if(*(key->string + z) <= 'Z' && *(key->string + z) >= 'A') {
                y = 1;
                *(key->string + z) += 32;
                }
            }
            if(y == 1) {
                if(num <= 1) {
                    printf("csv%d zone name ",num + 1);
                } else if(num == 2) {
                    printf("root_servers name ");
                } else if(num == 3) {
                    printf("upstream_servers name ");
                } else {
                    printf("unknown num %d name ",num);
                }
                show_esc_stdout(key);
                printf(" had upper-case letters.  Converted.\n");
                }
        }

    /* If it already exists, return a -3 (unless using += operator) */
    if(mhash_get_js(dvar[num],key) != 0 && is_plus != 1)
        return -3;

    /* Copy over the value */
    if(is_plus != 1) {
        if((mhash_put_js(dvar[num],key,value)) == JS_ERROR)
                return JS_ERROR;
    } else { /* += parsing */
            js_string *see, *base;
            if((base = mhash_get_js(dvar[num],key)) == 0) {
                    return -4; /* Can't do += to something not there */
            }
            if(is_numeric_js(base) == 1) {
                    return -5; /* Sorry, += only supported for strings */
            }
            if((see = js_create(256,1)) == 0) {
                    return JS_ERROR;
            }
            if(js_set_encode(see,MARA_LOCALE) == JS_ERROR) {
                    return JS_ERROR;
            }
            if(js_copy(base,see) == JS_ERROR) {
                    return JS_ERROR;
            }
            if(js_append(value,see) == JS_ERROR) {
                    js_destroy(see);
                    return JS_ERROR;
            }
            if(js_copy(see,value) == JS_ERROR) {
                    js_destroy(see);
                    return JS_ERROR;
            }
            js_destroy(see);
            if((see = (js_string *)mhash_undef(dvar[num],key)) == 0) {
                    return JS_ERROR;
            }
            js_destroy(see);
            if((mhash_put_js(dvar[num],key,value)) == JS_ERROR) {
                    return JS_ERROR;
            }
    }

    /* Grow the table if needed */
    return mhash_autogrow(dvar[num]);

    }

/* Parseline: Given a line of the Kiwirc file, parse that line
   input: A js_String object pointing to the contents of the line,
          A js_string object that will contain the name of the variable
          on the line ("ERROR" on syntax error),
          A js_string object that will contain the variable's key (if
          applicable, otherwise "NOTHASH")
          A js_string object that will contain the variable's value
          (description of problem on syntax error)
   output: JS_ERROR on fatal error, 1 if it is a string (or syntax error),
           2 if it is an assosciative array (dictionary), 3 if it inits a
           dictionary
   note:  This needs to be rewritten to be less hackish
*/

int parseline(js_string *line, js_string *var, js_string *key,
              js_string *value, int *do_plus) {

    static js_string *quotes = 0, *alphanumeric = 0, *numbers = 0,
           *equals = 0, *plusq = 0, *hashq = 0, *bslashq = 0, *allq = 0,
           *leftq = 0, *rightq = 0, *cleftq = 0, *crightq = 0,
           *blankq = 0;
    int quote1, quote2, quote3, quote4; /* Location of quotes in
                                           js_string line */
    int varstart,varend, valstart, valend; /* Pointers to beginning and end
                                              of the variable name and the
                                              value for the variable */
    int equalp, hashp; /* Location on equals sign and of hash */
    int tempp; /* temporary pointer */
    int ret = JS_SUCCESS; /* return value */
    char quote = '"';
    char plus = '+';
    char equal = '=';
    char hash = '#';
    char left = '[';
    char right = ']';
    char cleft = '{';
    char cright = '}';
    char bslash = '\\';

    if(do_plus != 0)
            *do_plus = 0;

    /* Sanity checks */
    if(mara_goodjs(line) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(var) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(key) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(value) == JS_ERROR)
        return JS_ERROR;
    /* Alocate strings */
    if(quotes == 0)
        if((quotes = js_create(256,1)) == 0)
                return JS_ERROR;
    if(numbers == 0)
        if((numbers = js_create(256,1)) == 0)
                return JS_ERROR;
    if(alphanumeric == 0)
        if((alphanumeric = js_create(256,1)) == 0)
                return JS_ERROR;
    if(plusq == 0) {
            if((plusq = js_create(256,1)) == 0)
                    return JS_ERROR;
    }
    if(equals == 0)
        if((equals = js_create(256,1)) == 0)
                return JS_ERROR;
    if(hashq == 0)
        if((hashq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(bslashq == 0)
        if((bslashq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(allq == 0)
        if((allq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(leftq == 0)
        if((leftq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(rightq == 0)
        if((rightq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(cleftq == 0)
        if((cleftq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(crightq == 0)
        if((crightq = js_create(256,1)) == 0)
                return JS_ERROR;
    if(blankq == 0)
        if((blankq = js_create(256,1)) == 0)
                return JS_ERROR;

    /* Initialize the various sets we look for */
    js_str2js(equals,&equal,1,1);
    js_str2js(plusq,&plus,1,1);
    js_str2js(hashq,&hash,1,1);
    js_str2js(bslashq,&bslash,1,1);
    js_str2js(leftq,&left,1,1);
    js_str2js(rightq,&right,1,1);
    js_str2js(cleftq,&cleft,1,1);
    js_str2js(crightq,&cright,1,1);
    js_set_encode(alphanumeric,MARA_LOCALE);
    js_set_encode(numbers,MARA_LOCALE);
    js_set_encode(blankq,MARA_LOCALE);
    js_an_chars(alphanumeric);
    js_numbers(numbers);
    js_space_chars(blankq);
    /* AllQ is the union of all parsable characters */
    js_set_encode(allq,MARA_LOCALE);
    js_set_encode(quotes,MARA_LOCALE);
    js_space_chars(allq);
    /* Temporary usage of quotes string to store set of newlines to append */
    js_newline_chars(quotes);
    js_append(quotes,allq);
    js_append(quotes,blankq);
    /* Give quotes it correct value now */
    js_str2js(quotes,&quote,1,1);
    js_append(quotes,allq);
    js_append(equals,allq);
    js_append(plusq,allq);
    js_append(hashq,allq);
    js_append(bslashq,allq);
    js_append(alphanumeric,allq);
    js_append(leftq,allq);
    js_append(rightq,allq);
    js_append(cleftq,allq);
    js_append(crightq,allq);

    /* Initialize the return values to nulls */
    js_qstr2js(var,"");
    js_qstr2js(value,"");
    /* Initialize the key to "NOTHASH" */
    js_qstr2js(key,"NOTHASH");

    /* By default, no quotes on the line */
    quote1 = quote2 = quote3 = quote4 = -2;

    /* If the line is blank, return now, otherwise it gets to be a mess
       later on (as I learned the hard way) */
    /* Locate the hash 1st (since a line with only stuff after a hash is
       functionally blank) */
    if((hashp = js_match(hashq,line)) == JS_ERROR)
        return JS_ERROR;
    tempp = js_notmatch(blankq,line);
    if(tempp == JS_ERROR)
        return JS_ERROR;
    if(tempp == -2 || tempp == hashp)
        return JS_SUCCESS;

    /* Locate the quotes */
    if((quote1 = js_match(quotes,line)) == JS_ERROR)
        return JS_ERROR;
    if(quote1 != -2) {
        quote2 = js_match_offset(quotes,line,quote1 + 1);
        if(quote2 != -2) {
            quote3 = js_match_offset(quotes,line,quote2 + 1);
            if(quote3 != -2) {
                if((quote4 = js_match_offset(quotes,line,quote3 + 1)) == -2) {
                    js_qstr2js(var,"ERROR");
                    js_qstr2js(value,
                               L_2ND_UNQUOTE); /* "2nd quoted expression needs to be unquoted" */
                    return JS_SUCCESS;
                    }
                }
            }
        else {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_NEED_UNQUOTE); /* "Quoted expression needs to be unquoted" */
            return JS_SUCCESS;
            }
        }

    /* Locate the hash */
    if((hashp = js_match(hashq,line)) == JS_ERROR)
        return JS_ERROR;
    /* Look for it beyond 2nd quote if found in quotes */
    if(hashp > quote1 && hashp < quote2)
        hashp = js_match_offset(hashq,line,quote2);
    /* It might be between the 3rd and 4th quotes */
    if(hashp > quote3 && hashp < quote4)
        hashp = js_match_offset(hashq,line,quote4);
    /* Take it beyond the end of the line if not found */
    if(hashp == -2)
        hashp = js_length(line) + 1;
    /* If the quotes are after the hash, remove them */
    if(quote1 > hashp)
        quote1 = quote2 = quote3 = quote4 = -2;
    if(quote3 > hashp)
        quote3 = quote4 = -2;

    /* Error out on any unsupported characters not between quotes nor after
       the hash */
    if((tempp = js_notmatch(allq,line)) == JS_ERROR)
        return JS_ERROR;
    /* If the unsupported character is foind and is before the has pointer
       and the unsupported character is not between the first quote pair
       and the unsupported character is not between the second quote pair */
    if(tempp != -2 && tempp < hashp && (tempp < quote1 || tempp > quote2) &&
        (tempp < quote3 || tempp > quote4)) {
        js_qstr2js(var,"ERROR");
        js_qstr2js(value,L_UNKNOWN_CHAR); /* "Unknown character in line" */
        return JS_SUCCESS;
        }

    /* Error out if there is more than four quotes on a line */
    if(quote4 != -2) {
        if((tempp = js_match_offset(quotes,line,quote4 + 1)) == JS_ERROR)
            return JS_ERROR;
        if(tempp != -2 && tempp < hashp) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_MAX4QUOTES); /* "Maximum allowed quotes on a line is four" */
            return JS_SUCCESS;
            }
        }

    /* Locate the equals */
    if((equalp = js_match(equals,line)) == JS_ERROR)
        return JS_ERROR;
    /* See if there is a plus immediately before the equals */
    if((tempp = js_match(plusq,line)) == JS_ERROR)
            return JS_ERROR;
    if(tempp != -2 && tempp != equalp - 1) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,"+ only allowed in += form");
            return JS_SUCCESS;
    }
    if(tempp == equalp - 1 && do_plus != 0)
            *do_plus = 1;
    if(js_match_offset(plusq,line,equalp) != -2) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,"+ only allowed once on line");
            return JS_SUCCESS;
    }

    /* Find the beginning and end of the first word */
    varstart = varend = -2;
    if((varstart = js_match(alphanumeric,line)) == JS_ERROR)
        return JS_ERROR;
    if(varstart != -2 && varstart < hashp) {
        varend = varstart;
        while(js_match_offset(alphanumeric,line,varend + 1) == varend + 1)
            varend++;
        }
    else if(varstart >= hashp)
        varstart = -2;
    /* Doesn't count if you are in quotes -- this is a syntax error */
    if((varstart > quote1 && varend < quote2) ||
       (varstart > quote3 && varend < quote4)) {
        js_qstr2js(var,"ERROR");
        js_qstr2js(value,L_VAR_NO_QUOTES); /* "Variable name can not be in quotes" */
        return JS_SUCCESS;
        }

    /* Handle the case of this being a dictionary reference */
    tempp = js_match(leftq,line);
    if(tempp != -2) {

        /* Check for invalid syntax */
        if(tempp != varend + 1) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,
             L_LNEXT); /* "Left square bracket must be immediately after variable name" */
            return JS_SUCCESS;
            }
        if(quote1 != tempp + 1) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_QUOTE_DICT); /* "Dictionary element must be in quotes" */
            return JS_SUCCESS;
            }
        if(js_match_offset(leftq,line,tempp + 1) != -2) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_ONE_LEFT); /* "Multiple left square brackets forbidden" */
            return JS_SUCCESS;
            }
        if(js_match(rightq,line) != quote2 + 1) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_RAFTER_QUOTE); /* "Right square bracket must be after quotes" */
            return JS_SUCCESS;
            }

        /* OK, valid syntax.  The *key* is between the first two quotes */
        if((js_substr(line,key,quote1 + 1,quote2 - quote1 - 1)) == JS_ERROR)
            return JS_ERROR;

        /* So the rest of the code, written to not handle dictionary
           thingys, does not have to be rewritten, make quote1 and quote2
           the quote3 and quote4 values.  The earlier code had only quote1
           and quote2 */
        quote1 = quote3;
        quote2 = quote4;
        quote3 = quote4 = -2;
        ret = 2; /* We found a hash reference */
        }

    /* find the beginning and end of the second word */
    valstart = valend = -2;
    /* If we are in quotes, look for it there */
    if(quote1 != -2 && quote2 != -2) {
        valstart = quote1 + 1;
        valend = quote2 - 1;
        /* We need to make sure there are no bare words between varend and
           the first quote, allowing 'foo bar = "baz"' to return an error */
        if(ret != 2) {
            int q;
            /* Always matches in key["foo"] = "bar" cases */
            q = js_match_offset(alphanumeric,line,varend + 1);
            if(q < quote1 && q != -2) {
                js_qstr2js(var,"ERROR");
                js_qstr2js(value,L_2ND_WORD); /* "Second bare word found before quotes" */
                return JS_SUCCESS;
                }
            }
        }
    /* If the value is unquoted, then look for bare numbers after = */
    else {
        /* Syntax error if no equals sign */
        if(equalp < 0) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_NEED_EQUAL); /* "Statement needs an = sign" */
            return JS_SUCCESS;
            }
        if((valstart = js_match_offset(numbers,line,equalp)) == JS_ERROR)
            return JS_ERROR;

        if(valstart != -2 && valstart < hashp) {
            valend = valstart;
            while(js_match_offset(alphanumeric,line,valend + 1) == valend + 1)
                valend++;
            }
        /* If the variable name was not found, look for '{}' */
        else {
            tempp = js_match_offset(cleftq,line,equalp);
            if(tempp != -2) {
                if(js_match(crightq,line) != tempp + 1) {
                    js_qstr2js(var,"ERROR");
                    js_qstr2js(value,L_CURLY_TOGETHER); /* "{ must be immediately followed by }" */
                    return JS_SUCCESS;
                    }
                if(ret == 1)
                    ret = 3;
                else {
                    js_qstr2js(var,"ERROR");
                    js_qstr2js(value,
                   L_NO_HOH); /* "Dictionary elements pointing to dictionaries unsupported" */
                    return JS_SUCCESS;
                    }
                }
            else {
                js_qstr2js(var,"ERROR");
                js_qstr2js(value,L_NEED_VAL); /* "Something must follow =" */
                return JS_SUCCESS;
                }
            }
        }

    /* return error if there is backslash in line */
    if(js_match(bslashq,line) != -2) {
        js_qstr2js(var,"ERROR");
        js_qstr2js(value,L_NO_BACKSLASH); /* "Backslash not supported yet" */
        return JS_SUCCESS;
        }

    /* Now that va[rl]start and va[rl]end have values, do the substrs */

    if(varstart >=0 && varend >= varstart) {
        /* Syntax error if no equals sign */
        if(equalp == -2) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_VARNAME_EQUAL); /* "Variable name needs an = sign" */
            return JS_SUCCESS;
            }
        /* Syntax error if before equals sign */
        if(varstart > equalp) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_EQUAL_BEFORE); /* "Equals sign before variable name" */
            return JS_SUCCESS;
            }
        if((js_substr(line,var,varstart,varend - varstart + 1)) == JS_ERROR)
            return JS_ERROR;
        }

    if(valstart >=0 && valend >= valstart) {
        /* Syntax error if first equals on line is in quotes */
        if(equalp > quote1 && equalp < quote2) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_QUOTE_NO_EQUAL); /* "Quoted string not preceeded by equals sign" */
            return JS_SUCCESS;
            }
        /* Syntax error if after equals sign */
        if(valstart < equalp) {
            js_qstr2js(var,"ERROR");
            js_qstr2js(value,L_EQUAL_AFTER); /* "Equals sign after variable value" */
            return JS_SUCCESS;
            }
        if((js_substr(line,value,valstart,valend - valstart + 1)) == JS_ERROR)
            return JS_ERROR;
        }

    /* Syntax error if any weird stuff exists after end of variable value */
    js_space_chars(allq);
    js_append(quotes,allq);
    js_newline_chars(quotes);
    js_append(quotes,allq);
    tempp = js_notmatch_offset(allq,line,valend + 1);
    if(tempp < hashp && tempp != -2) {
        js_qstr2js(var,"ERROR");
        js_qstr2js(value,L_UNEXPECTED_CHAR); /* "Unexpected character near end of line" */
        return JS_SUCCESS;
        }

    return ret;

    }

/* find_mararc: Find the mararc file we are supposed to read
           Input: js_string to place mararc file in
           Output: JS_ERROR on error, JS_SUCCESS on success
*/
int find_mararc(js_string *out) {

    /* Sanity checks */
    if(mara_goodjs(out) == JS_ERROR)
        return JS_ERROR;

    /* Simple and secure: We look for it in /etc/mararc */
    return js_qstr2js(out,"/etc/mararc");

    }

/* read_mararc: Read /etc/mararc, and set the appropriate symbols
   input: location of rc file, place to put error string (if needed),
          place to put error number (0 if no error, -1 if the error
          does not have a line number)
   output: JS_ERROR on error, JS_SUCCESS on success
   global vars: dvar
*/

int read_mararc(js_string *fileloc,js_string *errorstr,int *errorret) {
    static js_string *line = 0;
    static js_string *var = 0;
    static js_string *key = 0;
    static js_string *value = 0;
    static js_string *tstr = 0; /* Temporary string */

    int error = 0; /* Line error is found on */
    int linenum = 1, command;
    int tnum; /* temporary number */
    int is_plus = 0; /* Whether the line in question is a += instead of an =
                        operator */

    static js_file *file = 0;

    *errorret = -1; /* Fatal error */

    /* Allocate memory for the variables */
    if(line == 0)
        if((line = js_create(256,1)) == 0) {
            js_qstr2js(errorstr,L_JSCREATE_FATAL); /* "Fatal error creating js_string" */
            return JS_ERROR;
            }
    if(var == 0)
        if((var = js_create(256,1)) == 0) {
            js_qstr2js(errorstr,L_JSCREATE_FATAL); /* "Fatal error creating js_string" */
            return JS_ERROR;
            }
    if(key == 0)
        if((key = js_create(256,1)) == 0) {
            js_qstr2js(errorstr,L_JSCREATE_FATAL); /* "Fatal error creating js_string" */
            return JS_ERROR;
            }
    if(value == 0)
        if((value = js_create(256,1)) == 0) {
            js_qstr2js(errorstr,L_JSCREATE_FATAL); /* "Fatal error creating js_string" */
            return JS_ERROR;
            }
    if(tstr == 0)
        if((tstr = js_create(256,1)) == 0) {
            js_qstr2js(errorstr,L_JSCREATE_FATAL); /* "Fatal error creating js_string" */
            return JS_ERROR;
            }
    if(file == 0) {
        if((file = js_alloc(1,sizeof(js_file))) == 0) {
            js_qstr2js(errorstr,L_FILEMAKE_FATAL); /* "Fatal error creating file" */
            return JS_ERROR;
            }
        file->buffer = 0;
    }

    /* Initialize values */
    js_qstr2js(errorstr,"");
    js_set_encode(line,MARA_LOCALE);
    js_set_encode(var,MARA_LOCALE);
    js_set_encode(key,MARA_LOCALE);
    js_set_encode(value,MARA_LOCALE);
    js_set_encode(tstr,MARA_LOCALE);
    /* We should have some kind of check that this has not been done yet */
    init_dvars();
    init_kvars();

    /* Start reading and processing lines from the file */
    if(js_open_read(fileloc,file) == JS_ERROR) {
        *errorret = -1;
        js_qstr2js(errorstr,L_CANNOT_OPEN); /* "Could not open mararc file at " */
        js_append(fileloc,errorstr);
        return JS_SUCCESS;
        }
    while(!js_buf_eof(file)) {
        if((js_buf_getline(file,line)) <= JS_ERROR) {
            js_qstr2js(errorstr,L_JSBUFGETLINE_FATAL); /* "Fatal error calling js_buf_getline" */
            js_close(file);
            return JS_ERROR;
            }
        if((command = parseline(line,var,key,value,&is_plus)) == JS_ERROR) {
            js_qstr2js(errorstr,L_PARSELINE_FATAL); /* "Fatal error calling parseline" */
            js_close(file);
            return JS_ERROR;
            }
        if(command == 2 && !error) { /* Add or append element to
                                      * dictionary object */
            tnum = dkeyword2num(var);
            if(tnum == JS_ERROR) {
                js_qstr2js(errorstr,L_KEYWORD2NUM_FATAL); /* "Fatal error calling keyword2num" */
                js_close(file);
                return JS_ERROR;
                }
            if(tnum == -2) { /* If the symbol was not found */
                /* If an error happened parsing the line... */
                js_qstr2js(tstr,"ERROR");
                if(js_issame(tstr,var)) {
                    if(!error) {
                        error = linenum;
                        *errorret = error;
                        js_copy(value,errorstr);
                        }
                    }
                }
            else if(!error) {
                int result;
                result = write_dvar(var,key,value,is_plus);
                if(result == -3) {
                /* Exit if dictionary element exists more than once */
                    printf("%s",L_DT_PMRC);
                    js_show_stdout(var);
                    printf("%s","[\"");
                    js_show_stdout(key);
                    printf("%s","\"]");
                    printf("%s",L_DECLARED_TWICE);
                    js_show_stdout(var);
                    printf("%s","[\"");
                    js_show_stdout(key);
                    printf("%s","\"] = \"");
                    js_show_stdout(value);
                    printf("%s","\"\n");
                    printf("Error in line %d\n",linenum);
                    exit(1);
                    }
                else if(result == -4) {
                    printf("+= operator target must be previously ");
                    printf("defined with = operator\n");
                    printf("Error in line %d\n",linenum);
                    exit(1);
                    }
                else if(result == -5) {
                    printf("+= operator target not supported for ");
                    printf("numeric values\n");
                    printf("Error in line %d\n",linenum);
                    exit(1);
                    }
                else if(result == -6) {
                    printf("Trying to access unitizalized dictionary var.\n");
                    printf("Try adding this line to the beginning of the ");
                    printf("mararc file:\n\n");
                    js_show_stdout(var);
                    printf(" = {}\n");
                    printf("Error in line %d\n",linenum);
                    exit(1);
                    }
                }
            }
        else if(command == 1 && !error) { /* Add element to string object */
            tnum = keyword2num(var);
            if(tnum == -2) {
                /* If an error happened parsing the line... */
                js_qstr2js(tstr,"ERROR");
                if(js_issame(tstr,var)) {
                    if(!error) {
                        error = linenum;
                        *errorret = error;
                        js_copy(value,errorstr);
                        }
                    }
                }
            if(tnum == -2 && var->unit_count > 0 && !error) {
                printf("FATAL ERROR: Unknown mararc variable ");
                show_esc_stdout(var);
                printf("\nPlease look for the uncommented string \"");
                show_esc_stdout(var);
                printf("\"\nin your mararc file and remove this line.\n");
                printf("\nThe line this error is on looks like this:\n");
                /* Hackish way of chopping final newline */
                if(*(line->string + line->unit_count - 1) == '\n' &&
                   line->unit_count > 0) {
                        line->unit_count--;
                   }
                show_esc_stdout(line);
                printf("\n");
                exit(10);
                }
            if(tnum == JS_ERROR) {
                js_qstr2js(errorstr,L_KEYWORD2NUM_FATAL); /* "Fatal error calling keyword2num" */
                js_close(file);
                return JS_ERROR;
                }
            if(tnum == -2) { /* If the symbol was not found */
                /* If an error happened parsing the line... */
                js_qstr2js(tstr,"ERROR");
                if(js_issame(tstr,var)) {
                    if(!error) {
                        error = linenum;
                        *errorret = error;
                        js_copy(value,errorstr);
                        }
                    }
                }
            else if(!error) {
                    int result;
                    result = write_kvar(var,value,is_plus);
                    if(result == -4) {
                            printf("+= operator target must be previously ");
                            printf("defined with = operator\n");
                            printf("Error in line %d\n",linenum);
                            exit(1);
                    }
                    else if(result == -5) {
                            printf("+= operator target not supported for ");
                            printf("numeric values\n");
                            printf("Error in line %d\n",linenum);
                            exit(1);
                    }
                }
            }
        else if(command == 3)
                new_dvar(var);
        linenum++;
        }

    if(!error)
        *errorret = 0;

    js_close(file);

    /* DEBUG; show them everything set in the MaraRC file */
    /* Disaled by commenting out */
    /*
    printf("Normal string variables: \n");
    for(linenum = 0; linenum < KEYCOUNT; linenum++) {
            printf("\t%s = \"",keywords[linenum]);
            show_esc_stdout(kvar[linenum]);
            printf("\"\n");
    }
    printf("\nDictionary variables: \n");
    for(linenum = 0; linenum < DKEYCOUNT; linenum++) {
            mhash *dvh;
            js_string *key;
            key = js_create(256,1);
            dvh = (mhash *)dvar_raw(linenum);
            if(dvh == 0) {
                    printf("\t%s is undefined\n",dkeywords[linenum]);
            } else {
                    if(mhash_firstkey(dvh,key) == 0) {
                            printf("\t%s is empty\n",dkeywords[linenum]);
                    } else {
                            do {
                                    printf("\t%s[\"",dkeywords[linenum]);
                                    show_esc_stdout(key);
                                    printf("\"] = \"");
                                    show_esc_stdout(mhash_get_js(dvh,key));
                                    printf("\"\n");
                            } while(mhash_nextkey(dvh,key) != 0);
                    }
            }
    }
    printf("\n\n"); */
    /* End DEBUG code to show everything read in */

    return JS_SUCCESS;
    }

