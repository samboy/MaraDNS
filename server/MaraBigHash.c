/* Copyright (c) 2002-2014 Sam Trenholme
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

/* Langauge-specific labels */
#include "MaraBigHash_locale.h"

/* Include stuff needed to be a UDP server */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifndef MINGW32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock.h>
#include <wininet.h>
#endif
#include "../dns/functions_dns.h"
#include "../parse/functions_parse.h"
#include "../parse/Csv2_database.h"
#include "../parse/Csv2_read.h"
#include "../parse/Csv2_functions.h"
#include "functions_server.h"
#include "timestamp.h"

extern int log_level;
extern int no_cname_warnings;
extern int dns_records_served;
int cname_warnings_shown = 0;


/* Handler to handle warnings.
   Input: Pointer to js_string object with warning message,
          line number (-1 to display no line number)
   output: JS_SUCCESS */

int warning(js_string *msg, int line) {
    if(log_level == 0)
        return JS_SUCCESS;
    printf("%s",L_WARNING); /* "Warning: " */
    js_show_stdout(msg);
    if(line != -1)
        printf("%s%d",L_ONLINE,line); /* " on line ", line */
    printf("%s",L_F); /* "\n" */
    return JS_SUCCESS;
    }

/* Given a js_string object containing a raw UDP dname,
   if the data starts off with a "star record" (<01>*), convert the
   star record to a '_'.  There should be no metacharacters in domain
   labels--use EDNS-style labels for metainformation!
   input: input to label we modify in place, whether we are recursive
          (and not permit star labels at the end of a record)
   output: JS_SUCCESS if we were successful, JS_ERROR on error
*/

int starrecord_to_meta(js_string *rr, int recursive) {

    int counter;
    if(js_has_sanity(rr) == JS_ERROR)
        return JS_ERROR;
    if(rr->unit_size != 1)
        return JS_ERROR;

    /* This only changes strings at least 2 units long */
    if(rr->unit_count < 2)
        return JS_SUCCESS;

    /* If this string starts with <01>*, change the star record to a '_' */
    if(*(rr->string) == 1 && *(rr->string + 1) == '*') {
        *(rr->string) = '_';
        if(rr->unit_count > rr->max_count)
            return JS_ERROR;
        for(counter = 1; counter < rr->unit_count; counter++)
            *(rr->string + counter) = *(rr->string + counter + 1);
        rr->unit_count--;
        }

    /* If the dlabel ends with <01>*<00>, return a "no stars
       at the end" error message (if recursion is enabled), and convert
       the star label in question */
    counter = dlabel_length(rr,0);
    counter -= 3;
    if(counter < 0)
        return JS_SUCCESS;
    if(*(rr->string + counter) == 1 && *(rr->string + counter + 1) == '*') {
        *(rr->string + counter) = '_';
        counter++;
        for(; counter < rr->unit_count; counter++)
            *(rr->string + counter) = *(rr->string + counter + 2);
        rr->unit_count -= 2;
        if(recursive == 1) {
            show_timestamp();
            printf(
"Warning: star labels at the end can not be used when recursion is enabled\n");
            }
        }

    return JS_SUCCESS;
    }

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, get the query type for the string in
   question.
   Input: js_string object with raw UDP data
   Output: JS_ERROR on error, record type (0-65535) on success */

int get_rtype(js_string *js) {

    int rtype;

    /* Sanity tests */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_count < 3)
        return JS_ERROR;

    /* get the last two bytes */
    rtype = (*(js->string + js->unit_count - 1) & 0xff) |
            (*(js->string + js->unit_count - 2) & 0xff) << 8;

    return rtype;
    }

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, and the desired new record number for
   that data type, convert the record type to the new number.
   Input: js_string object with raw UDP data, the desired new record type
   Output: JS_ERROR on error, JS_SUCCESS on success */

int change_rtype(js_string *js, int newtype) {

    /* Sanity tests */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_count < 3)
        return JS_ERROR;
    if(newtype < 0 || newtype > 65535)
        return JS_ERROR;

    /* Change the last two bytes */
    *(js->string + js->unit_count - 1) = newtype & 0xff;
    *(js->string + js->unit_count - 2) = (newtype & 0xff00) >> 8;

    return JS_SUCCESS;
    }

/* Initialize a rr data structure
   Input: Pointer to the rr
   Output: none
 */

void init_rr(rr *data) {
     data->expire = data->ttl = data->authoritative = data->rr_type = 0;
     data->next = data->ip = 0;
#ifdef IPV6
     data->ip6 = 0;
#endif
     data->query = data->data = 0;
     data->ptr = 0;
     data->seen = 0;
     data->zap = 0;
     data->expire = data->ttl = data->authoritative = 0;
     data->perms = 0;
     data->list = 0;
     data->rcode = 0;
     return;
     }

/* Add a host (domain) name to the big hash
   Input: Pointer to hash, host name, host ttl, authoritative flag,
          expire (currently always 0)
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int mhash_put_rr(mhash *hash, js_string *query, js_string *value, uint32 ttl,
                 uint32 authoritative, uint32 expire, perm_t perms) {

    rr *data = 0;
    js_string *new = 0;
    int ret, rrtype;
    /* Create a structure for putting the rr data in */
    if((data = js_alloc(1,sizeof(rr))) == 0)
        return JS_ERROR;

    /* First, clear out all the fields */
    init_rr(data);

    /* Store the simple data in the rr data */
    data->expire = 0;
    data->ttl = ttl;
    data->authoritative = authoritative;
    data->perms = perms;
    /* Get the rr type from the query string */
    rrtype = get_rtype(query);
    if(rrtype == JS_ERROR) {
        js_dealloc(data);
        return JS_ERROR;
        }
    if(rrtype < 0 || rrtype > 65535) {
        js_dealloc(data);
        return JS_ERROR;
        }
    data->rr_type = rrtype;

    /* Create a js_string object to store the raw binary answer */
    if((new=js_create(value->unit_count + 1,value->unit_size)) == 0) {
        js_dealloc(data);
        return JS_ERROR;
        }
    if(js_copy(value,new) == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }
    /* And put a pointer to that js_string in the rr data */
    data->data = new;
    /* This is a new record, so the pointers to other records this uses
       are blank */
    data->ip = data->next = 0;

    /* Store that data in the big hash */
    ret = mhash_put(hash,query,data,MARA_DNSRR);

    /* Add this entry to the corresponding ANY chain */
    if(any_add_rr(hash,query,data) == JS_ERROR) {
        return JS_ERROR;
        }

    /* Automatically grow the hash if appropriate */
    mhash_autogrow(hash);

    /* Now that we have copied the key to the big hash, add a pointer
       to that key to the data.  BTW, don't use mhash_get_immutable_key then
       change the value of the key string--dong so will mess things up
       badly (it will make it impossible to ever get that hash element
       again). */

    data->query = mhash_get_immutable_key(hash,query);

    if(ret == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }

    return JS_SUCCESS;
    }

/* Add a host (domain) name to an already existing element in the big hash
   Input: Pointer to hash, host name, host ttl, authoritative flag,
          expire (currently always 0)
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int mhash_add_rr(mhash *hash, js_string *query, js_string *value, uint32 ttl,
                 uint32 authoritative, uint32 expire, perm_t perms) {

    rr *data, *point;
    js_string *new;
    mhash_e spot_data;
    int rrtype;

    /* Create a structure for putting the rr data in */
    if((data = js_alloc(1,sizeof(rr))) == 0)
        return JS_ERROR;

    /* First, clear out all the fields */
    init_rr(data);

    /* Store the simple data in the rr data */
    data->expire = 0;
    data->ttl = ttl;
    data->authoritative = authoritative;
    data->perms = perms;

    /* Get the rr type from the query string */
    rrtype = get_rtype(query);
    if(rrtype == JS_ERROR) {
        js_dealloc(data);
        return JS_ERROR;
        }
    if(rrtype < 0 || rrtype > 65535) {
        js_dealloc(data);
        return JS_ERROR;
        }
    data->rr_type = rrtype;

    /* Create a js_string object to store the raw binary answer */
    if((new=js_create(value->unit_count + 1,value->unit_size)) == 0) {
        js_dealloc(data);
        return JS_ERROR;
        }
    if(js_copy(value,new) == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }
    /* And put a pointer to that js_string in the rr data */
    data->data = new;

    /* Find the element in the big hash to add this data to */
    spot_data = mhash_get(hash,query);
    if(spot_data.value == 0) { /* If the element does not exist */
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR; /* Or maybe we should just add the data... */
        /* ret = mhash_put(hash,query,data,MARA_DNSRR); (Error check) */
        }
    /* Exit if the data pointed to is *not* a DNS resource record */
    if(spot_data.datatype != MARA_DNSRR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }

    /* OK, now we have to go through the linked list and find the
       the first NS record */

    /* Point to the first link in the chain */
    point = spot_data.value;

    /* Make a note of what question (query) the first answer points to.
       Since the inserted data will be an additional answer for the
       same question, we can do it this way. */
    data->query = point->query;

    /* Find the place to insert our data */
    while(point->next != 0 && point->next->rr_type != RR_NS)
        point = point->next;
    /* Insert that data in the linked list */
    data->next = point->next;
    point->next = data;

    return JS_SUCCESS;

    }

/* Add a PTR pointer to the first record in a given chain of records
   (if it does not already have a PTR record)
   This is used by the recursive code, hence we need to be careful that
   we don't make the data inconsistant
   Input: Pointer to hash, host name, pointer to string with value
          of PTR record
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int mhash_add_ptr(mhash *hash, js_string *query, js_string *value) {

    rr *point;
    js_string *new;
    mhash_e spot_data;

    /* Create a js_string object to store the raw ptr answer */
    if((new=js_create(value->unit_count + 1,value->unit_size)) == 0) {
        /* Jaakko things that we should add a js_destroy(new); here.
           I disagree--if the creation of the object returns a 0,
           it was never created. */
        return JS_ERROR;
        }
    if(js_copy(value,new) == JS_ERROR) {
        js_destroy(new);
        return JS_ERROR;
        }
    /* And put a pointer to that js_string in the rr data */

    /* Find the element in the big hash to add this data to */
    spot_data = mhash_get(hash,query);
    if(spot_data.value == 0) { /* If the element does not exist */
        js_destroy(new);
        return JS_ERROR; /* Or maybe we should just add the data... */
        /* ret = mhash_put(hash,query,data,MARA_DNSRR); (Error check) */
        }
    /* Exit if the data pointed to is *not* a DNS resource record */
    if(spot_data.datatype != MARA_DNSRR) {
        js_destroy(new);
        return JS_ERROR;
        }

    /* OK, now all we have to do is add the ptr if it is not already set */

    /* Point to the first link in the chain */
    point = spot_data.value;

    /* In order to avoid inconsistant data, we only add the PTR once */
    if(point->ptr != 0) {
        js_destroy(new);
        return JS_SUCCESS; /* It was, technically, sucessful */
        }

    point->ptr = new;
    return JS_SUCCESS;

    }

/* Add a pointer to an IP to the first record in a given chain of records
   (if it does not already have an IP)
   This is used by the recursive code, hence we need to be careful that
   we don't make the data inconsistant
   Input: Pointer to hash, host name, value of A record
   Output: JS_ERROR on error, JS_SUCCESS on success
   NOTE: This will do really weird things if you add an IP to something that
         is not a CNAME or NS record.
*/

int mhash_add_ip(mhash *hash, js_string *query, js_string *value) {

    rr *data = 0, *point = 0;
    js_string *new = 0, *new_query = 0;
    mhash_e spot_data;
    int rrtype;

    /* Create a structure for putting the rr data in */
    if((data = js_alloc(1,sizeof(rr))) == 0)
        return JS_ERROR;

    /* First, clear out all the fields */
    init_rr(data);

    /* Since we are adding an IP, the rrtype is always RR_A */
    rrtype = RR_A;
    data->rr_type = rrtype;

    /* Create a js_string object to store the raw binary answer */
    if((new=js_create(value->unit_count + 1,value->unit_size)) == 0) {
        js_dealloc(data);
        /* Jaakko things that we should add a js_destroy(new); here.
           I disagree--if the creation of the object returns a 0,
           it was never created. */
        return JS_ERROR;
        }
    if(js_copy(value,new) == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }
    /* And put a pointer to that js_string in the rr data */
    data->data = new;

    /* Find the element in the big hash to add this data to */
    spot_data = mhash_get(hash,query);
    if(spot_data.value == 0) { /* If the element does not exist */
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR; /* Or maybe we should just add the data... */
        /* ret = mhash_put(hash,query,data,MARA_DNSRR); (Error check) */
        }
    /* Exit if the data pointed to is *not* a DNS resource record */
    if(spot_data.datatype != MARA_DNSRR) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }

    /* OK, now we have to go through the linked list and find the
       the record not pointing to an IP already */

    /* Point to the first link in the chain */
    point = spot_data.value;

    /* In order to avoid inconsistant data, we only add an IP to
       the first element in the chain */
    if(point->ip != 0) {
        js_dealloc(data);
        js_destroy(new);
        return JS_ERROR;
        }

    /* We need to synthesize a "query" for the IP data that this record
       points to */
    if((new_query = js_create(point->data->unit_count + 3,1)) == 0) {
        js_dealloc(data);
        js_destroy(new);
        /* Jaakko feels that we should have a js_destroy(new_query); here.
           I disagree, since the memory was never allocated, and it is
           possible that a free(0) will cause a segfault--something we
           definitly don't want on a daemon */
        return JS_ERROR;
        }
    if(js_copy(point->data,new_query) == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        js_destroy(new_query);
        return JS_ERROR;
        }
    if(js_adduint16(new_query,RR_A) == JS_ERROR) {
        js_dealloc(data);
        js_destroy(new);
        js_destroy(new_query);
        return JS_ERROR;
        }
    /* Make a note of what question (query) the first answer points to.
       Since the inserted data will be an additional answer for the
       same question, we can do it this way. */
    data->query = new_query;

    /* Insert that data in the linked list */
    data->next = 0;
    point->ip = data;
    /* Store the simple data in the rr data */
    data->expire = point->expire;
    data->ttl = point->ttl;
    data->authoritative = point->authoritative;

    return JS_SUCCESS;

    }

/* Add a ns pointer to an already existing element in the big hash
   Input: Pointer to hash, query to change, query of ns record to add
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int mhash_add_ns(mhash *hash, js_string *query, js_string *ns) {

    rr *point, *ns_rr;
    mhash_e spot_data;
    int rrtype;

    /* Get the rr type from the query string */
    rrtype = get_rtype(query);
    if(rrtype == JS_ERROR) {
        return JS_ERROR;
        }
    if(rrtype < 0 || rrtype > 65535) {
        return JS_ERROR;
        }

    /* We do not add NS records to NS records (it makes no sense to do so) */
    if(rrtype == RR_NS)
        return JS_SUCCESS;

    /* Get the rr type from the ns string */
    rrtype = get_rtype(ns);
    if(rrtype == JS_ERROR) {
        return JS_ERROR;
        }
    if(rrtype < 0 || rrtype > 65535) {
        return JS_ERROR;
        }

    /* We only add to non-NS records (it makes no sense to add to NSes) */
    if(rrtype != RR_NS)
        return JS_SUCCESS;

    /* Find the element in the big hash to add this data to */
    spot_data = mhash_get(hash,query);
    if(spot_data.value == 0) { /* If the element does not exist */
        return JS_ERROR;
        }
    /* Exit if the data pointed to is *not* a DNS resource record */
    if(spot_data.datatype != MARA_DNSRR) {
        return JS_ERROR;
        }

    point = spot_data.value;

    /* Next: Find the NS RR (or RR set) we will point to */
    spot_data = mhash_get(hash,ns);
    if(spot_data.value == 0) { /* If the NS element does not exist */
        return JS_SUCCESS; /* We may not have a NS record in place yet;
                              just make it an RR without a NS then */
        }
    /* Exit if the NS data pointed to is *not* a DNS resource record */
    if(spot_data.datatype != MARA_DNSRR) {
        return JS_ERROR;
        }

    ns_rr = spot_data.value;

    /* OK, now we have to go through the linked list and find the
       the end */

    while(point->next != 0)
        point = point->next;
    /* Insert the pointer to the NS rr at the end of the linked list */
    point->next = ns_rr;

    return JS_SUCCESS;
    }

/* Populate the main assosciative array (the one where the raw UDP query is
   the key and the value is the answer) with the data from the various
   csv1 files (this is called from populate_main)
   Input: A pointer to the hash to populate, a pointer to the string to
          put an error message in, whether MaraDNS is being recursive or
          not
   Ouput: JS_ERROR on error, -2 on parsing error, 0 if we don't
          put anything in the csv hash, JS_SUCCESS on success
   Global vars used: The kvars and dvars
 */

int parse_csv1s(mhash *maintable, js_string *error, int recursive) {
    mhash *csvs; /* List of CSV1 files to read */
    js_string *zone;
    js_string *udpzone, *filename, *line, *soaline, *pline;
    js_string *query, *data;
    js_file *desc;
    uint32 ttl;
    int rr_type, linenum = 0, rrnum = 0, in_ns = 1;
    int result;

    /* Sanity check */
    if(js_has_sanity(error) == JS_ERROR)
        return JS_ERROR;

    /* Blank out the error string */
    js_qstr2js(error,"");

    /* Create the js_String objects containing the zone name and
       corresponding filename */
    if((udpzone = js_create(128,1)) == 0) {
        return JS_ERROR;
        }
    if((filename = js_create(256,1)) == 0) {
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((line = js_create(MAX_RECORD_LENGTH + 3,1)) == 0) {
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if(js_set_encode(line,MARA_LOCALE) == JS_ERROR) {
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((pline = js_create(MAX_RECORD_LENGTH + 3,1)) == 0) {
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if(js_set_encode(pline,MARA_LOCALE) == JS_ERROR) {
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((soaline = js_create(256,1)) == 0) {
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if(js_set_encode(soaline,MARA_LOCALE) == JS_ERROR) {
        js_destroy(soaline);
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((query = js_create(256,1)) == 0) {
        js_destroy(soaline);
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((data = js_create(MAX_RECORD_LENGTH + 3,1)) == 0) {
        js_destroy(query);
        js_destroy(soaline);
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((zone = js_create(MAX_ZONE_SIZE,1)) == 0) {
        js_destroy(data);
        js_destroy(query);
        js_destroy(soaline);
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }
    if((desc = js_alloc(1,sizeof(js_file))) == 0) {
        js_destroy(zone);
        js_destroy(data);
        js_destroy(query);
        js_destroy(soaline);
        js_destroy(pline);
        js_destroy(line);
        js_destroy(filename);
        js_destroy(udpzone);
        return JS_ERROR;
        }

    desc->buffer = 0;

    /* Pass 1: fill up the hash with the AN and NS answers */

    /* Get all of the keys in the csv1 hash */
    csvs = (mhash *)dvar_raw(dq_keyword2n("csv1"));

    if(csvs == 0) {
        /* A csv1 hash is no longer mandatory, now that MaraDNS has recursive
           capability */
        js_destroy(udpzone); js_destroy(filename); js_destroy(line);
        js_destroy(pline); js_destroy(soaline); js_destroy(query);
        js_destroy(data); js_destroy(zone); js_dealloc(desc);
        return 0;
        /*js_qstr2js(error,L_INITCSV); */
        /*"csv1 hash is not correctly initialized.\nMake sure to have csv1 initialized with csv1 = {}, and that it has one or\nmore elements." */
        /*return -2;*/
        }
    /* Point to the first key in the hash */
    if(mhash_firstkey(csvs,zone) == 0) {
        /* We actually do not need to have anything in the hash, in
           the case of people running a recursive nameserver */
        js_destroy(udpzone); js_destroy(filename); js_destroy(line);
        js_destroy(pline); js_destroy(soaline); js_destroy(query);
        js_destroy(data); js_destroy(zone); js_dealloc(desc);
        return 0;
        }
    do {
    /*while((offset = mhash_nextkey(csvs,offset)) != 0) */
        /* If this hash element points to live data */
        if(zone != 0) {

            /* Make udpzone be like zone, but in raw RFC1035 format */
            if(js_qstr2js(udpzone,"A") == JS_ERROR) {
                js_destroy(udpzone); js_destroy(filename); js_destroy(line);
                js_destroy(pline); js_destroy(soaline); js_destroy(query);
                js_destroy(data); js_destroy(zone); js_dealloc(desc);
                return JS_ERROR;
                }
            if(js_append(zone,udpzone) == JS_ERROR) {
                js_destroy(udpzone); js_destroy(filename); js_destroy(line);
                js_destroy(pline); js_destroy(soaline); js_destroy(query);
                js_destroy(data); js_destroy(zone); js_dealloc(desc);
                return JS_ERROR;
                }
            if(hname_2rfc1035(udpzone) == JS_ERROR) {
                js_qstr2js(error,L_BADZONE); /* "A zone file is incorrectly named.  All zone files must end with a dot, e.g.\ncsv1[\"example.com.\"] = \"filename\".\nBad zone name: " */
                js_qappend("\ncsv1[\"",error);
                js_append(zone,error);
                js_qappend("\"] = \"",error);
                js_append(mhash_get_js(csvs,zone),error);
                js_qappend("\"\n",error);
                js_destroy(udpzone); js_destroy(filename); js_destroy(line);
                js_destroy(pline); js_destroy(soaline); js_destroy(query);
                js_destroy(data); js_destroy(zone); js_dealloc(desc);
                return -2;
                }
            /* Add the binary RR_NS to the end of the udpzone string
               (This makes authoritative checks easier) */
            if(js_addbyte(udpzone,0) == JS_ERROR) {
                js_destroy(udpzone); js_destroy(filename); js_destroy(line);
                js_destroy(pline); js_destroy(soaline); js_destroy(query);
                js_destroy(data); js_destroy(zone); js_dealloc(desc);
                return JS_ERROR;
                }
            if(js_addbyte(udpzone,RR_NS) == JS_ERROR) {
                js_destroy(udpzone); js_destroy(filename); js_destroy(line);
                js_destroy(pline); js_destroy(soaline); js_destroy(query);
                js_destroy(data); js_destroy(zone); js_dealloc(desc);
                return JS_ERROR;
                }

            /* Get the file name to open from the element's value */
            js_destroy(filename);
            filename = mhash_get_js(csvs,zone);
            /* Open up the filename in question */
            if(js_open_read(filename,desc) == JS_ERROR) {
                js_qstr2js(error,L_ZONEOPEN); /* "Can not open zone file " */
                js_append(zone,error);
                warning(error,-1);
                continue;
                }

            /* Initialize the linenum and rrnum for each zone file */
            linenum = rrnum = 0;
            in_ns = 1;

            /* Read the zone file and parse each line one by one */
            while(!js_buf_eof(desc)) {

                /* Get the line */
                result = js_buf_getline(desc,line);
                if(result == JS_ERROR) {
                    js_destroy(udpzone); js_destroy(filename);
                    js_destroy(line);
                    js_destroy(pline); js_destroy(soaline); js_destroy(query);
                    js_destroy(data); js_destroy(zone); js_dealloc(desc);
                    return JS_ERROR;
                    }
                else if(result == -2) {
                    printf("%s%d%s",L_LINE_NUMBER,linenum + 1,L_TOO_LONG);
                    show_esc_stdout(filename);
                    printf("\n");
                    /* "line number ... is too long in file " */
                    js_destroy(udpzone); js_destroy(filename);
                    js_destroy(line);
                    js_destroy(pline); js_destroy(soaline); js_destroy(query);
                    js_destroy(data); js_destroy(zone); js_dealloc(desc);
                    return JS_ERROR;
                    }

                /* Increment the Line Number */
                linenum++;

                /* Handle blank zone files and zone files with only
                   SOA and authoritative NS records */
                if(js_buf_eof(desc) && in_ns && line->unit_count == 0) {
                    /* Yes, there is the special case of a zone with
                       no records */
                    if(js_length(soaline) == 0)
                        continue;
                    /* Add the SOA in the special case of the zone
                       only having SOA and NS records */
                    if(parse_csv1_line(soaline,query,data,&ttl) != RR_SOA) {

                        js_destroy(udpzone); js_destroy(filename);
                        js_destroy(line);
                        js_destroy(pline); js_destroy(soaline);
                        js_destroy(query);
                        js_destroy(data); js_destroy(zone); js_dealloc(desc);
                        return JS_ERROR;
                        }
                    add_rr_to_bighash(maintable,query,data,ttl,udpzone,0);
                    break;
                    }

                /* We stop processing this file if we are at the end */
                if(js_buf_eof(desc) && line->unit_count == 0)
                    break;

                /* Process the % character and any \ sequences */
                if(bs_process(line,pline,zone) == JS_ERROR) {
                    js_destroy(udpzone); js_destroy(filename);
                    js_destroy(line);
                    js_destroy(pline); js_destroy(soaline); js_destroy(query);
                    js_destroy(data); js_destroy(zone); js_dealloc(desc);
                    return JS_ERROR;
                    }

                /* Parse the line and get the rr type of the query */
                rr_type = parse_csv1_line(pline,query,data,&ttl);

                /* If the query is a star record, change it to MaraDNS'
                   EDNS-style label for star records */
                starrecord_to_meta(query,recursive);

                /* Handle error conditions */
                if(rr_type == JS_ERROR) {
                    js_qstr2js(error,L_FATAL); /* "Fatal error in zone file " */
                    js_append(zone,error);
                    js_qappend(L_ABOUT_THIS,error); /* " (aborting this zone file)" */
                    warning(error,linenum);
                    /* Stop processing the rest of the zone file */
                    break;
                    }
                if(rr_type == -2) {
                    js_qstr2js(error,L_S_ZONE); /* "Syntax error in zone file" */
                    js_append(zone,error);
                    js_qappend(L_L,error); /* " (" */
                    js_append(data,error);
                    js_qappend(L_R,error); /* ")" */
                    warning(error,linenum);
                    continue;
                    }
                /* Process lines with legitimate rr types */
                if(rr_type > 0) { /* Only process lines w/ data to process */
                    rrnum++;
                    /* The first record must be a SOA record */
                    if(rrnum == 1 && rr_type != RR_SOA) {
                        js_qstr2js(error,
                        L_FIRST_SOA); /* "First record in csv1 zone file must be SOA record." */
                        js_qappend(L_ZONE,error); /* "Zone: " */
                        js_append(zone,error);
                        warning(error,1);
                        break;
                        }
                    /* Do not actually add the SOA record until we
                       add all the NS records for this zone (so the SOA
                       record knows what NS records to place in the NS
                       section of the answer) */
                    else if(rrnum == 1) {
                        if(js_copy(pline,soaline) == JS_ERROR) {
                            js_destroy(udpzone); js_destroy(filename);
                            js_destroy(line);
                            js_destroy(pline); js_destroy(soaline);
                            js_destroy(query);
                            js_destroy(data); js_destroy(zone);
                            js_dealloc(desc);
                            return JS_ERROR;
                            }
                        }
                    /* Only one SOA allowed per zone */
                    else if(rrnum != 1 && rr_type == RR_SOA) {
                        js_qstr2js(error,L_SECOND_SOA); /* "Second SOA in zone file " */
                        js_append(zone,error);
                        warning(error,linenum);
                        continue;
                        }
                    /* We actually add the SOA record to the big hash
                       before adding the first non-authoritative NS record
                       to the zone */
                    /* If this is a non-NS record or a NS record for another
                       zone */
                    else if((rr_type != RR_NS || !js_issame(query,udpzone))
                            && in_ns) {
                        /* Add the SOA after the zone's NS records */
                        if(parse_csv1_line(soaline,query,data,&ttl) !=
                           RR_SOA) {
                            js_destroy(udpzone); js_destroy(filename);
                            js_destroy(line);
                            js_destroy(pline); js_destroy(soaline);
                            js_destroy(query);
                            js_destroy(data); js_destroy(zone);
                            js_dealloc(desc);
                            return JS_ERROR;
                            }
                        add_rr_to_bighash(maintable,query,data,ttl,udpzone,0);
                        /* Now, add the record we are looking at (the
                           first non-SOA and non-authoritative-NS record) */
                        rr_type = parse_csv1_line(pline,query,data,&ttl);
                        if(rr_type == JS_ERROR) {
                            js_qstr2js(error,L_FATAL); /* "Fatal error in zone file " */
                            js_append(zone,error);
                            js_qappend(L_ABORT,error); /* " (aborting zone file)" */
                            warning(error,linenum);
                            /* Stop processing the rest of the zone file */
                            break;
                            }
                        else if(rr_type == -2) {
                            js_qstr2js(error,L_S_ZONE); /* "Syntax error in zone file" */
                            js_append(zone,error);
                            js_qappend(L_L,error); /* " (" */
                            js_append(data,error);
                            js_qappend(L_R,error); /* ")" */
                            warning(error,linenum);
                            continue;
                            }
                        add_rr_to_bighash(maintable,query,data,ttl,udpzone,0);
                        in_ns = 0;
                        }
                    else
                        add_rr_to_bighash(maintable,query,data,ttl,udpzone,0);
                    }
                }
            js_close(desc);
            }
        } while(mhash_nextkey(csvs,zone) != 0);
    js_destroy(udpzone); js_destroy(filename); js_destroy(line);
    js_destroy(pline); js_destroy(soaline); js_destroy(query);
    js_destroy(data); js_destroy(zone); js_dealloc(desc);
    return JS_SUCCESS;
}

/* This program parses all of the zone files and adds the records
 * to the MaraDNS database */
int populate_main(mhash *maintable, js_string *error, int recursive) {
        /* Pass 1: parse all of the zone files */
        parse_csv1s(maintable,error,recursive);
        csv2_parse_main_bighash(maintable,0);

        /* Pass 2: add the appropriate A records */
        return add_an(maintable,error);
}

/* Warn about the existance of a DDIP record
   Input: pointer to query with ddip value
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int warn_ddip(js_string *query) {
    int a = 0, l = 0;
    if(log_level == 0 || query == 0 || query->string == 0)
        return JS_SUCCESS;
    /* "Dotted decimal IP for NS, CNAME, or MX does not work with some DNS servers" */
    printf("%s%s",L_DDIP_WARN,L_F);
    printf("Hostname of record with problem: ");
    for(a = 0 ; a < query->unit_count ; a++) {
        l = *(query->string + a);
        if(l < 1 || l > 64) {
            printf("\n");
            return JS_SUCCESS;
        }
        for(;l>0;l--) {
            char c;
            a++;
            c = *(query->string + a);
            if(c>' ' && c < '~') {
                printf("%c",c);
            } else {
                printf("~");
            }
        }
        printf(".");
    }
    printf("\n");
    return JS_SUCCESS;
}

/* Synthesize a DDIP record, just in case a MX, NS, or CNAME points to a
   dotted-decimal IP
   Input: A pointer to the hash to populate, a pointer to the query
          that may be a dotted decimal IP
   Output: 0 if the IP is not a ddip, JS_SUCCESS if it is, and JS_ERROR
           if a fatal error happened
*/

int make_ddip(mhash *bighash, js_string *query) {
    unsigned char ip[4], length, val;
    int critter,counter,lenl,value;
    js_string *js_ip;

    /* Sanity Checks */
    if(query->unit_size != 1)
        return JS_ERROR;
    if(query->unit_count >= query->max_count)
        return JS_ERROR;

    /* We presently only do ddip translation for A records
       (DJB only supports this in Dnscache) */
    if(get_rtype(query) != RR_A)
        return 0;

    if(query->unit_count < 9) /* The minimum possible length for a
                                 ddip domain label */
        return 0;

    /* Synthesize an ip based on the ddip quad */
    lenl = 0;
    for(counter=0;counter<4;counter++) {
        length = *(query->string + lenl);
        if(length < 1 || length > 3)
            return 0;
        critter = lenl + 1;
        lenl += length + 1;
        if(lenl > query->unit_count)
            return JS_ERROR;
        for(value = 0;critter < lenl;critter++) {
            val = *(query->string + critter);
            if(val > '9' || val < '0')
                return 0;
            value *= 10;
            value += val - '0';
            }
        if(value < 0 || value > 255)
            return 0;
        ip[counter] = value;
        }

    if(*(query->string + lenl) != 0)
        return 0;

    /* OK, it is definitely a ddip label.  Convert the ip in to a DNS reply */

    if((js_ip = js_create(5,1)) == 0)
        return JS_ERROR;

    if(js_str2js(js_ip,(char *)ip,4,1) == JS_ERROR) {
        js_destroy(js_ip);
        return JS_ERROR;
        }

    if(mhash_put_rr(bighash,query,js_ip,8675309,1,0,0) == JS_ERROR) {
        js_destroy(js_ip);
        return JS_ERROR;
        }
    else {
        js_destroy(js_ip);
        return JS_SUCCESS;
        }

    }

/* Make pointers in MX, NS, and CNAME records so we can have A records in the
   AR section (AN section with CNAMEs)
   Input: A pointer to the hash to populate, a pointer to the string to
          put an error message in
   Output: JS_ERROR on error, -2 on non-fatal error, JS_SUCCESS when there
           is one or more authoritative records, 0 when there are no
           authoritative records
 */

int add_an(mhash *bighash, js_string *error) {

    js_string *query, *a_query;
    mhash_e qdata = {0,0,0}, adata = {0,0,0};
    rr *record;
    int qtype;

    if((a_query = js_create(256,1)) == 0)
        return JS_ERROR;
    if((query = js_create(MAX_ZONE_SIZE,1)) == 0) {
        js_destroy(a_query);
        return JS_ERROR;
        }

    /* Go through the big hash, looking for MX, NS, and CNAME records */

    if(mhash_firstkey(bighash,query) <= 0) {
        js_destroy(a_query);
        js_destroy(query);
        return 0;
        }

    do {
        /* Determine if this is a MX, NS, or CNAME query */
        qtype = get_rtype(query);
        if(qtype == JS_ERROR)
            continue;
        qdata = mhash_get(bighash,query);
        /* If it is a MX/NS query, proceed to find the assosciated
           A (IPV4 address) value (if it exists) */
        if(qtype == RR_MX || qtype == RR_NS) {
            if(qdata.datatype == MARA_DNSRR) {
                /* See if we have a corresponding A record for each of
                   the answers */
                record = qdata.value;
                do {
                    if(record != 0 &&
                       answer_ip_query(qtype,record->data,a_query) == JS_ERROR)
                        continue;
                    if(change_rtype(a_query,RR_A) == JS_ERROR)
                        continue;
                    adata = mhash_get(bighash,a_query);
                    /* If so, point to it */
                    if(adata.datatype == MARA_DNSRR) {
                        if(record != 0 && adata.value != 0)
                            record->ip = adata.value;
                        }
                    /* If not, maybe this is a dotted-decimal quad */
                    else if(make_ddip(bighash,a_query) == JS_SUCCESS) {
                        warn_ddip(query);
                        adata = mhash_get(bighash,a_query);
                        if(adata.datatype == MARA_DNSRR) {
                            if(record != 0 && adata.value != 0) {
                                record->ip = adata.value;
                                }
                            }
                        }
#ifdef IPV6
                    if(change_rtype(a_query,RR_AAAA) == JS_ERROR)
                        continue;
                    adata = mhash_get(bighash,a_query);
                    /* If so, point to it */
                    if(adata.datatype == MARA_DNSRR) {
                        if(record != 0 && adata.value != 0) {
                            record->ip6 = adata.value;
                            }
                        else { if(record != 0) {record->ip6 = 0;} }
                        }
#endif
                    } while ((record = record->next) != 0);
                }
            /* If it is a CNAME query, proceed to find the assosciated
             * ANY value */
            } else if(qtype == RR_CNAME) {
                /* Look for a corresponding ANY value (which needs to be
                 * there) */
                record = qdata.value;
                do {
                    if(answer_ip_query(qtype,record->data,a_query) == JS_ERROR)
                        continue;
                    if(record->rr_type != RR_CNAME)
                        break;
                    if(change_rtype(a_query,RR_ANY) == JS_ERROR)
                        continue;
                    adata = mhash_get(bighash,a_query);
                    /* If so, point to it */
                    if(adata.datatype == MARA_DNS_LIST) {
                        if(record != 0 && adata.value != 0)
                            record->list = adata.value;
                        }
                    else if(no_cname_warnings == 0 &&
                               cname_warnings_shown < 10) {
                        printf("Warning: The CNAME record ");
                        human_readable_dns_query(query,1);
                        printf(" is a dangling CNAME record.\n"
"Please read the FAQ entry about FAQ entry about dangling CNAME records.\n");
                        cname_warnings_shown++;
                        }
                    else if(no_cname_warnings == 0 &&
                              cname_warnings_shown == 10) {
                       printf("Warning: More dangling CNAME records exist.\n");
                       cname_warnings_shown++;
                       }
                    } while ((record = record->next) != 0);
                }
        } while(mhash_nextkey(bighash,query) != 0);
    js_destroy(a_query);
    js_destroy(query);
    return JS_SUCCESS;
    }

/* Give the RR type and a pointer to a js_string object we will put
   data in, make the corresponding A query for the data in question
   Input:  The query type this is (as an int), a pointer to the
           js string with the answer, a pointer to a js string
           which we will place the corresponding A record in question
   Output: JS_ERROR on fatal error, otherwise JS_SUCCESS
*/

int answer_ip_query(int qtype, js_string *qu, js_string *ar) {
    int start,length;

    /* Sanity checks */
    if(js_has_sanity(qu) == JS_ERROR)
        return JS_ERROR;
    if(qu->unit_size != 1)
        return JS_ERROR;
    if(js_has_sanity(ar) == JS_ERROR)
        return JS_ERROR;
    if(ar->unit_size != 1)
        return JS_ERROR;

    /* Blank out ar */
    ar->unit_count = 0;

    /* Each type has a different offset before the domain label in question
       begins, and an offset from the end before the label ends
     */
    switch(qtype) {
        case RR_NS:
        case RR_CNAME:
            start = 0;
            /* This record goes to the end of the string */
            length = qu->unit_count - start;
            break;
        case RR_MX:
            start = 2;
            /* This record also goes to the end of the string */
            length = qu->unit_count - start;
            break;
        /* Exit on unsupported types */
        default:
            return JS_SUCCESS;
        }

    /* Copy just the domain label over */
    if(js_substr(qu,ar,start,length) == JS_ERROR)
        return JS_ERROR;

    /* Add an "A" query type to the end (A records have a code of 1,
       and its 16-bit unsigned, hence 0 followed by one) */
    if(js_addbyte(ar,0) == JS_ERROR)
        return JS_ERROR;
    if(js_addbyte(ar,1) == JS_ERROR)
        return JS_ERROR;

    return JS_SUCCESS;
    }

/* Add a resource record to the big hash of RRs.
   Input: Pointer to the main table
          Binary form of query (dname followed by two-byte type)
          Answer to query
          Ttl for query in question
          Zone this record is in (to determine whether to flag it as
                                  authoritative or a "glue" record)
          We will do the following to determine if the data is
          authoritative:
          1) If the query is the same as the zone name (for all records)
             then the data is authoritative
          2) If the query is <single label>.<zone.name> (for example:
             If the zone is example.com, then anything.example.com
             fits, but some.thing.example.com does not fit), then
             the data is data for all RR types except NS and SOA.
          3) If this data is authoritative, overwrite any non-authoritative
             data in the database.  If it is authoritative, and authoritative
             data is there, do nothing.

          The "perms" (what set of IPs are allowed to view this record) of
          the record in question; if a given perm bit is one, only the IP
          corresponding to the perm bit in question is allowed to view this
          record.  If it is zero, this is the default value: any IP on
          the internet can see the record in question.

   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int add_rr_to_bighash(mhash *bighash,
                      js_string *query, js_string *data, uint32 ttl,
                      js_string *zone, perm_t perms) {

    int label_len,has_authority = 0,qtype;
    mhash_e hash_spot;
    rr *nukeme, *point;

    /* Sanity checks */
    if(js_has_sanity(query) == JS_ERROR || js_has_sanity(data) == JS_ERROR
       || js_has_sanity(query) == JS_ERROR)
         return JS_ERROR;
    if(query->unit_count < 3 || zone->unit_count < 3)
        return JS_ERROR;

    /* Get the query type */
    if((qtype = get_rtype(query)) == JS_ERROR)
        return JS_ERROR;

    /* We are not allowed to add RR_ANY data to the bighash */
    if(qtype == RR_ANY)
        return JS_ERROR;

    /* Nor are we allowed to add "AXFR" nor "IXFR" data to the bighash */
    if(qtype == 251 /* IXFR */ || qtype == 252 /* AXFR */)
        return JS_ERROR;

    /* Increment the number of DNS records we are serving */
    dns_records_served++;

    /* See if the data is authoritative or not */
    /* Change the type so the two strings are the same */
    if(change_rtype(zone,qtype) == JS_ERROR) {
        change_rtype(zone,RR_NS);
        return JS_ERROR;
        }
    /* First, if the query for the record is the same as the zone, it
       has authority. */
    if(js_issame(zone,query))
        has_authority = 1;
    /* OK, if that fails, then we have authority if any only if,
       1) The record is not a NS record
       2) When we strip off the first domain label, the two (the zone
          we have authority over and the stripped label) are the same
     */
    else if(get_rtype(query) != RR_NS) {
        /* Determine the length of the first label */
        label_len = JS_ERROR;
        /* _: How MaraDNS internally stores * (star) records */
        if(*query->string != '_' && *query->string < 64)
            label_len = *query->string + 1;
        else if(*query->string == '_')
            label_len = 1;
        else {
            change_rtype(zone,RR_NS);
            return JS_ERROR;
            }
        /* OK, check to see if dname - first label is the same as the
           authoritative zone */
        if(zone->unit_count == query->unit_count - label_len &&
           js_fgrep(zone,query) == label_len)
            has_authority = 1;
        }

    /* Now that we know whether the record in question is authoritative,
       add the record to the big hash table */

    /* Change this back because we need to do NS lookups for this zone
       again */
    change_rtype(zone,RR_NS);

    hash_spot = mhash_get(bighash,query);
    /* If the element does not exist at all, add it, with a pointer to
       the first NS record for this zone if this is a non-NS record.  */
    if(hash_spot.value == 0) {
        /* Add the data */
        if(mhash_put_rr(bighash,query,data,ttl,has_authority,0,perms)
                        == JS_ERROR)
            return JS_ERROR;
        if(mhash_add_ns(bighash,query,zone) == JS_ERROR)
            return JS_ERROR;
        return JS_SUCCESS;
        }

    /* The data must point to a RR, of course */
    if(hash_spot.datatype != MARA_DNSRR)
        return JS_ERROR;

    point = hash_spot.value;

    /* If the element exists, and it points to an authoritative record,
       and we have authority for this record --OR--, if the element
       exists, and points to a non-authoritative record, and we do
       *not* have authority for this record, then add this to the chain
       between the last record and the first NS for this record (or at
       the beginning in the case of NS records) */
    if((point->authoritative == 1 && has_authority == 1) ||
       (point->authoritative == 0 && has_authority == 0)) {
        if(mhash_add_rr(bighash,query,data,ttl,has_authority,0,perms)
                        == JS_ERROR)
            return JS_ERROR;
        return JS_SUCCESS;
        }

    /* If the element exists, and it points to something non-authoritative,
       and we have authoirty for this record, then overwrite the record
       in question */
    if(point->authoritative == 0 && has_authority == 1) {
        /* Delete the old data */
        /* To do: traverse through the linked list and delete all elements
           from the last non-NS (unless this is a NS, then until the end)
           to the top */
        nukeme = (rr *)mhash_undef(bighash,query);
        if(nukeme == 0)
            return JS_ERROR;
        /* Remove this entry from the corresponding
         * ANY chain */
        if(any_zap_rr(bighash,query,nukeme) == JS_ERROR) {
            return JS_ERROR;
            }
        /* Remove the entry once and for all */
        if(js_dealloc(nukeme) == JS_ERROR)
            return JS_ERROR;

        /* Add the data */
        if(mhash_put_rr(bighash,query,data,ttl,has_authority,0,perms)
                        == JS_ERROR)
            return JS_ERROR;
        if(mhash_add_ns(bighash,query,zone) == JS_ERROR)
            return JS_ERROR;
        return JS_SUCCESS;
        }


    /* If the element exists, and it points to something authoritative, and
       we do not have authority for this record, then do nothing */
    if(point->authoritative == 1 && has_authority == 0)
        return JS_SUCCESS;

    /* If we got here, something wrong happened */
    return JS_ERROR;
    }

