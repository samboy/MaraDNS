/* Copyright (c) 2009, 2011 Sam Trenholme
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

/* This is a series of function designed to implement a dictionary
 * in Deadwood; this is similar to a hash.
 *
 * However, a hash is optimized for caching dynamic data; a Deadwood hash
 * is a fixed-sized cache of a potentially infinite external dataset (the
 * entire DNS space of the internet).  A dict (sort for "dictionary") is
 * for storing data locally that is dynamic in size.  The data, like
 * Deadwood's hash, is an assosciative array of dw_str objects indexed
 * by dw_str elements
 *
 * It's a "one dimensional" assosciative array, in the sense that an element
 * of the array is always a dw_str object (we don't have Perl5 or Python
 * style "hashes of hashes" or dictionaries where a given dictionary
 * element is itself a dictionary)
 */

#include "DwStr.h"
#include "DwStr_functions.h"
#include "DwDict.h"

/* Keep -Wall happy.  We can "legally" call this since we are a, if you
 * will, "derived class" of DwHash.c */
uint32_t dwh_hash_compress(dw_str *obj);

/* Initialize a Deadwood dictionary store */
dwd_dict *dwd_init() {
        return dwh_hash_init(2);
}

/* Add a dictionary key/value pair to the compiled list of MaraRC
 * parameters.
 *
 * Input: Number of MaraRC parameter to modify
 *        Dictionary key index to modify
 *        Value for said key index
 *
 * Output: Location of hash in memory after performing operation; this may
 *         move as we grow the dictionary to accommodate more data in the
 *         hash
 *
 */
dwd_dict *dwd_add(dwd_dict *hash, dw_str *key, dw_str *value) {
        int a = 0;
        a = dwh_add(hash,key,value,1,0);
        if(a == -1) {
                return hash;
        }
        return dwh_hash_autogrow(hash);
}

/* Fetch a value from a given dictionary variable (num is the number for
 * the dictionary variable we are seeking a given value for, given the
 * dictionary variable and the key inside that variable) */
dw_str *dwd_fetch(dwd_dict *hash, dw_str *key) {
        /* Ignore expire 1; use_fila 0 */
        return dwh_get(hash, key, 1, 0);
}

/* For a given dictionary variable, and a key, return (as a *copied* dw_str
 * object) the next key or 0 if we're at the last key.  If the key given to
 * this function is 0, return the first key. */
dw_str *dwd_nextkey(dwd_dict *hash, dw_str *key) {
        int32_t count = 0;
        int found = 0, noloop = 0;
        dw_element *point = 0, *next = 0;

        if(hash == 0) {
                return 0;
        }

        if(key == 0) {
                found = 1;
                count = 0;
        } else {
                count = dwh_hash_compress(key) & hash->mask; /* Fast lookup */
        }

        /* Look for the key */
        for(;count <= hash->mask; count++) {
                point = hash->hash[count];
                for(noloop = 0; noloop < 10000 && point != 0; noloop++) {
                        next = point->next;
                        if(found == 1) {
                                return dw_copy(point->key);
                        }
                        if(dw_issame(point->key,key) == 1) {
                                found = 1;
                        }
                        point = next;
                }
        }
        /* Not found or last key in hash */
        return 0;
}

