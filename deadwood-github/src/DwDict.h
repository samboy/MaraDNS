/* Copyright (c) 2009 Sam Trenholme
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

#include "DwHash.h"
#define dwd_dict dw_hash

/* Initialize a Deadwood dictionary store */
dwd_dict *dwd_init();

/* Add a dictionary key/value pair to the compiled list of MaraRC
 * parameters.
 *
 * Input: Number of MaraRC parameter to modify
 *        Dictionary key index to modify
 *        Value for said key index
 *
 * Output: Location of hash in memory after performing operation; this may
 *         move as we grow the dictionary to accommodate more data in the
 *         hash.  This *must* always be called like this:
 *
 *              hash = dwd_add(hash,key,value);
 *
 */
dwd_dict *dwd_add(dwd_dict *hash, dw_str *key, dw_str *value);

/* Fetch a value from a given dictionary variable (num is the number for
 * the dictionary variable we are seeking a given value for, given the
 * dictionary variable and the key inside that variable) */
dw_str *dwd_fetch(dwd_dict *hash, dw_str *key);

/* For a given dictionary variable, and a key, return (as a *copied* dw_str
 * object) the next key or 0 if we're at the last key.  If the key given to
 * this function is 0, return the first key. */
dw_str *dwd_nextkey(dwd_dict *hash, dw_str *key);

