/* Copyright (c) 2006,2011 Sam Trenholme
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

/* Note: This file is encoded using utf-8 encoding */
/* Note also: This is the revamped linked-list based hash which was changed
   for MaraDNS 0.8.30 */
/* MaraHash: A series of functions to make assosciative arrays using
   js_string objects as keys and values.

   This is done with a hash that grows as needed for the data in question

   This source file also contains the tools for creating and manipulating
   (as such) the mara_tuple objects (similiar to Python tuples--immutable
   lists) */

#ifndef JS_STRING_INCLUDED
#include "JsStr.h"
#endif
#include "MaraHash.h"
#include <stdio.h>

/* Masks to limit the size of the hash */
/* These are powers of two, minus one */
mhash_offset mhash_mask[31] = { 1, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023,
                          2047, 4095, 8191, 16383, 32767, 65535, 131071,
                          262143, 524287, 1048575, 2097151, 4194303, 8388607,
                          16777215, 33554431, 67108863, 134217727,
                          268435455, 536870911, 1073741823 };

mhash_offset mhash_secret_add_constant = 7;

/* Create a new, blank mhash object
   input: none
   output: pointer to the object in quesiton on success, NULL (0)
           otherwise
*/

mhash *mhash_create(int hash_bits) {

    mhash *new;
    int counter;

    if((new = js_alloc(1,sizeof(mhash))) == 0)
        return 0;

    new->hash_bits = hash_bits;

    /* Create that hash table */
    /* mhash_mask[hash_bits] + 1 has a value of 2 to the power of hash_bits */
    if((new->hash_table =
       js_alloc(mhash_mask[hash_bits] + 1,sizeof(mhash_spot *))) == 0) {
        js_dealloc(new);
        return 0;
        }

    /* Zero out the hash table */
    for(counter=0;counter<=mhash_mask[hash_bits];counter++)
        new->hash_table[counter] = 0;

    /* Zero elements in the assosciative array */
    new->spots = 0;

    /* Exit */
    return new;

    }

/* Determine a hash for a given js_string object
   input: A pointer to the js_string object in question,
          the number of bits for the hash in the hash table
   output: A table offset to try (0 indicates error)
*/

mhash_offset mhash_js(js_string *tohash, int hash_bits) {

    mhash_offset ret = 0;
    unsigned char *point, *max;

    int shift = 0; /* number of bits shifted */

    if(js_has_sanity(tohash) == JS_ERROR)
        return 0;
    point = tohash->string;
    max = point + (tohash->unit_count * tohash->unit_size);
    if(max > point + js_octets(tohash)) /* Overflow protection */
        return 0;

    /* Simple enough hash */
    while(point < max) {
        ret += (mhash_offset)(*point << shift);
        ret += mhash_secret_add_constant;
        ret *= 45737;
        shift += 7;
        shift %= hash_bits;
        point++;
        }

    /* Do something useful with those extra seven bits */
    ret ^= ret >> 7;

    /* Make the hash fit in the table in question */
    ret = ret & mhash_mask[hash_bits];

    /* A return of 0 always indicates an error */
    if(ret == 0)
        ret++;

    return ret;

    }

/* Add an element to the hash
   input: js_string key of dictionaty lookup
          anonymous pointer to the data for the dictionary key
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int mhash_put(mhash *hash, js_string *key, void *value, int datatype) {

    mhash_offset first_found;
    js_string *new_key; /* We copy the key values because the key value is,
                           by necessity, static.  */
    mhash_spot *point, *new;

    /* Sanity check */
    if(js_has_sanity(key) == JS_ERROR)
        return JS_ERROR;

    /* Find the element in the hash table we will mutilate */
    first_found = mhash_js(key,hash->hash_bits);
    if(first_found == 0)
        return JS_ERROR;

    /* Copy the key to the new_key, which needs to be immutable */
    /* Since the key is "immutable", we make it as compact as possible */
    if((new_key=js_create(key->unit_count + 1,key->unit_size)) == 0) {
        js_dealloc(hash->hash_table[first_found]);
        return JS_ERROR;
        }
    if(js_copy(key,new_key) == JS_ERROR) {
        js_dealloc(hash->hash_table[first_found]);
        js_destroy(new_key);
        return JS_ERROR;
        }

    /* Create a key/value pair */
    if((new = js_alloc(1,sizeof(mhash_spot))) == 0) {
        return JS_ERROR;
        }
    /* Put values in the newly created mhash_spot structure */
    new->key = new_key;
    new->value = value;
    new->datatype = datatype;
    new->next = 0;

    /* Find where to put the data */
    point = hash->hash_table[first_found];

    if(point == 0) {
        hash->hash_table[first_found] = new;
        }
    /* If needed, add this to the end of a linked list */
    else {
        /* We do not allow the same key to be in the hash twice */
        if(js_issame(point->key,new_key))
            goto cleanup;
        while(point->next != 0) {
             /* We do not allow the same key to be in the hash twice */
             if(js_issame(point->key,new_key))
                 goto cleanup;
             point = point->next;
             }
        /* We do not allow the same key to be in the hash twice */
        if(js_issame(point->key,new_key))
            goto cleanup;
        point->next = new;
        }

    /* Increment the number of elements in the hash. */
    hash->spots++;

    return JS_SUCCESS;

    cleanup:
        js_destroy(new_key);
        js_dealloc(new);
        return JS_ERROR;
    }

/* Get an element from the hash
   input: js_string key of dictionaty lookup
          anonymous pointer to the data for the dictionary key
   output: A mhash_e struct with the data in question.  "Value"
           points to 0 if there was a problem
*/

mhash_e mhash_get(mhash *hash, js_string *key) {

    mhash_offset first_found;
    mhash_spot *point;
    mhash_e ret;

    ret.point = 0;
    ret.value = 0;
    ret.datatype = -1;

    /* Sanity check */
    if(js_has_sanity(key) == JS_ERROR)
        return ret;

    /* Find the element in the hash table we will get data from */
    first_found = mhash_js(key,hash->hash_bits);

    /* Handle the case of looking up a non-existant element */
    if(hash->hash_table[first_found] == 0) {
        ret.value = 0;
        ret.datatype = 0;
        ret.point = 0;
        return ret;
        }

    point = hash->hash_table[first_found];

    /* Traverse the linked list, as needed */
    while(!js_issame(key,point->key)) {
        /* If the element is not in the table, return error */
        if(point->next == 0) {
            ret.value = 0;
            ret.datatype = 0;
            ret.point = 0;
            return ret;
            }
        point = point->next;
        }

    /* Now that we know what element in the hash table to view, view it */
    ret.point = &(point->value);
    ret.value = point->value;
    ret.datatype = point->datatype;

    return ret;

    }

/* Get a direct pointer to the "immutable" key from the hash
   input: pointer to hash table, js_string key of dictionary lookup
   output: A pointer to the instance of that key in the hash table,
           0 if it isn't there/an error occured
*/

js_string *mhash_get_immutable_key(mhash *hash, js_string *key) {

    mhash_offset first_found;
    mhash_spot *point;

    /* Sanity check */
    if(js_has_sanity(key) == JS_ERROR)
        return 0;

    /* Find the element in the hash table we will get data from */
    first_found = mhash_js(key,hash->hash_bits);

    /* Handle the case of looking up a non-existant element */
    if(hash->hash_table[first_found] == 0)
        return 0;

    point = hash->hash_table[first_found];

    /* Look for the key in the hash table */
    while(!js_issame(key,point->key)) {
        /* If the element is not in the table, return error */
        if(point->next == 0)
            return 0;
        point = point->next;
        }

    /* Now that we know what key in the hash table to view, return a
       pointer to it */
    return point->key;

    }

/* Remove an element from the assosciative array (hash)
   input: Hash to change, element to remove
   output: Pointer to value of array element to remove (which
           you will probably want to deallocate), 0 on error
*/
void *mhash_undef(mhash *hash, js_string *key) {
    mhash_offset first_found;
    mhash_spot *point, *last;
    void *ret;

    /* Find the element in the hash table we will remove */
    first_found = mhash_js(key,hash->hash_bits);
    if(first_found == 0) {
        return 0;
        }

    /* Handle the case of looking up a non-existant element */
    if(hash->hash_table[first_found] == 0) {
        return 0;
        }

    point = hash->hash_table[first_found];
    last = 0;

    /* Find the element in the hash */
    while(point != 0) {
        /* If we find the element we want to delete, break out of loop */
        if(js_issame(key,point->key))
            break;
        last = point;
        point = point->next;
        }

    /* If not found, return 0 */
    if(point == 0)
        return 0;

    /* Remove a pointer to the element in the hash */
    if(last == 0)
        hash->hash_table[first_found] = point->next;
    else
        last->next = point->next;

    /* Decrement the number of elements in the hash */
    hash->spots--;

    /* Deallocate the memory set aside for the hash key */
    if(js_destroy(point->key) == JS_ERROR) {
        return 0;
        }

    /* Remember the pointer to the hash value */
    ret = point->value;

    /* Deallocate the memory set aside for the mhash_spot */
    if(js_dealloc(point) == JS_ERROR) {
        return 0;
        }

    /* Return a pointer to the hash value, which the code calling
       this function will probably deallocate in short order */
    return ret;
    }

/* Function to add a js_string to a mhash structure
   input: Hash to change, key, value
   output: JS_ERROR: bad JS_SUCCESS: good
*/

int mhash_put_js(mhash *hash, js_string *key,js_string *value) {
    js_string *new;
    int ret;

    /* While the anonymous pointer is nice for flexibility, the
       developer probably expects to create a new string when adding
       a value to the table */
    /* We make the value as compact as possible, since it
       won't change */
    if((new=js_create(value->unit_count + 1,value->unit_size)) == 0)
        return JS_ERROR;
    if(js_copy(value,new) == JS_ERROR) {
        js_destroy(new);
        return JS_ERROR;
        }

    ret = mhash_put(hash,key,new,MARA_JS);

    if(ret == JS_ERROR)
        js_destroy(new);

    return ret;
    }

/* Function to get a js_string object from a mhash structure
   input: Hash to view, key
   output: pointer to js_string on success, 0 on error */

js_string *mhash_get_js(mhash *hash, js_string *key) {
   mhash_e info;
   info = mhash_get(hash,key);
   if(info.value == 0)
       return 0; /* Error condition */
   if(info.datatype != MARA_JS)
       return 0; /* Another error condition--we are looking for a js_string */
    if(js_has_sanity(info.value) == JS_ERROR)
        return 0; /* Make sure the string is kosher */
   return info.value;
   }

/* Function to remove a js_string object from a mhash structure
   input: Hash to fondle, key
   output: JS_SUCCESS or JS_ERROR, depending on success/failure */

int mhash_undef_js(mhash *hash, js_string *key) {
    js_string *tonuke;
    tonuke = mhash_undef(hash,key);
    if(tonuke == 0) {
        js_destroy(tonuke);
        return JS_ERROR;
        }
    return js_destroy(tonuke);
    }

/* Function to resize a hash table.
   input: pointer to mhash object (assosciative array), desired size of
          new hash table
   output: JS_SUCCESS on success, JS_ERROR on error
*/

int mhash_resize(mhash *hash,int new_bits) {
    mhash_offset counter;
    mhash_offset old_tablesize;
    mhash_spot **new_hash_table,**old_hash_table;
    mhash_spot *point, *save;

    /* If the value is out of range, return error */
    if(new_bits < 1 || new_bits > 29)
        return JS_ERROR;

    /* Allocate the new hash table -- mhash_mask[new_bits] + 1 is 2^new_bits */
    if((new_hash_table =
        js_alloc(mhash_mask[new_bits] + 1,sizeof(mhash_spot *))) == 0)
        return JS_ERROR;

    /* Zero out the new hash table */
    for(counter=0;counter<=mhash_mask[new_bits];counter++)
        new_hash_table[counter] = 0;

    /* Keep track of where the old hash table is */
    old_hash_table = hash->hash_table;

    /* Set the value of old_tablesize to size of the old hash table
       minus one (to make code more efficient) */
    old_tablesize = mhash_mask[hash->hash_bits];

    /* Have the hash (assosciative array) object point to the
       new hash table */
    hash->hash_table = new_hash_table;
    hash->hash_bits = new_bits;

    /* Copy over data from the old hash table to the new, shiny hash table */
    for(counter = 1;counter <= old_tablesize; counter++) {

        /* Copy found elements over */
        if(old_hash_table[counter] != 0) {
            point = old_hash_table[counter];

            /* Go down every "branch" of linked list elements */
            while(point != 0) {
                /* Sanity checks */
                if(point->key == 0)
                    continue;
                if(js_has_sanity(point->key) == JS_ERROR)
                    continue;

                /* Add the element to the new hash */
                mhash_put(hash,point->key,point->value,point->datatype);

                /* Go to the next element, destorying this element in the
                   process */
                save = point->next;
                js_dealloc(point);
                point = save;
                }
            }
        }

    /* Destroy the old hash table */
    js_dealloc(old_hash_table);

    return JS_SUCCESS;
    }

/* Function to, if needed, automatically grow a hash table
   Input: pointer hash table
   Output: JS_ERROR if something bad happened, 1 if the table did not grow,
           2 if the table grew.
*/

int mhash_autogrow(mhash *hash) {

    int bits;

    bits = hash->hash_bits;
    if(bits < 1 || bits > 29)
        return JS_ERROR;

    /* If is is really small, always grow it */
    if(bits < 4) {
        if(mhash_resize(hash,bits + 1) == JS_ERROR)
            return JS_ERROR;
        return 2;
        }

    /* Integer arithmetic, ugh.  If the hash is more than 50% full,
       we grow it.  Make this mhash_mask[bits - 1] to grow at 25% size and
       mhash_mask[bits - 2] + mhash_mask[bits - 3] to grow at 37% size */

    if(hash->spots >= mhash_mask[bits - 1]) {
        if(mhash_resize(hash,bits + 1) == JS_ERROR)
            return JS_ERROR;
        return 2;
        }

    /* Normally, we do not grow */
    return 1;
    }

/* This is part of the mhash method of getting keys from the hash,
   e.g. "for a in dict.keys()" equavalent.  What this routine does
   is find the first key in the hash, and overwrite the supplied
   key argument with the value of the hash's first key.
   input: pointer to hash, pointer to js_string object where we will
          put the first hash key
   output: JS_ERROR on fatal error, JS_SUCCESS we we found a key,
           0 if the hash is empty
*/
int mhash_firstkey(mhash *hash, js_string *key) {
    mhash_offset offset = 0;
    mhash_spot *point;

    while(offset < mhash_mask[hash->hash_bits] + 1) {
        /* If we found the first element in the hash, copy
           it over to the key, and return (usually) success */
        if(hash->hash_table[offset] != 0) {
            point = hash->hash_table[offset];
            return js_copy(point->key,key);
            }
        else {
            offset++;
            }
        }

    /* We are at the end of the hash */
    return 0;
    }

/* This is the mhash method of getting keys from the hash, e.g.
   "for a in dict.keys()" equavalent.  The way we do this is by having
   two arguments: The pointer to the hash, and a malleable js_string
   object which contins the current pointer that we need to rplace
   with the next pointer in the hash.
   input: pointer to hash, pointer to js_string object with current key
   output: JS_ERROR on fatal error, JS_SUCCESS if we incremented the
           hash pointer, 0 if we are at the last element in the hash
*/

int mhash_nextkey(mhash *hash, js_string *key) {
    mhash_spot *point;
    mhash_offset offset;

    /* Determine where we currently are in the hash */
    offset = mhash_js(key,hash->hash_bits);

    /* Sanity check */
    if(offset > mhash_mask[hash->hash_bits] || offset < 0)
        return JS_ERROR;

    /* Determine where we are in this branch, to look for the element
       in question */
    point = hash->hash_table[offset];

    /* If we are pointing at nothing, return error */
    if(point == 0)
        return JS_ERROR;

    /* Find the element we are looking for */
    while(!js_issame(key,point->key)) {
        /* If the key is not in the hash, return error */
        if(point->next == 0) {
            return JS_ERROR;
            }
        point = point->next;
        }

    /* OK, now, find out what the next element is. */

    /* If there is a subsequent element in this "branch" of the
       hash, then we simply copy over the pointer there */

    if(point->next != 0) {
        return js_copy(point->next->key,key);
        }

    /* Otherwise, we need to find the next element in the hash that has
       an element */
    offset++;

    while(offset < mhash_mask[hash->hash_bits] + 1) {
        /* If we found the next element in the hash, copy
           it over to the key, and return (usually) success */
        if(hash->hash_table[offset] != 0) {
            point = hash->hash_table[offset];
            return js_copy(point->key,key);
            }
        else {
            offset++;
            }
        }

    /* We are at the end of the hash */
    return 0;
    }

/* Create a new mara_tuple object
   input: Number of elements in mara_tuple table
   output: pointer to object in question, 0 on error */

mara_tuple *mtuple_new(int elements) {
    mara_tuple *ret;
    int counter;

    if((ret = js_alloc(1,sizeof(mara_tuple))) == 0)
        return 0;

    ret->elements = elements;
    if((ret->tuple_list = js_alloc(elements,sizeof(js_string *))) == 0) {
        js_dealloc(ret);
        return 0;
        }

    /* Zero out the tuple list table */
    for(counter=0;counter<elements;counter++)
        ret->tuple_list[counter] = 0;

    return ret;
    }

/* Copy a js_string object over to an element in a mara_tuple table.
   Since tuples are "immutable", this funciton will only change empty
   elements.
   input: Pointer to mara_tuple object, pointer to js_string to copy,
          element to copy in to
   output: JS_ERROR on error, JS_SUCCESS on success */

int mtuple_put(mara_tuple *tuple, js_string *js, int element) {
    js_string *copy;

    /* Make sure the "element" value makes sense: It should fit in
       the mara_tuple, and the element in the mara_tuple needs to
       be blank */
    if(element >= tuple->elements || element < 0)
        return JS_ERROR;
    if(tuple->tuple_list[element] != 0)
        return JS_ERROR;

    /* Begin copying over to copy */
    /* We make the copy as compact as possible, since it will not
       change */
    if((copy=js_create(js->unit_count + 1,js->unit_size)) == 0)
        return JS_ERROR;
    if(js_copy(js,copy) == JS_ERROR)
        return JS_ERROR;

    tuple->tuple_list[element] = copy;

    return JS_SUCCESS;
    }

/* Get the pointer to a js_string object in a mara_tuple table.
   input: Pointer to mara_tuple object, element we wish to look at
   output: pointer to appropriate js_string object on success,
           0 on error
*/

js_string *mtuple_get(mara_tuple *tuple, int element) {

    /* Make sure we are given sane numbers */
    if(element >= tuple->elements || element < 0)
        return 0;

    return tuple->tuple_list[element];
    }

/* Read four bytes from a filename and use that as a secret add constant */
int mhash_set_add_constant(char *filename) {
        FILE *read = 0;

        read = fopen(filename,"rb");
        if(read == NULL) {
                return -1;
        }

        mhash_secret_add_constant ^= getc(read);
        mhash_secret_add_constant <<= 8;
        mhash_secret_add_constant ^= getc(read);
        mhash_secret_add_constant <<= 8;
        mhash_secret_add_constant ^= getc(read);
        mhash_secret_add_constant <<= 7;
        mhash_secret_add_constant ^= getc(read);
        fclose(read);
        return 1;
}

