/* Copyright (c) 2007-2009 Sam Trenholme
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

#ifndef __DWHASH_H_DEFINED__
#define __DWHASH_H_DEFINED__

/* A circular linked list that we use to determine what records to delete
 * when the hash is full */
typedef struct dw_fila {
        struct dw_fila *last;
        struct dw_fila *next;
        struct dw_element *record;
} dw_fila;

/* A single element in a dw_hash */
typedef struct dw_element {
        dw_str *key;
        dw_str *value;
        dw_fila *fila;  /* Element in fila for this record */
        int8_t immutable; /* Whether we can delete this element */
        int64_t expire; /* When this record expires */
        struct dw_element *next;
        struct dw_element **prev; /* A pointer to the pointer to this element,
                                   * either in the dw_hash hash list, or
                                   * the "next" element one up */
} dw_element;

typedef struct {
        dw_fila *fila;  /* List used to delete unused elements */
        dw_element **hash;
        uint32_t mask; /* "and" mask used to determine size of hash list */
        int32_t size; /* Number of elements in hash */
        int32_t max;  /* Maximum number of elements in hash */
} dw_hash;

/* Called before reading dwood3rc, this sets add_constant based on
 * secret.txt in Windows and /dev/urandom in Unix */
void set_add_constant();

/* Zap (destroy) a created hash */
void dwh_hash_zap(dw_hash *hash);

/* The public functions in DwHash.c */

/* Set global variables (namely, the cache size) based on dwood2rc
 * parameters */
void dwh_process_mararc_params();

/* Create a new hash with "elements" number of elements; if "elements" is
 * 0, and we have called dwh_process_mararc_params(), we get the number
 * of elements from the dwood2rc file */
dw_hash *dwh_hash_init(uint32_t elements);

/* Given a hash and hash key (or just a direct pointer to the element in the
 * hash), remove an element from the hash. -1 on error;
 * 1 on success; 0 if no such element in the hash.  While this is a public
 * function, the Deadwood-2 cache code should have no need to call this
 * function.  use_fila should always be 1 (the only time it isn't is in
 * the derived class in DwDict.c), or 2 if the element is a special
 * "immutable" element (used for NS referrals in one's dwood3rc file) */
int dwh_zap(dw_hash *hash, dw_str *key, dw_element *seek, int use_fila);

/* Add a (key,value) pair to a given dw_hash */
int dwh_add(dw_hash *hash, dw_str *key, dw_str *value, int32_t ttl,
            int use_fila);

/* Copy an element from the hash and put it in a js_str object which we
 * give to whoever calls the function.  Should the element not be found,
 * or an error occurs, return 0.  If the element is in the hash but
 * expired, we will return 0 is ignore_expire is 0, and the element if
 * ignore_expire is 1. use_fila should always be 1 (the only time it isn't
 * is in the derived class in DwDict.c) */

dw_str *dwh_get(dw_hash *hash, dw_str *key, int ignore_expire, int use_fila);

/* What is the TTL for a given hash element? */
int32_t dwh_get_ttl(dw_hash *hash, dw_str *key);

/* Make a hash bigger.  This code *only* works for hashes without a fila;
 * if the hash has a fila, this will just return an error.  This should
 * *only* be used by the derived class in DwDict.c.
 *
 * This routine destroys the hash pointed to and returns a newly
 * resized hash if the hash needs to change size; otherwise the
 * code returns a pointer to the old hash.
 */
dw_hash *dwh_hash_autogrow(dw_hash *hash);

/* Write an entire hash (assosciated array) to a given file; 1 on
 * success; -1 on error.  This is a public function. */
int dwh_write_hash(dw_hash *hash, char *filename);

/* Read a hash from a file, and return the hash read from the file
 * as a hash pointer to the calling function */
dw_hash *dwh_read_hash(char *filename);

#endif /* __DWHASH_H_DEFINED__ */
