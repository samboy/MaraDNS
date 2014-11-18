/* Copyright (c) 2002-2013 Sam Trenholme
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
#include "../MaraDns.h"
#include "Compress_rrs.h"
#include "functions_dns.h"

/* Maximum allowed number of dlabel points */
#define MAX_DLABEL_POINTS 160

/* Maximum allowed length of compressed string; this is 4096 for TCP
 * packets */
#ifdef AUTHONLY
#define MAX_COMPRESSED_LEN 4096
#else
#define MAX_COMPRESSED_LEN 512
#endif


/* We use three "private" functions in Decompress.c */
extern js_string
    *decomp_get_label(js_string *compressed, int compressed_offset);
extern rrdesc **decomp_export_rrformats();
extern char *decomp_get_rrdesc(int rr_num);

/* Compression state */

typedef struct compress_state {
    js_string *compressed;
    js_string *uncompressed;
    unsigned int uncompressed_offset;
    unsigned int this_dlabel_begin;
    int *dlabel_points;
    unsigned int this_rdlength_begin;
    int this_rr_type;
    int current_rdlength;
    int valid_state;
    int number_answers;
    } compress_state;

/* compress_init_state

   This creates a new compress_state object, and initializes its values.
   uncompressed is the string which we intend to compress.

 */

compress_state *compress_init_state(js_string *uncompressed) {
    compress_state *new;

    /* Sanity check */
    if(js_has_sanity(uncompressed) != JS_SUCCESS)
        return 0;

    /* Allocate the memory */
    if((new = js_alloc(1,sizeof(compress_state))) == 0)
        return 0;

    /* Initialize the values which do not allocate memory */
    new->uncompressed_offset = 0;
    new->this_dlabel_begin = 0;
    new->this_rdlength_begin = 0;
    new->this_rr_type = 0;
    new->current_rdlength = 0;
    new->valid_state = 1;
    new->number_answers = 0;
    new->uncompressed = uncompressed;

    /* Initialize the values which allocate memory */
    if((new->compressed = js_create(MAX_COMPRESSED_LEN + 4,1)) == 0) {
        js_dealloc(new);
        return 0;
        }
    if((new->dlabel_points = js_alloc(MAX_DLABEL_POINTS + 3,sizeof(int)))
                == 0) {
        js_destroy(new->compressed);
        js_dealloc(new);
        return 0;
        }
    new->dlabel_points[0] = 0;

    /* Success! */
    return new;
    }

/* compress_get_dlabel

   This function retrieves a dlabel from an incomplete compressed DNS
   packet starting at offset, and copies it over to a js_string object
   created by the function

 */

js_string *compress_get_dlabel(js_string *packet, int offset) {
    return decomp_get_label(packet,offset);
    }

/* compress_issame: Determine if two js_string objects are identical
   Case insensitive search ('A' is the same as 'a')
   input: Pointers to the two string objects
   output: 1 if they are the same, 0 otherwise, -1 on error */
int compress_issame(js_string *js1, js_string *js2) {
    int counter = 0;
    int max;
    int lc1, lc2;

    /* Sanity checks */
    if(js_has_sanity(js1) == -1)
        return -1;
    if(js_has_sanity(js2) == -1)
        return -1;

    /* They are not the same if they have different sizes for a character */
    if(js1->unit_size != js2->unit_size)
        return 0;
    /* Nor are they the same if they have different lengths */
    if(js1->unit_count != js2->unit_count)
        return 0;
    /* They both have to use the same encoding */
    /*if(js1->encoding != js2->encoding)
        return 0; */ /* This requirement disabled because this just
                        causes annoyances */

    max = js1->unit_count;

    /* If any characters in the actual string differer, they are different */
    while(counter < (max * js1->unit_size)) {
        lc1 = *(js1->string + counter);
        lc2 = *(js2->string + counter);
        if(lc1 >= 'A' && lc1 <= 'Z') { lc1 += 32; }
        if(lc2 >= 'A' && lc2 <= 'Z') { lc2 += 32; }
        if(lc1 != lc2)
            return 0;
        counter++;
        }

    /* Otherwise, they are identical */
    return 1;
    }

/* compress_compare_dlabels

   This compares two dlabels inside two (or the same) js_string objects.
   This function returns 0 if the strings are not identical, 1 if they
   are, and JS_ERROR if there was an error processing the data.

 */

int compress_compare_dlabels(js_string *packet1, js_string *packet2,
                                    int offset1, int offset2) {
    js_string *a, *b;
    int ret;

    a = compress_get_dlabel(packet1,offset1);
    if(a == 0)
        return JS_ERROR;
    b = compress_get_dlabel(packet2,offset2);
    if(b == 0) {
        js_destroy(a);
        return JS_ERROR;
        }
    ret = compress_issame(a,b);
    js_destroy(a);
    js_destroy(b);
    return ret;

    }

/* compress_add_dlabel_points

   Given an offset offset which starts at the beginning of a dlabel in
   the compressed string, add all of the label boundary offsets in that
   dlabel (in other words, the beginning and dots in a domain name like
   "www.nodoubt.com.", with the exception of the trailing dot) to the
   end of the dlabel_points member of the state structure.  Naturally,
   it is important that this function performs bounds checking.

   This returns JS_SUCCESS on successful adding of the dlabel points,
   and JS_ERROR on unsuccessful adding of the dlabel points (in addition
   to marking the state as "invalid")

 */

int compress_add_dlabel_points(compress_state *state, int offset) {
    int counter, limit;

    /* Sanity check */
    if(state == 0)
        return JS_ERROR;
    if(state->valid_state != 1) {
        return JS_ERROR;
        }
    /* Find the first uninitialized dlabel point in the state */
    counter = 0;
    while(state->dlabel_points[counter] != 0 &&
          counter < MAX_DLABEL_POINTS - 10) {
        counter++;
        }

    /* Add the points to the end of dlabel_points */
    limit = 0;
    while(limit < 257) {
        unsigned int len;

        /* Bounds checking */
        if(offset >= state->compressed->unit_count) {
            state->valid_state = 0;
            return JS_ERROR;
            }

        /* Get the length */
        len = *(state->compressed->string + offset);
        if(len >= 192) /* Compression pointer */
            break;

        /* More bounds checking */
        if(offset + len >= state->compressed->unit_count) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(counter >= MAX_DLABEL_POINTS - 10) {
            state->valid_state = 0;
            return JS_ERROR;
            }

        /* Add the length to the dlabel_points array */
        state->dlabel_points[counter] = offset;
        state->dlabel_points[counter + 1] = 0;
        counter++;
        if(len == 0 || len > 63) {
            break;
            }
        offset += len;
        offset += 1;

        /* Even more bounds checking */
        limit++;
        }

    /* Yet more bounds checking */
    if(limit >= 257) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    return JS_SUCCESS;
    }

/* compress_sub_dlabel

   Given the uncompressed_offset in the state which starts at the
   beginning of a label inside a dlabel, compress the dlabel in question
   and append the compressed dlabel to the end of the compressed string.

   This returns 1 if we could not compress the sub label, 2 if we could,
   0 if we are at the end of the dlabel, 3 if we are at the end of the
   packet, and JS_ERROR on unsuccessful
   adding of the dlabel points (in addition to marking the state as
   "invalid")

 */

int compress_sub_dlabel(compress_state *state) {

    unsigned int len,counter;

    /* Sanity checks */
    if(state == 0) {
        return JS_ERROR;
        }
    if(state->valid_state != 1) {
        return JS_ERROR;
        }
    if(state->uncompressed_offset >= state->uncompressed->unit_count) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Determine the length of the string */
    len = *(state->uncompressed->string + state->uncompressed_offset);
    if(len == 0) {
        /* Append the "dot after .com" */
        if(js_substr_append(state->uncompressed,state->compressed,
                        state->uncompressed_offset,1) != JS_SUCCESS) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(state->uncompressed_offset + 1 > state->uncompressed->unit_count
           || state->uncompressed_offset + 1 >=
              state->uncompressed->max_count) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(state->uncompressed_offset == state->uncompressed->unit_count) {
            return 3;
            }
        state->uncompressed_offset += 1;
        return 0;
        }
    if(len > 63 || len < 0) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    if(state->uncompressed_offset + len + 1 >= state->uncompressed->unit_count
       || state->uncompressed_offset + len + 1 >=
          state->uncompressed->max_count) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Note that we use the variable len near the end of the function */

    counter = 0;
    while(counter < MAX_DLABEL_POINTS - 5) {

        /* Check for end of points array */
        if(state->dlabel_points[counter] == 0) {
            break;
            }

        /* Check for point array element pointing at our dlabel */
        if(state->dlabel_points[counter] >= state->this_dlabel_begin) {
            break;
            }

        /* Compare the two */
        if(compress_compare_dlabels(state->uncompressed,state->compressed,
           state->uncompressed_offset,state->dlabel_points[counter]) == 1) {
            /* Append the compression pointer to the compressed string */
            uint16 compress_pointer;
            int length;
            if(state->dlabel_points[counter] < 12 ||
               state->dlabel_points[counter] >= 16384) {
                 state->valid_state = 0;
                 return JS_ERROR;
                 }
            compress_pointer = state->dlabel_points[counter];
            compress_pointer |= 0xc000;
            if(js_adduint16(state->compressed,compress_pointer)!= JS_SUCCESS) {
                state->valid_state = 0;
                return JS_ERROR;
                }

            /* Move the uncompressed offset to the end of the dlabel */
            length = dlabel_length(state->uncompressed,
                                   state->uncompressed_offset);
            if(length == JS_ERROR) {
                state->valid_state = 0;
                return JS_ERROR;
                }
            if(state->uncompressed_offset + length >
               state->uncompressed->unit_count ||
               state->uncompressed_offset + length >=
               state->uncompressed->max_count) {
                state->valid_state = 0;
                return JS_ERROR;
                }
            state->uncompressed_offset += length;
            if(state->uncompressed_offset == state->uncompressed->unit_count) {
                return 3;
                }
            return 2;
            }
        counter++;
        }

    /* Bounds checking */
    if(counter >= MAX_DLABEL_POINTS - 5) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Add this dlabel to the end of the compressed string */
    if(js_substr_append(state->uncompressed,state->compressed,
                        state->uncompressed_offset,len + 1) != JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    state->uncompressed_offset += len;
    state->uncompressed_offset += 1;
    return 1;
    }

/* compress_dlabel

   Given the uncompressed_offset in the state which starts at the
   beginning of a dlabel, compress the dlabel in question and append
   the compressed dlabel to the end of the compressed string.  This also
   calls compress_add_dlabel_points.

   This returns JS_SUCCESS on successful appending of the possibly
   compressible string, and JS_ERROR on error (in addition to marking
   the state as "invalid")

 */

int compress_dlabel(compress_state *state) {
    int offset,ret;

    /* Sanity check */
    if(state->valid_state != 1) {
        return JS_ERROR;
        }

    offset = state->compressed->unit_count;
    state->this_dlabel_begin = state->uncompressed_offset;

    ret = 1;
    while(ret == 1) {
        ret = compress_sub_dlabel(state);
        }

    /* There is no need to add dlabel points at the end of the packet */
    if(ret == 3) {
        return JS_SUCCESS;
        }

    if(compress_add_dlabel_points(state,offset) != JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    return JS_SUCCESS;
    }

/* compress_get_tocomp

   Given the type (rr_num) (e.g. The resource record number where 1 is A,
   etc.), give them a pointer to a null-terminated string which
   contains the compiled rr description

   This returns a 0 on error or unknown rr type (do not compress)
   This returns a 1 if the RR in question can be compressed
   This returns a 0 if the RR in question should not be compressed

 */

char compress_get_tocomp(int rr_num) {
    rrdesc *point, **hash;

    hash = decomp_export_rrformats();
    if(hash == 0) {
        return 0;
        }

    point = hash[rr_num % RR_HASH_SIZE];

    if(point == 0)
        return 0;

    while(point->rr_num != rr_num) {
        point = point->next;
        if(point == 0)
            return 0;
        }

    return point->tocompress;

    }

/* compress_rddata

   Given the uncompressed_offset in the state which starts at the
   beginning of the rdlength field in the DNS header, copy the rdlength
   label and the data in the uncompressed string, compressing any and
   all dlabels in the field as needed.

   This returns JS_SUCCESS on success, and JS_ERROR on error (in addition
   to marking the state as "invalid")

 */

int compress_rddata(compress_state *state) {

    char *desc, to_compress;
    int subtype, total, ctotal;

    /* Sanity check */
    if(state->valid_state != 1) {
        return JS_ERROR;
        }

    desc = decomp_get_rrdesc(state->this_rr_type);
    to_compress = compress_get_tocomp(state->this_rr_type);

    if(desc == 0) { /* Unknown RR type */
        if(state->current_rdlength == 0) {
            return JS_SUCCESS;
            }
        if(js_substr_append(state->uncompressed,state->compressed,
                            state->uncompressed_offset,
                            state->current_rdlength) != JS_SUCCESS) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        else {
            state->uncompressed_offset += state->current_rdlength;
            return JS_SUCCESS;
            }
        }
    else {
        subtype = *desc;
        total = 0;
        ctotal = 0;
        while(subtype != 0) {
            /* Fix-length data fields */
            if(subtype > 0 && subtype < 64) {
                if(js_substr_append(state->uncompressed,
                                    state->compressed,
                                    state->uncompressed_offset,
                                    subtype) != JS_SUCCESS) {
                    state->valid_state = 0;
                    return JS_ERROR;
                    }
                total += subtype;
                ctotal += subtype;
                state->uncompressed_offset += subtype;
                }
            /* Dlabels (which we may or may not compress, depending) */
            else if(subtype == RRSUB_DLABEL) {
                /* If we can not compress this dlabel */
                if(to_compress == 0) {
                    int len,point;
                    len = dlabel_length(state->uncompressed,
                                        state->uncompressed_offset);
                    if(len < 1) {
                        state->valid_state = 0;
                        return JS_ERROR;
                        }
                    point = state->compressed->unit_count;
                    if(js_substr_append(state->uncompressed,
                                        state->compressed,
                                        state->uncompressed_offset,
                                        len) != JS_SUCCESS) {
                        state->valid_state = 0;
                        return JS_ERROR;
                        }
                    if(compress_add_dlabel_points(state,point) != JS_SUCCESS) {
                        state->valid_state = 0;
                        return JS_ERROR;
                        }
                    state->uncompressed_offset += len;
                    total += len;
                    ctotal += len;
                    }
                else {
                    int len,clen,coffset;
                    len = dlabel_length(state->uncompressed,
                                        state->uncompressed_offset);
                    if(len < 1) {
                        state->valid_state = 0;
                        return JS_ERROR;
                        }
                    coffset = state->compressed->unit_count;
                    if(compress_dlabel(state) != JS_SUCCESS) {
                        state->valid_state = 0;
                        return JS_ERROR;
                        }
                    total += len;
                    clen = dlabel_length(state->compressed,coffset);
                    ctotal += clen;
                    }
                }
            /* Text data fields */
            else if(subtype == RRSUB_TEXT) {
                int len;
                if(state->uncompressed_offset >=
                   state->uncompressed->unit_count) {
                    state->valid_state = 0;
                    return JS_ERROR;
                    }
                len = *(state->uncompressed->string +
                        state->uncompressed_offset);
                if(len < 0 || len > 256) {
                    state->valid_state = 0;
                    return JS_ERROR;
                    }
                if(js_substr_append(state->uncompressed,
                                    state->compressed,
                                    state->uncompressed_offset,
                                    len) != JS_SUCCESS) {
                    state->valid_state = 0;
                    return JS_ERROR;
                    }
                total += len;
                ctotal += len;
                state->uncompressed_offset += len;
                }
            /* Variable length data (length determined by rdlength) */
            else if(subtype == RRSUB_VARIABLE) {
                int len;
                len = state->current_rdlength - total;
                if(len == 0) {
                    break;
                    }
                if(js_substr_append(state->uncompressed,
                                    state->compressed,
                                    state->uncompressed_offset,
                                    len) != JS_SUCCESS) {
                    state->valid_state = 0;
                    return JS_ERROR;
                    }
                total += len;
                ctotal += len;
                state->uncompressed_offset += len;
                }
            /* Unlisted RR subtype; should never happen */
            else {
                state->valid_state = 0;
                return JS_ERROR;
                }
            desc++;
            /* RRSUB_VARIABLE must be the last subtype */
            if(subtype != RRSUB_VARIABLE)
                subtype = *desc;
            else
                subtype = 0; /* break the loop */
            }
       /* Sanity check: Make sure the rdlength is kosher */
       if(state->current_rdlength != total) {
           state->valid_state = 0;
           return JS_ERROR;
           }
       }

    /* Change the compressed rdlength when compressing */
    if(ctotal != total) {
        unsigned char left, right;
        unsigned int off;
        off = state->this_rdlength_begin;
        if(ctotal > 65535 || ctotal < 2) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        left = (ctotal >> 8) & 0xff;
        right = ctotal & 0xff;
        if(off < 12 || off >= state->compressed->unit_count - 1) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        *(state->compressed->string + off) = left;
        *(state->compressed->string + off + 1) = right;
        }

    /* The rddata was sucessfully compressed */
    return JS_SUCCESS;
    }

/* compress_get_uint16

   Given the uncompressed_offset in the state which starts at the
   beginning of a uint16 number (big endian 16-bit number), copy
   the number in question from the uncompressed string to
   the compressed string.

   This returns the number in question on successful appending of
   the uint16, and JS_ERROR on error (in addition to marking the
   state as "invalid").

 */

int compress_get_uint16(compress_state *state) {
    int number;

    if(state->valid_state != 1) {
        return JS_ERROR;
        }

    number = js_readuint16(state->uncompressed,state->uncompressed_offset);
    if(number == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    if(number < 0 || number > 65535) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    if(js_adduint16(state->compressed,number) != JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    state->uncompressed_offset += 2;
    if(state->uncompressed_offset > state->uncompressed->unit_count) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Success */
    return number;
    }

/* compress_get_type_etc

   Given that the uncompressed_offset (in the state) starts at the
   beginning of the type field in the uncompressed data, this function
   obtains the type, which it uses to change this_rr_type in state.

   After it is done, it goes past type, class, and rdlength;
   It copies over the type, class, and rdlength to the compressed
   string.

   This returns JS_SUCCESS on success, and JS_ERROR on error (in addition
   to marking the state as "invalid")

 */

int compress_get_type_etc(compress_state *state) {
    int number;

    if(state->valid_state != 1) {
        return JS_ERROR;
        }

    /* Type */
    number = compress_get_uint16(state);
    if(number == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    state->this_rr_type = number;

    /* Class */
    number = compress_get_uint16(state);
    if(number == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* TTL */
    number = js_readuint32(state->uncompressed,state->uncompressed_offset);
    if(number == 0xffffffff) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    if(js_adduint32(state->compressed,number) != JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    state->uncompressed_offset += 4;
    if(state->uncompressed_offset >= state->uncompressed->unit_count) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Success! */
    return JS_SUCCESS;
    }

/* compress_get_header

   This gets the header from the uncompressed string and copies it over
   to the compressed string, modifying number_answers in state so that
   it reflects the number of answers in the uncompressed packet.

 */

int compress_get_header(compress_state *state) {
    /* See RFC1035 4.1.1 */
    int qdcount,ancount,nscount,arcount;
    /* The total number of answers */
    int total;

    /* Sanity checks */
    if(state->valid_state != 1) {
        return JS_ERROR;
        }
    /* We only want to run this at the top, of course */
    if(state->uncompressed_offset != 0) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Copy over the ID and flags */
    if(js_substr_append(state->uncompressed,state->compressed,0,4) !=
       JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Advance the pointer */
    state->uncompressed_offset += 4;
    if(state->uncompressed_offset >= state->uncompressed->unit_count) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* QDCOUNT */
    qdcount = compress_get_uint16(state);
    if(qdcount == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* ANCOUNT */
    ancount = compress_get_uint16(state);
    if(ancount == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* NSCOUNT */
    nscount = compress_get_uint16(state);
    if(nscount == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* ARCOUNT */
    arcount = compress_get_uint16(state);
    if(arcount == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    /* Not in any RFC, but only a qdcount of 0 or 1 is supported by any
       actual DNS server */
    if(qdcount < 0 || qdcount > 1) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    total = ancount + nscount + arcount;

    /* To have an answer, one must have a question */
    if(total != 0 && qdcount != 1) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    if(qdcount == 0) {
        state->number_answers = -2;
        return JS_SUCCESS;
        }

    state->number_answers = total;
    return JS_SUCCESS;
    }

/* compress_get_question

   This gets the single question from the uncompressed string and copies
   it over to the compressed string.  It calls compress_dlabel to insure
   that dlabel_points in state is correctly initialized with pointers
   to the label boundaries in the question.

 */

int compress_get_question(compress_state *state) {

    /* Sanity checks */
    if(state->valid_state != 1) {
        return JS_ERROR;
        }
    if(state->uncompressed_offset != 12) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    if(state->number_answers == -2) { /* No questions nor answers */
        return JS_SUCCESS;
        }

    /* The domain name question */
    if(compress_dlabel(state) != JS_SUCCESS) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    /* The type */
    if(compress_get_uint16(state) == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    /* The class */
    if(compress_get_uint16(state) == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }

    return JS_SUCCESS;
    }

/* compress_get_rdlength

   Get the rdlength from the uncompressed string */

int compress_get_rdlength(compress_state *state) {
    int number;

    /* Set this so we can change it if we compress the data */
    state->this_rdlength_begin = state->compressed->unit_count;

    number = compress_get_uint16(state);
    if(number == JS_ERROR) {
        state->valid_state = 0;
        return JS_ERROR;
        }
    state->current_rdlength = number;

    return JS_SUCCESS;
    }

/* compress_answers

   Get and compress all of the answers which are in the DNS packet.

 */

int compress_answers(compress_state *state) {
    int counter;

    if(state->valid_state != 1) {
        return JS_ERROR;
        }

    for(counter = 0; counter < state->number_answers; counter++) {
        if(compress_dlabel(state) == JS_ERROR) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(compress_get_type_etc(state) == JS_ERROR) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(compress_get_rdlength(state) == JS_ERROR) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        if(compress_rddata(state) == JS_ERROR) {
            state->valid_state = 0;
            return JS_ERROR;
            }
        }
    return JS_SUCCESS;
    }

/* compress_destroy_state

   Once a string is successfully compressed, this function destroys
   the compressed state state.  This function returns a pointer to the
   compressed string inside state.

 */

js_string *compress_destroy_state(compress_state *state) {
    js_string *ret;
    js_dealloc(state->dlabel_points);
    ret = state->compressed;
    js_dealloc(state);
    return ret;
    }

/* compress_data

   This is the routine called by other parts of MaraDNS that actually
   compressed the RR in question.  The API to this function is
   identical to the original compress_data API

   Input: a pointer to the uncompressed string we wish to compress,
   a pointer to the compressed string which we will compress.

   Output: JS_ERROR on error, JS_SUCCESS on success

 */

int compress_data(js_string *in, js_string *out) {
    js_string *compressed;
    compress_state *state;

    state = compress_init_state(in);
    if(state == 0)
        return JS_ERROR;

    /*printf("Packet to compress: ");
    show_esc_stdout(in);
    printf("\n");*/

    if(compress_get_header(state) == JS_ERROR) {
        compressed = compress_destroy_state(state);
        js_destroy(compressed);
        return JS_ERROR;
        }

    if(compress_get_question(state) == JS_ERROR) {
        compressed = compress_destroy_state(state);
        js_destroy(compressed);
        return JS_ERROR;
        }

    if(compress_answers(state) == JS_ERROR) {
        compressed = compress_destroy_state(state);
        js_destroy(compressed);
        return JS_ERROR;
        }

    compressed = compress_destroy_state(state);

    /*printf("Compressed packet: ");
    show_esc_stdout(compressed);
    printf("\n");*/

    if(js_copy(compressed,out) == JS_ERROR) {
        js_destroy(compressed);
        return JS_ERROR;
        }

    js_destroy(compressed);
    return JS_SUCCESS;

    }
