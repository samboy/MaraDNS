/* Copyright (c) 2002-2006 Sam Trenholme
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

#include <stdio.h>
#include "../MaraDns.h"
#include "../server/timestamp.h"
#include "Compress_rrs.h"
#include "Compress_rrdescs.h" /* The description of RRs to decompress */
#include "functions_dns.h"

/* Some definitions */
#define MAX_DLABEL_LEN 256
#define MAX_RR_SECTIONS 16

/* The hash that stores RRs */
rrdesc **rr_formats;

/* Whether to show verbose messages */
int dlog_level = -1; /* -1 means uninitialized */

/* decomp_message: Show, if needed, a message to the user.

   Input: null-terminated string with the message, minimum log level
          before which we will show the message

   Output: JS_SUCCESS

*/

int decomp_message(char *message, int min_log_level) {
    if(dlog_level >= min_log_level) {
        show_timestamp();
        printf("%s\n",message);
        }
    return JS_SUCCESS;
    }

/* decomp_get_label:  Uncompress a dlabel from a compressed string,
   generating a js_string object which will store the decompressed
   dlabel.

   Input:
   compressed: The compressed string
   compressed_offset: The offset from the beginning of the string
   where the compressed dlabel begins

   Output:
   The output of this function is a newly created js_string object
   which contains the decompressed dlabel.  If there was any problem
   decompressing the dlabel in question, this routine will return a 0.
*/

js_string *decomp_get_label(js_string *compressed,
                            unsigned int compressed_offset) {
    js_string *ret; /* The string we return */
    int counter, cplace, cplace_save, dplace, limit;

    decomp_message("Performing sanity checks on compressed string...",5);

    /* Sanity checks */
    if(compressed == 0)
        return 0;
    if(compressed->unit_size != 1)
        return 0;
    if(compressed->unit_count > compressed->max_count)
        return 0;
    if(compressed_offset > compressed->unit_count)
        return 0;

    decomp_message("Compressed string is sane.  Initializing variables...",5);

    /* Initialize the variables */
    cplace = compressed_offset;
    cplace_save = cplace;
    dplace = 0;
    counter = 0;
    limit = 0;
    if((ret = js_create(MAX_DLABEL_LEN + 3,1)) == 0)
        return 0;

    decomp_message("Variables initalized.",5);

    /* Decompress and copy */
    do {
        if(cplace >= compressed->unit_count) {
            js_destroy(ret);
            return 0;
        }
        limit++;
        counter = *(compressed->string + cplace);
        /* We do not allow invalid length values */
        if(counter > 63 && counter < 0xC0) {
            decomp_message("Invalid length value in compressed string",4);
            js_destroy(ret);
            return 0;
            }
        else if(counter >= 0xC0) { /* Compression pointer */
            /* Make sure we have two bytes for the compression pointer */
            if(cplace + 1 >= compressed->unit_count) {
                decomp_message("Compression pointer isn't fitting",4);
                js_destroy(ret);
                return 0;
                }
            /* Get the compression pointer */
            cplace_save = cplace;
            cplace = ((counter & 0x3F) << 8);
            cplace |= *(compressed->string + cplace_save + 1);
            /* All compression labels must go backwards */
            if(cplace >= cplace_save) {
                decomp_message("Compressed pointer goes forward",4);
                js_destroy(ret);
                return 0;
                }
            /* All compression lables must start past the header */
            if(cplace < 12) {
                decomp_message("Compressed pointer points to header",4);
                js_destroy(ret);
                return 0;
                }
            }
        /* Normal length dlabel */
        else if(counter > 0 && counter <= 63) {
            counter++;
            if(dplace + counter >= ret->max_count) {
                decomp_message("Pointing past end of ret string",4);
                js_destroy(ret);
                return 0;
                }
            if(cplace + counter >= compressed->unit_count) {
                decomp_message("Pointing past end of compressed string",4);
                js_destroy(ret);
                return 0;
                }
            while(counter > 0) {
                *(ret->string + dplace) = *(compressed->string + cplace);
                ret->unit_count++;
                dplace++;
                cplace++;
                counter--;
                }
            counter = 100; /* So we don't break out of loop */
            }
        else if(counter == 0) {
            if(dplace + counter >= ret->max_count) {
                decomp_message("Pointing past end of the compressed string",4);
                js_destroy(ret);
                return 0;
                }
            *(ret->string + dplace) = 0;
            ret->unit_count++;
            }
        else { /* Should never happen */
            decomp_message("This, folks, should never happen",4);
            js_destroy(ret);
            return 0;
            }
        } while(counter > 0 && limit < 256);

    if(limit >= 256) {
        decomp_message("Limit exceeded when decompressing dlabel",4);
        js_destroy(ret);
        return 0;
        }

    /* Force core dump */
    /**(ret->string + 1000000) = 0;*/
    return ret;
    }

/* decomp_append_dlabel: Get a dlabel from the compressed string,
   appending the uncompressed dlabel to the uncompressed string.

   Input:

   compressed: The compressed string
   uncompressed: The partially decompressed string
   compressed_offset: Where in the string to look (0 is the top of the
                      string, 1 is the second byte of the string, etc.)

   Output:

   The length of the compressed dlabel; JS_ERROR if there was an
   error decompressing

 */

int decomp_append_dlabel(js_string *compressed, js_string *uncompressed,
                         unsigned int compressed_offset) {

    js_string *dlabel;
    int length = 0;

    /* Sanity checks */
    if(js_has_sanity(compressed) != JS_SUCCESS) {
        return JS_ERROR;
        }
    if(js_has_sanity(uncompressed) != JS_SUCCESS) {
        return JS_ERROR;
        }
     if(compressed->unit_size != 1) {
        return JS_ERROR;
        }
     if(uncompressed->unit_size != 1) {
        return JS_ERROR;
        }
     if(compressed_offset >= compressed->unit_count) {
        return JS_ERROR;
        }

    /* Get and process the actual compressed dname to append */
    dlabel = decomp_get_label(compressed, compressed_offset);
    if(dlabel == 0) {
        return JS_ERROR;
        }
    length = dlabel_length(compressed,compressed_offset);
    if(length == JS_ERROR) {
        js_destroy(dlabel);
        return JS_ERROR;
        }

    /* Append the label in question */
    if(js_append(dlabel,uncompressed) == JS_ERROR) {
        js_destroy(dlabel);
        return JS_ERROR;
        }

    /* Success! */
    js_destroy(dlabel);
    return length;
    }

/* decomp_append_bytes:

   Given the user-specified substring of one js_string object, append
   that data to another js_string (this is used a lot with the
   decompression code)

   Input

   compressed:        The string we will be appending from
   uncompressed:      The string we will be appending to
   compressed_offset: The offset to start the appending from
   length:            The number of bytes to append

   Output

   JS_ERROR on error
   JS_SUCCESS on success

   Note

   This really should eventually become a JsStr primitive

 */

int decomp_append_bytes(js_string *compressed, js_string *uncompressed,
                        unsigned int compressed_offset, int length) {

    js_string *temp;
    if((temp = js_create(length + 2,1)) == 0) {
        return JS_ERROR;
        }

    if(compressed->unit_count < compressed_offset + length) {
        js_destroy(temp);
        return JS_ERROR;
        }

    if(js_substr(compressed,temp,compressed_offset,length) != JS_SUCCESS) {
        js_destroy(temp);
        return JS_ERROR;
        }

    if(js_append(temp,uncompressed) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    js_destroy(temp);
    return JS_SUCCESS;
    }

/* decomp_get_type_etc:

   Get the resource record type (and some other data: The class and TTL, which
   do not matter as far as decompressing a string are concerned) from the
   compressed string, and copy the data over to the uncompressed string.

   Input

   compressed: The compressed string
   uncompressed: The partially decompressed string
   compressed_offset: Where in the string to look (0 is the top of the
                      string, 1 is the second byte of the string, etc.)

   Output

   JS_ERROR on error;  RR type (0-65536) on success

   Increase offset by eight bytes after running this.

 */

int decomp_get_type_etc(js_string *compressed, js_string
                        *uncompressed, unsigned int compressed_offset) {

    int type;

    type = js_readuint16(compressed,compressed_offset);

    if(decomp_append_bytes(compressed,uncompressed,compressed_offset,8) !=
       JS_SUCCESS) {
        return JS_ERROR;
        }

    return type;

    }

/* decomp_get_rdlength

   Get the resource record rdlength from the compressed string.
   Note that this is how long the rddata is *compressed*, the
   length can very well change when it is uncompreseed.

   Input

   compressed: The compressed string
   compressed_offset: Where in the string to look (0 is the top of
                      the string, 1 is the second byte of the string,
                      etc.)

   Output

   JS_ERROR on error, RDLENGTH (0-65536) on success

 */

int decomp_get_rdlength(js_string *compressed,
                        unsigned int compressed_offset) {

    int rdlength;

    rdlength = js_readuint16(compressed,compressed_offset);

    return rdlength;

    }

/* decomp_get_header

   Get the 12 byte header for a DNS packet; making sure that qdcount
   (bytes 5 and 6 in big endian format) is 0 or one; and that there are
   no answers if qdcount is 0.

   Input

   compressed: The compressed string
   uncompressed: The empty uncompressed string (returns error if string
                 is not empty)

   Output

   The total number of answers; -2 if there are no questions and no
   answers; JS_ERROR (-1) on error; -3 if there are no questions and
   one answer (yes, some DNS servers do this with zone files)

 */

int decomp_get_header(js_string *compressed, js_string *uncompressed) {
    int qdcount, ancount, nscount, arcount, total;

    /* Sanity checks */
    if(js_has_sanity(compressed) == JS_ERROR) {
        return JS_ERROR;
        }
    if(js_has_sanity(uncompressed) == JS_ERROR) {
        return JS_ERROR;
        }
    if(compressed->unit_count < 12) {
        return JS_ERROR;
        }
    if(uncompressed->unit_count != 0) {
        return JS_ERROR;
        }

    /* Get the number of questions */
    qdcount = js_readuint16(compressed,4);
    if(qdcount < 0 || qdcount > 1)
        return JS_ERROR;

    /* Get the number of answers */
    ancount = js_readuint16(compressed,6);
    if(ancount < 0 || ancount > 65535)
        return JS_ERROR;
    nscount = js_readuint16(compressed,8);
    if(nscount < 0 || nscount > 65535)
        return JS_ERROR;
    arcount = js_readuint16(compressed,10);
    if(arcount < 0 || arcount > 65535)
        return JS_ERROR;

    total = ancount + nscount + arcount;

    /* Copy the data over */
    if(decomp_append_bytes(compressed,uncompressed,0,12) != JS_SUCCESS)
        return JS_ERROR;

    /* Yes, some zone servers do this */
    if(qdcount == 0 && total >= 1)
        return -2 - total;

    /* And return the number of answers */
    if(qdcount == 0)
        return -2;

    return total;

    }

/* decomp_get_question

   Get the question from the DNS packet; it is assumed that the question
   starts on the 13th byte.

   Input

   compressed: The compressed string
   uncompressed:  The compressed string with only 12 bytes in it (returns
                  error if string does not have 12 bytes)

   Output

   The length of the question; JS_ERROR on fatal error parsing question.

 */

int decomp_get_question(js_string *compressed, js_string *uncompressed) {
    int length;

    /* Sanity checks */
    if(compressed->unit_count < 12) {
        return JS_ERROR;
        }

    if(uncompressed->unit_count != 12) {
        return JS_ERROR;
        }

    /* Append the dlabel to the uncompressed string */
    length = decomp_append_dlabel(compressed,uncompressed,12);
    if(length < 1) {
        return JS_ERROR;
        }

    /* Append the type and class to the uncompressed string */
    if(decomp_append_bytes(compressed,uncompressed,12 + length,4)
       != JS_SUCCESS) {
        return JS_ERROR;
        }

    length += 4;

    return length;

    }

/* decomp_init_rrdesc:

   Initialize the rr_formats hash

   Input

   None

   Output

   JS_ERROR on error
   JS_SUCCESS

   Global variables affected

   rr_formats

 */

int decomp_init_rrdesc() {
    int counter;

    if((rr_formats = js_alloc(RR_HASH_SIZE,sizeof(rrdesc *))) == 0)
        return JS_ERROR;

    /* Zero out the hash table */
    for(counter = 0; counter < RR_HASH_SIZE; counter++)
        rr_formats[counter] = 0;

    return JS_SUCCESS;

    }

/* decomp_add_rrdesc:

   Add a description of a RR to the rr_formats hash

   Input

   A js_string which describes the record in question

   Output

   JS_ERROR on error
   JS_SUCCESS on success
   -2 for error in field 2, -3 for error in field 3, -4 for error in
      field 4, and -5 for error in field 5.

   Global variables used

   rr_formats

 */

int decomp_add_rrdesc(js_string *desc) {
    int rtype, place, counter, fieldnum, subfieldnum;
    unsigned char c;
    rrdesc *new, *point;

    /* Sanity checks */
    if(js_has_sanity(desc) != JS_SUCCESS)
        return JS_ERROR;
    js_set_encode(desc,JS_US_ASCII); /* So js_atoi works */

    /* Determine where to place this record in the hash */
    if((new = js_alloc(1,sizeof(rrdesc))) == 0) {
        return JS_ERROR;
        }

    /* Set up the description.  This is a format where the description
       of each section of the RR is converted in to a single number */
    if((new->description = js_alloc(MAX_RR_SECTIONS,1)) == 0) {
        js_dealloc(new);
        return JS_ERROR;
        }
    /* Clear out the new->description array */
    for(counter = 0; counter < MAX_RR_SECTIONS - 1; counter++) {
        new->description[counter] = 0;
        }

    /* Initialize the "tocompress" field to uninitialized; this is
       a positive number under 127 because some versions of GCC on
       some architectures consider 'char' without 'unsigned' an
       unsigned value. */
    new->tocompress = 79;

    /* Now, parse the string describing the message */
    fieldnum = subfieldnum = 1;
    rtype = -1;
    for(counter = 0; counter < desc->unit_count ; counter++) {
        c = *(desc->string + counter);
        if(fieldnum == 1) { /* RR number field */
            if(subfieldnum == 1) /* Before first colon */ {
                if(c == ':') {
                    subfieldnum++;
                    }
                }
            else if(subfieldnum == 2) /* Number immediately after colon */ {
                if(rtype == -1) {
                    rtype = js_atoi(desc,counter);
                    if(rtype <= 0 || rtype > 65535) {
                        js_dealloc(new->description);
                        js_dealloc(new);
                        return JS_ERROR;
                        }
                    new->rr_num = rtype;
                    }
                if(c == '|') {
                    subfieldnum = 1;
                    fieldnum = 2;
                    }
                }
            }
        else if(fieldnum == 2) { /* RR name field */
            if(c == '|') {
                subfieldnum = 1;
                fieldnum = 3;
                }
            }
        else if(fieldnum == 3) { /* The description of the RRs themselves */
            /* Bounds check */
            if(subfieldnum > MAX_RR_SECTIONS - 2) {
                js_dealloc(new->description);
                js_dealloc(new);
                return JS_ERROR;
                }
            /* Process the RR subfield; this code only supports one-character
               labels (quick and dirty; but I want to get 1.0 out the door)
             */
            if(new->description[subfieldnum - 1] == 0) {
                if(c >= '1' && c <= '9') {
                    new->description[subfieldnum - 1] = c - '0';
                    }
                else if(c == 'D') {
                    new->description[subfieldnum - 1] = RRSUB_DLABEL;
                    }
                else if(c == 'T') {
                    new->description[subfieldnum - 1] = RRSUB_TEXT;
                    }
                else if(c == 'V') {
                    new->description[subfieldnum - 1] = RRSUB_VARIABLE;
                    }
                else { /* Unknown type */
                    js_dealloc(new->description);
                    js_dealloc(new);
                    return JS_ERROR;
                    }
                }
             else if(c != ';' && c != '|') { /* Multi-char description */
                 js_dealloc(new->description);
                 js_dealloc(new);
                 return JS_ERROR;
                 }
             else if(c == ';') {
                 /* Variable ('V') *must* be the last subfield */
                 if(new->description[subfieldnum - 1] == RRSUB_VARIABLE) {
                    js_dealloc(new->description);
                    js_dealloc(new);
                    return JS_ERROR;
                    }
                 subfieldnum++;
                 }
             else if(c == '|') {
                 subfieldnum = 1;
                 fieldnum = 4;
                 }
             else { /* Should never happen */
                 js_dealloc(new->description);
                 js_dealloc(new);
                 return JS_ERROR;
                 }
             }
         else if(fieldnum == 4) { /* Whether we can compress this field
                                     or not; currently ignored */
             if(c == 'C' && new->tocompress == 79) {
                new->tocompress = 1;
                }
             else if(c == 'N' && new->tocompress == 79) {
                new->tocompress = 0;
                }
             else if(c == '|' && new->tocompress != 79) {
                subfieldnum = 1;
                fieldnum = 5;
                }
             else { /* Invalid for field num */
                js_dealloc(new->description);
                js_dealloc(new);
                return -4;
                }
             }
         else if(fieldnum == 5) { /* Description of field; currently
                                     ignored */
             /* XXX: We really want something here which makes sure we
                     have at least three subfields and considers a colon
                     the start of a new RR */
             break;
             }
         }

     /* Now that the new field is set up, add the new element to the
        hash of rr descriptions */

     place = rtype % RR_HASH_SIZE;
     if(rr_formats == 0) {
        js_dealloc(new->description);
        js_dealloc(new);
        return JS_ERROR;
        }
     point = rr_formats[place];
     if(point == 0) {
         rr_formats[place] = new;
         }
     else {
         while(point->next != 0)
             point = point->next;
         point->next = new;
         }

     new->next = 0;

     /* OK, we're done (finally!) */
     return JS_SUCCESS;
     }

/* decomp_init

   Initialize the decompression code; set up the RRs, and set the
   log_level global variable in the decompression code.

   Input

   The desired log_level for all of the decompression code

   Output

   JS_SUCCESS on success
   JS_ERROR on error

   Global variables affected

   rr_formats (indirectly via decomp_add_rrdesc)
   log_level

 */

int decomp_init(int alog_level) {
    js_string *temp; /* Used for storing the indivual RR descriptions */
    int counter;

    /* Create the string */
    if((temp = js_create(256,1)) == 0) {
        return JS_ERROR;
        }

    /* Add the records to the big hash */
    decomp_init_rrdesc();
    for(counter = 0 ; counter < RR_COUNT ; counter++) {
        if(js_qstr2js(temp,rr_descs[counter]) != JS_SUCCESS) {
            js_destroy(temp);
            return JS_ERROR;
            }
        if(decomp_add_rrdesc(temp) != JS_SUCCESS) {
            js_destroy(temp);
            return JS_ERROR;
            }
        }

    /* Set the log level */
    dlog_level = alog_level;

    js_destroy(temp);
    return JS_SUCCESS;

    }

/* decomp_get_rddesc

   Given the rtype (rr_num) (e.g. The resource record number where 1 is A,
   etc.), give them a pointer to a null-terminated string which
   contains the compiled rr description

   Input

   The number RR they wish

   Output

   A pointer to the compiled rr description.  0 if there was any
   problem getting that

   Global variables used

   The "rr_formats" hash

   Notes

   This string can not be changed; if it is bad things can happen

 */

char *decomp_get_rrdesc(int rr_num) {
    rrdesc *point;

    if(rr_formats == 0)
        return 0;

    point = rr_formats[rr_num % RR_HASH_SIZE];
    if(point == 0)
        return 0;

    while(point->rr_num != rr_num) {
        point = point->next;
        if(point == 0)
            return 0;
        }

    return point->description;

    }

/* decomp_get_rddata

   Get the rddata from the compressed string, decompressing any dlabels
   as needed, and append the data to the uncompressed string.

   Input

   compressed: The compressed string
   out: A js_string object to place the output in
   compressed_offset: Where in the string to look (0 is the top of the
     string, 1 is the second byte of the string, etc.)
   type: The type of resource record (1 for A, 2 for NS, etc.)
   rdlength: The rdlength this resource record should have

   Output

   JS_ERROR on error, JS_SUCCESS if there was no problem processing

 */

int decomp_get_rddata(js_string *compressed, js_string *out,
                      unsigned int compressed_offset, int type, int rdlength) {

    char *desc;
    int subtype, total, len;

    desc = decomp_get_rrdesc(type);

    if(desc == 0) { /* Unknown RR type */
        if(rdlength == 0) {
            return JS_SUCCESS;
            }
        if(decomp_append_bytes(compressed,out,compressed_offset,
                               rdlength) != JS_SUCCESS) {
            return JS_ERROR;
            }
        else {
            return JS_SUCCESS;
            }
        }
    else {
        subtype = *desc;
        total = 0;
        /* Handle the various types of data we can get in the RR RDDATA */
        while(subtype != 0) {
            /* Fix-length data fields */
            if(subtype > 0 && subtype < 64) {
                if(decomp_append_bytes(compressed,out,
                   compressed_offset,subtype) != JS_SUCCESS) {
                       return JS_ERROR;
                       }
                total += subtype;
                compressed_offset += subtype;
                }
            /* Dlabels (which may be compressed) */
            else if(subtype == RRSUB_DLABEL) {
                len = decomp_append_dlabel(compressed,out,
                        compressed_offset);
                if(len == JS_ERROR) {
                    return JS_ERROR;
                    }
                total += len;
                compressed_offset += len;
                }
            /* Text data fields */
            else if(subtype == RRSUB_TEXT) {
                /* Data abstraction violation */
                len = *(compressed->string + compressed_offset);
                len += 1; /* To account for the one byte which
                             describes the length */
                if(len < 0 || len > 256) {
                    return JS_ERROR;
                    }
                if(decomp_append_bytes(compressed,out,
                                       compressed_offset,len) !=
                   JS_SUCCESS) {
                    return JS_ERROR;
                    }
                total += len;
                compressed_offset += len;
                }
            /* Variable length data (length determined by rdlength) */
            else if(subtype == RRSUB_VARIABLE) {
                len = rdlength - total;
                if(len == 0) {
                    break;
                    }
                if(decomp_append_bytes(compressed,out,
                                       compressed_offset,len) != JS_SUCCESS) {
                    return JS_ERROR;
                    }
                total += len;
                compressed_offset += len;
                }
            else { /* Should never happen */
                return JS_ERROR;
                }
            desc++;
            /* RRSUB_VARIABLE must be the last subtype */
            if(subtype != RRSUB_VARIABLE)
                subtype = *desc;
            else
                subtype = 0; /* break the loop */
            }
        /* Sanity check; make sure that rdlength panned out */
        if(rdlength != total) {
            return JS_ERROR;
            }
        }

    /* The record's rddata was sucessfully decompressed */
    return JS_SUCCESS;
    }

/* decomp_decompress_packet

   Uncompressed a query (or reply) compressed with the RFC1035 compression
   alogrithm (see RFC1035  4.1.4)

   Input

   Pointer to compressed DNS packet
   Pointer to uncompressed DNS packet

   Output

   JS_ERROR on error
   JS_SUCCESS on success

 */

int decomp_decompress_packet(js_string *compressed, js_string *uncompressed) {

    int answers; /* Number of answers */
    int type, rdlength; /* As per RFC1035  3.2.1 */
    int offset,length;
    js_string *rddata;

    /* Sanity checks */

    if(js_has_sanity(compressed) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(uncompressed) == JS_ERROR)
        return JS_ERROR;
    if(compressed->unit_size != 1 || uncompressed->unit_size != 1)
        return JS_ERROR;
    if(uncompressed->unit_count != 0)
        return JS_ERROR;

    /* Create the string for storing the rddata */
#ifndef AUTHONLY
    if((rddata = js_create(512,1)) == 0) {
        return JS_ERROR;
        }
#else
    if((rddata = js_create(4512,1)) == 0) {
        return JS_ERROR;
        }
#endif
    /* Read the header */

    answers = decomp_get_header(compressed,uncompressed);
    if(answers == -2) { /* No questions and no answers */
        js_destroy(rddata);
        return JS_SUCCESS;
        }
    else if(answers == JS_ERROR) {
        js_destroy(rddata);
        return JS_ERROR;
        }

    /* Process the question (if applicable) */
    if(answers <= -3) {
        answers = -2 - answers; /* So -3 becomes 1 answer, -4 becomes
                                   2 answers, etc. */
        length = 0;
        }
    else {
        length = decomp_get_question(compressed,uncompressed);
        if(length < 1) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        }

    offset = 12 + length;

    /* Process the answers */
    while(answers > 0) {
        length = decomp_append_dlabel(compressed,uncompressed,offset);
        if(length < 1) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        offset += length;
        type = decomp_get_type_etc(compressed,uncompressed,offset);
        if(type == JS_ERROR) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        offset += 8;
        rdlength = decomp_get_rdlength(compressed,offset);
        if(rdlength == JS_ERROR) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        offset += 2;
        /* Hack: zero out the rddata string */
        rddata->unit_count = 0;
        if(decomp_get_rddata(compressed,rddata,offset,type,rdlength)
           != JS_SUCCESS) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        /* Add the decompressed rdlength */
        if(js_adduint16(uncompressed,rddata->unit_count) == JS_ERROR) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        /* And the decompressed rddata */
        if(js_append(rddata,uncompressed) == JS_ERROR) {
            js_destroy(rddata);
            return JS_ERROR;
            }
        offset += rdlength; /* The compressed rdlength */
        answers--;
        }

    js_destroy(rddata);
    return JS_SUCCESS;
    }

/* decompress_data

   This and the decomp_init function are the only functions which should
   be visible to other code; the only "public methods" so to speak

   Input

   compressed string, uncompressed string

   Output

   JS_ERROR on error, JS_SUCCESS on success

 */

int decompress_data(js_string *compressed, js_string *uncompressed) {
    /* zero-out the uncompressed string */
    uncompressed->unit_count = 0;

    if(dlog_level >= 5) {
       printf("About to decompress packet: ");
       show_esc_stdout(compressed);
       printf("\n");
       }

    if(dlog_level == -1) { /* Uninitialized, return error */
        return JS_ERROR;
        }
    else {
        return decomp_decompress_packet(compressed,uncompressed);
        }

    /* We should never end up here */
    return JS_ERROR;
    }

/* Since the compression code needs to use the same rr_formats database,
   this bit of code exports the rr_formats hash so that the compression
   code can use it */

rrdesc **decomp_export_rrformats() {
    return rr_formats;
    }

