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

#include "../libs/JsStr.h"

/* Given the output of show_esc_stdout, create a binary js_string
   object.
   Input: js_string object to convert escape sequences in to binary
          sequences
   Output: Pointer to newly created js_string object which contains
           the binary sequence; 0 if any problems happened
 */

js_string *decode_esc_sequence(js_string *esc) {
    js_string *ret;
    int iplace, oplace, counter, inescape, octal_value;
    unsigned char octet;
    iplace = oplace = 0;

    if(js_has_sanity(esc) != JS_SUCCESS) {
        return 0;
        }

    /* Find out how big to make the output string */
    for(counter = 0 ; counter < esc->unit_count ; counter++) {
        octet = *(esc->string + counter);
        if(octet == '\\') {
            counter++;
            if(counter >= esc->unit_count) {
                return 0;
                }
            octet = *(esc->string + counter);
            /* Anything besides a number is a single character escaped */
            if(octet < '0' || octet > '7') {
                oplace++;
                }
            else {
                for(inescape = 0; inescape < 3 ; inescape++) {
                    octet = *(esc->string + counter);
                    /* We only accept three-digit octal sequences */
                    if(octet < '0' || octet > '7') {
                        return 0;
                        }
                    if(inescape < 2)
                        counter++;
                    if(counter >= esc->unit_count) {
                        return 0;
                        }
                    }
                oplace++;
                }
            }
        /* Normal non-escape character */
        else {
            oplace++;
            }
        }

    /* oplace now has the number of octets the outputted string should
       have; if there was anything unusual in the escape sequences,
       we will not have gotten to here */
    if((ret = js_create(oplace + 2,1)) == 0) {
        return 0;
        }

    ret->unit_count = oplace;

    /* Now, copy over the escaped string to the unescaped return string */
    oplace = 0;
    for(counter = 0 ; counter < esc->unit_count ; counter++) {
        octet = *(esc->string + counter);
        if(octet == '\\') {
            counter++;
            if(counter >= esc->unit_count) {
                js_destroy(ret);
                return 0;
                }
            octet = *(esc->string + counter);
            /* Anything besides a number is a single character escaped */
            if(octet < '0' || octet > '7') {
                *(ret->string + oplace) = *(esc->string + counter);
                oplace++;
                }
            else {
                octal_value = 0;
                for(inescape = 0; inescape < 3 ; inescape++) {
                    octal_value *= 8;
                    octet = *(esc->string + counter);
                    /* We only accept three-digit octal sequences */
                    if(octet < '0' || octet > '7') {
                        js_destroy(ret);
                        return 0;
                        }
                    octal_value += octet - '0';
                    if(inescape < 2)
                        counter++;
                    if(counter >= esc->unit_count) {
                        js_destroy(ret);
                        return 0;
                        }
                    }
                *(ret->string + oplace) = octal_value;
                oplace++;
                }
            }
        /* Normal non-escape character */
        else {
            *(ret->string + oplace) = *(esc->string + counter);
            oplace++;
            }
        }

    return ret;
    }

main() {
    js_string *in, *out, *compressed, *uncompressed, *dlabel;

    int result, place, counter;

    if((in = js_create(1024,1)) == 0) {
        exit(1);
        }
    if((uncompressed = js_create(1024,1)) == 0) {
        exit(1);
        }

     /* <ESC>:<linenum>s/\\/\\\\/g is your friend */
     result = js_qstr2js(in,
"V\\214\\200\\000\\000\\001\\000\\002\\000\\000\\000\\000\\004news\\003com\\003com\\000\\000\\001\\000\\001\\004news\\003com\\003com\\000\\000\\005\\000\\001\\000\\000\\001,\\000\\015\\003www\\003com\\003com\\000\\003www\\003com\\003com\\000\\000\\001\\000\\001\\000\\000\\001,\\000\\004@|\\355\\214"
     );

     if(result != JS_SUCCESS) {
         exit(2);
         }

     /* Make a binary string */
     out = decode_esc_sequence(in);

     if(out == 0) {
         exit(3);
         }

     /* Compress that string */
     compressed = js_create(1024,1);
     if(compressed == 0) {
         exit(4);
         }

     if(compress_data(out,compressed) != JS_SUCCESS) {
         exit(5);
         }

     /* Output some stuff */
     show_esc_stdout(in);
     printf("\n");
     show_esc_stdout(out);
     printf("\n");
     show_esc_stdout(compressed);
     printf("\n");

     /* Show each byte by number of the compressed string */
     for(counter = 0; counter < compressed->unit_count ; counter++) {
         printf("%d:\%3o%c;",counter,*(compressed->string + counter),
                                     *(compressed->string + counter));
         }
     printf("\n");

     /* Try to decompress the first non-question dlabel */
     dlabel = decomp_get_label(compressed,12);
     show_esc_stdout(dlabel);
     printf("\n");
     place = 12 + js_length(dlabel);
     place += 4;
     js_destroy(dlabel);
     dlabel = decomp_get_label(compressed,place);
     show_esc_stdout(dlabel);
     printf("\n");
     js_destroy(dlabel);
     dlabel = decomp_get_label(compressed,place + 5);
     show_esc_stdout(dlabel);
     printf("\n");
     js_destroy(dlabel);

     /* OK, lets see if we can initialize the decompression */
     decomp_init(5);

     /* And lets see if we can decompress a label */
     printf("decomp_decompress_packet result: %d\n",
            decomp_decompress_packet(compressed,uncompressed));
     show_esc_stdout(uncompressed);
     printf("\n");
     /* And lets see if we can decompress a label (legacy) */
     /*printf("legacy_decompress_data result: %d\n",
            legacy_decompress_data(compressed,uncompressed));*/
     show_esc_stdout(uncompressed);
     printf("\n");

     }

