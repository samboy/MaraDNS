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

/* Routines for handling utf8 data */

#include "../libs/MaraHash.h"

/* Convert an iso 8859-1 string in to a UTF-8 string.
   input: js_string object encoded with iso 8859-1,js_string object
          to encode with UTF-8
   output: JS_SUCCESS on success, JS_ERROR on failure
*/

int iso88591_to_utf8(js_string *i8859, js_string *utf8) {

    int iplace = 0, oplace = 0;
    unsigned char octet;

    /* Sanity checks */
    if(js_has_sanity(i8859) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(utf8) == JS_ERROR)
        return JS_ERROR;
    if(i8859->encoding != JS_8859_1)
        return JS_ERROR;
    if(i8859->unit_size != 1 || utf8->unit_size != 1)
        return JS_ERROR;

    /* Perform the conversion */
    while(iplace < i8859->unit_count) {
        octet = *(i8859->string + iplace);
        if(octet <= 0x7f) {
            if(oplace >= utf8->max_count)
                return JS_ERROR;
            *(utf8->string + oplace) = octet;
            oplace++;
            }
        else { /* Convert it to UTF8 */
            if(oplace + 1 >= utf8->max_count)
                return JS_ERROR;
            *(utf8->string + oplace) = (octet >> 6) | 0xc0;
            *(utf8->string + oplace + 1) = (octet & 0x3f) | 0x80;
            oplace += 2;
            }
        iplace++;
        }

    utf8->unit_count = oplace;
    utf8->encoding = JS_UTF8;
    }

