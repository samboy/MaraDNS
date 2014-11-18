/* Copyright (c) 2002 Sam Trenholme
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

#include "../MaraDns.h"
#include "../libs/MaraHash.h"

/* Given a domain-label, change this label in-place so that the first domain
   label is lopped off of it.  Eg. '\003www\007example\003com\000" becomes
   "\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           zero-length already
*/

int bobbit_label(js_string *js) {
    int counter = 0;
    unsigned char length;

    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count >= js->max_count)
        return JS_ERROR;
    if(js->unit_count < 1)
        return JS_ERROR;

    length = *(js->string);

    if(length == '_') /* Special case if star record */
        length = 0;
    else if(length + 1 > js->unit_count || length > 63)
        return JS_ERROR;
    else if(length == 0)
        return 0;

    length++;

    while(counter < js->unit_count - length) {
        *(js->string + counter) = *(js->string + counter + length);
        counter++;
        }

    js->unit_count -= length;

    return JS_SUCCESS;

    }

