/* Copyright (c) 2002-2005 Sam Trenholme
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
#include "../parse/functions_parse.h"
#ifndef MINGW32
#include <netinet/in.h>
#else
#include <winsock.h>
#include <wininet.h>
#endif
#include "functions_server.h"
#include "timestamp.h"
#include <stdio.h>
#include <stdlib.h>
#define L_KVAR_Q "Could not create kvar_query"

/* Routine which reads a numeric kvar from the database of values set
   in the mararc file (this can not be used for dictionary variables).

   Input: A null-terminated string with the desired variable name,
          the default value for the kvar in question (if not set)

   Output: The numeric value in question (always positive or zero)
           -1 (JS_ERROR) if a fatal error happened

 */

int read_numeric_kvar(char *name,int default_value) {
    js_string *kvar_name;
    js_string *kvar_value;
    int ret,status;

    if((kvar_name = js_create(64,1)) == 0) {
        printf("Aieeeeeee!\n");
        exit(1);
        return JS_ERROR;
        }

    if((kvar_value = js_create(256,1)) == 0) {
        printf("Aieeeeeeee!\n");
        exit(1);
        js_destroy(kvar_name);
        return JS_ERROR;
        }

    js_set_encode(kvar_name,MARA_LOCALE);
    js_set_encode(kvar_value,MARA_LOCALE);

    if(js_qstr2js(kvar_name,name) == JS_ERROR) {
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        }

    status = read_kvar(kvar_name,kvar_value);

    if(status == JS_ERROR) { /* Fatal error parsing it */
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        show_timestamp();
        printf("%s%s\n","Error processing value for ",name);
        return default_value;
        }

    if(status == 0) { /* Variable not set in mararc */
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        return default_value;
        }

    ret = js_atoi(kvar_value,0);

    js_destroy(kvar_name);
    js_destroy(kvar_value);
    return ret;

    }

/* Routine which reads a string kvar from the database of values set
   in the mararc file (this can not be used for dictionary variables).

   Input: A null-terminated string with the desired variable name,

   Output: A pointer to the string with the value in question.  This
           string will be blank if the kvar is not set; 0 (NULL) if
           there was an error

 */

js_string *read_string_kvar(char *name) {
    js_string *kvar_name;
    js_string *kvar_value;
    int status;

    if((kvar_name = js_create(64,1)) == 0) {
        printf("Aiiieeeeeee!\n");
        exit(1);
        return 0;
        }

    if((kvar_value = js_create(256,1)) == 0) {
        printf("Aiiieeeeeeeeee!\n");
        exit(1);
        js_destroy(kvar_name);
        return 0;
        }

    js_set_encode(kvar_name,MARA_LOCALE);
    js_set_encode(kvar_value,MARA_LOCALE);

    if(js_qstr2js(kvar_name,name) == JS_ERROR) {
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        harderror(L_KVAR_Q); /* "Could not create kvar_query" */
        }

    status = read_kvar(kvar_name,kvar_value);

    if(status == JS_ERROR) { /* Fatal error parsing it */
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        show_timestamp();
        printf("%s%s\n","Error processing value for ",name);
        return 0;
        }

    if(status == 0) { /* Variable not set in mararc */
        js_destroy(kvar_name);
        js_destroy(kvar_value);
        return 0;
        }

    js_destroy(kvar_name);
    return kvar_value;

    }

