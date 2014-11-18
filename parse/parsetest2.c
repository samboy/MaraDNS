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


/* This tests the parsing of the KiwiParse routines */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include <stdio.h>

extern int read_mararc();
extern int num2dkeyword();
extern int dvar_raw();
extern int mhash_firstkey();
extern int mhash_nextkey();
extern int num2keyword();
extern int read_kvar();

int main() {
        js_string *line, *v1, *v2, *v3;
        js_file *f;
        int c, error;
        mhash *h;
        js_string *key, *value;

        line = js_create(256,1);
        v1 = js_create(256,1);
        v2 = js_create(256,1);
        v3 = js_create(256,1);
        key = js_create(MAX_ZONE_SIZE,1);
        f = js_alloc(1,sizeof(js_file));

        js_qstr2js(v1,"example_mararc");
        js_set_encode(v1,MARA_LOCALE);
        js_set_encode(v2,MARA_LOCALE);
        js_set_encode(v3,MARA_LOCALE);
        read_mararc(v1,v2,&error);
        if(error != 0) {
            printf("Error in parsing file: ");
            js_show_stdout(v2);
            printf("\n");
            }
        /* Read the dictionaries */
        for(c=0;c<1;c++) {
            num2dkeyword(v1);
            printf("Hash name: ");
            js_show_stdout(v1);
            printf("\n");
            h=(mhash *)dvar_raw(c);
            /* Skip over uninited indices */
            if(h == 0)
                continue;
            if(mhash_firstkey(h,key) == 0)
                continue;
            do {
                printf("Key: ");
                js_show_stdout(key);
                value = mhash_get_js(h,key);
                if(value != 0) {
                    printf(" Value: ");
                    js_show_stdout(value);
                    }
                printf("\n");
                } while(mhash_nextkey(h,key) != 0);
            }
        /* Display the string literals */
        for(c=0;c<1;c++) {
            num2keyword(c,v1);
            read_kvar(v1,v2);
            printf("String name: ");
            js_show_stdout(v1);
            printf(" Value: ");
            js_show_stdout(v2);
            printf("\n");
            }
        return 0;
        }

