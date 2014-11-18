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


/* This tests the parsing of the ParseMaraRc routines */

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include <stdio.h>

extern int parseline(js_string *line, js_string *var, js_string *key,
                js_string *value, int *do_plus);

int main() {
        js_string *line, *v1, *v2, *v3;
        js_file *f;

        line = js_create(256,1);
        v1 = js_create(256,1);
        v2 = js_create(256,1);
        v3 = js_create(256,1);
        f = js_alloc(1,sizeof(js_file));

        js_qstr2js(v1,"example_mararc");
        js_set_encode(v1,MARA_LOCALE);
        js_set_encode(v2,MARA_LOCALE);
        js_set_encode(line,MARA_LOCALE);
        js_open_read(v1,f);
        while(!js_buf_eof(f)) {
                js_buf_getline(f,line);
                printf("\nLine: ");
                js_show_stdout(line);
                printf("%s%d%s","Parse value: ",parseline(line,v1,v2,v3,0),
                                "\n");
                printf("Variable: ");
                js_show_stdout(v1);
                printf("\nKey: ");
                js_show_stdout(v2);
                printf("\nValue: ");
                js_show_stdout(v3);
                printf("\n");
                }
        return 0;
        }

