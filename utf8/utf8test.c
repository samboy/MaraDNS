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
/* Test the ability to convert iso 8859-1 to UTF-8 */

#include "../libs/MaraHash.h"
#include <stdio.h>

int main() {
    js_string *s1,*s2,*s3,*get;
    js_file *f1;
    char strn[256];
    int counter,place,number;

    s1=js_create(256,1);
    s2=js_create(256,1);
    s2=js_create(256,1);

    /* Test reading a file line by line */
    js_qstr2js(s1,"8859-1data");
    f1 = js_alloc(1,sizeof(js_file));
    js_open_read(s1,f1);
    js_set_encode(s1,JS_8859_1); /* Mandatory for line-by-line reading */
    while(!js_buf_eof(f1)) {
        printf("%s","Reading a line from file:\n");
        js_buf_getline(f1,s1);
        iso88591_to_utf8(s1,s2);
        js_show_stdout(s1);
        js_show_stdout(s2);
        }

    }
