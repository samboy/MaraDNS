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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../MaraDns.h"

int harderror(char *msg) {
    printf("Hard error: %s\n",msg);
    exit(1);
    }

main() {

    js_string *indata, *outdata;
    js_file desc;

    /* Initialize the strings */
    if((indata = js_create(1024,1)) == 0)
        harderror("making indata");

    if((outdata = js_create(1024,1)) == 0)
        harderror("making outdata");

    /* Get the contents for the DNS reply to compress */
    js_qstr2js(outdata,"example.uncompressed");
    if(js_open_read(outdata,&desc) == JS_ERROR)
        harderror("Unable to read example.uncompressed file");
    if(js_read(&desc,indata,215) == JS_ERROR)
        harderror("Unable to read example.uncompressed contents");
    js_close(&desc);

    show_esc_stdout(indata);

    /* OK, try to compress the data */

    printf("\n\n%d\n\n",compress_data(indata,outdata));

    show_esc_stdout(outdata);

    printf("\n");

    }

