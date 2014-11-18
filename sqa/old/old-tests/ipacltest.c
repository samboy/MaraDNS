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

#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include <stdio.h>

int harderror(char *msg) {
    printf("Hard error: %s\n",msg);
    exit(1);
    }

main() {
    ipv4pair ips;
    js_string *js;
    int offset;

    if((js = js_create(257,1)) == 0)
        harderror("Could not make js string");
    if(js_set_encode(js,JS_8859_1) == JS_ERROR)
        harderror("Could not change string encoding");

    if(js_qstr2js(js,"192.68.69.70/255.255.255.0") == JS_ERROR)
        harderror("js_qstr2js");
    offset = 0;
    do {
        js_show_stdout(js);
        offset = ddip_ip_mask(js,&ips,offset);
        printf("\n%d\n",offset);
        printf("%x %x\n",ips.ip,ips.mask);
        } while(offset > 0);

    if(js_qstr2js(js,"192.68.69.70/24") == JS_ERROR)
        harderror("js_qstr2js");
    offset = 0;
    do {
        js_show_stdout(js);
        offset = ddip_ip_mask(js,&ips,offset);
        printf("\n%d\n",offset);
        printf("%x %x\n",ips.ip,ips.mask);
        } while(offset > 0);

    if(js_qstr2js(js,"192.68.69.70/24,10.1.2.3/12") == JS_ERROR)
        harderror("js_qstr2js");
    offset = 0;
    do {
        js_show_stdout(js);
        offset = ddip_ip_mask(js,&ips,offset);
        printf("\n%d\n",offset);
        printf("%x %x\n",ips.ip,ips.mask);
        } while(offset > 0);

    }

