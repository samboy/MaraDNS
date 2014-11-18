/* Copyright (c) 2007 Sam Trenholme
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

#include "DwStr.h"
#include "DwStr_functions.h"
#include <stdio.h>

/* This actually isn't a public function; we just have it declared here
 * so we can compile w/o warnings when -Wall is used */
uint32_t dwh_hash_compress(dw_str *obj);

int main() {
        dw_str *test = 0, *c1 = 0, *c2 = 0, *c3 = 0;
        int a = 0;
        test = dw_create(256);
        if(test == 0) {
                printf("String creation failed.\n");
                goto catch_main;
        }
        /* Add some strings to the function */
        if(dw_qspush((uint8_t *)"Life",test) == -1) {
                printf("Appending failed.\n");
                goto catch_main;
        }
        dw_stdout(test);

        if(dw_qspush((uint8_t *)"liberty",test) == -1) {
                printf("Appending failed.\n");
                goto catch_main;
        }
        dw_stdout(test);

        if(dw_qspush((uint8_t *)"happiness",test) == -1) {
                printf("Appending failed.\n");
                goto catch_main;
        }
        dw_stdout(test);

        /* Test dw_fetch_u16 */
        printf("16-bit value at offsets 0 2 4 7: ");
        printf("%d ",(unsigned int)dw_fetch_u16(test,0));
        printf("%d ",(unsigned int)dw_fetch_u16(test,2));
        printf("%d ",(unsigned int)dw_fetch_u16(test,4));
        printf("%d\n",(unsigned int)dw_fetch_u16(test,7));

        /* Test dw_copy and dw_substr */
        printf("TEST: dw_copy and dw_substr\n");
        c1 = dw_copy(test);
        c2 = dw_substr(test,-9,-1,0);
        c3 = dw_substr(test,5,7,0);
        dw_stdout(c1);
        dw_stdout(c2);
        dw_stdout(c3);

        printf("\n");
        printf("c1 hash: %x\n",(unsigned int)dwh_hash_compress(c1));
        printf("c2 hash: %x\n",(unsigned int)dwh_hash_compress(c2));
        printf("c3 hash: %x\n",(unsigned int)dwh_hash_compress(c3));
        printf("\n");

        /* Test dw_qspop */
        printf("TEST: dw_qspop\n");
        dw_destroy(c1);
        c1 = 0;
        c1 = dw_qspop(test);
        dw_stdout(c1);
        dw_destroy(c1);
        c1 = 0;
        c1 = dw_qspop(test);
        dw_stdout(c1);
        dw_destroy(c1);
        c1 = 0;
        c1 = dw_qspop(test);
        dw_stdout(c1);
        dw_destroy(c1);
        c1 = 0;

        /* Test dw_zap_lws */
        c1 = dw_create(256);
        dw_qrappend((uint8_t *)" \t  test",c1,0);
        dw_stdout(c1);
        dw_destroy(c2);
        c2 = 0;
        c2 = dw_zap_lws(c1);
        dw_stdout(c2);
        dw_destroy(c2);
        c2 = 0;

        c1 = dw_create(5);
        printf("blank hash: %x\n",(unsigned int)dwh_hash_compress(c1));
        c1->len = 1; /* Don't do this in production code! */
        for(a = 0; a<16;a++) {
                *(c1->str) = a; /* Again, not in production code! */
                printf("hash of %d: %x\n",a,(unsigned int)dwh_hash_compress(c1));
        }

        /* Coding style requires that we always have the following part
         * at the end of any function that allocates strings */

catch_main:
        if(test != 0) {
                dw_destroy(test);
        }
        if(c1 != 0) {
                dw_destroy(c1);
        }
        if(c2 != 0) {
                dw_destroy(c2);
        }
        if(c3 != 0) {
                dw_destroy(c3);
        }
        return 0;
}
