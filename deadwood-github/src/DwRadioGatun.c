/* Copyright (c) 2007-2012 Sam Trenholme
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

/* This is a tiny implementation of the Radio Gatun hash function/
 * stream cipher */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "DwStr.h"
#include "DwStr_functions.h"
#include "DwRadioGatun.h"

/* This is the mill part of the RadioGatun algorithm */
void dwr_beltmill(DWR_WORD *a, DWR_WORD *b) {
        DWR_WORD q[DWR_BELTROWS];
        DWR_WORD A[DWR_MILLSIZE];
        DWR_WORD x;
        int s = 0;
        int i = 0;
        int v = 0;
        int y = 0;
        int r = 0;
        int z = 0;
        for(s = 0; s < DWR_BELTROWS ; s++) {
                q[s] = b[((s * DWR_BELTCOL) + DWR_BELTCOL - 1)];
                for(i = DWR_BELTCOL - 1; i > 0; i--) {
                        v = i - 1;
                        if(v < 0) {
                                v = DWR_BELTCOL - 1;
                        }
                        b[((s * DWR_BELTCOL) + i)] =
                                b[((s * DWR_BELTCOL) + v)];
                }
                b[(s * DWR_BELTCOL)] = q[s];
        }
        for(i = 0; i < DWR_BELTFEED ; i++) {
                s = (i + 1) + ((i % DWR_BELTROWS) * DWR_BELTCOL);
                b[s] ^= a[(i + 1)];
        }
        for(i = 0; i < DWR_MILLSIZE ; i++) {
                y = (i * 7) % DWR_MILLSIZE;
                r = ((i * (i + 1)) / 2) % DWR_WORDSIZE;
                x = a[y] ^ (a[ ((y + 1) % DWR_MILLSIZE) ] |
                    (~a[ ((y + 2) % DWR_MILLSIZE) ]));
                A[i] = (x >> r) | (x << (DWR_WORDSIZE - r));
        }
        for(i = 0; i < DWR_MILLSIZE ; i++) {
                y = i;
                r = (i + 1) % DWR_MILLSIZE;
                z = (i + 4) % DWR_MILLSIZE;
                a[i] = A[y] ^ A[r] ^ A[z];
        }
        a[0] ^= 1;
        for(i = 0; i < DWR_BELTROWS; i++) {
                a[(i + DWR_BELTCOL)] ^= q[i];
        }
}

/* Destroy an already created RadioGatun state */
void dwr_zap(dwr_rg *tozap) {
        if(tozap != 0) {
                if(tozap->mill != 0) {
                        free(tozap->mill);
                }
                if(tozap->belt != 0) {
                        free(tozap->belt);
                }
                free(tozap);
        }
        return;
}

/* Create a new blank RadioGatun state (this is private and only called
 * from dwr_init_rg() ) */
dwr_rg *dwr_new() {
        int q = 0;
        dwr_rg *new = 0;
        DWR_WORD *a = 0, *b = 0;

        new = dw_malloc(sizeof(dwr_rg));
        if(new == 0) {
                goto catch_dwr_new;
        }
        new->mill = dw_malloc((DWR_MILLSIZE + 1) * sizeof(DWR_WORD));
        new->belt = dw_malloc(((DWR_BELTROWS * DWR_BELTCOL) + 1) *
                           sizeof(DWR_WORD));
        new->index = 0;
        a = new->mill;
        b = new->belt;
        if(a == 0 || b == 0) {
                goto catch_dwr_new;
        }
        for(q = 0; q < DWR_MILLSIZE; q++) {
                a[q] = 0;
        }
        for(q = 0; q < DWR_BELTROWS * DWR_BELTCOL; q++) {
                b[q] = 0;
        }
        return new;
catch_dwr_new:
        dwr_zap(new);
        return 0;
}

#define dwr_input_map()         for(c = 0; c < 3; c++) { \
                                        b[c * 13] ^= p[c]; \
                                        a[16 + c] ^= p[c]; \
                                } \
                                dwr_beltmill(a,b)

/* Create a Radio Gatun state, using the contents of a dw_str object
 * as the key */
dwr_rg *dwr_init_rg(dw_str *obj) {
        DWR_WORD p[3];
        int q = 0;
        int c = 0;
        int r = 0;
        int done = 0;
        dwr_rg *new = 0;
        DWR_WORD *a = 0, *b = 0;
        int index = 0;
        int32_t counter = 0;

        if(dw_assert_sanity(obj) == -1) {
                return 0;
        }
        new = dwr_new();
        if(new == 0) {
                return 0;
        }
        a = new->mill;
        b = new->belt;
        for(counter = 0; counter < 16777218; counter++) {
                p[0] = p[1] = p[2] = 0;
                for(r = 0; r < 3; r++) {
                        for(q = 0; q < DWR_WORDSIZE; q+=8) {
                                int x = 0;
                                x = (int)*(obj->str + index);
                                index++;
                                x &= 0xff;
                                if(index > obj->len) {
                                        done = 1;
                                        x = 1; /* Append with single byte
                                                * w/ value of 1 */
                                }
                                p[r] |= x << q;
                                if(done == 1) {
                                        dwr_input_map();
                                        for(c = 0; c < 16; c++) {
                                                dwr_beltmill(a,b);
                                        }
                                        return new;
                                }
                        }
                }
                dwr_input_map();
        }
        return 0;
}

/* Given a RadioGatun state, generate a 16-bit psuedo-random number.
 * Note that this only works if DWR_WORD is a 32-bit integer,
 * and DWR_WORDSIZE is 32. */
uint16_t dwr_rng(dwr_rg *in) {
        DWR_WORD *o;
        if(in == 0) {
                return 0;
        }
        if(DWR_WORDSIZE != 32) {
                return 0;
        }
        o = in->mill + 1;
        if(in->index >= 100000000) {
                in->index = 0; /* I am considering rekeying here */
        }
        if(in->index % 4 == 0) {
                dwr_beltmill(in->mill, in->belt);
                in->index++;
                return ((o[0] & 0xff) << 8) | ((o[0] & 0xff00) >> 8);
        } else {
                in->index++;
                switch(in->index % 4) {
                        case 2:
                                return ((o[0] & 0xff0000) >> 8) |
                                        ((o[0] & 0xff000000) >> 24);
                        case 3:
                                return ((o[1] & 0xff) << 8) |
                                        ((o[1] & 0xff00) >> 8);
                        case 0:
                                return ((o[1] & 0xff0000) >> 8) |
                                        ((o[1] & 0xff000000) >> 24);
                }
        }
        return 0;
}

#ifdef HAVE_MAIN

main(int argc, char **argv) {
        dw_str *q = 0;
        dwr_rg *r = 0;
        int c = 0;
        if(argc != 2) {
                printf("Usage: rg32 {input to hash}\n");
                exit(1);
        }
        q = dw_create(2048);
        dw_qrappend(argv[1],q,0);
        r = dwr_init_rg(q);
        for(c = 0; c < 20; c++) {
                printf("%04x ",dwr_rng(r));
        }
        printf("\n");
        dw_destroy(q);
        dwr_zap(r);
}

#endif /* HAVE_MAIN */

