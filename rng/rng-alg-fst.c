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
 *
 * Note that this copyrighted code is based on public domain code
 */

/**
 * rng-alg-fst.c
 *
 * @version 3.0 (December 2000)
 *
 * Note: This is a Rijndael variant.
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * The original code was hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "rng-alg-fst.h"
#include "rng-32bit-tables.h"

static const u32 rcon[] = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1B000000, 0x36000000, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

/* The scramble chart and the scrambled tables; this is my code that
 * makes this AES variant only vulnerable to cache sniffing attacks
 * during key setup */

unsigned char Sc[256];
u32 STe0[256];
u32 STe1[256];
u32 STe2[256];
u32 STe3[256];
u32 STe4[256];

#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)

#ifdef _MSC_VER
#define GETU32(p) SWAP(*((u32 *)(p)))
#define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
#else
#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
#endif

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return      the number of rounds for the given cipher key size.
 */
/* This code may be vulnerable to cache sniffing attacks */
int rngKeySetupEnc(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits) {
        int i = 0;
        unsigned char rbytes[512];
        unsigned char u8_swap;
        u32 u32_swap;
        u32 temp;
        u32 *rks;

        rks = rk;

        rk[0] = GETU32(cipherKey     );
        rk[1] = GETU32(cipherKey +  4);
        rk[2] = GETU32(cipherKey +  8);
        rk[3] = GETU32(cipherKey + 12);
        if (keyBits == 128) {
                for (;;) {
                        temp  = rk[3];
                        rk[4] = rk[0] ^
                                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                                rcon[i];
                        rk[5] = rk[1] ^ rk[4];
                        rk[6] = rk[2] ^ rk[5];
                        rk[7] = rk[3] ^ rk[6];
                        if (++i == 10) {
                                break;
                        }
                        rk += 4;
                }
        }
        else {
                printf("Fatal error during rng setup\n");
                exit(1);
        }
        /* Now that the key is set up, set up the scramble tables */
        for(i = 0; i < 256; i++) {
                Sc[i] = i;
                STe0[i] = Te0[i];
                STe1[i] = Te1[i];
                STe2[i] = Te2[i];
                STe3[i] = Te3[i];
                STe4[i] = Te4[i];
        }
        /* Scramble the Sc and corresponding STe tables */
        /* Create a table where each set of 16 bytes is different */
        for(i = 0; i < 512 ; i++) {
                rbytes[i] = (i * 7) % 256;
                if(i > 255) { rbytes[i] ^= 0xff; }
        }

        /* Now, we can make that table a random table by using that table
           as plaintext */
        for(i = 0; i< 512 ; i+=16) {
                int q;
                rngEncrypt(rks,10,rbytes + i,rbytes + i);
                for(q = 0; q < 16; q++) {
                        unsigned char z,x,y;
                        z = rbytes[i + q];

                        /* Swap the two; no we're not doing hacks like
                           a = a + b; b = a - b; a = a - b; */

                        u8_swap = Sc[z];
                        Sc[z] = Sc[1];
                        Sc[1] = u8_swap;

                        /* Prepare for the corresponding encrypt table swap */
                        x = Sc[z];
                        y = Sc[1];

                        /* Do the corresponding swap for the encrypt tables */
                        u32_swap = STe0[x];
                        STe0[x] = STe0[y];
                        STe0[y] = u32_swap;

                        u32_swap = STe1[x];
                        STe1[x] = STe1[y];
                        STe1[y] = u32_swap;

                        u32_swap = STe2[x];
                        STe2[x] = STe2[y];
                        STe2[y] = u32_swap;

                        u32_swap = STe3[x];
                        STe3[x] = STe3[y];
                        STe3[y] = u32_swap;

                        u32_swap = STe4[x];
                        STe4[x] = STe4[y];
                        STe4[y] = u32_swap;
                }

        }

        return 10;
}

void rngEncrypt(const u32 rk[/*4*(Nr + 1)*/], int Nr, const u8 pt[16], u8 ct[16]) {
        u32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

        /*
         * map byte array block to cipher state
         * and add initial round key:
         */
        s0 = GETU32(pt     ) ^ rk[0];
        s1 = GETU32(pt +  4) ^ rk[1];
        s2 = GETU32(pt +  8) ^ rk[2];
        s3 = GETU32(pt + 12) ^ rk[3];

        /* Deliberately make some reads from the Sc table to minimize the
         * cache of key data being visible by cache probing.  Hopefully,
         * the compiler won't optimize these operations away. */
        t0 = Sc[0];
        t1 = Sc[32];
        t2 = Sc[64];
        t3 = Sc[96];
        t0 = Sc[128];
        t1 = Sc[160];
        t2 = Sc[192];
        t3 = Sc[224];

        /*
         * Nr - 1 full rounds:
         */
    r = Nr >> 1;
    for (;;) {
        t0 =
            STe0[Sc[(s0 >> 24)       ]] ^
            STe1[Sc[(s1 >> 16) & 0xff]] ^
            STe2[Sc[(s2 >>  8) & 0xff]] ^
            STe3[Sc[(s3      ) & 0xff]] ^
            rk[4];
        t1 =
            STe0[Sc[(s1 >> 24)       ]] ^
            STe1[Sc[(s2 >> 16) & 0xff]] ^
            STe2[Sc[(s3 >>  8) & 0xff]] ^
            STe3[Sc[(s0      ) & 0xff]] ^
            rk[5];
        t2 =
            STe0[Sc[(s2 >> 24)       ]] ^
            STe1[Sc[(s3 >> 16) & 0xff]] ^
            STe2[Sc[(s0 >>  8) & 0xff]] ^
            STe3[Sc[(s1      ) & 0xff]] ^
            rk[6];
        t3 =
            STe0[Sc[(s3 >> 24)       ]] ^
            STe1[Sc[(s0 >> 16) & 0xff]] ^
            STe2[Sc[(s1 >>  8) & 0xff]] ^
            STe3[Sc[(s2      ) & 0xff]] ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
            STe0[Sc[(t0 >> 24)       ]] ^
            STe1[Sc[(t1 >> 16) & 0xff]] ^
            STe2[Sc[(t2 >>  8) & 0xff]] ^
            STe3[Sc[(t3      ) & 0xff]] ^
            rk[0];
        s1 =
            STe0[Sc[(t1 >> 24)       ]] ^
            STe1[Sc[(t2 >> 16) & 0xff]] ^
            STe2[Sc[(t3 >>  8) & 0xff]] ^
            STe3[Sc[(t0      ) & 0xff]] ^
            rk[1];
        s2 =
            STe0[Sc[(t2 >> 24)       ]] ^
            STe1[Sc[(t3 >> 16) & 0xff]] ^
            STe2[Sc[(t0 >>  8) & 0xff]] ^
            STe3[Sc[(t1      ) & 0xff]] ^
            rk[2];
        s3 =
            STe0[Sc[(t3 >> 24)       ]] ^
            STe1[Sc[(t0 >> 16) & 0xff]] ^
            STe2[Sc[(t1 >>  8) & 0xff]] ^
            STe3[Sc[(t2      ) & 0xff]] ^
            rk[3];
    }
        /*
         * apply last round and
         * map cipher state to byte array block:
         */
        s0 =
                (STe4[Sc[(t0 >> 24)       ]] & 0xff000000) ^
                (STe4[Sc[(t1 >> 16) & 0xff]] & 0x00ff0000) ^
                (STe4[Sc[(t2 >>  8) & 0xff]] & 0x0000ff00) ^
                (STe4[Sc[(t3      ) & 0xff]] & 0x000000ff) ^
                rk[0];
        PUTU32(ct     , s0);
        s1 =
                (STe4[Sc[(t1 >> 24)       ]] & 0xff000000) ^
                (STe4[Sc[(t2 >> 16) & 0xff]] & 0x00ff0000) ^
                (STe4[Sc[(t3 >>  8) & 0xff]] & 0x0000ff00) ^
                (STe4[Sc[(t0      ) & 0xff]] & 0x000000ff) ^
                rk[1];
        PUTU32(ct +  4, s1);
        s2 =
                (STe4[Sc[(t2 >> 24)       ]] & 0xff000000) ^
                (STe4[Sc[(t3 >> 16) & 0xff]] & 0x00ff0000) ^
                (STe4[Sc[(t0 >>  8) & 0xff]] & 0x0000ff00) ^
                (STe4[Sc[(t1      ) & 0xff]] & 0x000000ff) ^
                rk[2];
        PUTU32(ct +  8, s2);
        s3 =
                (STe4[Sc[(t3 >> 24)       ]] & 0xff000000) ^
                (STe4[Sc[(t0 >> 16) & 0xff]] & 0x00ff0000) ^
                (STe4[Sc[(t1 >>  8) & 0xff]] & 0x0000ff00) ^
                (STe4[Sc[(t2      ) & 0xff]] & 0x000000ff) ^
                rk[3];
        PUTU32(ct + 12, s3);
}

