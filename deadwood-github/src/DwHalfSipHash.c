/* Copyright (c) 2022 Sam Trenholme
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

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

uint32_t HalfSip13(uint8_t *str, int32_t l,
                   uint32_t sipKey1, uint32_t sipKey2) {
        if(str == NULL) {
                return 0;
        }
        size_t offset = 0;
        uint32_t v0, v1, v2, v3, m;
        int shift = 0, round = 0;

        v0 = sipKey1;
        v1 = sipKey2;
        v2 = v0 ^ 0x6c796765;
        v3 = v1 ^ 0x74656462;
        m = 0;
        while(offset <= l) {
                if(offset < l) {
                        m |= (uint32_t)(str[offset] & 0xff) << shift;
                        shift += 8;
                }
                while(shift >= 32 || offset == l) { // "while" to avoid goto
                        if(offset == l && shift != 32) {
                                m |= (uint32_t)(l & 0xff) << 24;
                                offset++;
                        }
                        shift = 0;
                        v3 ^= m;

                        v0 += v1;
                        v1 = (v1 << 5) | (v1 >> 27);
                        v1 ^= v0;
                        v0 = (v0 << 16) | (v0 >> 16);
                        v2 += v3;
                        v3 = (v3 << 8) | (v3 >> 24);
                        v3 ^= v2; v0 += v3;
                        v3 = (v3 << 7) | (v3 >> 25);
                        v3 ^= v0; v2 += v1;
                        v1 = (v1 << 13) | (v1 >> 19);
                        v1 ^= v2;
                        v2 = (v2 << 16) | (v2 >> 16);

                        v0 ^= m;
                        shift = 0;
                        m = 0;
                }
                offset++;
        }
        v2 ^= 255;
        for(round = 0; round < 3; round++) {
                v0 += v1;
                v1 = (v1 << 5) | (v1 >> 27);
                v1 ^= v0;
                v0 = (v0 << 16) | (v0 >> 16);
                v2 += v3;
                v3 = (v3 << 8) | (v3 >> 24);
                v3 ^= v2; v0 += v3;
                v3 = (v3 << 7) | (v3 >> 25);
                v3 ^= v0; v2 += v1;
                v1 = (v1 << 13) | (v1 >> 19);
                v1 ^= v2;
                v2 = (v2 << 16) | (v2 >> 16);
        }
        return v1 ^ v3;
}

#ifdef RUNTESTS
#include <stdlib.h>
int main() {
        uint8_t test1[66];
        int counter;
        printf("Test #1: Reference vectors\n");
        printf("See https://github.com/samboy/HalfSipTest for ref code\n");
        for(counter = 0; counter < 64; counter++) {
                test1[counter] = counter;
                printf("%08x\n",
                       HalfSip13(test1,counter,0x03020100, 0x07060504));
        }
        printf("Test #2: Inverted reference vectors\n");
        for(counter = 0; counter < 64; counter++) {
                test1[counter] = counter ^ 0xff;
                printf("%08x\n",
                         HalfSip13(test1,counter,0xfcfdfeff, 0xf8f9fafb));
        }
}
#endif // RUNTESTS
