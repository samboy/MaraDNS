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

/* This verifies that we are, in fact, properly hashing at a key and
   block size of 128 bits for the RNG MaraDNS uses.

   This program needs to output the same contents as the rngtest.out file

*/

#include "../rng/rng-api-fst.h"
#include <unistd.h>
#include <fcntl.h>

#define BLOCK_BYTES 16
#define KEY_BYTES 16
#define KEY_BITS 128

/* Routine that tests to make sure we are, in fact, running a true
   AES
   input: ASCII representation of the key and the input
   output: -1 on failure, 1 on success
*/

int test_rng(char *key, char *input) {
    BYTE r_inBlock[BLOCK_BYTES + 1], r_outBlock[BLOCK_BYTES + 1],
         r_binKey[KEY_BYTES + 1];
    keyInstance r_keyInst;
    cipherInstance r_cipherInst;
    int counter;
    char left, right, nibble, byt;

    /* Convert the key from an ASCII key to a binary key */
    for(counter = 0; counter < KEY_BYTES; counter++) {

        /* Get the left nibble of this byte */
        left = *key;
        /* Convert to lower case if needed */
        if(left >= 'A' && left <= 'Z')
            left += 32;
        /* Make sure the left nibble is in bounds */
        if(left < '0' || (left > '9' && left < 'a') || left > 'f')
            return -1;

        /* Now, do the same for the right nibble */
        key++;
        right = *key;
        if(right >= 'A' && right <= 'Z')
            right += 32;
        if(right < '0' || (right > '9' && right < 'a') || right > 'f')
            return -1;
        key++;

        /* Take the two nibbles, and make a byte out of them */
        if(left <= '9')
            nibble = left - '0';
        else
            nibble = left + 10 - 'a';
        nibble <<= 4;
        if(right <= '9')
            byt = right - '0';
        else
            byt = right + 10 - 'a';
        byt |= nibble;

        /* Make that the key byte */
        r_binKey[counter] = byt;
        }

    /* Convert the input from ASCII input to binary input */
    for(counter = 0; counter < BLOCK_BYTES; counter++) {
        /* This is the same as above */

        /* Left nibble... */
        left = *input;
        if(left >= 'A' && left <= 'Z')
            left += 32;
        if(left < '0' || (left > '9' && left < 'a') || left > 'f')
            return -1;

        /* Right nibble... */
        input++;
        right = *input;
        if(right >= 'A' && right <= 'Z')
            right += 32;
        if(right < '0' || (right > '9' && right < 'a') || right > 'f')
            return -1;
        input++;

        /* And make the nibbles a byte */
        if(left <= '9')
            nibble = left - '0';
        else
            nibble = left + 10 - 'a';
        nibble <<= 4;
        if(right <= '9')
            byt = right - '0';
        else
            byt = right + 10 - 'a';
        byt |= nibble;

        r_inBlock[counter] = byt;
        }

    /* Show them the key and input */
    printf("   key     = ");
    for(counter = 0; counter < KEY_BYTES; counter++)
        printf("%02x",r_binKey[counter] & 0xff);
    printf("\n");
    printf("   input   = ");
    for(counter = 0; counter < KEY_BYTES; counter++)
        printf("%02x",r_inBlock[counter] & 0xff);
    printf("\n");

    /* Prepare the encryption */
    if(makeKey(&r_keyInst, DIR_ENCRYPT, KEY_BITS, r_binKey) != 1) {
        return -1;
        }
    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1) {
        return -1;
        }

    /* Perform the encryption */
    if(blockEncrypt(&r_cipherInst, &r_keyInst, r_inBlock, KEY_BITS,
                    r_outBlock) != KEY_BITS) {
        return -1;
        }

    /* Show them the ciphertext */
    printf("   enc     = ");
    for(counter = 0; counter < KEY_BYTES; counter++)
        printf("%02x",r_outBlock[counter] & 0xff);
    printf("\n\n");

    return 1;
    }

main() {
    test_rng("2b7e151628aed2a6abf7158809cf4f3c",
             "3243f6a8885a308d313198a2e0370734");
    test_rng("00000000000000000000000000000000",
             "00000000000000000000000000000000");
    test_rng("ffffffffffffffffffffffffffffffff",
             "00000000000000000000000000000000");
    test_rng("ffffffffffffffffffffffffffffffff",
             "ffffffffffffffffffffffffffffffff");
    test_rng("000102030405060708090a0b0c0d0e0f",
             "000102030405060708090a0b0c0d0e0f");
    test_rng("00ffeeddccbbaa998877665544332211",
             "112233445566778899aabbccddeeff00");
    test_rng("ffeeddccbbaa99887766554433221100",
             "00112233445566778899aabbccddeeff");
    test_rng("00000000000000000000000000000000",
             "ffffffffffffffffffffffffffffffff");
    test_rng("00000000000000000000000000000000",
             "fffffffffffffffffffffffffffffffe");
    test_rng("00000000000000000000000000000000",
             "00000000000000000000000000000001");
    test_rng("00000000000000000000000000000000",
             "000000000000000000000000ffffffff");
    test_rng("000102030405060708090a0b0c0d0e0f",
             "00000000000000000000000000000000");
    test_rng("000102030405060708090a0b0c0d0e0f",
             "ffffffffffffffffffffffffffffffff");
    test_rng("ffffffffffffffffffffffffffffffff",
             "0102030405060708090a0b0c0d0e0f10");
    }

