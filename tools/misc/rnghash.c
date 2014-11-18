/* Copyright (c) 2002-2006 Sam Trenholme
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

/* This code is based on the aeshash.pdf file, written by Bram Cohen and
   Ben Laurie.  The code currently uses the 128-bit key and block size of
   MaraDNS's hasher, making a 128-bit hash */

/* Note that you need to change the cipher we call to change these
   constants */
#define HASH_BITS 128
#define HASH_BYTES (HASH_BITS / 8)

/* Buffered read */
#define BUF_MAX 4096

#include "../../rng/rng-api-fst.h"
#include <unistd.h>
#include <fcntl.h>

/* Routine that performs buffered reads, since I found out that doing direct
   16-byte reads slows the beegeezes out of I/O.
   Input: pointer of file descripter, pointer to buffer, number of bytes to
          reading
   Output: Number of bytes read
   Warning: Uses static variables.  Do not use this on more than one file
            at a time.  Do not use this if you read clumps of the file which
            are not an even divisor of BUF_MAX
*/
int bread(int desc, char *buf, size_t nbytes) {
    static char bufr[BUF_MAX + 1];
    static int bufr_place = -1;
    static int readed;

    int counter;

    if(bufr_place == -1) {
        readed = read(desc,bufr,BUF_MAX);
        bufr_place = 0;
        }

    if(bufr_place + nbytes < readed) {
        for(counter = 0; counter < nbytes; counter++) {
            *(buf + counter) = bufr[bufr_place];
            bufr_place++;
            }
        }
    else if(bufr_place + nbytes < BUF_MAX) {
        for(counter = 0; counter < nbytes; counter++) {
           if(bufr_place == readed)
               return counter;
           *(buf + counter) = bufr[bufr_place];
           bufr_place++;
           }
        }
    /* XXX: This makes too many assumptions about how we use bread */
    else {
        for(counter = 0; counter < nbytes; counter++) {
            *(buf + counter) = bufr[bufr_place];
            bufr_place++;
            }
        bufr_place = -1;
        }

    return counter;

    }

/* Routine that runs the compression funciton of our hash.
   Input: Plaintext we wish to compress (which is HASH_BYTES long),
          current state of the hash
   Output: The current state of the hash is modified
           1 on success, -1 on fail
*/

int hash_compress(char *input, char *state) {
    MARA_BYTE r_inBlock[HASH_BYTES + 1], r_outBlock[HASH_BYTES + 1],
         r_binKey[HASH_BYTES + 1];
    keyInstance r_keyInst;
    cipherInstance r_cipherInst;
    int counter;

#ifdef DEBUG
    for(counter = 0; counter < HASH_BYTES; counter++) {
        if(input[counter] >= 32 && input[counter] < 128)
            printf("%c",input[counter] & 0xff);
        else
            printf("");
        }
    printf("\n");
#endif /* DEBUG */

    /* Copy over the input of the hash to the key for the cipher */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        r_binKey[counter] = input[counter];
        }

    /* Copy over the state and make it the "plaintext" of the cipher */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        r_inBlock[counter] = state[counter];
        }

    /* Prepare the encryption */
    if(makeKey(&r_keyInst, DIR_ENCRYPT, HASH_BITS, r_binKey) != 1) {
        return -1;
        }

    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1) {
        return -1;
        }

    /* Perform the encryption */
    if(blockEncrypt(&r_cipherInst, &r_keyInst, r_inBlock, HASH_BITS,
                    r_outBlock) != HASH_BITS) {
        return -1;
        }

    /* XOR the ciphertext with the current hash state */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        r_outBlock[counter] ^= state[counter];
        }

    /* Make the modified ciphertext the new state */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        state[counter] = r_outBlock[counter];
        }

    return 1;
    }

/* The main routine.  This reads a file specified on the command line,
   then makes a hash out of that file. */

main(int argc, char **argv) {
    char state[HASH_BYTES + 1], input[HASH_BYTES + 1];

    int readed = 0, desc, counter;

    unsigned int len = 0;

    /* Check the command line argument */
    if(argc != 2) {
        if(argc >= 1) {
            printf("Usage: %s {filename}\n",argv[0]);
            exit(1);
            }
        else {
            printf("Usage: <this program> {filename}\n");
            exit(2);
            }
        }

    /* Initialize the state */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        state[counter] = 0xff;
        }

    /* Open the file */
    if((desc = open(argv[1],O_RDONLY)) < 0) {
        perror("Could not open file");
        exit(3);
        }

    for(;;) {
        readed = bread(desc,input,HASH_BYTES);
        len += readed;
#ifdef DEBUG
        printf("len: %d\n",len);
#endif
        if(readed != HASH_BYTES)
            break;
        hash_compress(input,state);
        }

    /* Pad the final block */
#ifdef ONE_PAD
    if(readed == 0) {
        readed = 1;
        input[0] = 1;
        }
    else if(readed <= (HASH_BYTES / 2) - 1) {
        input[readed] = 1;
        readed++;
        }
    else if(readed < HASH_BYTES) {
        input[readed] = 1;
        readed++;
#else
    if(readed >= HASH_BYTES / 2) {
#endif
        while(readed < HASH_BYTES) {
            input[readed] = 0;
            readed++;
            }
        hash_compress(input,state);
        readed = 0;
        }
    else if(readed == HASH_BYTES) {
        hash_compress(input,state);
#ifdef ONE_PAD
        readed = 1;
        input[0] = 1;
#else
        readed = 0;
#endif
        }

    while(readed < HASH_BYTES - 4) {
        input[readed] = 0;
        readed++;
        }

    /* We count bits, not bytes (as specified in the aeshash pdf document),
       so multiply len times eight */
    len *= 8;

    /* Pad the length to the hash input */
    for(counter = 3; counter >= 0; counter--) {
        input[readed] = (len >> (counter * 8)) & 0xff;
        readed++;
        }
    hash_compress(input,state);
    hash_compress(state,state);

    printf("MaraRNG = ");
    for(counter = 0; counter < HASH_BYTES; counter++) {
        printf("%02x",state[counter] & 0xff);
        }
    printf("\n");

    }

