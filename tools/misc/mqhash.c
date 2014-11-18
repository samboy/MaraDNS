/* Copyright (c) 2002-2012 Sam Trenholme
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

#include "../../rng/rng-api-fst.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

/* The Radio Gatun 32-bit core */
/* This determines the word size we use for this particular Radio Gatun
 * implementation; DWR_WORDSIZE needs to be a multiple of 8.  Note also
 * that dwr_rng() needs to be rewritten if these values are changed. */
#define DWR_WORD uint32_t
#define DWR_WORDSIZE 32

/* These are hard coded in the Radio Gatun specification */
#define DWR_MILLSIZE 19
#define DWR_BELTROWS 3
#define DWR_BELTCOL 13
#define DWR_BELTFEED 12

/* A structure contining a RadioGatun state */
typedef struct {
        DWR_WORD *mill;
        DWR_WORD *belt;
        int32_t index;
} dwr_rg;
/* This is the mill part of the RadioGatun algorithm */
void dwr_mill(DWR_WORD *a) {
        DWR_WORD A[DWR_MILLSIZE];
        DWR_WORD x;
        int i = 0;
        int y = 0;
        int r = 0;
        int z = 0;
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
}

/* This is the belt part of the RadioGatun algorithm */
void dwr_belt(DWR_WORD *a, DWR_WORD *b) {
        DWR_WORD q[DWR_BELTROWS];
        int s = 0;
        int i = 0;
        int v = 0;
        for(s = 0; s < DWR_BELTROWS ; s++) {
                q[s] = b[((s * DWR_BELTCOL) + DWR_BELTCOL - 1)];
        }
        for(i = DWR_BELTCOL - 1; i > 0; i--) {
                for(s = 0; s < DWR_BELTROWS ; s++) {
                        v = i - 1;
                        if(v < 0) {
                                v = DWR_BELTCOL - 1;
                        }
                        b[((s * DWR_BELTCOL) + i)] =
                                b[((s * DWR_BELTCOL) + v)];
                }
        }
        for(s = 0; s < DWR_BELTROWS; s++) {
                b[(s * DWR_BELTCOL)] = q[s];
        }
        for(i = 0; i < DWR_BELTFEED ; i++) {
                s = (i + 1) + ((i % DWR_BELTROWS) * DWR_BELTCOL);
                b[s] ^= a[(i + 1)];
        }
        dwr_mill(a);
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

        new = malloc(sizeof(dwr_rg));
        if(new == 0) {
                goto catch_dwr_new;
        }
        new->mill = malloc((DWR_MILLSIZE + 1) * sizeof(DWR_WORD));
        new->belt = malloc(((DWR_BELTROWS * DWR_BELTCOL) + 1) *
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
                                dwr_belt(a,b)

/* Create a Radio Gatun state, using the contents of a null-terminated string
 * as the input */
dwr_rg *dwr_init_rg(char *obj) {
        DWR_WORD p[3];
        int q = 0;
        int c = 0;
        int r = 0;
        int done = 0;
        dwr_rg *new = 0;
        DWR_WORD *a = 0, *b = 0;
        int index = 0;
        int32_t counter = 0;

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
                                x = (int)*(obj + index);
                                index++;
                                x &= 0xff;
                                if(x == 0) {
                                        done = 1;
                                        x = 1; /* Append with single byte
                                                * w/ value of 1 */
                                }
                                p[r] |= x << q;
                                if(done == 1) {
                                        dwr_input_map();
                                        for(c = 0; c < 16; c++) {
                                                dwr_belt(a,b);
                                        }
                                        return new;
                                }
                        }
                }
                dwr_input_map();
        }
        return 0;
}

/* Given a RadioGatun state, generate a psuedo-random number. */
DWR_WORD dwr_rng(dwr_rg *in) {
        DWR_WORD *o;
        DWR_WORD out;
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
        if(in->index % 2 == 0) {
                dwr_belt(in->mill, in->belt);
                in->index++;
                out = o[0];
        } else {
                in->index++;
                out = o[1];
                }
        /* Endian issues */
        out = ((out & 0xff0000) >> 8) | ((out & 0xff000000) >> 24) |
              ((out & 0xff00) << 8) | ((out & 0xff) << 24);
        return out;
}

/* The main routine.  This reads a file specified on the command line,
   then makes a hash out of that file. */

main(int argc, char **argv) {
    char state[HASH_BYTES + 1], input[HASH_BYTES + 1];

    int readed, counter;
    FILE *sh;
    char copy[HASH_BYTES * 43];
    int n = 0;
    int q = 0;

    unsigned int len = 0;

    /* Check the command line argument */
    if(argc != 3 && argc != 5) {
        if(argc >= 1) {
            printf("Usage: %s [-n #] [-s] [-u] {data to hash}\n",argv[0]);
            exit(1);
            }
        else {
            printf("Usage: <this program> [-n #] [-s] [-u] {data to hash}\n");
            exit(2);
            }
        }

    /* Initialize the state */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        state[counter] = 0xff;
        }

    if(argc == 5 && (*(argv[1]) != '-' || *(argv[1] + 1) != 'n')) {
            printf("Usage: <this program> [-n #] [-s] [-u] {data to hash}\n");
            exit(3);
            }
    else if(argc == 5) {
            n = atoi(argv[2]);
            if(n < 1 || n > 900) {
                printf("n must be between 1 and 900\n");
                exit(4);
                }
            }
    /* Open up what we prepend to the hash if -s is in argv */
    if((argc == 3 && *(argv[1]) == '-' && *(argv[1] + 1) == 's') ||
       (argc == 5 && *(argv[3]) == '-' && *(argv[3] + 1) == 's')) {
            char fp[100];
            int zork;

            if(strncpy(fp,getenv("HOME"),50) == NULL) {
                    perror("Problem copying string");
                    exit(35);
            }
            if(strcat(fp,"/.mhash_prefix") == NULL) {
                    perror("Problem making string");
                    exit(36);
            }
            if((sh = fopen(fp,"rb")) == NULL) {
                perror("Could not open file ~/.mhash_prefix");
                exit(5);
                }
            /* Get only one line from this file: A string we put at
             * the beginning of the hash we will make */
            for(counter = 0; counter < 85; counter++) {
                copy[counter] = 0;
                }
            fgets(copy,79,sh);
            fclose(sh);
            counter = strnlen(copy,85);
            counter--;
            /* Remove :, which is a metacharacter */
            for(zork = 0; zork <= counter; zork++) {
                if(copy[zork] == ':') {
                    copy[zork] = '@';
                    }
                }
            copy[counter] = ':';
            counter++;
            }
    else if((argc == 3 && *(argv[1]) == '-' && *(argv[1] + 1) == 'q') ||
       (argc == 5 && *(argv[3]) == '-' && *(argv[3] + 1) == 'q')) {
            char fp[100];
            int zork;

            if(strncpy(fp,getenv("HOME"),50) == NULL) {
                    perror("Problem copying string");
                    exit(35);
            }
            if(strcat(fp,"/.mhash_prefix2") == NULL) {
                    perror("Problem making string");
                    exit(36);
            }
            if((sh = fopen(fp,"rb")) == NULL) {
                perror("Could not open file ~/.mhash_prefix2");
                exit(5);
                }
            /* Get only one line from this file: A string we put at
             * the beginning of the hash we will make */
            for(counter = 0; counter < 85; counter++) {
                copy[counter] = 0;
                }
            fgets(copy,79,sh);
            fclose(sh);
            counter = strnlen(copy,85);
            counter--;
            /* Remove :, which is a metacharacter */
            for(zork = 0; zork <= counter; zork++) {
                if(copy[zork] == ':') {
                    copy[zork] = '@';
                    }
                }
            copy[counter] = ':';
            counter++;
            q = 1;
            }
    else if((argc == 3 && *(argv[1]) == '-' && *(argv[1] + 1) == 'u') ||
       (argc == 5 && *(argv[3]) == '-' && *(argv[3] + 1) == 'u')) {
       counter = 0;
       }
    else {
       printf("Usage: <this program> [-n #] [-s] [-u] {data to hash}\n");
       exit(6);
       }

    if(strnlen(argv[argc - 1],HASH_BYTES * 35) >= HASH_BYTES * 31) {
         printf("Hash input is too long!\n");
         }

    readed = counter;
    for(;counter < HASH_BYTES * 42; counter++)
        copy[counter] = 0;
    counter = readed;
    for(;counter < HASH_BYTES * 41; counter++) {
        /* The ':' is always a metacharacter */
        if(argv[argc - 1][counter - readed] == ':')
            argv[argc - 1][counter - readed] = '@';
        if(argv[argc - 1][counter - readed] == '\0')
            break;
        copy[counter] = argv[argc - 1][counter - readed];
        }

    /* Initialize the state */
    for(counter = 0; counter < HASH_BYTES; counter++) {
        state[counter] = 0xff;
        }

    for(counter = 0;counter < 128;counter+=16) {
        for(readed = 0; readed < 16; readed++) {
            input[readed] = copy[counter + readed];
            if(input[readed] == '\0')
                break;
            }
        if(input[readed] == '\0' && readed < 16)
            break;
        hash_compress(input,state);
        }

    len = readed + counter;
#ifdef DEBUG
    printf("%d\n",len);
#endif

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

    if(n == 0) {
        printf("marahash: ");

        for(counter = 0; counter < HASH_BYTES; counter++) {
            printf("%02x",state[counter] & 0xff);
            if(counter % 4 == 3) {printf(" ");}
            }
        printf("\n");
        }

    /* OK, now give them the rg32 hash of the same input */
    dwr_rg *rg32;
    rg32=dwr_init_rg(copy);
    if(n != 0) {
        printf("rg32hash: ");
        for(counter = 1; counter < n; counter++) {
            dwr_rng(rg32);
        }
        if(q == 1) {
                for(counter = 1; counter < n; counter++) {
                    dwr_rng(rg32);
                }
                printf("%08x",dwr_rng(rg32));
        }
        printf("%08x ",dwr_rng(rg32));
        printf("%d",n);
        printf("\n");
        }

    }

