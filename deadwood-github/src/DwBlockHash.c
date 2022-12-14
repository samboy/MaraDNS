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

#include "DwBlockHash.h"
#include "DwHalfSipHash.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef MINGW
#include <io.h>
#endif // MINGW


// The numbers are big endian
uint32_t DBH_Read32bitNumber(uint8_t *block, uint32_t offset, uint32_t max) {
        uint32_t out = 0;
        if(offset + 3 >= max) {
                return 0;
        }
        out |= block[offset] << 24;
        out |= (block[offset + 1] & 0xff) << 16;
        out |= (block[offset + 2] & 0xff) << 8;
        out |= block[offset + 3];
        return out;
}

// See if a black has a given binary string (string str, length len)
// 1: Yes, it does
// 0: No, it does not
// -1: An error happened when trying to find the string
int DBH_BlockHasString(blockHash *b, uint8_t *str, int32_t len) {
        uint32_t sipHashBucket;
        uint32_t offset;
        if(b == NULL || str == NULL || len < 0 || len > 0xff00) {
                return -1; // Error
        }
        sipHashBucket = HalfSip13(str, len, b->sipKey1, b->sipKey2) %
                        b->hashSize;
        offset = DBH_Read32bitNumber(b->block, 16+(4*sipHashBucket), b->max);
        if(offset == 0) {
                return 0; // Not found: No strings for this hash bucket
        }
        if(offset >= b->max - 1) { // - 1 because we will read 16-bit number
                return -1; // Error
        }
        while(offset < b->max) {
                int32_t stringLen, strOffset;
                uint32_t strEnd;
                stringLen = b->block[offset];
                if(stringLen == 0xff) { // End of hash chain
                        return 0; // Not found: End of hash bucket chain
                }
                offset++;
                stringLen <<= 8;
                if(offset >= b->max - 1) { return -1; } // Avoid 2nd bounds chk
                stringLen |= b->block[offset];
                if(stringLen < 0 || stringLen > 0xff00) { return -1; }
                offset++;
                strEnd = offset + stringLen;
                if(strEnd > b->max) { return -1; }
                if(stringLen != len) { // Different length, try next string
                        offset = strEnd;
                        continue;
                }
                strOffset = 0;
                while(stringLen > 0) {
                        if(b->block[offset] != str[strOffset]) {
                                // Different string, try next
                                offset = strEnd;
                                break;
                        }
                        stringLen--;
                        strOffset++;
                        offset++;
                }
                if(stringLen == 0) {
                        return 1; // Strings match, found
                }
        }
        return -1; // We should never get here, error
}

// Read a file and make a blockHash structure
blockHash *DBH_makeBlockHash(char *filename) {
        blockHash *out = NULL;
        int fileDesc;
        out = malloc(sizeof(blockHash));
        if(out == NULL) { return NULL; }
        struct stat get;
        if(stat(filename,&get) == -1) {
                free(out); return NULL;
        }
        out->max = get.st_size;
        if(out->max < 16) { free(out); return NULL; }
        out->block = malloc(out->max + 3);
        if(out->block == NULL) { free(out); return NULL; }
        fileDesc = open(filename, 0);
        if(fileDesc == -1) { free(out->block); free(out); return NULL; }
#ifdef MINGW
        setmode(fileDesc, O_BINARY);
#endif // MINGW
        if(read(fileDesc, out->block, out->max) != out->max) {
                free(out->block); free(out); return NULL;
        }
        if(out->block[0] != 0 || out->block[1] != 'D' || out->block[2] != 'w'
           || out->block[3] != 'B') {
                free(out->block); free(out); return NULL;
        }
        out->sipKey1 = DBH_Read32bitNumber(out->block,4,out->max);
        out->sipKey2 = DBH_Read32bitNumber(out->block,8,out->max);
        out->hashSize = DBH_Read32bitNumber(out->block,12,out->max);
        if(out->hashSize > out->max) {
                free(out->block); free(out); return NULL;
        }
        return out;
}

