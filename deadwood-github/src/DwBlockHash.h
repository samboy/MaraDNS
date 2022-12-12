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

typedef struct {
        uint8_t *block;
        uint32_t max;
        uint32_t sipKey1;
        uint32_t sipKey2;
        int32_t hashSize;
} blockHash;

// See if a black has a given binary string (string str, length len)
// 1: Yes, it does
// 0: No, it does not
// -1: An error happened when trying to find the string
int DBH_BlockHasString(blockHash *b, uint8_t *str, int32_t len);

// Read a file and make a blockHash structure
blockHash *DBH_makeBlockHash(char *filename);

