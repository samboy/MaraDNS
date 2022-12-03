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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  uint8_t *block;
  uint32_t max;
  uint32_t sipKey1;
  uint32_t sipKey2;
  int32_t hashSize;
} blockHash;

blockHash *globalBlockHash;
uint32_t globalSipKey1 = 0;
uint32_t globalSipKey2 = 0;

// The numbers are big endian
uint32_t read32bitNumber(uint8_t *block, uint32_t offset, uint32_t max) {
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
        m |= (uint64_t)(l & 0xff) << 24;
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

// See if a black has a given binary string (string str, length len)
// 1: Yes, it does
// 0: No, it does not
// -1: An error happened when trying to find the string
int blockHasString(blockHash *b, uint8_t *str, int32_t len) {
  uint32_t sipHashBucket;
  uint32_t offset;
  if(b == NULL || str == NULL) {
    return -1; // Error
  }
  sipHashBucket = HalfSip13(str, len, b->sipKey1, b->sipKey2) % b->hashSize;
  offset = read32bitNumber(b->block, 16 + (4 * sipHashBucket), b->max); 
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
      return 0; // Not found: End of hash bucket chain reached
    }
    offset++;
    stringLen <<= 8;
    if(offset >= b->max - 1) { return -1; } // - 1 to avoid 2nd bounds check
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
      if(b->block[offset] != str[strOffset]) { // Different string, try next
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
blockHash *makeBlockHash(char *filename) {
  blockHash *out = NULL;
  int fileDesc;
  out = malloc(sizeof(blockHash));
  if(out == NULL) { return NULL; }
  struct stat get;
  if(stat(filename,&get) == -1) {
    return NULL; 
  }
  out->max = get.st_size;
  if(out->max < 16) { free(out); return NULL; }
  out->block = malloc(out->max + 3);
  if(out->block == NULL) { free(out); return NULL; }
  fileDesc = open(filename, 0);
  if(fileDesc == -1) { free(out->block); free(out); return NULL; }
  if(read(fileDesc, out->block, out->max) != out->max) {
    free(out->block);
    free(out);
    return NULL;
  }
  if(out->block[0] != 0 || out->block[1] != 'D' || out->block[2] != 'w' 
     || out->block[3] != 'B') { free(out->block); free(out); return NULL; }
  out->sipKey1 = read32bitNumber(out->block,4,out->max);
  out->sipKey2 = read32bitNumber(out->block,8,out->max);
  out->hashSize = read32bitNumber(out->block,12,out->max);
  return out;
}

int main(int argc, char **argv) {
  globalBlockHash = makeBlockHash("bigBlock.bin");
  if(globalBlockHash == NULL) {
    printf("Error reading bigBlock.bin");
    return 1;
  }
  printf("%p %d %08x %08x %d\n",globalBlockHash->block, globalBlockHash->max,
      globalBlockHash->sipKey1, globalBlockHash->sipKey2, 
      globalBlockHash->hashSize);
  char *testString = "\3www\4fejs\2ml\0";
  int testLength = 13;
  printf("www.fejs.ml test result should be 1: %d\n",
      blockHasString(globalBlockHash,(uint8_t *)testString, testLength));
  char *testString2 = "\3www\4fexs\2ml\0";
  printf("www.fexs.ml test result should be 0: %d\n",
      blockHasString(globalBlockHash,(uint8_t *)testString2, testLength));
  return 0;
}
