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

/* Make a block list hash by reading a file from standard input */

#include <stdio.h>
#include <stdint.h>
#include <string.h> // For strlen()
#include <stdlib.h>

// Linked list string item
typedef struct blStr {
  int16_t len;
  uint8_t *str;
  struct blStr *listNext;
  struct blStr *hashNext;
} blStr;

// HalfSip 1-3 key
uint32_t sipKey1 = 0x01020304;
uint32_t sipKey2 = 0xfffefdfc;

blStr **hashBuckets = NULL;
int32_t hashSize = -1;
int32_t maxChainLen = 0;

// Half Sip Hash 1 - 3 (One round while processing string; three
// rounds at end)
uint32_t HalfSip13(uint8_t *str, int32_t l) {
  uint32_t v0, v1, v2, v3, m;
  int shift = 0, round = 0;
  size_t offset = 0;
  if(str == NULL || l < 0) {
    return 0;
  }

  // We calculate the hash via SipHash, for security reasons
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

blStr *newBl(int len, uint8_t *str) {
  blStr *new;
  new = malloc(sizeof(blStr));
  if(new == 0) { 
    return 0;
  }
  new->len = len;
  new->str = str;
  new->listNext = NULL;
  new->hashNext = NULL;
  return new;
}

blStr *readFile(FILE *inp, int *elements) {
  blStr *top = NULL, *bottom = NULL, *new = NULL;
  if(elements != NULL) {
    *elements = 0;
  }
  while(!feof(inp)) {
    uint8_t line[1020];
    uint8_t *nstr = NULL;
    int len;
    line[0] = 32; // One space before the string for DNS conversion
    if(fgets((char *)(line + 1),1010,inp) == NULL) {
      return top;
    }
    len = strlen(line); 
    nstr = malloc(len + 2);
    if(nstr == NULL) {
      return top;
    }
    strncpy(nstr,line,len + 1);
    if(top == NULL) {
       top = newBl(len, nstr);
       bottom = top;
       if(top == NULL) {
         return top;
       }
     } else {
       new = newBl(len, nstr);
       if(new == NULL) {
         return top;
       }
       bottom->listNext = new;
       bottom = new;
    }
    if(elements != NULL) {
      *elements = *elements + 1;
    }
  }
  return top;
}

// Set the SipHash key (global variables)
void setSipKey() {
  char noise[10];
  int a = 0;
#ifndef MINGW
  FILE *rfile = NULL;
  rfile = fopen("/dev/urandom","rb");
  if(rfile == NULL) {
    puts("You do not have /dev/urandom");
    puts("I refuse to run under these conditions");
    exit(1);
  }
  for(a=0;a<8;a++) {
    int b;
    b = getc(rfile);
    noise[a] = b;
  }
#else // MINGW
  HCRYPTPROV CryptContext;
  int q;
  q = CryptAcquireContext(&CryptContext, NULL, NULL, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT);
  if(q == 1) {
    q = CryptGenRandom(CryptContext, 8, noise);
  }
  if(q == 0) {
    puts("I can not generate strong random numbers");
    puts("I refuse to run under these conditions");
    exit(1);
  }
#endif // MINGW
  noise[8] = 0;
  for(a = 0; a < 4; a++) {
    sipKey1 <<= 8;
    sipKey1 ^= noise[a];
  }
  for(a = 4; a < 8; a++) {
    sipKey2 <<= 8;
    sipKey2 ^= noise[a];
  }
}

// Initialize the hash with a given size
int initHash(int32_t size) {
  int32_t counter;
  hashSize = size;
  hashBuckets = malloc(hashSize * sizeof(blStr *));
  if(hashBuckets == NULL) {
    return 1; // Error
  }
  for(counter = 0; counter < hashSize; counter++) {
    hashBuckets[counter] = NULL;
  }
  return 0; // Success
}

// Compare the strings in two blStr elements
// 1 if same, 0 if different, -1 if error
int isSameString(blStr *a, blStr *b) {
  int counter;
  if(a == NULL || b == NULL) {
    return -1; // Error
  }
  if(a->len != b->len) {
    return 0; // Different
  }
  for(counter = 0; counter < a->len; counter++) {
    if(a->str[counter] != b->str[counter]) {
      return 0; // Different
    }
  }
  return 1; // Same
}

// Fill the hash with the contents of a buffer.
// Note that, to avoid copying, the buffer will have its hashNext elements
// altered 
int fillHash(blStr *buf) {
  uint32_t hashKey = 0;
  while(buf != NULL) {
    hashKey = HalfSip13(buf->str,buf->len);
    hashKey %= hashSize;
    if(hashBuckets[hashKey] == NULL) {
      hashBuckets[hashKey] = buf;
    } else {
      int32_t chainLen = 1;
      blStr *point;
      point = hashBuckets[hashKey];
      if(isSameString(buf,point) == 1) {
        buf = buf->listNext;
        continue;
      }
      while(point != NULL && point->hashNext != NULL) {
        if(isSameString(buf,point) == 1) {
          break; 
        }
        point = point->hashNext;
        chainLen++;
      }
      if(isSameString(buf,point) == 1) {
        buf = buf->listNext;
        continue;
      }
      if(point != NULL) {
        point->hashNext = buf;
      }
      if(chainLen > maxChainLen) {
        maxChainLen = chainLen;
      }
    }
    buf = buf->listNext;
  }
  return 0; // Success
}

#ifdef DEBUG
void showHash() {
  int counter;
  for(counter = 0; counter < hashSize; counter++) {
    printf("hashKey: %d hashBucket: %p\n",counter,hashBuckets[counter]);
  } 
}
#endif // DEBUG

int main(int argc, char **argv) {
  uint32_t hashValue;
  int32_t size;
  blStr *buf;
  buf = readFile(stdin, &size);
  setSipKey();
  if(initHash(size + (size >> 2)) != 0) {
    return 1;
  }
  fillHash(buf);
#ifdef DEBUG
  showHash();
#endif // DEBUG
  printf("size: %d longest chain: %d\n",hashSize,maxChainLen);
  return 0;
}
