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

uint32_t sipKey1 = 0x01020304;
uint32_t sipKey2 = 0xfffefdfc;

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

typedef struct blStr {
  int16_t len;
  uint8_t *str;
  struct blStr *next;
} blStr;

blStr *newBl(int len, uint8_t *str) {
  blStr *new;
  new = malloc(sizeof(blStr));
  if(new == 0) { 
    return 0;
  }
  new->len = len;
  new->str = str;
  new->next = NULL;
  return new;
}

blStr *readFile(FILE *inp, int *elements) {
  if(elements != NULL) {
    *elements = 0;
  }
  blStr *top = NULL, *bottom = NULL, *new = NULL;
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
       bottom->next = new;
       bottom = new;
    }
    if(elements != NULL) {
      *elements = *elements + 1;
    }
  }
  return top;
}

int main(int argc, char **argv) {
  uint32_t hashValue;
  int size;
  blStr *buf;
  buf = readFile(stdin, &size);
  while(buf != NULL) {
    hashValue = HalfSip13(buf->str,buf->len);
    printf("%s %08x\n",(char *)buf->str,hashValue);
    buf = buf->next;
  }
  printf("%d\n",size);
  return 0;
}
