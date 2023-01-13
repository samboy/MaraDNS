/* Copyright (c) 2022,2023 Sam Trenholme
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef MINGW
#include <winsock.h>
#include <wincrypt.h>
#include <io.h>
#endif // MINGW

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
uint32_t stringsTotalSize = 0;
uint32_t maxOffset = 0;

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

/* Convert a string in to a DNS name.  For example, 
 * " www.example.com\n" becomes "\3www\7example\3com\0".
 * The string is altered by this process.  The first character
 * in the string will be overwritten with the length of the first 
 * DNS label; the input should be a string in the form <space>
 * followed by the DNS name in question, followed by a \n or space
 * This changes the string in place.
 */
int16_t dnsConvertString(int32_t len, uint8_t *str) {
  int dnsPoint = 0;
  int dnsLength = 0;
  int counter;
  if(len > 1040) { 
    return 0; // Error
  }
  for(counter = 1; counter < len; counter++) {
    if(dnsPoint >= len || counter >= len) {
      return 0; // Error
    }
    if(str[counter] <= 'Z' && str[counter] >= 'A') {
      str[counter] += 32; // Make upper case lower case
    }
    if(str[counter] == '.' || str[counter] == '\n' || 
       str[counter] == ' ' || str[counter] == '\r') {
      dnsLength = counter - dnsPoint - 1;
      if(dnsLength >= 0 && dnsLength < 64) {
        str[dnsPoint] = dnsLength;
      } else {
        return 0; // Error
      }
      if(dnsLength == 0) {
        return dnsPoint + 1; // A 0-length for a DNS label is end of string
      }
      dnsPoint = counter;
    }
  } 
  dnsLength = counter - dnsPoint - 1;
  if(dnsLength >= 0 && dnsLength < 64) {
    str[dnsPoint] = dnsLength;
  }
  return len; 
}

// Convert all strings in to DNS names (see dnsConvertString above for
// details
void dnsConvertChain(blStr *a) {
  while(a != NULL) {
    int32_t newLen = a->len;
    if(a->str != NULL) {
      newLen = dnsConvertString(newLen, a->str);
      if(newLen > 0) {
        a->len = newLen;
      }
    }
    a = a->listNext;
  }
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

    // We do not parse lines which start with a hash character
    if(line[1] == '#') {
      continue;
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
      stringsTotalSize += buf->len + 2; // Two-byte length header
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
      stringsTotalSize += buf->len + 2; // Two-byte length header
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

// Written number is big endian
int write32BitNumber(uint8_t *block, uint32_t number, uint32_t offset,
                     uint32_t max) {
  if(offset + 3 >= max) { 
    return 1; // Error
  }
  block[offset] =     number >> 24;
  block[offset + 1] = (number >> 16) & 0xff;
  block[offset + 2] = (number >> 8) & 0xff;
  block[offset + 3] = number & 0xff;
  return 0; // Success
}

// Again, big endian
int write16BitNumber(uint8_t *block, uint16_t number, uint32_t offset,
                     uint32_t max) {
  if(offset + 1 >= max) { 
    return 1; // Error
  }
  block[offset] =     number >> 8;
  block[offset + 1] = number & 0xff;
  return 0; // Success
}

// We keep track of the highest offset used to know how big the final
// string is; this means a global variable gets altered
int writeHashBucketChainTerminator(uint8_t *block, uint32_t offset, 
                                   uint32_t max) { 
  if(offset >= max) {
    return 1; // Error
  }
  block[offset] = 0xff;
  if(offset > maxOffset) {
    maxOffset = offset;
  }
  return 0; // Success
}

int writeString(uint8_t *block, uint8_t *str, int16_t len, uint32_t offset,
                uint32_t max) {
  int counter;
  if(offset + len >= max) {
    return 1; // Error
  }
  for(counter = 0; counter < len; counter++) {
    block[offset + counter] = str[counter];
  }
  return 0;
}

// Based on global variables, write the header of a block
int writeBlockHeader(uint8_t *block, uint32_t max) {
  if(max < 16) {
    return 1; // Error
  }
  block[0] = 0; block[1] = 'D'; block[2] = 'w'; block[3] = 'B';
  if(write32BitNumber(block,sipKey1,4,max) != 0) {return 1;}
  if(write32BitNumber(block,sipKey2,8,max) != 0) {return 1;}
  if(write32BitNumber(block,hashSize,12,max) != 0) {return 1;}
  return 0;
}

// Write a chain of strings for a single hash bucket
// Output: 0 on error
// Updated offset on success
// Global hash used in this function
uint32_t writeStringChain(int32_t bucket, uint8_t *block, uint32_t thisOffset,
                     uint32_t max) {
  blStr *point;
  if(thisOffset >= max) { return 0; /* Error */ }
  if(hashBuckets == NULL) { return 0; /* Error */ }
  if(bucket < 0 || bucket >= hashSize) { return 0; /* Error */ }
  point = hashBuckets[bucket];
  if(point == NULL) { return 0; /* Error */ }
  while(point != NULL) {
    if(point->len < 0 || point->len > 1040) { return 0; /* Error */ }
    if(write16BitNumber(block,point->len,thisOffset,max) != 0) {return 0;} 
    thisOffset += 2;
    if(writeString(block, point->str, point->len, thisOffset, max) != 0) {
      return 0;
    }
    thisOffset += point->len;
    point = point->hashNext;
  }
  if(writeHashBucketChainTerminator(block, thisOffset, max) != 0) {return 0;}
  return thisOffset;
}

// Write one bucket.  MaxOffset used and altered to know where to put a 
// string in the string list
int writeOneBucket(int32_t bucket, uint8_t *block, uint32_t max) {
  uint32_t thisOffset;
  thisOffset = maxOffset + 1;
  if(hashBuckets == NULL) { return 1; }
  if(bucket < 0 || bucket >= hashSize) { return 1; }
  if(hashBuckets[bucket] == NULL) { 
    if(write32BitNumber(block,0,16 + (4 * bucket),max) != 0) {
      return 1;
    }
  } else {
    if(write32BitNumber(block,thisOffset,16 + (4 * bucket),max) != 0) {
      return 1;
    }
    if(writeStringChain(bucket, block, thisOffset, max) == 0) { return 1; }
    thisOffset = maxOffset + 1;
  }
  return 0;
}
  
// Based on global variables, write the rest of the block
int writeAllBuckets(uint8_t *block, uint32_t max) {
  int bucket;
  maxOffset = (16 + (hashSize * 4)) - 1;
  for(bucket = 0; bucket < hashSize; bucket++) {
    if(writeOneBucket(bucket, block, max) != 0) {return 1;}
  }
  return 0;
}

// Hash state is global variables
uint8_t *makeBlock(uint32_t *blockMax) {
  uint8_t *block = NULL;
  if(blockMax == NULL) {
    return NULL;
  }
  // 16: header
  // 4 * hashSize: List of buckets
  // stringsTotalSize: All strings in hash + two bytes per string for lengths
  // hashSize: The terminating 0xff to end a hash bucket chain
  *blockMax = 16 + (4 * hashSize) + stringsTotalSize + hashSize;
  block = malloc(*blockMax);
  if(block == NULL) {
    return NULL;
  }
  if(writeBlockHeader(block, *blockMax) != 0) { free(block); return NULL; }
  if(writeAllBuckets(block, *blockMax) != 0) { free(block); return NULL; }
  return block;
}

int writeBlockFile(uint8_t *block, uint32_t max, char *fileName) {
  int handle;
  handle = open(fileName, O_CREAT|O_WRONLY, 0644);
  if(handle == -1) { return 1; /* Error */ }
#ifdef MINGW
  setmode(handle, O_BINARY);
#endif // MINGW
  if(write(handle, block, max) == -1) { return 1; /* Error */ }
  if(close(handle) == -1) { return 1; /* Error */ }
  return 0;
}
  
#ifdef DEBUG
void showHash() {
  int counter;
  for(counter = 0; counter < hashSize; counter++) {
    printf("hashKey: %d hashBucket: %p\n",counter,hashBuckets[counter]);
  } 
}

void showBlock(uint8_t *block, uint32_t max) {
  uint32_t counter;
  for(counter = 0; counter < max; counter+= 16) {
    int a;
    printf("%08x | ",counter);
    for(a = 0; a < 16; a++) {
      if(counter + a < max) {
        printf("%02x ",block[counter + a]);
      }
    } 
    printf(" | ");
    for(a = 0; a < 16; a++) {
      if(counter + a < max) {
        uint8_t b = block[a + counter];
        if(b < 32 || b > 126) {
          printf("¿");
        } else {
          printf("%c", b);
        }
      }
    }
    printf("\n");
  } 
}

#endif // DEBUG

int main(int argc, char **argv) {
  uint32_t blockMax;
  uint8_t *bigBlock;
  int32_t size;
  blStr *buf;
  char *filename;
  int32_t hashBucketCount = 12345;
  // Usage: blackHashMake {filename} {sipHash key} (both args optional)
  if(argc < 2) {
    filename = "bigBlock.bin";
  } else {
    filename = argv[1];
  }
  if(*filename == '-') {
    printf("blockHashMake version 1.0.06\n");
    printf("Usage: blockHashMake {filename} {sipHash key} {hash buckets}\n");
    printf("filename is file to write hash block file to\n");
    printf("sipHash key is a hex number from 0 to ffff\n");
    printf("hash buckets is number of hash buckets to have\n");
    printf("All arguments are optional\n\n");
    printf("Standard input is a list of DNS names to put in the block\n");
    printf("hash, one DNS name per line\n");
    return 0;
  }
  if(argc < 3) {
    setSipKey();
  } else {
    // SipHash keys specified on the command line range from 
    // 0x0000000000000000 to 0x000000000000ffff
    sipKey1 = strtol(argv[2],NULL,16); // Hex number
    if(sipKey1 > 0xffff || sipKey1 < 0) {
      sipKey1 = 0;
    }
    sipKey2 = 0;
  }
  buf = readFile(stdin, &size);
  dnsConvertChain(buf); // Convert strings in to DNS over-the-wire strings
  if(argc < 4) {
    hashBucketCount = size + (size >> 2);
  } else {
    hashBucketCount = atoi(argv[3]);
    if(hashBucketCount < 1024) {
      hashBucketCount = 1024;
    }
  }  
  if(initHash(hashBucketCount) != 0) {
    return 1;
  }
  fillHash(buf);
  bigBlock = makeBlock(&blockMax);
  if(bigBlock == NULL) {
    return 1;
  }
#ifdef DEBUG
  showHash();
  showBlock(bigBlock, blockMax);
#endif // DEBUG
  if(writeBlockFile(bigBlock, maxOffset + 1, filename) != 0) {
    printf("Error writing block to disk\n");
    return 1;
  }
  printf("%s written to disk\n",filename);
  printf("size: %d longest chain: %d\n",hashSize,maxChainLen);
  return 0;
}
