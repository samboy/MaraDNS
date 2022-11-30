/* Make a block list hash by reading a file in standard input */

#include <stdio.h>
#include <stdint.h>
#include <string.h> // For strlen()

uint32_t sipKey1 = 0x01020304;
uint32_t sipKey2 = 0xfffefdfc;

// Half Sip Hash 1 - 3 (One round while processing string; three
// rounds at end)
uint32_t HalfSip13(const char *str, size_t l) {
  uint32_t v0, v1, v2, v3, m;
  int shift = 0, round = 0;
  size_t offset = 0;

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

int main(int argc, char **argv) {
  uint32_t hashValue;
  hashValue = 0xdeadbeef;
  if(argc <= 1 || !argv[1]) {
    printf("Usage: HalfSip13 ${Input to hash}");
    return 1;
  }
  if(argv[1]) {
    hashValue = HalfSip13(argv[1],strlen(argv[1]));
  } else {
    printf("Usage: HalfSip13 ${Input to hash}");
    return 1;
  }
  printf("HalfSip value for string: %08x\n",hashValue);
  return 0;
}
