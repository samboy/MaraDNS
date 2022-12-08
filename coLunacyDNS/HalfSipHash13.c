/* Luancy stuff */
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <stdlib.h>

int main() {
	char test[66];
        int a;
	SipHashSetKey(0x03020100, 0x07060504);
	printf("Test #1: Reference vectors\n");
	printf("See https://github.com/samboy/HalfSipTest for ref code\n");
        for(a = 0; a < 64; a++) { 
		test[a] = a;
		printf("%08x\n",SipHash(test, a)); 
	}
	SipHashSetKey(0xfcfdfeff, 0xf8f9fafb);
	printf("Test #2: Inverted reference vectors\n");
        for(a = 0; a < 64; a++) {
                test[a] = a ^ 0xff;
                printf("%08x\n",
                         SipHash(test,a));
        }
}
