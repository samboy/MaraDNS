/* Luancy stuff */
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <stdlib.h>

int main() {
	char test[66];
        int a;
        uint64_t result;
	SipHashSetKey(0x0706050403020100, 0x0f0e0d0c0b0a0908);
        for(a = 0; a < 64; a++) { 
		test[a] = a;
		printf("%ll016x\n",SipHash(test, a)); 
	}
}
