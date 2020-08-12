/* Luancy stuff */
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <stdlib.h>

int main() {
	char test[66];
        int a;
	SipHashSetKey(0x03020100, 0x07060504);
        for(a = 0; a < 64; a++) { 
		test[a] = a;
		printf("%08x\n",SipHash(test, a)); 
	}
}
