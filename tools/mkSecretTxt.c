/* Placed in public domain 2010 by Sam Trenholme */

/* To compile:
 *
 * Install MinGW-3.4.2 (Look for MinGW-3.4.2.exe on the internet)
 *
 * Install MSYS-1.0.10 (Look for MSYS-1.0.10.exe on the internet; use
 *      newer MSYS if using a 64-bit system)
 *
 * From a MSYS command prompt: gcc -Os -o mkSecretTxt mkSecretTxt.c
 *
 * This is only for Windows systems; the *NIX equivalent is:
 *
 * dd if=/dev/urandom of=secret.txt bs=64 count=1
 */

#include <stdio.h>
#include <stdint.h>
#include <winsock.h>
#include <wincrypt.h> /* Windows only; *NIX has /dev/random */

main() {
        uint8_t pool[65];
        HCRYPTPROV CryptContext;
        int a;
        int b;
        FILE *out;

        for(a = 0; a < 64 ; a++) {
                pool[a] = 0;
        }

        out = fopen("secret.txt","rb");
        if(out != NULL) {
                printf("secret.txt already exists\n");
                return 4;
        }

        out = fopen("secret.txt","wb");
        if(out == NULL) {
                printf("Fatal error opening secret.txt for writing");
                return 3;
        }

        b = CryptAcquireContext(&CryptContext, NULL, NULL, PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT);
        if(b != 1) {
                printf("Fatal error with CryptAcquireContext()\n");
                return 1;
        }
        b = CryptGenRandom(CryptContext, 64, pool);
        if(b != 1) {
                printf("Fatal error with CryptGenRandom()\n");
                return 2;
        }
        CryptReleaseContext(CryptContext,0);

        for(a = 0; a < 64 ; a++) {
                putc(pool[a], out);
        }

        fclose(out);
        return 0;

}

