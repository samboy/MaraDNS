/* Make a file one with an incomplete last line */

#include <stdio.h>

main() {
        int a,n;
        n = 0;
        for(;;) {
                a = getc(stdin);
                if(feof(stdin)) {
                        exit(0);
                }
                if(n == 1) {
                        printf("\n");
                        n = 0;
                }
                if(a != '\n') {
                        printf("%c",a);
                } else {
                        n = 1;
                }
        }
}
