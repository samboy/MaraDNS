/* Copyright (c) 2002-2005 Sam Trenholme
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

/* Strip out control characters */

#include <stdio.h>

int main() {
        unsigned char a;
        while(!feof(stdin)) {
                a = getc(stdin);
                /* Change this for UTF8 instead of ISO-8859-1 */

                if((a & 0x7f) < 32)
                        printf("<%x>",a);
                else
                        printf("%c",a);

                }
        return 0;
        }


