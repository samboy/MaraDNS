/* Copyright (c) 2002,2003 Sam Trenholme
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

#include <stdio.h>

/* Convert an iso 8859-1 string in to a UTF-8 string.
   input: iso 8859-1 character
   output: output to stadnard output utf-8 (or ASCII) sequence
*/

int iso88591_to_utf8(unsigned char i8859) {


        if(i8859 <= 0x7f) {
            printf("%c",i8859);
            }
        else { /* Convert it to UTF8 */
            printf("%c%c",(i8859 >> 6) | 0xc0,(i8859 & 0x3f) | 0x80);
            }

    }

main() {
    unsigned char x;
    while(!feof(stdin)) {
       x = getc(stdin);
       if(!feof(stdin))
           iso88591_to_utf8(x);
       fflush(stdout);
       }
    }

