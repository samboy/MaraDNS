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


/* This is a simple program which takes standard input, removes any
   backspaces, only showing the last character which would have been
   made visible.  I had to write this because of bugs in GNU's col when
   used with a utf-8 terminal.  This program assumes latin1 or any other
   one-byte-per-character as the input stream; this is only used in
   pipelines for converting the output of man in to various other
   formats.  This is a "quick and dirty" hack; don't use for anything else */

#include <stdio.h>
#define BUFSIZE 512

main() {
        unsigned char p[BUFSIZE];
        int position = 0;
        unsigned char d;

        while(!feof(stdin)) {
            d=getc(stdin);
            if(feof(stdin))
                break;
            if((d == 8 || d == 16) && position > 0)
                position--;
            else if(d >= 32 || d == 9) { /* ASCII/hibit or tab */
                p[position] = d;
                p[position + 1] = 0;
                if(position < BUFSIZE - 7)
                    position++;
                }
            else if(d==10) {
                printf("%s\n",p);
                position = 0;
                p[0] = 0;
                }
            }

        }

