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

/* Process a UTF-8 sequence so that it becomes an iso 8859-1 string;
   hi-level unicodes become hash marks */

#include <stdio.h>

main() {
      int a,v;
      unsigned char c;

      while(!feof(stdin)) {
          c = getc(stdin);
          if(c<128) {
              printf("%c",c);
              }
          else {
              if(c < 0xe0) { /* two-byte sequence */
                  v = c & 0x1f;
                  v <<= 6;
                  c = getc(stdin);
                  if(c != 255)
                      v = v + (c & 0x3f);
                  else
                      exit(1);
                  printf("%c",v);
                  }
              else { /* multi-byte sequence */
                  while(c & 0xc0 == 0x80 && !feof(stdin)) {
                      c = getc(stdin);
                      }
                  if(!feof(stdin))
                      printf("%c",'#');
                  }
              }
           fflush(stdout);
           }
        }
