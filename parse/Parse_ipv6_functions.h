/* Copyright (c) 2004 Sam Trenholme
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

/* Function prototypes */
int set_nybble(unsigned int nybble, char *istring, int point, int length);
int hchar_to_nybble(char i);
int set_nybble_char(char nybble, char *istring, int point, int length);
int set_nybble_js(js_string *i, int i_offset, js_string *o, int o_offset);
int is_hex_digit(char c);
int is_colon(char c);
int count_thingys(js_string *i, int offset, int (*is_thingy)(char in));
int count_digits(js_string *i, int offset);
int see_double_colon(js_string *i, int offset);
int count_thingys_all(js_string *i, int offset, int (*is_thingy)(char in));
int count_colons(js_string *i, int offset);
int see(char *z);
js_string *ip6_to_raw(js_string *i);

