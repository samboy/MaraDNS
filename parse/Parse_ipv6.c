/* Copyright (c) 2004,2020 Sam Trenholme
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
#include "../libs/MaraHash.h"

/* Set_nybble: Set a single nybble in a character string;
 *
 * Input:  A nybble with a value between 0x00 and 0x0f
 *         A character string we set the nybble in
 *         The nybble we set (starting from left hand side of string;
 *         nybble 0 is the left side of the first byte, nybble 1 is
 *         the right side of the first byte, nybble 2 is the left side
 *         of the second byte, etc.)
 *         The maximum length of said character string
 * Output: JS_SUCCESS on success, JS_ERROR on error
 *
 */

int set_nybble(unsigned int nybble, unsigned char *istring, int point,
               int length) {
        char temp;
        int place;
        if(nybble < 0 || nybble > 0x0f) {
                return JS_ERROR;
        }
        if(length < 0) {
                return JS_ERROR;
        }
        if(length * 2 < point) {
                return JS_ERROR;
        }
        place = point >> 1;
        temp = *(istring + place);
        if((point & 1) == 0) { /* Nybble affects left side of byte */
                nybble <<= 4;
                temp &= 0x0f;
                temp |= nybble;
        }
        else { /* Nybble affects right side of byte */
                temp &= 0xf0;
                temp |= nybble;
        }
        *(istring + place) = temp;
        return JS_SUCCESS;
}

/* hchar_to_nybble: Convert an ASCII character, [0-9a-fA-F] in to a
 * hex nybble, or return -1 (JS_ERROR) if the character is not a hex digit,
 * return -2 if the character is a colon */

int hchar_to_nybble(char i) {
        if(i >= '0' && i <= '9')
                return i - '0';
        if(i >= 'a' && i <= 'f')
                return i + 10 - 'a';
        if(i >= 'A' && i <= 'F')
                return i + 10 - 'A';
        if(i == ':')
                return -2;
        return -1;
}

/* set_nybble_char: Set a singly nybble in a byte when the nybble in question
 * is an ASCII representation of a hexadecimal digit.
 *
 * Input: Same as set_nybble
 * Output: JS_SUCCESS on success, JS_ERROR on error, -2 if the character
 * we are looking at is a ':'.
 */

int set_nybble_char(char nybble, unsigned char *istring, int point, int length) {
        int n;
        n = hchar_to_nybble(nybble);
        if(n == -1)
                return -1; /* JS_ERROR */
        if(n == -2)
                return -2;
        return set_nybble(n,istring,point,length);
}

/* set_nybble_js: Given an input js_string object (with an ASCII representation
 * of a hexadecimal number), an offset in that string (in
 * bytes), an output js_string, an offset for said output (in nybbles),
 * and a maximum length, set the output nybble appropriately */

int set_nybble_js(js_string *i, int i_offset, js_string *o, int o_offset) {
        if(js_has_sanity(i) != JS_SUCCESS)
                return JS_ERROR;
        if(js_has_sanity(o) != JS_SUCCESS)
                return JS_ERROR;
        if(i->unit_size != 1)
                return JS_ERROR;
        if(o->unit_size != 1)
                return JS_ERROR;
        if(i_offset > i->unit_count)
                return JS_ERROR;
        if(o_offset > o->unit_count * 2)
                return JS_ERROR;
        return set_nybble_char(*(i->string + i_offset),o->string,o_offset,
                        o->unit_count);
}

/* is_hex_digit: Given a single character, determine whether the digit in
 * question is a hex digit.
 *
 * Input: The character in question
 * Output: Whether the digit is a hex digit
 */

int is_hex_digit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')
                        || (c >= 'a' && c <= 'f');
        }

/* is_colon: Given a single character, determine whether the character in
 * question is a colon.
 *
 * Input:  The character in question
 * Output: Whether the digit is a colon
 */

int is_colon(char c) {
        return (c == ':');
}

/* Count_thungys: Generalized function that counts the number of
 * characters as defined by the function we pass as an argument,
 *
 * Input: The js_string object we look at, the offset in said string
 * Output: The number of digits on normal exit, JS_ERROR on error
 */

int count_thingys(js_string *i, int offset, int (*is_thingy)(char in)) {
        int count;
        if(i->unit_size != 1) {
                return JS_ERROR;
        }
        if(i->unit_count >= i->max_count) {
                return JS_ERROR;
        }
        if(offset > i->unit_count) {
                return JS_ERROR;
        }
        count = 0;
        while(is_thingy(*(i->string + offset))) {
                count++;
                offset++;
                if(offset == i->unit_count) {
                        return count;
                }
                if(offset > i->unit_count) {
                        return JS_ERROR;
                }
        }
        return count;
}

/* count_digits: Given a js_string object, and an offset inside of the
 * string, count the number of hex digits [0-9a-fA-F] starting from the
 * offset; if the character at the offset is a digit, the count is one.
 * If the character at the offset is *not* a digit, return a count of zero.
 * Count of two if the current digit and the next digit are hex digits, etc.
 *
 * Input: The js_string object we look at, the offset in said string
 * Output: The number of digits on normal exit, JS_ERROR on error
 */

int count_digits(js_string *i, int offset) {
        return count_thingys(i,offset,is_hex_digit);
}

/* see_double_colon counts the number of colons starting at the
 * current place; it is almost identical to count_digits */
int see_double_colon(js_string *i, int offset) {
        return count_thingys(i,offset,is_colon);
}

/* count_thingys_all: Count all of the occurrences of a given character
 * (or list of characters) starting at the offset until the end of
 * the string.
 *
 * Input: String we're looking at
 *        The offset in the string in question
 *        A pointer to a function that determines whether a character
 *              is a thingy
 *
 * Used in count_colons but generalized for future use by other functions.
 */

int count_thingys_all(js_string *i, int offset, int (*is_thingy)(char in)) {
        int count;
        if(i->unit_size != 1) {
                return JS_ERROR;
        }
        if(i->unit_count >= i->max_count) {
                return JS_ERROR;
        }
        if(offset > i->unit_count) {
                return JS_ERROR;
        }
        count = 0;
        while(offset < i->unit_count) {
                if(is_thingy(*(i->string + offset))) {
                        count++;
                }
                offset++;
        }
        return count;
}

/* Count colons:  Count the number of colons in the rest of a js_string
 * object, starting at a specified offset.
 *
 * Input: The js_string object we look at, the offset in said string.
 * Output: The number of digits on normal exit, JS_ERROR on error
 */

int count_colons(js_string *i, int offset) {
        return count_thingys_all(i, offset, is_colon);
}

/* Convert ipv6 ::-style notation to a raw 16-byte js_string object
 * Input: A js-string object that has a "ffe:501:ffff::b:c:d"
 * style string in out
 * Output: A 16-byte js-string in the form
 * "0f:fe:05:01:ff:ff:00:00:00:00:00:0b:00:0c:00:0d", or 0 on error
 */

js_string *ip6_to_raw(js_string *i) {
        js_string *o;
        int input_point, output_point;
        int counter, l, c;
        int skipped = 0;
        int init_colon = 1;

        /* Sanity checks */
        if(js_has_sanity(i) != JS_SUCCESS) {
                return 0;
        }
        if(i->unit_size != 1) {
                return 0;
        }

        /* Create the output string */
        if((o = js_create(16,1)) == 0) {
                return 0;
        }

        /* Zero out the output string */
        for(counter = 0; counter < 16; counter++) {
                *(o->string + counter) = 0;
        }
        o->unit_count = 16;

        input_point = output_point = 0;

        l = js_length(i);

        c = 0;

        while(output_point < 32 && input_point < l) {
                int q;
                int n;
                /* Count the digits in the current hex block, to see how
                 * many zeros we need to pad at the beginning */
                n = count_digits(i,input_point);
                if(init_colon == 1 && n == 0) {
                        goto zeros;
                }
                init_colon = 0;
                if(n > 4 || n < 1) { /* Syntax error */
                        show_esc_stdout(o); printf("\n");
                        js_dealloc(o);
                        return 0;
                }
                /* Pad the zeros at the beginning of this block */
                for(counter = 0; counter < 4 - n; counter++) {
                        set_nybble(0,o->string,output_point,o->unit_count);
                        output_point++;
                }
                for(counter = 4 - n; counter < 4; counter++) {
                        if(set_nybble_js(i,input_point,o,output_point) !=
                                        JS_SUCCESS) {
                                js_dealloc(o);
                                return 0;
                        }
                        input_point++;
                        output_point++;
                }
zeros:
                /* See if we have a double colon; if so, skip ahead the
                 * appropriate number of nybbles */
                if(input_point < i->unit_count) {
                        q = see_double_colon(i,input_point);
                } else if(input_point == i->unit_count) {
                        q = 0;
                } else {
                        js_dealloc(o);
                        return 0;
                }
                if(q == JS_ERROR) {
                        js_dealloc(o);
                        return 0;
                }
                if(q == 2) {
                        int cc;
                        if(skipped != 0) { /* puke on a:b::c::d:e-style
                                            * addresses: addresses that
                                            * have more than one
                                            * double-colon */
                                js_dealloc(o);
                                return 0;
                        }
                        skipped = 1;
                        input_point++;
                        /* The following needs some explanation
                         * 4: Because, in ipv6 notation, a single number
                         * between colons is 4 nybbles long
                         * 8: The number of 4-nybble chunks in an ipv6
                         * address
                         * c: how far from the left we are
                         * cc: How many colons there are on the right
                         */
                        cc = count_colons(i,input_point);
                        if(cc == JS_ERROR) {
                                js_dealloc(o);
                                return 0;
                        }
                        if(init_colon == 1) {
                                cc--;
                        }
                        output_point += (4 * (8 - (c + 1) - cc));
                        input_point++;
                }
                else if(q == 1) {
                        input_point++;
                }
                else if(q == 0 && input_point == i->unit_count) {
                        return o;
                }
                else {
                        js_dealloc(o);
                        return 0;
                }
                init_colon = 0;
                c++;
        }
        if(input_point < l) {
                js_dealloc(o);
                return 0;
        }
        return o;
}

#ifdef SELF_CONTAINED

/* For debugging purposes.  To compile this self-contained:
 *
cc Parse_ipv6.c ../libs/JsStr.o ../libs/JsStrCP.o ../libs/JsStrOS.o -DSELF_CONTAINED
 */

js_show_hex(js_string *i) {
        int a;
        printf("s: %d\n",i->unit_count);
        for(a = 0; a < i->unit_count; a++) {
                printf("%02x",*(i->string + a));
                if(a < i->unit_count - 1) {
                        printf(":");
                }
        }
        printf("\n");
}

int see(char *z) {
        js_string *a, *b;
        a = js_create(256,1);
        js_qstr2js(a,z);
        b = ip6_to_raw(a);
        show_esc_stdout(a);
        printf("\n");
        js_show_hex(a);
        if(b == 0) { printf("fatal error parsing string!\n\n"); return; }
        show_esc_stdout(b);
        printf("\n");
        js_show_hex(b);
        printf("\n");
}

main() {
        see("ffe:501:ffff::b:c:d");
        see("ff::5");
        see("f::a005");
        see("e::");
        see("::e:f");
        see("::c");
        see("1111:2222:3333:4444:5555:6666:7777:8888");
        see("1111:2222:3333:4444:5555:6666:7777:8888:9999");
        see("1111::4444:5555:6666:7777:8888");
        see("::");
}

#endif /* SELF_CONTAINED */

/* Again:
cc Parse_ipv6.c ../libs/JsStr.o ../libs/JsStrCP.o ../libs/JsStrOS.o -DSELF_CONTAINED
 */

