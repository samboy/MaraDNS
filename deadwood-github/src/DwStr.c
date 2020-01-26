/* Copyright (c) 2007-2014 Sam Trenholme
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

#include "DwStr.h"
#include "DwSys.h" /* So we can log errors */

/* Make sure a dw_str object is sane.
 * Input: Pointer to dw_str
 * Output: 0 if sane; -1 if not */

int dw_assert_sanity(dw_str *object) {
        if(object == 0) {
                return -1;
        }
        if(object->sane != 114) {
                return -1;
        }
        if(object->str == 0) {
                return -1;
        }
        if(object->len >= object->max) {
                return -1;
        }
        if(object->len > 0x0fffffff) {
                return -1;
        }
        return 0;
}

/* Create a new dw_str object.
 * Input: Maximum length allowed for the string
 * Output: Pointer to newly created string
 */
dw_str *dw_create(uint32_t size) {
        dw_str *new;
        new = dw_malloc(sizeof(dw_str));
        if(new == 0) {
                return 0; /* We should probably give an "aiee" and
                           * exit(1) here */
        }
        if(size >= 134217728 /* 2 ** 27 */) {
                free(new);
                return 0;
        }
        /* 2 byte cushion to avoid off-by-one security problems */
        new->str = dw_malloc(size + 2);
        if(new->str == 0) {
                free(new);
                return 0;
        }
        new->len = 0;
        new->max = size;
        new->sane = 114;
        return new;
}

/* Destroy a dw_str object.
 * Input: Pointer to string to destroy
 * Output: 0 on success; -1 on failure
 */
int dw_destroy(dw_str *object) {
        if(object == 0) {
                return -1;
        }
        /* Make sure we are, in fact, destroying a dw_str object */
        if(object->sane != 114) {
                return -1;
        }
        if(object->str == 0) {
                free(object);
                return -1;
        }
        free(object->str);
        /* Reset values just in case we try and use a freed string */
        object->str = 0;
        object->sane = 0;
        object->len = 0;
        object->max = 0;
        free(object);
        return 0;
}

/* Add a single character to the DwStr */

int dw_addchar(uint8_t add, dw_str *object) {
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(object->max > object->len + 1) {
                *(object->str + object->len) = add;
                object->len++;
        } else {
                return -1;
        }
        return 0;
}

/* Add a C-string (which may have NULL characters) to a DwStr object.
 * Input: Pointer to string; number of characters we will add to DwStr
 * object; pointer to dw_str object.  Output: -1 on error; 0 on success */
int dw_cstr_append(uint8_t *add, int32_t len, dw_str *obj) {
        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }
        if(add == 0) {
                return -1;
        }
        if(len < 0) {
                return -1;
        }
        if(obj->len + len >= obj->max) { /* Bounds checking */
                return -1;
        }
        while(len > 0) {
                *(obj->str + obj->len) = *add;
                add++;
                obj->len++;
                len--;
        }
        return 0;
}

/* Add a null-terminated string to a DwStr; should the null-terminated string
 * have the character specified in 'nope', don't append that character and
 * stop appending to the string. Input: String to append; DwStr to append
 * to; 'nope' character we're not allowed to add (make this 0 if you want
 * to allow all non-NULL characters) */
int dw_qrappend(uint8_t *add, dw_str *object, char nope) {
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(add == 0) {
                return -1;
        }
        while(*add != 0 && *add != nope && object->len < object->max) {
                *(object->str + object->len) = *add;
                add++;
                object->len++;
        }
        return 0;
}

#ifdef OTHER_STUFF
/* Add an arbitrary null-terminated string of length "len" to a DwStr object */
int dw_bin_append(uint8_t *add, int len, dw_str *object) {
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(add == 0) {
                return -1;
        }
        while(*add != 0 && len > 0 && object->len < object->max) {
                *(object->str + object->len) = *add;
                add++;
                len--;
                object->len++;
        }
        return 0;
}
#endif /* OTHER_STUFF */

#ifdef OTHER_STUFF
/* Add a null-terminated string to a DwStr; if the DwStr is non-0 length,
 * first add a comma.  If the null-terminated string has a comma, stop
 * appending the string.
 * Input: C string to add; DwStr to add string to
 * Output: 0 on success; -1 on failure */
int dw_qspush(uint8_t *add, dw_str *object) {
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(add == 0) {
                return -1;
        }
        /* Add a comma to the end if not first element */
        if(object->len > 0) {
                if(dw_addchar(',',object) == -1) {
                        return -1;
                }
        }
        /* Add the string to the end of the string */
        if(dw_qrappend(add,object,',') == -1) {
                return -1;
        }
        return 0;
}
#endif /* OTHER_STUFF */

#ifdef XTRA_STUFF
/* For debug purposes: Output a dw_str object on the standard output. */
void dw_stdout(dw_str *object) {
        uint8_t *look = 0, q = 0;
        uint32_t p = 0;
        if(dw_assert_sanity(object) == -1) {
                printf("Object at %p does not look kosher.\n",object);
                return;
        }
        /* We don't need this junk; it just makes it harder to debug */
        /*printf("Object at %p has length %d, max length %d, and string at %p\n"
               ,object,(int)object->len,(int)object->max,object->str);
        printf("Object's string is (non-printable-ASCII hex-escaped): ");*/
        look = object->str;
        for(p = 0 ; p < object->len; p++) {
                q = *(look + p);
                if(q >= 32 && q <= '~' /* Last ASCII char */) {
                        printf("%c",q);
                } else {
                        printf("\\x%02X",q); /* Hex */
                        /* printf(" %d \\x%02X ",p,q); */ /* Hex w/ offset */
                        /*printf("\\%03o",q); */ /* Octal */
                }
        }
        printf("\n");
        return;
}
#endif /* XTRA_STUFF */

/* Take some of, or all, of a dw_str, and copy it in to a new dw_str object.
 * return 0 (NULL) if there is an error copying the string.  The parameters
 * are:
 * 1) The dw_string we want to copy
 * 2) The first character we starting copying from.  If this value has
 *    a value of 0, then we start copying from the start of the
 *    string.  If this has a value of -1, then we start copying at
 *    the end of the string (meaning, we can only copy the very last
 *    character). -2 is the second-to-last character in the string; 1 is
 *    the second character in the string (c indexes, ugh)
 * 3) The number of characters we copy.  0 means no characters (making
 *    a zero-length string); 1 means 1 character, etc.  If this is negative
 *    then we copy relative to the end of the string.  In other words, if
 *    the length has a value of -1, we copy until the end of the string;
 *    if length has a value of -2, we copy until the second to last character
 *    in the string, etc.
 * 4) The maximum allowed length for the string.  Should this have a positive
 *    value or 0, the string is allowed to add that many characters to the end
 *    of the string (0: The string can not grow; 1: the string can grow by
 *    one character, etc).  If it has a value of -1, then the string has the
 *    same maximum permitted size as the string we are copying.  Otherwise,
 *    we return an error.
 *
 * Output: We create a new dw_str object, which has the copied substr.
 *
 * Some common parameters: dw_substr(str,0,-1,-1): Copies the entire string
 */

dw_str *dw_substr(dw_str *obj, int32_t begin, int32_t amount, int32_t max) {
        dw_str *copy = 0;
        int c = 0;

        if(dw_assert_sanity(obj) == -1) {
                goto catch_dw_substr;
        }

        /* Process negative arguments */
        if(begin < 0) {
                begin = obj->len + begin;
        }
        if(amount < 0) {
                amount = obj->len - begin + amount + 1;
        }

        /* Make the string */
        if(max >= 0) {
                copy = dw_create(amount + max + 1);
        } else if(max == -1) {
                copy = dw_create(obj->max);
        } else {
                goto catch_dw_substr;
        }

        if(copy == 0) {
                goto catch_dw_substr;
        }

        /* Do the actual copying */
        for(c = 0; c < amount; c++) {
                /* Bounds checking */
                if(c + begin > obj->len || c >= copy->max) {
                        break;
                }
                *(copy->str + c) = *(obj->str + begin + c);
        }

        copy->len = c;

        return copy;

        /* Error catcher */
catch_dw_substr:
        if(copy != 0) {
                dw_destroy(copy);
                copy = 0;
        }
        return 0;

}

/* Read a 16-bit big-endian string that is in a dw_str as a number.  DNS
 * commonly has these kinds of numbers (can you say 1983?)
 * Input: Pointer to dw_str object; offset where we will look for number
 * (0 is top of string; -1 is last two bytes of string)
 * Output: The number; -1 on error */

int32_t dw_fetch_u16(dw_str *object, int32_t offset) {
        uint8_t *look = 0;
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(offset < 0) {
                offset = offset + object->len - 1;
        }
        if(offset + 1 > object->len || offset < 0) {
                return -1;
        }
        look = object->str;
        look += offset;
        return (*look << 8) | *(look + 1);
}

/* Read a 16-bit big-endian number at the end of a dw_str object, and
 * remove the string from the string object.  -1 on error */
int32_t dw_pop_u16(dw_str *object) {
        uint8_t *look = 0;
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(object->len < 2) {
                return -1;
        }
        look = object->str + object->len - 2;
        object->len -= 2;
        return (*look << 8) | *(look + 1);
}

/* Read an 8-bit number at the end of a dw_str object, and
 * remove the string from the string object.  -1 on error */
int32_t dw_pop_u8(dw_str *object) {
        uint8_t *look = 0;
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(object->len < 1) {
                return -1;
        }
        look = object->str + object->len - 1;
        object->len -= 1;
        return *look;
}

/* Read an 8-bit big-endian string that is in a dw_str as a number.
 * Input: Pointer to dw_str object; offset where we will look for number
 * (0 is top of string; negative numbers offsets from end of string [-1
 * last byte in string, -2 second-to-last byte in string, etc])
 * Output: The number; -1 on error */

int32_t dw_fetch_u8(dw_str *object, int32_t offset) {
        uint8_t *look = 0;
        if(dw_assert_sanity(object) == -1) {
                return -1;
        }
        if(offset < 0) {
                offset = object->len + offset;
        }
        if(offset > object->len || offset < 0) {
                return -1;
        }
        look = object->str;
        look += offset;
        return *look;
}

/* Put a 16-bit big-endian number (the argument "value") in a dw_str object.
 * Offset can be either a positive or negative number; should offset be
 * a positive number, then we put that byte in that many bytes from
 * the beginning of the string.  Should offset be a negative number, then
 * we put the number that many bytes from the end of the string.  This
 * function will, in certain cases make the string one or two bytes longer.
 * If offset is -1, then the number is added to the end of the string.
 * If offset is -2, then the number replaces the last byte of the string,
 * and adds a byte the the end of the string.  Should offset be 0, the
 * number replaces the first two numbers in the string (adding numbers
 * if needed)
 *
 * Should this function succeed, it will return a 0.  Otherwise, it
 * will return a -1 */

int dw_put_u16(dw_str *obj, uint16_t value, int32_t offset) {
        uint8_t *look = 0;
        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }

        /* Process negative offset amount */
        if(offset < 0) {
                offset = obj->len + offset + 1;
        }

        /* We may need to expand the string to fit the number */
        if(offset > obj->len || obj->len > 0x0fffffff) {
                return -1;
        } else if(offset >= (int32_t)(obj->len & 0x0ffffff) - 1) { /* -Wall */
                int expand_by;
                expand_by = obj->len - offset + 2;
                if(obj->len + expand_by >= obj->max) {
                        return -1;
                }
                obj->len += expand_by;
                if(obj->len > obj->max) {
                        obj->len -= expand_by;
                        return -1;
                }
        }

        look = obj->str + offset;
        *look = (value >> 8) & 0xff;
        *(look + 1) = value & 0xff;
        return 0;
}

/* Put an 8-bit (the argument "value") in a dw_str object.
 * Offset can be either a positive or negative number; should offset be
 * a positive number, then we put that byte in that many bytes from
 * the beginning of the string.  Should offset be a negative number, then
 * we put the number that many bytes from the end of the string.  This
 * function will, in certain cases make the string one byte longer.
 * If offset is -1, then the number is added to the end of the string.
 *
 * Should offset be 0, the number replaces the first number in the string
 * (adding numbers if needed)
 *
 * Should this function succeed, it will return a 0.  Otherwise, it
 * will return a -1
 *
 * BUG: Does not work correctly with length-1 (1-byte) strings
 */

int dw_put_u8(dw_str *obj, uint8_t value, int32_t offset) {
        uint8_t *look = 0;
        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }

        /* Process negative offset amount */
        if(offset < 0) {
                offset = obj->len + offset + 1;
        }

        /* We may need to expand the string to fit the number */
        if(offset > obj->len || obj->len > 0x0fffffff) {
                return -1;
        } else if(offset == (int32_t)(obj->len & 0x0ffffff)) { /* -Wall */
                obj->len++;
                if(obj->len > obj->max) {
                        obj->len--;
                        return -1;
                }
        }

        look = obj->str + offset;
        *look = value & 0xff;
        return 0;
}

#ifdef OTHER_STUFF
/* Read a single bit from a dw_str object.  The way we choose the bit is
 * to first choose the byte with the desired bit, then to choose the
 * bit in that byte.  0 is the least significant (rightmost) bit; 7 is the
 * most significant bit.
 * We return -1 on error, 0 if the bit is 0, and 1 if the bit is 1 */
int dw_get_bit(dw_str *obj, int32_t byte, int8_t bit) {
        int a = 0;
        uint8_t look;
        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }
        if(byte >= obj->len || byte < 0) {
                return -1;
        }
        if(bit < 0 || bit > 7) {
                return -1;
        }
        look = *(obj->str + byte);
        a = 1;
        a <<= bit;
        if((look & a) == a) {
                return 1;
        } else {
                return 0;
        }
}
#endif /* OTHER_STUFF */

/* Compare two dw_string objects to see if they are the same (different max
 * lengths are allowed).  -1 on error, 0 if not the same, and 1 if they are
 * the same */
int dw_issame(dw_str *a, dw_str *b) {
        int c = 0;
        if(dw_assert_sanity(a) == -1) {
                return -1;
        }
        if(dw_assert_sanity(b) == -1) {
                return -1;
        }
        if(a->len != b->len) {
                return 0;
        }
        for(c = 0; c < a->len; c++) {
                if(*(a->str + c) != *(b->str + c)) {
                        return 0;
                }
        }
        return 1;
}

/* Append one dw_string object to another dw_string.
 * Input: The two dw_string objects
 * Output: 0 on success, -1 on error */
int dw_append(dw_str *toappend, dw_str *target) {
        int c = 0;
        if(dw_assert_sanity(toappend) == -1) {
                return -1;
        }
        if(dw_assert_sanity(target) == -1) {
                return -1;
        }
        if(target->len + toappend->len >= target->max) {
                return -1;
        }
        for(c = 0; c < toappend->len; c++) {
                *(target->str + target->len + c) = *(toappend->str + c);
        }
        target->len += toappend->len;
        return 0;
}

/* Append a substring of one dw_string object to another dw_string.
 * Input: String we splice from, where we start cutting from that string,
 *        how many bytes to cut from said string, the string to append to
 * Output: 0 on success, -1 on error
 */
int dw_substr_append(dw_str *splice, int32_t begin, int32_t amount,
                dw_str *target) {
        dw_str *tmp = 0;

        tmp = dw_substr(splice, begin, amount, 1);
        if(tmp == 0) {
                return -1;
        }

        if(dw_append(tmp,target) == -1) {
                dw_destroy(tmp);
                return -1;
        }

        dw_destroy(tmp);
        return 0;
}

/* Copy a dw_string object in to a null-terminated C-string.
 * Input: The string to convert
 * Output: A pointer to a newly created C-string; 0 on error */

uint8_t *dw_to_cstr(dw_str *obj) {
        uint8_t *out = 0;
        int a = 0;

        if(dw_assert_sanity(obj) == -1) {
                return 0;
        }

        out = dw_malloc(obj->len + 3);
        for(a = 0; a < obj->len; a++) {
                *(out + a) = *(obj->str + a);
        }
        *(out + a) = 0; /* Null-terminated */

        return out;
}

/* Find the last instance of a given character in a DwStr object.
 * Input: The dw_str object, the character we are seeking
 * Output: The index in the string with the character in question
 * -1 on error; -2 on "not found"
 */

int32_t dw_rfind(dw_str *obj, uint8_t rx) {
        int index = 0;

        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }

        index = obj->len;

        /* We will never find the char in a 0-length string */
        if(index == 0) {
                return -2;
        }

        /* C indexes, ugh */
        index--;

        while(index >= 0 && *(obj->str + index) != rx) {
                index--;
        }

        if(index == -1) {
                return -2;
        }

        return index;

}

/* Take the last element of a comma-separated DwStr object, remove it
 * from said string, and create a new string with the popped comma-separated
 * object.  Should the source string not have a comma in it, then we take
 * the entire source string, blank it (make it 0-length) and copy it over
 * to the newly created string.  The final comma is removed from the
 * source string, but is *not* included in the destination string.
 * Input: The source string
 * Output: A newly created string with the last comma separated object */

dw_str *dw_qspop(dw_str *in) {
        int index = 0;
        int len = 0;
        dw_str *out = 0;

        if(dw_assert_sanity(in) == -1) {
                goto catch_dw_qspop;
        }

        index = dw_rfind(in,',');

        if(index == -2) { /* Not found */
                out = dw_copy(in);
                in->len = 0;
                return out;
        } else if(index < 0) { /* Error during seek */
                goto catch_dw_qspop;
        }

        len = in->len;
        index++; /* We don't include ',' in copied string */
        len = len - index;
        if(len < 0) { /* Sanity check */
                goto catch_dw_qspop;
        }
        out = dw_substr(in,index,len,1);
        in->len -= len + 1;
        if(in->len >= in->max) {
                in->len = 0;
                goto catch_dw_qspop;
        }

        return out;

catch_dw_qspop:
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;

}

/* Create a copy of a dw_str object with any leading whitespace in the
 * original object removed in the copy.  If the original is nothing
 * but whitespace, the copy will be a 0-length string.
 * Input: dw_str object we want to remove leading whitespace from
 * Output: Newly created dw_str object without the leading whitespace */

dw_str *dw_zap_lws(dw_str *obj) {
        int index = 0;
        dw_str *out = 0;

        if(dw_assert_sanity(obj) == -1) {
                goto catch_dw_zap_lws;
        }

        while(index < obj->len &&
              (*(obj->str + index) == ' ' || *(obj->str + index) == '\t') ) {
                index++;
        }

        if(index >= obj->len) { /* Obj is nothing but whitespace (or 0-len) */
                out = dw_create(1);
                return out;
        }

        out = dw_substr(obj,index,-1,1);
        return out;

catch_dw_zap_lws:
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;
}

/* Convert a dw_str object with a number in to an integer.  Leading
 * whitespace is ignored; anything that is not a number or letter stops
 * processing.
 * Input:
 *      obj: The dw_str object we convert in to a number
 *      index: How far in to the string we begin conversion (0 is
 *              beginning of string)
 *      base: The base we work in (2 is binary, 10 is decimal, 16 is
 *            hex; this can be up to 36)
 * Output:
 *      The number the string represents; -1 on error
 */

int32_t dw_atoi(dw_str *obj, int32_t index, int base) {
        int32_t out = 0;
        int num = 0, counter = 0;
        uint8_t look = 0;
        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }
        if(base < 2 || base > 36) {
                return -1;
        }
        if(index < 0 || index >= obj->len) {
                return -1;
        }
        look = *(obj->str + index);
        while(index < obj->len && (look == ' ' || look == '\t')) {
                index++;
                look = *(obj->str + index);
        }
        for(counter = 0; counter < 100; counter++) {
                if(index >= obj->len) {
                        return out;
                }
                look = *(obj->str + index);
                if(look >= '0' && look <= '9') {
                        num = look - '0';
                } else if(look >= 'a' && look <= 'z') {
                        num = look - 'a' + 10;
                } else if(look >= 'A' && look <= 'Z') {
                        num = look - 'A' + 10;
                } else {
                        return out;
                }
                if(num >= base) {
                        return -1;
                }
                out *= base;
                out += num;
                index++;
        }
        return -1;
}


/* This extracts just a DNS DNAME (without TYPE) from a raw c-string (with
 * ASCII nulls, since DNS packets have those) and puts it in a newly
 * created string.
 * Input: Pointer to raw string; offset where we look for DNS DNAME,
 *        maximum length of raw string
 * Output: A pointer to a new dw_str with NAME
 */
dw_str *dw_get_dname(uint8_t *raw, int offset, int max) {
        int len = 0, counter = 0;
        int soffset = 0;
        dw_str *out = 0;

        if(max > 260) {
                out = dw_create(max);
        } else {
                out = dw_create(260);
        }

        if(out == 0 || raw == 0) {
                goto catch_dw_get_dname;
        }

        for(counter = 0; counter < 400; counter++) {
                if(offset >= max - 2 || soffset > 255) {
                        goto catch_dw_get_dname;
                }

                len = *(raw + offset);
                if(len > 63 || len < 0) { /* No compression pointers */
                        goto catch_dw_get_dname;
                }

                *(out->str + soffset) = len;
                if(len == 0) { /* End of dlabel */
                        break;
                }
                while(len > 0) {
                        soffset++;
                        offset++;
                        len--;
                        if(offset >= max - 2 || soffset > 255) {
                                goto catch_dw_get_dname;
                        }
                        *(out->str + soffset) = *(raw + offset);
                        /* No ASCII control characters in DNS names */
                        if(*(out->str + soffset) < 32) {
                                goto catch_dw_get_dname;
                        }
                }
                soffset++;
                offset++;
        }
        out->len = soffset + 1;
        return out;

catch_dw_get_dname:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* This extracts a DNS DNAME, followed by a two-byte TYPE (the type of RR)
 * from a raw c-string (with ASCII nulls, since DNS packets have those)
 * and puts it in a newly created string.
 * Input: Pointer to raw string; offset where we look for DNS DNAME + TYPE,
 *        maximum length of raw string
 * Output: A pointer to a new dw_str with NAME + TYPE
 */
dw_str *dw_get_dname_type(uint8_t *raw, int offset, int max) {
        dw_str *out = 0;

        out = dw_get_dname(raw,offset,max);
        if(out == 0) {
                goto catch_dw_get_dname_class;
        }
        offset += out->len;

        /* Accoring to http://www.iana.org/assignments/dns-parameters,
         * records 65280 (0xff00) to 65535 (0xfffe) are "private use";
         * Deadwood uses 65392 - 65407 for internal use and will not
         * accept queries with these numbers in place; see
         * doc/internals/RR.Allocation for details on how Deadwood uses
         * these RR numbers */
        if(*(raw + offset)==0xff && (*(raw + offset + 1) & 0xf0)==0x70) {
                goto catch_dw_get_dname_class;
        }
        *(out->str + out->len) = *(raw + offset);
        *(out->str + out->len + 1) = *(raw + offset + 1);
        out->len += 2;
        return out;

catch_dw_get_dname_class:
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;
}

/* Determine where the end of a <domain-name> at offset in the string
 * is (ugh, DNS is ugly); -1 on error */
int32_t dw_get_dn_end(dw_str *in, int offset) {
        int len = 0, counter = 0;

        if(dw_assert_sanity(in) == -1) {
                return -1;
        }

        for(counter = 0; counter < 200; counter++) {
                if(offset + 1 > in->len) {
                        return -1;
                }

                len = *(in->str + offset);
                if(len >= 192) { /* Compression pointer */
                        offset++;
                        break;
                } else if(len > 63 || len < 0) { /* Invalid length */
                        return -1;
                } else if(len == 0) { /* End of dlabel */
                        break;
                }
                offset += len + 1;
        }

        return offset + 1;

}

/* Get a TTL that is buried in a DNS string.  We start at the beginning of
 * the DNS name, figure out how long the name is (ugh), then skip past
 * type and class to get the TTL; return -1 on error.  We don't support
 * TTLs longer than 31,536,000: One year (0x01E13380)
 *
 * Input: String we will get TTL from; offset from where we will get TTL,
 *        maximum allowed TTL (which should be 31536000 when called from
 *        another part of Deadwood), recursion depth (to stop infinite loops)
 *        Note that depth is a positive number that decrements.
 */
int32_t dw_get_a_dnsttl(dw_str *in, int offset, int32_t max, int depth) {
        int32_t out = 0, type = 0;
        uint8_t *raw = 0;

        if(dw_assert_sanity(in) == -1) {
                return -1;
        }

        if(depth <= 0) { /* End of packet/Depth exceeded */
                return max;
        }

        if(max > 31536000) {
                max = 31536000;
        }

        offset = dw_get_dn_end(in,offset);

        if(offset < 0 || (offset + 8) > in->len) {
                return -1;
        }

        raw = (in->str + offset);

        /* Get record type (A, CNAME, etc.) */
        type = ((int32_t)*(raw + 0) << 8) | ((int32_t)*(raw + 1));

        if(*(raw + 4) > 0x7f) {
                return 31536000; /* TTL out of bounds */
        }
        out = ((int32_t)*(raw + 4)<< 24) |
              ((int32_t)*(raw + 5) << 16) |
              ((int32_t)*(raw + 6) << 8) |
              ((int32_t)*(raw + 7));
        if(out < 60) {
                out = 60;
        } else if(out > max) {
                out = max;
        }

        if(type == 5 /* CNAME */) {
                offset = dw_get_dn_end(in,offset + 10);
                if(offset < 0 || offset > in->len) {
                        return -1;
                }
                return dw_get_a_dnsttl(in,offset,out,depth - 1);
        }

        return out;
}

#ifdef OTHER_STUFF
/* Given a dw_str object, where the dw_str is a raw DNS packet, determine
 * the TTL for the packet.  Note that this only looks at the TTL for the
 * first RR in a reply.  Things like "www.foo.bar. +86400 CNAME www.baz.bar. ~
 * www.baz.bar. +3600 192.168.42.102" will have the entire record cached
 * for a day (86400 seconds).
 *
 * Note that this routine is currenly not used by any other program.
 */
int32_t dw_get_ttl_from_packet(dw_str *in) {
        int offset = 0;

        if(dw_assert_sanity(in) == -1) {
                return -1;
        }

        if(in->len < 12) {
                return -1;
        }

        offset = dw_get_dn_end(in,12);

        if(offset < 0 || offset > in->len) {
                return -1;
        }

        /* BUG: This will not work with packets with only CNAME answers */
        return dw_get_a_dnsttl(in,offset,31536000,32);
}
#endif /* OTHER_STUFF */

/* Given a packet in the form put in the DNS cache (with things like type,
 * ancount, nscount, and arcount at the end of the string), tell the user how
 * many answers are in the packet. */
int32_t dw_cachepacket_to_ancount(dw_str *packet) {
        int32_t offset = 0;

        if(dw_assert_sanity(packet) == -1 || packet->len < 7) {
                return -1;
        }

        /* A cachepacket string is in the format
         * <packet><ancount><nscount><arcount><type>, where all numbers
         * are 16-bit, except for <type> which is 8-bit */

        offset = packet->len - 7;

        return dw_fetch_u16(packet,offset);
}

/* Given a raw pointer to a c-string (which can have NULLs), and a length
 * for that string, extract a dw_str object that is a cachable form of
 * the packet.  Basically:
 *      * Everything after the question is put at the beginning
 *        of the packet
 *      * This is followed by, in order, ancount, nscount, then
 *        arcount, and finally the 8-bit "type"
 */

dw_str *dw_packet_to_cache(uint8_t *raw, int len, uint8_t type) {
        int32_t ancount = 0, nscount = 0, arcount = 0;
        dw_str *hack = 0, *out = 0;
        int offset = 0;

        /* A very ugly, but fast, way to make recvfrom()'s str/len pair
         * in to a dw_str object.  */
        hack = dw_malloc(sizeof(dw_str));
        hack->max = len + 1;
        hack->len = len;
        hack->str = (uint8_t *)raw;
        hack->sane = 114;

        ancount = dw_fetch_u16(hack,6);
        nscount = dw_fetch_u16(hack,8);
        arcount = dw_fetch_u16(hack,10);

        if(ancount < 0 || nscount < 0 || arcount < 0) {
                goto catch_dw_packet_to_cache;
        }

        /* OK, hunt for the beginning of the packet */
        offset = dw_get_dn_end(hack,12);
        if(offset < 0) {
                goto catch_dw_packet_to_cache;
        }
        offset += 4;
        out = dw_substr(hack,offset,-1,7);
        dw_put_u16(out,ancount,-1);
        dw_put_u16(out,nscount,-1);
        dw_put_u16(out,arcount,-1);
        dw_addchar(type,out);
        free(hack);
        return out;

catch_dw_packet_to_cache:
        if(hack != 0) {
                free(hack);
                hack = 0;
        }
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;
}

/* Make sure a filename is sanitized; only lowercase letters, the '_',
 * the '-', and the '/' are allowed in file names; anything else becomes
 * a '_' */
int dw_filename_sanitize(dw_str *obj) {
        int index = 0;
        int look = 0;

        if(dw_assert_sanity(obj) == -1) {
                return -1;
        }

        for(index = 0; index < obj->len; index++) {
                look = *(obj->str + index);
                if((look < 'a' || look > 'z') && look != '/' &&
                   look != '-' && look != '_') {
                        *(obj->str + index) = '_';
                }
        }

        return 1;
}

/* See if a given ASCII name ends in a '.'; if it doesn't return -1, if
 * there is an unexpected error, return 0, and if it does end with '.', return
 * 1 */
int dw_ends_in_dot(dw_str *in) {
        if(dw_assert_sanity(in) == -1) {
                return 0;
        }

        if(in->len < 1) {
                return -1;
        }

        if(*(in->str + in->len - 1) != '.') {
                return -1;
        }

        return 1;
}

/* Used by dw_dnsname_convert, this part of the code converts DNS name
 * delimiters in the name (usually dots) into DNS' peculiar length
 * names.  It only does things one character at a time.
 *
 * Input: String to convert, output string to convert to, offset to
 *        convert at, place where the last delimiter was, pointer to "count"
 *        of characters in this label, character to use as delimiter
 *
 * Output: New location of delimiter
 */

int dw_dnsname_delim_convert(dw_str *in, dw_str *out, int a, int place,
        int *count, uint8_t delim) {

        if(*(in->str + a) == delim) {
                if(*count <= 0) {
                        return -1; /* bad label */
                }
                if(place < out->max) {
                        *(out->str + place) = *count;
                }
                place = a + 1;
                *count = -1;
        }
        *count += 1;
        if(a + 1 < out->max) {
                *(out->str + a + 1) = *(in->str + a);
        }
        if(*count > 63) {
                return -1; /* Label too long */
        }

        return place;
}


/* Convert an ASCII name, like "www.samiam.org." in to the DNS form of the
 * same name (\003www\006samiam\003org\000).  Output, as a new string, the
 * newly created DNS string; 0 if there is any error */
dw_str *dw_dnsname_convert(dw_str *in) {
        dw_str *out = 0;
        int c = 0, place = 0, a = 0;

        if(dw_assert_sanity(in) == -1) {
                return 0;
        }

        if(dw_ends_in_dot(in) != 1) {
                return 0;
        }

        out = dw_create(in->len + 4); /* Cushion to fit 2-byte qtype */
        if(out == 0) {
                return 0;
        }
        out->len = in->len + 1;

        if(*(in->str) == '.') {
                if(in->len != 1) {
                        goto catch_dw_dnsname_convert; /* bad label */
                }
                if(out->max > 1) {
                        *(out->str) = 0;
                }
                out->len = 1;
                return out;
        }

        for(a = 0 ; a < in->len ; a++) {
                place = dw_dnsname_delim_convert(in, out, a, place, &c, '.');
                if(place == -1) {
                        goto catch_dw_dnsname_convert;
                }
        }

        if(out->len - 1 < out->max) {
                *(out->str + out->len - 1) = 0; /* Final "dot" in hostname */
        }
        return out;

catch_dw_dnsname_convert:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* Chop off the first label of a DNS name; for example, the raw DNS form
 * of www.example.com. (\003www\007example\003com\000) becomes example.com
 * (\007example\003com\000).  This will also work with strings having data
 * after the end of the DNS name.
 *
 * This function creates a new string which needs to be freed by its caller
 */
dw_str *dw_dnslabel_chop(dw_str *in) {
        dw_str *out = 0;
        int offset = 0, a = 0, b = 0;

        if(dw_assert_sanity(in) == -1) {
                return 0;
        }

        if(in->len < 2) {
                return 0;
        }
        offset = *(in->str);
        if(offset < 1 || offset > 63) {
                return 0;
        }
        if(in->len < offset) {
                return 0;
        }

        out = dw_create(in->len - offset + 1);
        if(out == 0) {
                return 0;
        }

        a = offset + 1;
        b = 0;
        while(a < in->len && b < out->max) {
                *(out->str + b) = *(in->str + a);
                a++;
                b++;
        }

        out->len = b;
        return out;

}

/* Rotate data in a string: Given a start point and a pivot point, take all of
 * the string between the pivot point to the end, and put it where the start
 * point is.  Take all the data from the start point to the pivot point, and
 * put it at the end of the string.
 *
 * For example, if we have the string "0123456789", and the start is 3, and
 * the pivot 5, we would have the string "0125678934" after running
 * this function
 */

int dw_rotate(dw_str *in, int32_t start, int32_t pivot, int32_t end) {
        dw_str *part1 = 0, *part2 = 0, *part3 = 0;

        if(in == 0 || start >= pivot || pivot >= end || end >= in->len) {
                return -1;
        }

        part1 = dw_substr(in,start,pivot - start,1);
        if(part1 == 0) {
                return -1;
        }
        part2 = dw_substr(in,pivot,end - pivot,1);
        if(part2 == 0) {
                dw_destroy(part1);
                return -1;
        }
        part3 = dw_substr(in,end,-1,1);
        if(part3 == 0) {
                dw_destroy(part1);
                dw_destroy(part2);
                return -1;
        }
        in->len = start;
        dw_append(part2,in);
        dw_append(part1,in);
        dw_append(part3,in);
        dw_destroy(part1);
        dw_destroy(part2);
        dw_destroy(part3);
        return 1;
}

