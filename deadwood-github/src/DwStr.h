/* Copyright (c) 2007-2012 Sam Trenholme
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

#ifndef __DWSTR_DEFINED__
#define __DWSTR_DEFINED__
/* Malloc */
#include <stdlib.h>
#define dw_malloc malloc

/* Printf (used by dw_output) */
#include <stdio.h>

/* int8_t, int16_t, int32_t, int32_t, uint8_t, uint16_t, uint32_t, and
 * uint64_t as per the C99 specification */
#include <stdint.h>

/* assert(), so we can make sure there are no errors while debugging */
#include <assert.h>

typedef struct {
        uint32_t len; /* private */
        uint32_t max; /* private */
        uint8_t sane; /* private */
        uint8_t *str; } dw_str;

#define dw_copy(string) dw_substr(string,0,-1,-1)
#define dw_push_u16(number,string) dw_put_u16(string,number,-1)

#endif /* __DWSTR_DEFINED__ */
