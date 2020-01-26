/* Copyright (c) 2007-2010 Sam Trenholme
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

#ifndef __DWRADIOGATUN_H_DEFINED__
#define __DWRADIOGATUN_H_DEFINED__

/* This is a tiny implementation of the Radio Gatun hash function/
 * stream cipher */

/* This determines the word size we use for this particular Radio Gatun
 * implementation; DWR_WORDSIZE needs to be a multiple of 8.  Note also
 * that dwr_rng() needs to be rewritten if these values are changed. */
#define DWR_WORD uint32_t
#define DWR_WORDSIZE 32

/* These are hard coded in the Radio Gatun specification */
#define DWR_MILLSIZE 19
#define DWR_BELTROWS 3
#define DWR_BELTCOL 13
#define DWR_BELTFEED 12

/* A structure contining a RadioGatun state */
typedef struct {
        DWR_WORD *mill;
        DWR_WORD *belt;
        int32_t index;
} dwr_rg;

/* The three public functions in this routine */

/* Destroy an already created RadioGatun state */
void dwr_zap(dwr_rg *tozap);

/* Create a Radio Gatun state, using the contents of a dw_str object
 * as the key */
dwr_rg *dwr_init_rg(dw_str *obj);

/* Given a RadioGatun state, generate a 16-bit psuedo-random number. */
uint16_t dwr_rng(dwr_rg *in);

#endif /* __DWRADIOGATUN_H_DEFINED__ */
