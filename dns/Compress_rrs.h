/* Copyright (c) 2002 Sam Trenholme
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

/* Data structure to store the RRs in an easy-to-use format */
typedef struct rrdesc {
    int rr_num;
    char *description;
    char tocompress;
    struct rrdesc *next;
    } rrdesc;
#define RR_HASH_SIZE 7

/* Various field types in the resource record */
#define RRSUB_DLABEL 64
#define RRSUB_TEXT 65
#define RRSUB_VARIABLE 66

