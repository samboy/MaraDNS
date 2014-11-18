/* Copyright (c) 2004-2006 Sam Trenholme
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

#define FATAL_CSV2_READ -164
/* Headers for a csv2_read state */

typedef struct csv2_file {
        FILE *reading;
        char *filename;
        struct csv2_file *next;
} csv2_file;

typedef struct csv2_read {
        FILE *reading;
        char *filename;
        csv2_file *stack;
        char context[19];
        char chars_allowed;
        char tilde_seen;
        char tilde_handling;
        int stack_height;
        int cplace;
        int mnum;
        int mplace;
        int linenum;
        int justread;
        int32 unicode;
        int ok_to_read;
        char seen_bug_msg;
} csv2_read;

