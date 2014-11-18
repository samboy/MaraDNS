/* I am writing this program to determine how setgroups works */

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

#include <unistd.h>

/* The Linux man page does not point out that the following defines
   gid_t */
#include <stropts.h>

main() {
        gid_t group;
        group = 0;
        setgroups(1,&group);
        execl("/bin/sh","sh",NULL);
        }
