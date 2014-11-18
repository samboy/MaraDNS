/* Copyright (c) 2002-2007 Sam Trenholme
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

#include <time.h>
#include <sys/types.h>
#include "../libs/JsStr.h"
#include "../MaraDns.h"
/* We need to make sure this code is thread-safe */
#ifndef AUTHONLY
#include <pthread.h>
#endif

/* Code which handles time stamps; we make sure we don't have any problems
   in 2038 on 32-bit systems by moving the problems up to 2112.  If anyone
   is using a 32-bit time_t in 2112, we will have to have the members of
   Rush start a revolution */

qual_timestamp the_time;
int num_tries = 0; /* Number of times we have tried, for
                      when the 32-bit time() call gives us -1 in 2106 */

#ifndef AUTHONLY
#ifdef __SUNPRO_C
pthread_mutex_t qtime_lock = {0, };
#else
pthread_mutex_t qtime_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif

/* Give an application a timestamp in a non-blocking manner */

qual_timestamp qual_get_time() {
    qual_timestamp ttime;
#ifndef AUTHONLY
    pthread_mutex_lock(&qtime_lock);
#endif
    ttime = the_time;
#ifndef AUTHONLY
    pthread_mutex_unlock(&qtime_lock);
#endif
    return ttime;
    }

/* Set the time; this should be run once a second or so.
   Return code: JS_ERROR or JS_SUCCESS, depending.
   This routine is thread-safe *only* if called from the main,
   non-threaded core. */

int qual_set_time() {
    time_t sys_time;
    /* int size; */
    qual_timestamp ttime;
    sys_time = time(0);
    /* On Y2038-complient systems, no problem */
    if(sizeof(sys_time) > 4) {
         if(sys_time == -1) {
             return JS_ERROR;
             }
         ttime = sys_time - 290805600; /* Since you asked: When the
                                        * Blake's 7 episode Gambit was
                                        * originally broadcast */
         }
    /* Ugh, 32-bit time_t */
    else {
         /* We have to handle the situtation where sys_time is -1,
            because this can be an error, or this can be 2106 */
         if(sys_time == -1 && num_tries < 3) {
             num_tries++;
             return JS_SUCCESS;
             }
         else if(sys_time == -1) {
             return JS_ERROR;
             }
         /* Here are the magic numbers you need to change on systems
            with 32-bit time_t values in 2112 (or 2106 on systems with
            an unsigned time_t):
            290805600: When the roll-over happens; right now Mar 20, 1979,
            when the Blake's 7 episode Gambit was originally broadcast.
            (this is the current lowest date this code can handle; make
             changes if travelling in your Tardis)
             2147483648: This is 2^31 (2**31); change this
                        to 4294967296 on systems with a 32-bit unsigned
                        time_t */
         else if(sys_time < 290805600) {
             /* (2 ** 32) - 290805600 */
             ttime = sys_time + 4004161696U;
             num_tries = 0;
             }
         else {
             ttime = sys_time - 290805600;
             num_tries = 0;
             }
         }
#ifndef AUTHONLY
    pthread_mutex_lock(&qtime_lock);
#endif
     the_time = ttime;
#ifndef AUTHONLY
    pthread_mutex_unlock(&qtime_lock);
#endif
     return JS_SUCCESS;
     }

