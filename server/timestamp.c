/* Copyright (c) 2002, 2005 Sam Trenholme
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
#include <time.h>
#include <string.h>
#ifdef __FreeBSD__
#include <sys/time.h>
#endif
#include "MaraDNS_locale.h"
#include "../libs/JsStr.h"
#include <unistd.h>

int timestamp_type = 0;

/* Set the type of timestamp that we will display.
   Input:  The type of timestamp they want.
           0: "Timestamp: " followed by UNIX timestemp
           1: Just the UNIX timestamp
           2: A GMT timestamp in the Spanish language
           3: A local timestamp in the Spanish language
           4: A timestamp using asctime(gmtime()); usually in the English language
           5: No timestamp whatsoever is shown
           6: ISO GMT timestamp is shown
           7: ISO local timestamp is shown
   Output: JS_SUCCESS on success; JS_ERROR on error
*/

int set_timestamp(int type) {
    if(type >= 0 && type <= 128) {
        timestamp_type = type;
        return JS_SUCCESS;
        }
    return JS_ERROR;
    }

/* Display the timestamp based on the timestamp type above
   Input: None
   Output: JS_ERROR on error, JS_SUCCESS on success
   Outputs to standard output timestamp w/o carriage return
*/

int show_timestamp() {
    fflush(stdout);
    if(timestamp_type == 0) { /* Timestamp: <unix timestamp> */
        printf("%s%d ",L_TIMESTAMP,(int)time(0));
        }
    else if(timestamp_type == 1) { /* <unix timstamp> */
        printf("%d ",(int)time(0));
        }
    else if(timestamp_type == 2 || timestamp_type == 3) {
        /* Spanish language timestamp */
        struct tm *htime;
        time_t now;
        char *dow[7] = {
             "Domingo",
             "Lunes",
             "Martes",
             "Miercoles",
             "Jueves",
             "Viernes",
             "Sabado" };
        char *moy[12] = {
             "Enero",
             "Febrero",
             "Marzo",
             "Abril",
             "Mayo",
             "Junio",
             "Julio",
             "Agosto",
             "Septiembre",
             "Octubre",
             "Noviembre",
             "Diciembre" };
        now = time(0);
        if(timestamp_type == 2) { /* GMT timestamp */
            htime = gmtime(&now);
        } else { /* local timestamp */
            htime = localtime(&now);
        }
        /* Bounds check */
        if(htime->tm_mon < 0 || htime->tm_mon > 11)
            return JS_ERROR;
        if(htime->tm_wday < 0 || htime->tm_wday > 6)
            return JS_ERROR;
        /* Print it out */
        printf("%s, %d de %s, a %02d:%02d:%02d ",dow[htime->tm_wday],
            htime->tm_mday,moy[htime->tm_mon],htime->tm_hour,
            htime->tm_min,htime->tm_sec);
        if(timestamp_type == 2) /* GMT timestamp */
            printf("(UTC) ");
        }
    else if(timestamp_type == 4) { /* asctime(gmtime(t)) time */
        char ct[256];
        int count;
        time_t now;
        now = time(0);
        strncpy(ct,asctime(gmtime(&now)),100);
        for(count = 0;count < 100; count++) {
            if(ct[count] < 32) {
               ct[count] = 0;
               break;
               }
            }
        printf("%s GMT ",ct);
        }
    else if(timestamp_type == 5) { /* No timestamp whatsoever */
        }
    else if(timestamp_type == 6 || timestamp_type == 7) { /* ISO timestamp yyyy-mm-dd hh:mm:ss */
        struct tm *htime;
        time_t now;
        now = time(0);
        if(timestamp_type == 6) { /* GMT timestamp */
            htime = gmtime(&now);
        } else { /* local timestamp */
            htime = localtime(&now);
        }
        printf("%d-%02d-%02d %02d:%02d:%02d ",htime->tm_year+1900,
            htime->tm_mon+1,htime->tm_mday,htime->tm_hour,htime->tm_min,
            htime->tm_sec);
        }
    /* Feel free to add other timestamp formats here.  The
       code which gets the number for the timestamp format will
       accept any numeric value. */
    /* Default: Timestamp: <unix time> */
    else {
        printf("%s%d ",L_TIMESTAMP,(int)time(0));
        }
    return JS_SUCCESS;
    }

