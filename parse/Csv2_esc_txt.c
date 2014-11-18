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

#include "../libs/JsStr.h"
#include <stdio.h>

/* Generate Csv2-compatible output for TXT record from raw js_string
 * Quote ASCII sequences printed to standard output
 * Make listeral ' \'
 * Make \xXX (hex number) sequences of anything else
 */
int escape_stdout_csv2(js_string *js) {
    unsigned char this;
    int inquote = 0, counter = 0;

    /* Sanity checks */
    if(js_has_sanity(js) < 0)
        return -1;
    if(js->unit_size != 1)
        return -1;

    inquote = 0;

    while(counter < js->unit_count) {
        this = *(js->string + counter);
        if(this < 32 || this > 122 || this == '#') {
                                      /* 122 == 'z'; {|}~ are escaped since
                                         we currently don't allow the {
                                         character in csv2 zone files (to
                                         allow for future macro processing) */
            if(inquote == 1) {
                printf("\'");
                inquote = 0;
            }
            printf("\\x%02x",this);
        }
        else if(this == '\'') {
            if(inquote == 1) {
                printf("\'\\\'\'");
            }
            else {
                printf("\\\'");
            }
        }
        else {
            if(inquote == 0) {
                inquote = 1;
                printf("\'");
            }
            printf("%c",this);
        }
        counter++;
    }

    if(inquote == 1) {
        printf("\'");
    }

    return 1;
    }

/* Given a raw DNS query, show them the query in qtype:qname format, where
 * qname is a human-readable dns query */

void human_readable_dns_query(js_string *query, int hide_qtype) {
        unsigned char this;
        int counter = 0, dlen = -1, qtype, x;
        unsigned char *that;
        /* Sanity checks */
        if(js_has_sanity(query) < 0) {
                printf(":ERROR:\n");
                return;
        }
        if(query->unit_size != 1) {
                printf(":ERROR:\n");
                return;
        }

        if(query->unit_count < 2) {
                printf(":ERROR:\n");
        }

        that = query->string;
        qtype = *(that + query->unit_count - 1);
        qtype += *(that + query->unit_count - 2) << 8;
        if(hide_qtype != 1)
                printf("%d:",qtype);

        /* Print out the actual query */
        for(x=0;x<10000;x++) {
                if(counter > query->unit_count || counter < 0) {
                        printf(":ERROR:105:\n");
                        return;
                }
                dlen = *(query->string + counter);
                if(dlen == '_') {
                        printf("{STAR}");
                        if(counter == 0 &&
                                query->unit_count != 3) {
                                /* ('*' at beginning of hostname) */
                            counter++;
                            continue;
                        } else { /* '*' at end of hostname */
                            break;
                        }
                }
                if(dlen > 64 || dlen < 0) {
                        printf(":ERROR:110:%d:\n",dlen);
                        return;
                }
                if(dlen == 0) {
                        break;
                }
                while(dlen > 0) {
                        counter++;
                        if(counter > query->unit_count || counter < 0) {
                                printf(":ERROR:119:\n");
                                return;
                        }
                        this = *(query->string + counter);
                        if(this < 32 || this > 127 || this == '.' ||
                                        this ==':') {
                                printf("\\x%02x",this);
                        } else {
                                printf("%c",this);
                        }
                        dlen--;
                }
                counter++;
                printf(".");
        }

        if(counter != query->unit_count - 3) {
                printf(":ERROR:%d:%d:\n",counter,query->unit_count);
        }

}

