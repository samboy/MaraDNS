/* Copyright (c) 2009-2010 Sam Trenholme
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

#ifndef __DWDNSSTR_H_DEFINED__
#define __DWDNSSTR_H_DEFINED__

#include "DwStr.h"
#include "DwHash.h"
#include "DwDict.h"

typedef struct {
        dw_str *packet;
        uint16_t *an; /* Answers */
        uint16_t *ns; /* Name server answers */
        uint16_t *ar; /* Additional answers */
        int32_t ancount;
        int32_t nscount;
        int32_t arcount;
        uint8_t type;
} dns_string;

/* Public methods that create and destroy "DNS strings" */

/* Convert an uncompressed string in to a newly created dns_string object */
dns_string *dwc_make_dns_str(dw_str *in);

/* Destroy an already created dns_string object */
void dwc_zap_dns_str(dns_string *zap);

/* Public methods for processing the DNS cache */

/* This function can do one of two things:
 *
 * 1) Rotate DNS records in a string with a DNS answer packet
 *
 * 2) Let us know where the answer begins and ends in a DNS packet; this is
 *    used for extracting just the answer when finishing a CNAME chain in
 *    DwRecurse.c
 *
 * Case 1 is done with out_start and out_end have a value of 0; if both
 * out_start and out_end are set, we use this function to let the calling
 * function know where the RR(s) is/are in this DNS answer packet.
 */
int dwc_rr_rotate(dw_str *in, int32_t *out_start, int32_t *out_end);

/* Process an entry in the cache: Perform RR rotation, TTL aging, etc. */
void dwc_process(dw_hash *cache, dw_str *query, uint8_t action);

/* Public method for IP blacklist management */

/* See if an IP in our answer is blacklisted.  1 if it is, 0 if it's not or
 * we got an error */
int dwc_has_bad_ip(dw_str *answer, dwd_dict *blacklist_hash);

/* Convert any upper case letters in a DNS query in to lower case letters;
 * This modifies the "query" string in place */
int dwc_lower_case(dw_str *query);

#endif  /* __DWDNSSTR_H_DEFINED__ */
