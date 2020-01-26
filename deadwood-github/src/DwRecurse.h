/* Copyright (c) 2009-2011 Sam Trenholme
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

#ifndef __DWRECURSE_H_DEFINED__
#define __DWRECURSE_H_DEFINED__

#include "DwDnsStr.h"
#include "DwSocket.h"

typedef struct {
        dns_string *look;
        int8_t *an_types;
        int8_t *ns_types;
        int8_t *ar_types;
} dns_details;

/* RR number to an/ns/ar_type mapping:
 * If RR number <= 29, make low five bits RR number,
 * otherwise make low five bits 31 ("infinity").  A value of 30 indicates
 * "End of list"
 */
/* Some RR types relevant for Deadwood */
#define RR_A 1
#define RR_NS 2
#define RR_CNAME 5
#define RR_SOA 6
#define RR_MX 15
#define RR_AAAA 28
#define RR_ANY 255
/* These are only used for the {an/ns/ar}_types, and are not real RRs */
#define RRX_END_OF_LIST 30
#define RRX_INFINITY 31 /* Must be a power of two minus one */

/* RRX_FULL_GLUE_NS must be RRX_A_GLUE_NS | RRX_AAAA_GLUE_NS (logical or)
 * and RRX_GLUENESS_NS must be RRX_A_GLUE_NS & RRX_AAAA_GLUE_NS */
#define RRX_NS_MASK 0xfc /* 1111,1100 */
#define RRX_GLUELESS_NS 32 /* NS record without glue in the AR section */
#define RRX_A_GLUE_NS 33 /* NS record with only A (IPv4) glue */
#define RRX_AAAA_GLUE_NS 34 /* NS record with only IPv6 glue */
#define RRX_FULL_GLUE_NS 35 /* NS record with both IPv4 and IPv6 glue */

#define RRX_IGNORE 36 /* Do not use this record */
#define RRX_OOB_NS 37 /* NS record with bad bailiwick (Out-Of-Bailiwick) */
#define RRX_ANSWER_IN_AR 38 /* Answer to question in AR section */
/* These are used for linking A and AAAA glue records in the AR section of
 * a DNS reply with NS records in the NS section; the ranges for both
 * must be the same */
#define RRX_FIRST_AAAA_GLUE 64
#define RRX_LAST_AAAA_GLUE 79
#define RRX_FIRST_A_GLUE 80
#define RRX_LAST_A_GLUE 95
#define GLUE_RANGE 15

/* Some types of replies */
#define TYPE_ANSWER 0
#define TYPE_NXDOMAIN 1
#define TYPE_NOT_THERE 2 /* Non-NXDOMAIN negative reply */
#define TYPE_TRUNCATED 3 /* Non-NXDOMAIN truncated reply */
#define TYPE_TRUNCATED_NXDOMAIN 4 /* NXDOMAIN truncated reply */
#define TYPE_NS_REFER 16 /* NS referral */
#define TYPE_CNAME_REFER 17 /* CNAME referral */
#define TYPE_SERVER_TIMEOUT 18
#define TYPE_NO_USEFUL_DATA 19
#define TYPE_ERROR 20
#define TYPE_UPSTREAM_REFER 22 /* Upstream server; set RD and stop here */
#define TYPE_ANSWER_IN_AR 23 /* Answer only in AR section of reply */
/* These won't be used by Deadwood, but may be useful if I ever
 * expand DwHash to support for datatypes for elements besides
 * strings.
 */
#define TYPE_DW_STRING 32
#define TYPE_DW_HASH 33
#define TYPE_UINT8 34
#define TYPE_INT8 35
#define TYPE_UINT16 36
#define TYPE_INT16 37
#define TYPE_UINT32 38
#define TYPE_INT32 39
#define TYPE_UINT64 40
#define TYPE_INT64 41
#define TYPE_UINT128 42
#define TYPE_INT128 43
#define TYPE_FLOAT16 44 /* IEEE 754 half-percision float base-2 */
#define TYPE_FLOAT32 45 /* IEEE 754 single-percision float base-2 */
#define TYPE_FLOAT64 46 /* IEEE 754 double-percision float base-2 */
#define TYPE_FLOAT128 47 /* IEEE 754 quad-percision float base-2 */

#ifdef XTRA_STUFF
#define dw_px printf
#endif /* XTRA_STUFF */

/* Called from cache_dns_reply this determines whether the answer is
 * complete or not; if it's complete, we put it in the cache as-is; if
 * not, we put in the cache an incomplete DNS reply (NS referral),
 * and continue processing
 *
 * Input: Pointer to the cache, the query used, the reply upstream, the
 *      desired TTL for this reply
 * Output: The "type" of reply we got upstream, as follows:
 *      Type  0: Positive answer
 *      Type  1: NXDOMAIN negative reply
 *      Type  2: Non-NXDOMAIN negative reply
 *      Type 16: NS referral
 *      Type 17: CNAME referral
 */
int dwx_cache_reply(dw_hash *cache, dw_str *query, dw_str *in, int32_t ttl,
        int connection_number);

/* Given a line in the dwood3rc file with IPs, convert the line in to a NS
 * referral in the same format as created by dwx_make_ns_refer (see
 * that function for full description of format).
 *
 * Input: List of IPs as it exists in the mararc (ok dwood3rc) file;
 *        Whether this is a root (0) or upstream (1) NS record (whether
 *        to make the file byte TYPE_NS_REFER or TYPE_UPSTREAM_REFER)
 *
 * Output: The NS referral as described in the comments for
 *         dwx_make_ns_refer
 */
dw_str *dwx_ns_convert(dw_str *in, int is_upstream, dw_str *bailiwick);

ip_addr_T dwx_ns_getip(dw_str *list, dwr_rg *rng, int b);

/* Given an "address" with a NS referral (addr), and a connection which needs
 * to process the glueless referral (conn_number), create a new remote
 * connection to process the "child" glueless request while the parent
 * request waits (and has its timeout occasionally updated).
 *
 * Note that this function is responsible for freeing the allocated string
 * addr.glueless
 */
void dwx_do_ns_glueless(ip_addr_T addr, int32_t conn_number);

/* Once a glueless part of a query is finished, we have to make sure the
 * query that had to spawn the glueless query gets the NS record we looked
 * for and goes on processing the query */

void dwx_glueless_done(dw_str *query, int32_t conn_num);

/* Given a query, a socket, a remote connection_number (b), and a
 * local connection number for that remote connection (l), we get
 * a reply from the cache to send to the client in question.
 *
 * Don't confuse this with get_reply_from_cache, which does the same
 * thing with different arguments; this is a wrapper for
 * get_reply_from_cache() which is called from get_rem_udp_packet_core()
 * (as well as from dwx_make_cname_reply() )
 */
int send_reply_from_cache(unsigned char *a, ssize_t count, int b, int l);

/* Create a child query to solve an incomplete CNAME referral; private */
int dwx_do_cname_glueless(dw_str *query, int conn_num);

/* Handle having an incomplete CNAME query finished */
void dwx_incomplete_cname_done(dw_str *query, int child, int l);

/* Handle cache incomplete CNAME being solved */
void dwx_cached_cname_done(dw_str *query, int b, int l, int depth);

/* See if a CNAME referral is already cached; if so, chase the CNAME */
int dwx_cname_in_cache(dw_str *orig_query, dw_str *query,
        sockaddr_all_T *client, ip_addr_T *from_ip, int32_t local_id,
        SOCKET sock, uint16_t from_port);

/* This is used for completing incomplete CNAME referrals.
 * What this does is create a reply to give to the user, then
 * send that reply out.  This is a private method; it's only here
 * because we recursive call it from another function.
 */
int dwx_make_cname_reply(int conn_num, dw_str *query,
                dw_str *action, dw_str *answer, int depth);
#endif /* __DWRECURSE_H_DEFINED__ */
