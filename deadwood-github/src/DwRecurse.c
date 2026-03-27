/* Copyright (c) 2009-2022 Sam Trenholme
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

/* DwRecurse.c: Used for functions and framework so Deadwood has full
 * recursive DNS support */

#include "DwStr.h"
#include "DwStr_functions.h"
#include "DwDnsStr.h"
#include "DwHash.h"
#include "DwMararc.h"
#include "DwSys.h"
#include "DwRecurse.h"
#include "DwSocket.h"
#include "DwRadioGatun.h"
#include "DwCompress.h"
#include "DwDnsStr.h"
/* Numeric values for dwood3rc parameters */
extern int32_t key_n[];
/* List of pending remote UDP connections */
extern remote_T *rem;
extern SOCKET *b_remote;
/* DNS recursive cache */
extern dw_hash *cache;
/* Timestamp */
extern int64_t the_time;
extern int timeout_seconds;
/* Random number generator */
extern dwr_rg *rng_seed;
/* The list of active in-flight connections */
extern dw_hash *inflight;
/* Number of times to retry; needed for reset_rem() prototype */
extern int num_retries;
#ifdef MINGW
extern u_long dont_block;
#endif /* MINGW */
/* Numeric mararc parameters */
extern int_fast32_t max_ttl;
extern int_fast32_t min_ttl;
extern int maxttl_reduce_labels;
/* Maximum number of remote connections */
extern int_fast32_t maxprocs;

#ifdef OTHER_STUFF
/* Show a single character on the standard output, escaping the
 * character if it's not printable ASCII */

void dwx_stdout_char(dw_str *in, int32_t offset) {
        int8_t c = 0;

        if(in == 0 || in->str == 0 || offset > in->len) {
                return;
        }
        c = *(in->str + offset);

        if(c < 33 || c == '.' || c == '\\' || c > 126) {
                printf("\\x%02x",c & 0xff);
        } else {
                printf("%c",c);
        }
}

/* Show a human-readable form of the RR type for a record */
void dwx_stdout_rrtype(dw_str *in, int32_t offset) {
        int32_t type;

        type = dw_fetch_u16(in,offset);

        if(type < 0 || type > 65535) {
                printf("-- BAD RR TYPE -- ");
                return;
        } else if(type == RR_A) {
                printf("A ");
        } else if(type == RR_NS) {
                printf("NS ");
        } else if(type == RR_CNAME) {
                printf("CNAME ");
        } else if(type == RR_SOA) {
                printf("SOA ");
        } else if(type == RR_AAAA) {
                printf("AAAA ");
        } else {
                printf("%d ",type);
        }

}

/* Given a string with one or more DNS RRs in it, and a pointer to
 * the beginning of an RR, output on standard output a human-readable
 * form of the record in question
 */

int32_t dwx_stdout_rr(dw_str *in, int32_t offset) {
        int32_t len = 1, counter = 0;

        if(in == 0 || in->str == 0) {
                return -1;
        }

        /* Name */
        for(counter = 0; counter < 300; counter++) {
                len = *(in->str + offset);
                if(len < 0 || len > 63) { /* ERROR */
                        printf("%s"," -- ERROR --\n");
                        return -1;
                }
                offset++;
                if(len == 0) {
                        break;
                }
                if(counter > 0) {
                        printf("%c",'.');
                }
                while(len > 0) {
                        dwx_stdout_char(in,offset);
                        offset++;
                        len--;
                }
        }
        printf("%c ",'.');
        dwx_stdout_rrtype(in,offset);
        offset += 8; /* Past CLASS and TTL on to RDLENGTH */
        len = dw_fetch_u16(in,offset);
        if(len < 0 || len > 65535) {
                printf("%s\n","--ERROR GETTING RDLENGTH--\n");
                return -1;
        }
        offset += 2;
        while(len > 0) {
                dwx_stdout_char(in,offset);
                offset++;
                len--;
        }
        printf("\n");
        if(offset >= in->len) {
                return -1;
        }
        return offset;
}

/* Show an entire DNS reply on the standard output */
void dwx_stdout_dns_packet(dw_str *packet) {
        int32_t offset = 0;

        /* Quick and dirty; buggy and shows stuff after DNS data (the offsets)
         * but good enough for debugging */
        while(offset >= 0) {
                offset = dwx_stdout_rr(packet,offset);
        }
}

#endif /* OTHER_STUFF */

/* See if two strings pointing to dname objects are the
 * same.  p1: pointer to the first string; p2: pointer to the second
 * string; pmax: Maximum possible value for either string
 * 1 if they are, 0 if they are not, -1 on error */

int dwx_dname_issame(uint8_t *p1, uint8_t *p2, uint8_t *pmax1,
                uint8_t *pmax2) {
        int len = 0, counter = 0;
        uint8_t lc1, lc2; /* Lower case */

        for(counter = 0; counter < 260; counter++) {
                if(*p1 != *p2) { /* Both labels must be the same length */
                        return 0;
                }

                len = *p1;
                if(len > 63 || len < 0) {
                        return -1; /* Invalid length */
                }
                if(len == 0) {
                        return 1; /* Same */
                }

                for(;len >= 0 && counter < 260; len--) {
                        p1++;
                        p2++;
                        counter++;
                        /* Make sure we do not go out of bounds */
                        if(p1 > pmax1 || p2 > pmax2) {
                                return -1;
                        }
                        /* lc1/2 used to make label compare case insensitive */
                        lc1 = *p1;
                        lc2 = *p2;
                        if(lc1 >= 'A' && lc1 <= 'Z') { lc1 += 32; }
                        if(lc2 >= 'A' && lc2 <= 'Z') { lc2 += 32; }
                        if(lc1 != lc2) {
                                return 0;
                        }
                }
        }
        return -1;
}

/* See if two domain names embedded in a Deadwood string object are the
 * same.  1 if they are, 0 if they are not, -1 on error */
int dwx_dname_issame_dw(dw_str *in, uint32_t offset1, uint32_t offset2) {
        uint8_t *p1 = 0, *p2 = 0, *pmax = 0;

        if(dw_assert_sanity(in) == -1 ||
                        offset1 > in->len || offset2 > in->len) {
                return -1;
        }

        p1 = in->str + offset1;
        p2 = in->str + offset2;
        pmax = in->str + in->len;

        return dwx_dname_issame(p1,p2,pmax,pmax);

}

/* See if two domain name objects embedded in different Deadwood string
 * objects are the same.  1 if they are, 0 if they are not, -1 on error */
int dwx_dname_issame_2dw(dw_str *in1, uint32_t offset1, dw_str *in2,
                        uint32_t offset2) {
        uint8_t *p1 = 0, *p2 = 0, *pmax1 = 0, *pmax2 = 0;

        if(dw_assert_sanity(in1) == -1 || dw_assert_sanity(in2) == -1 ||
                        offset1 > in1->len || offset2 > in2->len) {
                return -1;
        }

        p1 = in1->str + offset1;
        p2 = in2->str + offset2;
        pmax1 = in1->str + in1->len;
        pmax2 = in2->str + in2->len;

        return dwx_dname_issame(p1,p2,pmax1,pmax2);

}

/* Destroy a dns_details object */
void dwx_zap_dns_details(dns_details *victim) {
        if(victim == 0) {
                return;
        }
        if(victim->an_types != 0) {
                free(victim->an_types);
                victim->an_types = 0;
        }
        if(victim->ns_types != 0) {
                free(victim->ns_types);
                victim->ns_types = 0;
        }
        if(victim->ar_types != 0) {
                free(victim->ar_types);
                victim->ar_types = 0;
        }
        if(victim->look != 0) {
                dwc_zap_dns_str(victim->look);
                victim->look = 0;
        }
        free(victim);
}

/* Convert a DNS rr type in to a {an/ns/ar_type} number */
int8_t dwx_rrtype_number(int32_t rr) {
        if(rr < 1) {
                return -1; /* Error */
        }
        if(rr >= RRX_END_OF_LIST) {
                return RRX_INFINITY;
        }
        /* Assertion sanity tests */
        if(RRX_INFINITY <= RRX_END_OF_LIST) {
                dw_fatal("RR_INFNITY must be greater than RRX_END_OF_LIST\n");
        }
        if((RRX_INFINITY & (RRX_INFINITY + 1)) != 0) {
                dw_fatal("RRX_INFINITY + 1 must be a power of 2\n");
        }
        return rr;
}

/* Create a blank dns_details structure */
dns_details *dwx_init_dns_details(dns_string *look) {
        dns_details *out = 0;

        if(look == 0) {
                return 0;
        }

        out = dw_malloc(sizeof(dns_details) + 1);
        if(out == 0) {
                dw_fatal("Fatal: Can not init dns_details\n");
        }
        out->look = look;
        out->an_types = dw_malloc((sizeof(int8_t) * look->ancount) + 1);
        out->ns_types = dw_malloc((sizeof(int8_t) * look->nscount) + 1);
        out->ar_types = dw_malloc((sizeof(int8_t) * look->arcount) + 1);
        if(out->an_types == 0 || out->ns_types == 0 || out->ar_types == 0) {
                dw_fatal("Fatal: Can not init dns_details types\n");
        }
        out->an_types[0] = 0;
        out->ns_types[0] = 0;
        out->ar_types[0] = 0;
        return out;
}

#ifdef XTRA_STUFF
/* Show a dns_details string on the standard output; used for debugging
 * purposes */

void dwx_stdout_dns_details(dns_details *view) {
        int counter = 0;
        if(view == 0) {
                printf("NULL dns_details\n");
                return;
        }
        if(view->look == 0) {
                printf("NULL dns_details look member\n");
                return;
        }
        for(counter = 0; counter < view->look->ancount; counter++) {
                printf("view->an_types[%d] = %d\n",counter,
                                view->an_types[counter]);
        }
        for(counter = 0; counter < view->look->nscount; counter++) {
                printf("view->ns_types[%d] = %d\n",counter,
                                view->ns_types[counter]);
        }
        for(counter = 0; counter < view->look->arcount; counter++) {
                printf("view->ar_types[%d] = %d\n",counter,
                                view->ar_types[counter]);
        }
}
#endif /* XTRA_STUFF */

/* Take a DNS packet and pull out the queries.  We want to know the record
 * type for each response in the packet, and whether a given response has the
 * same name as our original query */

dns_details *dwx_create_dns_details(dw_str *in, dw_str *query) {
        dns_string *look = 0;
        dns_details *out = 0;
        int counter = 0;

        if(in == 0) {
                return 0;
        }

        look = dwc_make_dns_str(in);
        if(look == 0) {
                goto catch_dwx_create_dns_details;
        }
        out = dwx_init_dns_details(look);
        if(out == 0) {
                goto catch_dwx_create_dns_details;
        }

        for(counter = 0; counter < look->ancount * 2; counter+=2) {
                out->an_types[(counter >> 1)] =
                     dwx_rrtype_number(dw_fetch_u16(in,look->an[counter + 1]));
        }
        for(counter = 0; counter < look->nscount * 2; counter+=2) {
                out->ns_types[(counter >> 1)] =
                     dwx_rrtype_number(dw_fetch_u16(in,look->ns[counter + 1]));
        }
        for(counter = 0; counter < look->arcount * 2; counter+=2) {
                out->ar_types[(counter >> 1)] =
                     dwx_rrtype_number(dw_fetch_u16(in,look->ar[counter + 1]));
        }

        return out;

catch_dwx_create_dns_details:
        if(look != 0 && (out == 0 || out->look != look)) {
                dwc_zap_dns_str(look);
        }
        if(out != 0) {
                dwx_zap_dns_details(out);
        }
        return 0;
}

/* 2022 note: This is for ANY queries.  Here in the 2020s, as per RFC8482, we
 * should just ignore and discard ANY queries, and never send them out */
int dwx_check_answer_section_any(dw_str *in, dw_str *query,dns_details *view) {
        int32_t qtype = 0; /* The type of record they want in the query */
        int counter = 0, cname_chain = 0, use_cname = 1;

        qtype = dw_fetch_u16(query,-1);
        if(qtype != RR_ANY) {
                return -1;
        }
        if(view == 0 || view->look == 0 || view->look->an == 0) {
                return -1;
        }

        for(counter = 0; counter < view->look->ancount * 2; counter +=2) {
                if(dwx_dname_issame_2dw(query,0,
                                in,view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) !=
                                RR_CNAME) {
                                /* Direct answer for our query */
                        use_cname = 0; /* No CNAMEs after direct answer */
                } else if(cname_chain == 0 &&
                                (counter >> 1) == cname_chain && use_cname == 1
                                && dwx_dname_issame_2dw(query,0,in,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                RR_CNAME) { /* First answer a CNAME */
                        cname_chain++;
                } else if(cname_chain > 0 &&
                                (counter >> 1) == cname_chain && use_cname == 1
                                && dwx_dname_issame_dw(in,
                                view->look->an[((cname_chain - 1) * 2) + 1]
                                + 10 /* 10: TYPE, CLASS, TTL, RDLENGTH */,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                RR_CNAME) { /* CNAME chain member */
                        cname_chain++;
                } else if(cname_chain > 0 &&
                                dwx_dname_issame_dw(in,
                                view->look->an[((cname_chain - 1) * 2) + 1]
                                + 10 /* 10: TYPE, CLASS, TTL, RDLENGTH */,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) !=
                                RR_CNAME) {
                        /* Answer after CNAME chain */
                        use_cname = 0; /* Answer found; no more CNAMEs */
                } else { /* Not an answer to our query nor a CNAME chain */
                        view->an_types[(counter >> 1)] = RRX_IGNORE;
                }
        }

        return 1;
}

/* Look at the responses in the answer section.  The only allowed responses
 * are responses where:
 *
 * 1) It is a direct reply to our query
 *
 * 2) It is a CNAME reply to our query
 *
 * 3) It is a CNAME or direct reply to where the immediate previous CNAME
 *    pointed to
 *
 * DNS replies in the answer section that do not meet the above
 * criteria in the AN section are marked RRX_IGNORE
 *
 * This function has the side effect of handling the unusual case where the
 * DNS stub resolver asks for a CNAME answer by ignoring everything after the
 * first link in a CNAME chain in the answer.
 *
 * Output: -1 on error, 1 on success
 */

int dwx_check_answer_section(dw_str *in, dw_str *query, dns_details *view,
                             dw_str *bailiwick) {
        int32_t qtype = 0; /* The type of record they want in the query */
        int counter = 0, cname_chain = 0, use_cname = 1, offset = 0;

        qtype = dw_fetch_u16(query,-1);
        if(qtype == -1) {
                return -1;
        }
        if(qtype == RR_ANY) {
                return dwx_check_answer_section_any(in, query, view);
        }
        if(view == 0 || view->look == 0 || view->look->an == 0) {
                return -1;
        }

        for(counter = 0; counter < view->look->ancount * 2; counter +=2) {
                if(dwx_dname_issame_2dw(query,0,
                                in,view->look->an[counter]) == 1 &&
                                offset >= 0 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                qtype) { /* Direct answer for our query */
                        offset++;
                        use_cname = 0; /* No CNAMEs after direct answer */
                } else if(cname_chain == 0 && qtype != RR_CNAME &&
                                offset == cname_chain &&
                                use_cname == 1 &&
                                dwx_dname_issame_2dw(query,0,in,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                RR_CNAME) { /* First answer a CNAME */
                        /* While it's not a security hole in Deadwood to
                         * use out of bailiwick replies in CNAME chains,
                         * poorly operated domains sometimes have out of
                         * bailiwick records in their DNS database, and
                         * since most DNS servers discard out of bailiwick
                         * CNAME records, they can very well point to the
                         * wrong IP. */
                        if(dwx_string_in_bailiwick(in,
                                view->look->an[1]+10,/* What CNAME points to */
                                bailiwick, 0) != 1) {
                            offset = -2;
                            cname_chain = -1;
                            use_cname = 0;
                        } else {
                          offset++;
                          cname_chain++;
                        }
                } else if(cname_chain > 0 && qtype != RR_CNAME &&
                                offset == cname_chain &&
                                use_cname == 1 &&
                                dwx_dname_issame_dw(in,
                                view->look->an[((cname_chain - 1) * 2) + 1]
                                + 10 /* 10: TYPE, CLASS, TTL, RDLENGTH */,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                RR_CNAME) { /* CNAME chain member */
                        if(dwx_string_in_bailiwick(in,
                                /* What name the CNAME record points to */
                                view->look->an[(cname_chain * 2) + 1]+10,
                                bailiwick, 0) != 1) {
                            offset = -2;
                            cname_chain = -1;
                            use_cname = 0;
                        } else {
                          offset++;
                          cname_chain++;
                        }
                } else if(cname_chain > 0 && qtype != RR_CNAME &&
                                dwx_dname_issame_dw(in,
                                view->look->an[((cname_chain - 1) * 2) + 1]
                                + 10 /* 10: TYPE, CLASS, TTL, RDLENGTH */,
                                view->look->an[counter]) == 1 &&
                                dw_fetch_u16(in,view->look->an[counter + 1]) ==
                                qtype) { /* Answer after CNAME chain */
                        offset++;
                        use_cname = 0; /* Answer found; no more CNAMEs */
                } else { /* Not an answer to our query nor a CNAME chain */
                        view->an_types[(counter >> 1)] = RRX_IGNORE;
                }
        }

        return 1;
}

/* A DNS packet with an answer section has all records in the NS
 * and AR section ignored.  This modifies view and outputs -1 on
 * error, 1 on success. */

int dwx_if_an_then_no_ns_nor_ar(dns_details *view) {
        int counter = 0;
        if(view == 0 || view->look == 0 || view->ns_types == 0 ||
                        view->ar_types == 0) {
                return -1;
        }

        if(view->look->ancount == 0) {
                return 1; /* No answer (AN) section; nothing to do */
        }

        for(counter = 0; counter < view->look->nscount * 2; counter += 2) {
                view->ns_types[(counter >> 1)] = RRX_IGNORE;
        }
        for(counter = 0; counter < view->look->arcount * 2; counter += 2) {
                view->ar_types[(counter >> 1)] = RRX_IGNORE;
        }

        return 1;
}

/* Clean up the NS and AR section.  Only NS and SOA records are used in the NS
 * section; only A and AAAA records are used in the AR (glue) section.
 * -1 on error; 1 on success */

int dwx_cleanup_ns_ar(dns_details *view) {
        int counter = 0;

        if(view == 0 || view->look == 0 || view->ns_types == 0 ||
                        view->ar_types == 0) {
                return -1;
        }

        for(counter = 0; counter < view->look->nscount * 2; counter += 2) {
                if(view->ns_types[(counter >> 1)] != RR_NS &&
                   view->ns_types[(counter >> 1)] != RR_SOA) {
                        view->ns_types[(counter >> 1)] = RRX_IGNORE;
                }
        }
        for(counter = 0; counter < view->look->arcount * 2; counter += 2) {
                if(view->ar_types[(counter >> 1)] != RR_A &&
                   view->ar_types[(counter >> 1)] != RR_AAAA) {
                        view->ar_types[(counter >> 1)] = RRX_IGNORE;
                }
        }
        return 1;
}

#ifdef XTRA_STUFF
/* This is scaffolding during the development cycle: Create a
 * "\0" string (DNS root) to use as a bailiwick */

dw_str *dwx_example_root_bailiwick() {
        dw_str *out;
        out = dw_create(3);
        if(out == 0) {
                return 0;
        }
        out->len = 1;
        *(out->str) = 0;
        return out;
}

/* And, likewise, make a dummy ".org" ("\3org\0") bailiwick */

dw_str *dwx_example_org_bailiwick() {
        dw_str *out;
        out = dw_create(7);
        if(out == 0) {
                return 0;
        }
        out->len = 5;
        *(out->str + 0) = 3;
        *(out->str + 1) = 'o';
        *(out->str + 2) = 'r';
        *(out->str + 3) = 'g';
        *(out->str + 4) = 0;
        return out;
}
#endif /* XTRA_STUFF */

/* Given a string with a domain name we are inspecting, the offset in
 * the string with the beginning of the domain name, the baliwick, and our
 * original query, see if the string is in bailiwick.
 *
 * Output:
 *
 * -1: Error
 *
 * 0: Not in bailiwick
 *
 * 1: In bailiwick
 *
 *
 * In more detail:
 *
 * Part 1:
 *
 * Look at what the NS record points at and the query sent by the client.
 *
 * If they are the same, go to the next part of the bailiwick check.
 *
 * Remove one label from our query (make www.example.com example.com or
 * make example.com simply .com, or make .com the name of the root server)
 *
 * See if they are the same; if they are we pass this part; if not, keep
 * lopping off labels until we match or the query is less than zero-length
 * (fail, exit routine)
 *
 * Part two:
 *
 * Let's get the Bailiwick for this query (if this NS record was told by
 * us upstream that these are records for .org; the bailiwick is .org; if
 * this is a root server, tha bailiwick is any querty; if this NS record was
 * told by us upstream this is for example.com, the bailiwick is example.com,
 * and so on)
 *
 * Let's remove one label from the NS record given to us
 *
 * Let's compare the NS record with the bailiwick this NS record has
 *
 * If they are the same, we're gold and have passed the bailiwick check
 *
 * Otherwise, remove labels from the NS record and compare with the
 * bailiwick until we either get a match or the truncated NS record is
 * shorter than our bailiwick. If we get a match, it's gold, otherwise
 * it's out-of-bailiwick
 */

/* Part one of the bailiwick check: Make sure the NS record is part of
 * our original query; in other words, make sure they're not giving us
 * NS records for paypal.com when we ask for malware.com.  If we ask for
 * makware.com, they're allowed to give us .com and malware.com NS records,
 * but not paypal.com
 *
 * Return 1 if in bailiwick and we can proceed; otherwise stop.
 *
 */
int dwx_string_bailiwick_query(dw_str *in, int32_t offset, dw_str *query) {

        int32_t q_offset = 0; /* Offset in query string */
        int noloop = 0;
        int32_t len = 0;

        if(query == 0 || in == 0) {
                return 0; /* Error */
        }

        if(query->len <= 2) {
                return 0; /* Error */
        }

        if(dwx_dname_issame_2dw(in,offset,query,0) == 1) {
                return 1; /* NS records same as name asked for */
        }

        /* Lop of names from the top of our query until it matches the
         * NS record offered; if no match is found, it is OOB */
        while(noloop < 1024 && *(query->str + q_offset) != 0) {

                /* Lop one label off of the query we asked for */
                len = *(query->str + q_offset);
                if(len < 0 || len > 63) {
                        return 0; /* Error */
                }
                q_offset += len;
                q_offset++;

                if(q_offset < 0 || q_offset >= query->len) {
                        return 0; /* Error */
                }

                if(dwx_dname_issame_2dw(in,offset,query,q_offset) == 1) {
                        return 1; /* NS record same as truncated query */
                }

                noloop++;
        }

        return 0; /* No match found */
}

/* Part two of the bailiwick check:
 *
 * See if the NS record we have is a subname (longer) for the bailiwick
 * we allow this query to have
 *
 */
int dwx_string_bailiwick_top(dw_str *in, int32_t offset, dw_str *bailiwick) {

        int noloop = 0;
        int32_t len = 0;

        if(bailiwick == 0 || in == 0) {
                return 0; /* Error */
        }

        if(offset < 0 || offset >= in->len) {
                return 0;
        }

        while(noloop < 1024 && *(in->str + offset) != 0) {

                len = *(in->str + offset);
                if(len < 0 || len > 63) {
                        return 0; /* Error */
                }

                offset += len;
                offset++;

                if(offset < 0 || offset >= in->len) {
                        return 0;
                }

                if(dwx_dname_issame_2dw(in,offset,bailiwick,0) == 1) {
                        return 1; /* In bailiwick */
                }

                noloop++;
        }

        return 0; /* No match found */
}

int dwx_string_in_bailiwick(dw_str *in, int32_t offset, dw_str *bailiwick,
                dw_str *query) {

        if(query != 0 && dwx_string_bailiwick_query(in,offset,query) != 1) {
                return 0;
        }

        if(dwx_string_bailiwick_top(in,offset,bailiwick) != 1) {
                return 0;
        }

        return 1;
}

/* Verify the bailiwick of the NS records.  A NS record is marked
 * out-of-bailiwick if it does not have at least one domain label more
 * than the current bailick (NS referrals must always bring us closer to
 * the answer we seek) or if its suffix is not the same as the name we
 * are actually seeking (we don't allow NS referrals to paypal.com when
 * looking up hackersite.example.com) */

int dwx_check_bailiwick_ns_section(dns_details *view, dw_str *query,
                dw_str *bailiwick) {
        int ns = 0;
        dw_str *in = 0;
        dns_string *look = 0;
        int max = 0;

        if(view == 0 || view->look == 0 || view->ns_types == 0 || query == 0) {
                return -1;
        }

        look = view->look;

        if(look->nscount <= 0) {
                return 1; /* No NS records */
        }
        if(look->nscount > GLUE_RANGE) {
                max = GLUE_RANGE;
        } else {
                max = look->nscount;
        }

        in = look->packet;
        if(in == 0) {
                return -1;
        }
        for(ns = 0; ns < max * 2; ns += 2) { /* For each NS record */
                /* Check its bailiwick */
                if(dwx_string_in_bailiwick(in,look->ns[ns],bailiwick,
                                query) != 1) {
                        view->ns_types[(ns >> 1)] = RRX_OOB_NS;
                }
        }
        return 1;
}

/* Make a single link between a NS record in the NS section and a glue
 * record in the AR section */
void dwx_make_link(dns_details *view, int ns, int ar) {
        if(view == 0 || view->look == 0) {
                return;
        }
        if((ns >> 1) > GLUE_RANGE) {
                return;
        }

        /* The NS record us marked as having glue */
        if(view->ar_types[(ar >> 1)] == RR_A ||
           (view->ar_types[(ar >> 1)] >= RRX_FIRST_A_GLUE &&
            view->ar_types[(ar >> 1)] <= RRX_LAST_A_GLUE)) {
                view->ns_types[(ns >> 1)] |= RRX_A_GLUE_NS;
        } else if(view->ar_types[(ar >> 1)] == RR_AAAA ||
           (view->ar_types[(ar >> 1)] >= RRX_FIRST_AAAA_GLUE &&
            view->ar_types[(ar >> 1)] <= RRX_LAST_AAAA_GLUE)) {
                view->ns_types[(ns >> 1)] |= RRX_AAAA_GLUE_NS;
        }

        /* The AR record has the glue record marked */
        if(view->ar_types[(ar >> 1)] == RR_A) {
                view->ar_types[(ar >> 1)] = RRX_FIRST_A_GLUE + (ns >> 1);
        } else if(view->ar_types[(ar >> 1)] == RR_AAAA) {
                view->ar_types[(ar >> 1)] = RRX_FIRST_AAAA_GLUE + (ns >> 1);
        }

}

/* Link NS records in the NS section of a DNS packet to their corresponding
 * A and AAAA glue records in the AR section.   Only do this *after*
 * confirming the NS records have acceptable bailiwick */

int dwx_link_ns_records(dns_details *view) {
        int ns = 0; /* The NS record we are looking at */
        int ar = 0; /* The AR (glue) record we are looking at */
        int max = 0;
        dw_str *in = 0;
        dns_string *look = 0;

        if(view == 0 || view->look == 0) {
                return -1;
        }

        look = view->look;

        if(look->nscount > GLUE_RANGE) { /* Cap on NS records */
                max = GLUE_RANGE;
        } else {
                max = look->nscount;
        }

        in = look->packet;

        for(ns = 0; ns < max * 2; ns += 2) { /* For each NS record */
                if(view->ns_types[(ns >> 1)] == RR_NS) {
                        view->ns_types[(ns >> 1)] = RRX_GLUELESS_NS;
                        for(ar = 0; ar < view->look->arcount * 2; ar += 2) {
                                if(dwx_dname_issame_dw(in,
                                   look->ns[ns + 1] + 10,
                                   look->ar[ar]) == 1) {
                                        dwx_make_link(view,ns,ar);
                                }
                        }
                }
        }
        return 1;
}

/* Given a dw_str object with one or more DNS packets, take
 * a single DNS packet and extract a single DNS packet starting
 * at the specified offset, returning a newly created dw_str object
 * with the single DNS packet (Or 0/NULL on any error)
 */

dw_str *dwx_get_1_dns_rr(dw_str *in, int32_t offset) {
        int32_t end = 0, rdlength = 0;
        dw_str *out = 0;

        if(in == 0 || offset < 0 || offset > in->len) {
                goto catch_dwx_get_1_dns_rr;
        }

        end = dw_get_dn_end(in, offset); /* End of name for packet */
        if(end == -1 || end < offset) {
                goto catch_dwx_get_1_dns_rr;
        }
        if(dw_fetch_u16(in,end + 2) != 1) { /* CLASS must be 1 */
                goto catch_dwx_get_1_dns_rr;
        }
        rdlength = dw_fetch_u16(in, end + 8);
        if(rdlength < 0) {
                goto catch_dwx_get_1_dns_rr;
        }

        end += 10 + rdlength; /* End of packet */
        if(end <= offset) {
                goto catch_dwx_get_1_dns_rr;
        }

        out = dw_substr(in,offset,end - offset,1);
        if(out == 0) {
                goto catch_dwx_get_1_dns_rr;
        }
        return out;

catch_dwx_get_1_dns_rr:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* Grab a single DNS name from a string.
 *
 * Input: String (dw_str) and offset where the DNS name begins in the
 *        string.
 *
 * Output: Newly created dw_str object with the DNS name in question
 */

dw_str *dwx_get_dns_string(dw_str *in, int32_t offset) {
        int32_t end = 0;

        if(in == 0 || offset < 0 || offset > in->len) {
                return 0;
        }

        end = dw_get_dn_end(in,offset);
        if(end < offset) {
                return 0;
        }

        return dw_substr(in,offset,end-offset,1);
}

/* Given a fully processed dns_details object which is for an incomplete
 * CNAME chain referral, create a special "incomplete CNAME chain" string
 * to store in the cache
 *
 * A CNAME referral is stored as a list of DNAME records in the
 * following format:
 *
 * {length}{DNAME}
 *
 * {length} is an unsigned 16-bit integer. {DNAME} is a raw DNS name
 * (samiam.org will be \x06samiam\x03org\x00). After this list, we
 * have the following three bytes
 *
 * {final offset}\0x11
 *
 * The final offset is an unsigned 16-bit integer with a pointer to
 * the beginning of the final DNAME entry.
 */

dw_str *dwx_make_cname_refer(dns_details *view) {
        int32_t offset = 0, final_offset = 0;
        dw_str *out = 0, *tmp = 0;
        int counter = 0;

        if(view == 0 || view->look == 0 || view->an_types == 0) {
                goto catch_dwx_make_cname_refer;
        }

        out = dw_create(257 * view->look->ancount);
        if(out == 0) {
                goto catch_dwx_make_cname_refer;
        }

        for(counter = 0; counter < view->look->ancount * 2; counter += 2) {
                if(view->an_types[(counter >> 1)] == RRX_IGNORE) {
                        continue;
                }
                if(view->an_types[(counter >> 1)] != RR_CNAME) {
                        goto catch_dwx_make_cname_refer;
                }
                offset = view->look->an[counter + 1];
                offset += 10;
                tmp = dwx_get_dns_string(view->look->packet,offset);
                if(tmp == 0) {
                        goto catch_dwx_make_cname_refer;
                }
                if(tmp->len > 256) {
                        goto catch_dwx_make_cname_refer;
                }
                final_offset = out->len;
                if(dw_push_u16(tmp->len,out) == -1) {
                        goto catch_dwx_make_cname_refer;
                }
                if(dw_append(tmp,out) == -1) {
                        goto catch_dwx_make_cname_refer;
                }
                dw_destroy(tmp);
                tmp = 0;
        }
        if(dw_push_u16(final_offset,out) == -1 ||
           dw_addchar(TYPE_CNAME_REFER,out) == -1) {
                goto catch_dwx_make_cname_refer;
        }
        return out;

catch_dwx_make_cname_refer:
        if(out != 0) {
                dw_destroy(out);
        }
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        return 0;
}

/* Make a single glued NS record to add to the list of NS referrals */
dw_str *dwx_make_nsglue(dw_str *in, int32_t toffset, int type) {
        int otype = 0, len = 0;
        dw_str *out = 0;

        if(in == 0) {
                return 0;
        }

        if(type >= RRX_FIRST_A_GLUE && type <= RRX_LAST_A_GLUE) {
                otype = RR_A;
                len = 4;
        } else if(type >= RRX_FIRST_AAAA_GLUE && type <= RRX_LAST_AAAA_GLUE) {
                otype = RR_AAAA;
                len = 16;
        } else {
                return 0;
        }

        out = dw_create(len + 2);
        if(out == 0) {
                return 0;
        }

        if(dw_addchar(otype,out) == -1) {
                dw_destroy(out);
                return 0;
        }

        if(dw_substr_append(in,toffset,len,out) == -1) {
                dw_destroy(out);
                return 0;
        }

        return out;
}

/* Make a single glueless NS record to add to the list of NS referrals */
dw_str *dwx_make_nsglueless(dw_str *in, int32_t offset) {
        dw_str *out = 0, *tmp = 0;
        int32_t rdlength = 0;

        if(in == 0) {
                return 0;
        }

        rdlength = dw_fetch_u16(in,offset);
        offset += 2;
        tmp = dwx_get_dns_string(in,offset);
        if(tmp == 0) {
                return 0;
        }
        if(tmp->len != rdlength) {
                dw_destroy(tmp);
                return 0;
        }

        out = dw_create(rdlength + 5);
        if(out == 0) {
                dw_destroy(tmp);
                return 0;
        }

        if(dw_addchar(RR_NS,out) == -1 ||
           dw_push_u16(rdlength,out) == -1 ||
           dw_append(tmp,out) == -1) {
                dw_destroy(out);
                dw_destroy(tmp);
                return 0;
        }

        dw_destroy(tmp);
        return out;
}

/* Add all of the glued records in a NS referral */
int dwx_make_ns_refer_glued(dns_details *view, dw_str *out, uint16_t *offset,
                int *onumber) {
        dw_str *tmp = 0;
        int counter = 0;
        int32_t toffset = 0;

        for(counter = 0; counter < view->look->arcount * 2; counter += 2) {
                toffset = view->look->ar[counter + 1];
                toffset += 10;
                if((view->ar_types[(counter >> 1)] >= RRX_FIRST_A_GLUE &&
                    view->ar_types[(counter >> 1)] <= RRX_LAST_A_GLUE) ||
                   (view->ar_types[(counter >> 1)] >= RRX_FIRST_AAAA_GLUE &&
                    view->ar_types[(counter >> 1)] <= RRX_LAST_AAAA_GLUE)) {
                        offset[*onumber] = out->len;
                        (*onumber)++;
                        tmp = dwx_make_nsglue(view->look->packet,toffset,
                                view->ar_types[(counter >> 1)]);
                        if(dw_append(tmp,out) == -1 ||
                           *onumber > (GLUE_RANGE * 2) + 1) {
                                dw_destroy(tmp);
                                return -1;
                        }
                        dw_destroy(tmp);
                        tmp = 0;
                }
        }

        return 1;
}

/* Create a NS referral string with the name this NS referral points to
 * as the first part of the packet.  The name the NS referral points to
 * is the longest in-bailiwick NS referral in the packet we received.
 */

dw_str *dwx_find_ns_referral(dns_details *view, int32_t out_len) {
        int counter = 0, max = 0, max_num = 0;
        int32_t len = 0;
        dw_str *out = 0;

        if(view == 0 || view->look == 0 || view->ns_types == 0 ||
                        view->look->ns == 0) {
                return 0;
        }

        /* Find the longest in-bailiwick NS name (the DNS space the NS
         * record covers) */
        for(counter = 0; counter < view->look->nscount; counter++) {
                if(view->ns_types[counter] != RRX_IGNORE &&
                   view->ns_types[counter] != RRX_OOB_NS) {
                        len = dw_get_dn_end(view->look->packet,
                                view->look->ns[(counter * 2)]) -
                                view->look->ns[(counter * 2)];
                        if(len > max) {
                                max = len;
                                max_num = counter;
                        }
                }
        }

        out = dw_substr(view->look->packet,view->look->ns[max_num * 2],
                        max,out_len + 3);
        return out;
}

/* Once dwx_make_ns_refer() verifies the sanity of "view" and gives us
 * the length of the ns referral string, do the process of making the
 * actual ns referral string */

dw_str *dwx_make_ns_refer_proc(dns_details *view, int32_t out_len) {
        uint16_t offset[(GLUE_RANGE * 2) + 3];
        int counter = 0, onumber = 0;
        int32_t toffset = 0;
        dw_str *out = 0, *tmp = 0;

        out = dwx_find_ns_referral(view,out_len);
        if(out == 0) {
                return 0;
        }

        if(dwx_make_ns_refer_glued(view,out,offset,&onumber) == -1) {
                goto catch_dwx_make_ns_refer_proc;
        }

        /* Now glueless NS referrals */
        for(counter = 0; counter < view->look->nscount * 2; counter += 2) {
                if(view->ns_types[(counter >> 1)] == RRX_GLUELESS_NS) {
                        offset[onumber] = out->len;
                        onumber++;
                        toffset = view->look->ns[counter + 1];
                        toffset += 8;
                        tmp = dwx_make_nsglueless(view->look->packet,toffset);
                        if(dw_append(tmp,out) == -1 ||
                           onumber > (GLUE_RANGE * 2) + 1) {
                                goto catch_dwx_make_ns_refer_proc;
                        }
                        dw_destroy(tmp);
                        tmp = 0;
                }
        }

        for(counter = 0; counter < onumber; counter++) { /* Offsets */
                if(dw_push_u16(offset[counter],out) == -1) {
                        goto catch_dwx_make_ns_refer_proc;
                }
        }
        if(dw_addchar(onumber,out) == -1 || /* Number of NS records */
           dw_addchar(TYPE_NS_REFER,out) == -1) { /* NS referral type */
                goto catch_dwx_make_ns_refer_proc;
        }

        return out;

catch_dwx_make_ns_refer_proc:
        if(out != 0) {
                dw_destroy(out);
        }
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        return 0;
}

/* Given a fully processed dns_details object which is for an incomplete
 * NS referral, create a special "NS referral" string to store in the cache
 *
 * A NS referral starts off with a dlabel describing the DNS space this
 * particular NS record covers.  This is followed by a list of the following:
 *
 * {type (A, AAAA, or name)}{data}
 *
 * Type in an eight-bit number which can be either A (1), AAAA (28),
 * or name (2). The type determines the data; an "A" NS referral is a 4-byte
 * IPv4 IP, an "AAAA" NS referral is a 16-byte IPv6 IP, and a "name" type
 * will be a DNAME with the glueless NS referral. (Stored as {length}{name},
 * with {length} being a 16-bit integer).
 *
 * After all of the NS referrals, we have a list of unsigned 16-bit
 * offsets pointing to the NS referrals in the string, followed by a signed
 * 8-bit number with the number of NS referrals (Deadwood ignores NS records
 * after the first 16 records), followed by the \x10 (16) byte indicating that
 * this record is a NS referral.
 */

dw_str *dwx_make_ns_refer(dns_details *view) {
        int32_t offset = 0, rdlength = 0;
        int counter;
        int32_t out_len = 0;

        if(view == 0 || view->look == 0 || view->ar_types == 0 ||
                        view->ns_types == 0 || view->look->ar == 0 ||
                        view->look->ns == 0) {
                return 0;
        }

        /* Find out how long our string will be */
        /* Glued answers */
        for(counter = 0; counter < view->look->arcount * 2; counter += 2) {
                if(view->ar_types[(counter >> 1)] >= RRX_FIRST_A_GLUE &&
                   view->ar_types[(counter >> 1)] <= RRX_LAST_A_GLUE) {
                        out_len += 8; /* 4: IP; 1: Type; 2: Offset; 1: Pad */
                }
                if(view->ar_types[(counter >> 1)] >= RRX_FIRST_AAAA_GLUE &&
                   view->ar_types[(counter >> 1)] <= RRX_LAST_AAAA_GLUE) {
                        out_len += 20; /* 16: IP; 1: Type; 2: Offset; 1: Pad */
                }
        }
        /* Glueless answers */
        for(counter = 0; counter < view->look->nscount * 2; counter += 2) {
                if(view->ns_types[(counter >> 1)] == RRX_GLUELESS_NS) {
                        offset = view->look->ns[counter + 1];
                        offset += 8;
                        rdlength = dw_fetch_u16(view->look->packet,offset);
                        if(rdlength <= 0) {
                                return 0;
                        }
                        out_len += rdlength + 6;
                }
        }

        return dwx_make_ns_refer_proc(view, out_len);

}

/* Copy over all of the records in a given section of a DNS packet (AN,
 * NS, or AR).  This is used by dwx_remake_complete_reply() to copy
 * over the records in to the string out which are usable (which aren't
 * RRX_IGNORE and RRX_OOB_NS records)
 */

int dwx_copy_over_section(dw_str *out, dw_str *packet, int8_t *types,
                uint16_t *section, int32_t count, uint16_t *offsets,
                int32_t *out_count, int *this_offset, int max_offset) {
        int counter = 0;
        dw_str *tmp = 0;

        if(out == 0 || types == 0 || section == 0 || offsets == 0) {
                goto catch_dwx_copy_over_section;
        }

        for(counter = 0; counter < count; counter++) {
                if(types[counter] == RRX_IGNORE ||
                   types[counter] == RRX_OOB_NS) {
                        continue;
                }
                tmp = dwx_get_1_dns_rr(packet,section[counter * 2]);
                if(tmp == 0 || *this_offset + 1 > max_offset) {
                        goto catch_dwx_copy_over_section;
                }
                offsets[*this_offset] = out->len;
                offsets[(*this_offset) + 1] = out->len +
                        (section[(counter * 2) + 1] - section[counter * 2]);
                (*this_offset) += 2;
                if(dw_append(tmp,out) == -1) {
                        goto catch_dwx_copy_over_section;
                }
                (*out_count)++;
                dw_destroy(tmp);
                tmp = 0;
        }

        return 1;

catch_dwx_copy_over_section:
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        return -1;
}

/* Make the footer (offsets, an/ns/ar count, type) to put at the end of
 * a recreated complete DNS reply. */

int dwx_remake_footer(dw_str *out, uint16_t *offsets, uint16_t an,
                uint16_t ns, uint16_t ar, int type) {
        int counter = 0;

        for(counter = 0; counter < (an + ns + ar) * 2;
                        counter++) { /* Add offsets */
                if(dw_push_u16(offsets[counter],out) == -1) {
                        return -1;
                }
        }

        /* Add the ancount, nscount, arcount, and 1-byte type */
        if(dw_push_u16(an,out) == -1 ||
           dw_push_u16(ns,out) == -1 ||
           dw_push_u16(ar,out) == -1 ||
           dw_addchar(type,out) == -1) {
                return -1;
        }

        return 1;
}

/* Given a fully processed dns_details object, if the string is an answer
 * (either positive or negative), make a string in the same format as
 * a decompressed string with only answers we consider "useful" in the
 * string
 *
 * The format is as follows:
 *
 * 1. First, we have a list of each DNS RR in uncompressed form
 *
 * 2. Then we have a list of 16-bit offsets; each DNS packet gets two offsets:
 *
 *      a. The beginning of the DNS label with the name of the RR in
 *         question.
 *
 *      b. The first byte after the end of same label (where the type is
 *         in the DNS RR)
 *
 * 3. Then we have the 16-bit ancount, followed by the nscount, followed
 *    by the arcount
 *
 * 4. We finish it off with a single TYPE byte of either TYPE_ANSWER,
 *    TYPE_NXDOMAIN, or TYPE_NOT_THERE
 *
 */

dw_str *dwx_remake_complete_reply(dns_details *view, int type) {
        uint16_t *offsets = 0;
        int this_offset = 0;
        int32_t total_count = 0, an = 0, ns = 0, ar = 0;
        dw_str *out = 0;

        if(view == 0 || view->look == 0 || view->look->packet == 0) {
                goto catch_dwx_make_complete_reply;
        }

        total_count = (view->look->ancount + view->look->nscount +
                      view->look->arcount) * 2;

        offsets = dw_malloc(((sizeof(uint16_t)) * total_count) + 1);
        if(offsets == 0) {
                goto catch_dwx_make_complete_reply;
        }

        out = dw_create(view->look->packet->len + 1);
        if(dwx_copy_over_section(out,view->look->packet,view->an_types,
                    view->look->an,view->look->ancount,offsets,&an,
                    &this_offset,total_count) == -1 ||
           dwx_copy_over_section(out,view->look->packet,view->ns_types,
                    view->look->ns,view->look->nscount,offsets,&ns,
                    &this_offset,total_count) == -1 ||
           dwx_copy_over_section(out,view->look->packet,view->ar_types,
                    view->look->ar,view->look->arcount,offsets,&ar,
                    &this_offset,total_count) == -1) {
                goto catch_dwx_make_complete_reply;
        }

        if(dwx_remake_footer(out,offsets,an,ns,ar,type) == -1) {
                goto catch_dwx_make_complete_reply;
        }

        free(offsets);
        return out;

catch_dwx_make_complete_reply:
        if(offsets != 0) {
                free(offsets);
        }
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* Given a fully processed dns_details object, and the original query they
 * sent us, determine what type of reply it is (direct answer, full CNAME
 * chain referral, incomplete CNAME chain referral, or NS referral) */

int dwx_determine_answer_type(dns_details *view, dw_str *query, dw_str *in) {
        int32_t query_type = 0;
        int counter = 0;
        int max = 32;
        int index = -1;
        int number_to_view = 0;

        if(query == 0 || view == 0 || view->look == 0) {
                return TYPE_ERROR;
        }
        query_type = dw_fetch_u16(query,-1);
        if(query_type == -1) {
                return TYPE_ERROR;
        }

        if(view->look->ancount > 0) { /* Is it an answer */
                number_to_view = view->look->ancount;
                if(number_to_view > 7) {
                        number_to_view = 7;
                }
                if(view->an_types == 0) {
                        return TYPE_ERROR;
                }
                for(index = 0; index < number_to_view; index++ ) {
                        if(view->an_types[index] ==
                                        dwx_rrtype_number(query_type) ||
                                (query_type == RR_ANY &&
                                        view->an_types[index] != RR_CNAME)) {
                                return TYPE_ANSWER;
                        }
                        if(view->an_types[index] == RR_CNAME) { /* CNAMEs */
                                if(view->look->ancount < max) {
                                        max = view->look->ancount;
                                }
                                for(counter = index + 1 ; counter < max ;
                                                counter++) {
                                        if(view->an_types[counter] ==
                                           dwx_rrtype_number(query_type) ||
                                           (query_type == RR_ANY &&
                                           view->an_types[counter] != RR_CNAME)
                                           ) {
                                                return TYPE_ANSWER;
                                        }
                                        if(view->an_types[counter] != RR_CNAME
                                           && view->an_types[counter] !=
                                           RRX_IGNORE) {
                                                return TYPE_NO_USEFUL_DATA;
                                        }
                                }
                        return TYPE_CNAME_REFER;
                        }
                        if(view->an_types[index] != RRX_IGNORE) {
                                return TYPE_NO_USEFUL_DATA;
                        }
                }
        }
        if(view->ns_types == 0) {
                return TYPE_ERROR;
        }
        if(view->ns_types[0] == RR_SOA) {
                return TYPE_NOT_THERE; /* May be NXDOMAIN; look at header */
        }
        if(view->ns_types[0] == RR_NS) {
                /* oncetv-ipn.net fix; also speeds up Deadwood */
                for(index = 0; index < view->look->arcount * 2; index +=2) {
                        if(dwx_dname_issame_2dw(query,0,in,
                                        view->look->ar[index]) == 1 &&
                           dw_fetch_u16(in,view->look->ar[index + 1]) ==
                                        query_type) {
                                view->ar_types[(index >> 1)]=RRX_ANSWER_IN_AR;
                                return TYPE_ANSWER_IN_AR;
                        }
                }
                return TYPE_NS_REFER;
        }
        return TYPE_NO_USEFUL_DATA;
}

/* Given a fully processed dns_details object, create a string that
 * we can store in the cache.
 *
 * Input: The processed dns_details object.
 *
 * Output: A newly-created string, 0 (NULL) on error
 */

dw_str *dwx_make_cache_string(dns_details *view, int type) {
        dw_str *out = 0;
        uint8_t in_type = 0;

        if(view == 0 || view->look == 0 || view->look->packet == 0
           || view->look->packet->len == 0 || view->look->packet->str == 0) {
                return 0;
        }

        in_type = *(view->look->packet->str + view->look->packet->len - 1);

        if(in_type == TYPE_NXDOMAIN && type == TYPE_NOT_THERE) {
                type = TYPE_NXDOMAIN;
        }

        if(in_type != TYPE_ANSWER && in_type != TYPE_NXDOMAIN) {
                return 0;
        }

        /* If the NXDOMAIN bit is set in the header, the answer must look like
         * a NXDOMAIN */
        /* Disabled: bookride.com screws this up, so there are out there in
         * the wild answers marked NXDOMAIN that actually aren't */
        /*if(in_type == TYPE_NXDOMAIN && type != TYPE_NXDOMAIN) {
                return 0;
        }*/

        if(type == TYPE_CNAME_REFER) {
                out = dwx_make_cname_refer(view);
        } else if(type == TYPE_NS_REFER) {
                out = dwx_make_ns_refer(view);
        } else if(type == TYPE_ANSWER || type == TYPE_NXDOMAIN ||
                        type == TYPE_NOT_THERE) {
                out = dwx_remake_complete_reply(view,type);
        } else {
                return 0;
        }

        return out;
}

/* Create a synthetic "not there" reply; this is used for empty replies
 * because a lot of broken DNS servers on the internet will give out a
 * reply with 0 DNS records when they don't have an answer for our query
 */

dw_str *dwx_synth_notthere(dw_str *query) {
        dw_str *hack, *out;
        int l = 20;

        hack = dw_malloc(sizeof(dw_str));
        if(hack == 0) {
                return 0;
        }
        hack->str = (uint8_t *)make_synth_not_there_answer(0,&l,1);
        hack->len = 40;
        hack->sane = 114;
        hack->max = 59;
        dw_put_u16(hack,0,-1);/*ancount*/
        dw_put_u16(hack,1,-1);/*nscount*/
        dw_put_u16(hack,0,-1);/*arcount*/
        dw_put_u8(hack,TYPE_NOT_THERE,-1);/* type */
        out = dwc_decompress(query,hack);
        dw_destroy(hack);

        return out;
}

/* oncetv-ipn.net fix: If the answer is in the AR section, we return
 * a packet where that answer (singular for the simple reason coding for
 * multiple is more difficult and no one is paying me to write this code)
 * is moved to the AN section */
dw_str *dwx_answer_in_ar(dns_details *view, dw_str *in) {
        dw_str *tmp = 0, *out = 0;
        int32_t dname_len = 0;
        int index = 0;

        if(view == 0 || in == 0) {
                return 0; /* Sanity test */
        }

        for(index = 0; index < view->look->arcount; index++) {
                if(view->ar_types[index] == RRX_ANSWER_IN_AR && tmp == 0) {
                        tmp = dwx_get_1_dns_rr(in,view->look->ar[index * 2]);
                        dname_len = view->look->ar[(index * 2) + 1] -
                                        view->look->ar[index * 2];
                }
        }

        if(tmp == 0) {
                return 0;
        }
        out = dw_create(tmp->len + 14);
        if(out == 0) {
                dw_destroy(tmp);
                return 0;
        }
        if(dw_append(tmp,out) == -1 ||
           dw_push_u16(0,out) == -1 || /* Offset 1: Top of string */
           dw_push_u16(dname_len,out) == -1 || /* Offset 2: End of dname */
           dw_push_u16(1,out) == -1 || /* One answer */
           dw_push_u16(0,out) == -1 || /* No NS records */
           dw_push_u16(0,out) == -1 || /* No AR records (moved to AN) */
           dw_addchar(TYPE_ANSWER,out) == -1) {
                dw_destroy(tmp);
                dw_destroy(out);
                return 0;
        }

        dw_destroy(tmp);
        return out;
}

/* Look at a DNS reply and determine how to proceed
 *
 * Input: The reply we got ("in"), and the query we sent ("query")
 *
 * Output: A dw_str object telling us how to proceed.
 */

dw_str *dwx_dissect_packet(dw_str *in, dw_str *query, dw_str *bailiwick) {
        dns_details *view = 0;
        dw_str *out = 0;
        int type = 0;
        int_fast32_t qtype = 0;

        if(in == 0 || query == 0 || bailiwick == 0) {
                return 0;
        }

        qtype = dw_fetch_u16(query,-1);

        if(qtype == -1) {
                return 0;
        }

        /* Back in 2010-2011, there was an issue where some servers
         * would respond to AAAA requests with a blank "server fail"
         * packet.  Since RedHat/CentOS at the time would try to
         * resolve an AAAA record when looking up a hostname before
         * giving up and resolving the A record, these server fail packets
         * would really slow down resolution.  As a workaround, I responded
         * to server fail with "OK, no host here, give up"; when that caused
         * an issue, I narrowed it down to being "OK, no host here" in the
         * case of sending an AAAA query because of another server giving
         * out a server fail.  I just checked, and the really bad practice
         * of responding with server fail to AAAA requests seems to have
         * gone away here in 2022 as I type this. */
        /* Disabled, as per the note above
        if(in->len == 7 && qtype == RR_AAAA) { // Blank packet 
                return dwx_synth_notthere(query);
        }
        */

        view = dwx_create_dns_details(in,query);

        if(view == 0 ||
           dwx_check_answer_section(in,query,view,bailiwick) == -1 ||
           dwx_if_an_then_no_ns_nor_ar(view) == -1 ||
           dwx_cleanup_ns_ar(view) == -1) {
                goto catch_dwx_dissect_packet;
        }
        type = dwx_determine_answer_type(view,query,in);
        if(type == TYPE_ANSWER_IN_AR) {
                out = dwx_answer_in_ar(view, in);
                if(view != 0) {
                        dwx_zap_dns_details(view);
                }
                return out;
        }
        if(type == TYPE_NS_REFER && (
           dwx_check_bailiwick_ns_section(view,query,bailiwick) == -1 ||
           dwx_link_ns_records(view) == -1 )) {
                goto catch_dwx_dissect_packet;
        }

        out = dwx_make_cache_string(view,type);
        dwx_zap_dns_details(view);
        return out;

catch_dwx_dissect_packet:
        if(view != 0) {
                dwx_zap_dns_details(view);
        }
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* When handling a NS referral, make the actual connection to the
 * upstream server */
void dwx_handle_ns_refer_connect(int connection_number, dw_str *packet,
                dw_str *query) {

        rem[connection_number].die = get_time() +
                ((int64_t)timeout_seconds << 8);

        /* Send said query upstream */
        if(rem[connection_number].socket != INVALID_SOCKET) {
                /* make_remote_connection() needs to have the socket be an
                 * invalid socket.
                 */
                closesocket(rem[connection_number].socket);
                rem[connection_number].socket = INVALID_SOCKET;
                b_remote[connection_number] = INVALID_SOCKET;
        }
        make_remote_connection(connection_number,(unsigned char *)packet->str,
                packet->len,query,rem[connection_number].socket);

}

/* Handle the case when upstream gives us a NS referral
 * Input: connection_number we are handling, NS referral we received
 * Output: void() (rem[connection_number] changed; as well as the
 *      cache)
 */
void dwx_handle_ns_refer(int connection_number, dw_str *action,
                dw_str *query, int32_t ttl) {
        dw_str *place = 0, *packet = 0;
        int label_count = -1;
        int_fast32_t this_max_ttl = max_ttl;

        if(rem[connection_number].ns == 0 || action == 0
                        || rem[connection_number].is_upstream == 1) {
                goto catch_dwx_handle_ns_refer;
        }

        if(dw_fetch_u8(action,-1) != TYPE_NS_REFER) {
                goto catch_dwx_handle_ns_refer;
        }

        /* Replace NS referral for this query with the NS referral we got */
        dw_destroy(rem[connection_number].ns);
        rem[connection_number].ns = 0;
        rem[connection_number].ns = dw_copy(action);

        /* Add this NS referral to the cache */
        place = dw_get_dname(action->str, 0, 260, &label_count);
        if(place == 0) {
                goto catch_dwx_handle_ns_refer;
        }
        if(ttl < 3600) { /* We store NS referrals in the cache for at least
                          * an hour for security reasons */
                ttl = 3600;
        }
	if(ttl < min_ttl) {
		ttl = min_ttl;
	}
        if(label_count > maxttl_reduce_labels) {
                this_max_ttl >>= (label_count - maxttl_reduce_labels);
                if(this_max_ttl < 30) {
                        this_max_ttl = 30;
                }
        }
        if(ttl > this_max_ttl) {
                ttl = this_max_ttl;
        }
        dw_put_u16(place, 65395, -1); /* Add "NS refer" private RR type */
        dwh_add(cache,place,action,ttl,1);

        /* Create a DNS query packet to send upstream */
        packet = make_dns_header(rem[connection_number].remote_id,
                0x0000,0,0,0);
        if(dw_append(query,packet) == -1 || dw_put_u16(packet,1,-1) == -1) {
                goto catch_dwx_handle_ns_refer;
        }

        dwx_handle_ns_refer_connect(connection_number, packet, query);

catch_dwx_handle_ns_refer:
        if(place != 0) {
                dw_destroy(place);
        }
        if(packet != 0) {
                dw_destroy(packet);
        }
        return;
}

/* Create a single CNAME RR (Name, type (CNAME), class, TTL, RDLENGTH,
 * RDDATA of cname pointer).
 * Input:
 * 1) String with question name
 * 2) Offset in question string
 * 3) String with answer
 * 4) Offset in answer string
 * 5) TTL of CNAME answer
 * 6) Maximum size of output string
 *
 * Output:
 * Newly create dw_str with full CNAME answer
 */
dw_str *dwx_make_one_cname_rr(dw_str *question, int32_t question_offset,
                dw_str *answer, int32_t answer_offset, int32_t ttl, int *len,
                int size) {
        dw_str *out = 0, *temp = 0;

        if(question == 0 || question_offset < 0 || answer == 0 ||
                        answer_offset < 0 || len == 0) {
                goto catch_dwx_make_one_cname_rr;
        }

        temp = dw_get_dname(question->str, question_offset, size, 0);
        if(temp == 0) {
                goto catch_dwx_make_one_cname_rr;
        }
        out = dw_copy(temp);
        if(out == 0) {
                goto catch_dwx_make_one_cname_rr;
        }
        *len = out->len; /* Length of first dlabel */
        if(dw_put_u16(out,RR_CNAME,-1) == -1 ||
                        dw_put_u16(out,1,-1) == -1 /* CLASS */ ||
                        dw_put_u16(out,(ttl >> 16) & 0xffff, -1) == -1 ||
                        dw_put_u16(out,(ttl & 0xffff), -1) == -1) {
                goto catch_dwx_make_one_cname_rr;
        }
        dw_destroy(temp);
        temp = dw_get_dname(answer->str, answer_offset, 260, 0);
        if(temp == 0 || dw_put_u16(out, temp->len, -1) == -1 ||
                        dw_append(temp,out) == -1) {
                goto catch_dwx_make_one_cname_rr;
        }
        dw_destroy(temp);
        temp = 0;

        return out;

catch_dwx_make_one_cname_rr:
        if(out != 0) {
                dw_destroy(out);
        }
        if(temp != 0) {
                dw_destroy(temp);
        }
        return 0;
}

/* Create the final answer, as well as the footer of the reply to give the
 * user */
void dwx_add_final_answer(dw_str *query, dw_str *answer, dw_str *value,
                uint16_t *offsets, int this_offset) {
        int32_t start = 0, end = 0;
        dw_str *temp = 0;
        int first_offset = 0, place = 0, rdlength = 0;
        int last_place = 0;

        if(value == 0) {
                return;
        }
        /* Extract DNS packets with answers to our query;
         * append said answers to value string */

        /* Set "start" and "end" to be the start and end of the answer */
        dwc_rr_rotate(answer, &start, &end);

        if(start < 0 || end < 0) {
                return;
        }

        temp = dw_substr(answer, start, end - start, 1);
        if(temp == 0) {
                return;
        }

        first_offset = value->len;
        while(this_offset < 15) {

                last_place = place;

                offsets[this_offset * 2] = place + first_offset;
                place = dw_get_dn_end(temp, place);
                if(place < 0) {
                        dw_destroy(temp);
                        return;
                }
                offsets[(this_offset * 2) + 1] = place + first_offset;
                place += 8; /* type, class, TTL (4) */
                rdlength = dw_fetch_u16(temp, place);
                if(rdlength < 0) {
                        dw_destroy(temp);
                        return;
                }
                place += rdlength + 2;

                /* Make sure string will fit in "value" */
                if(place + first_offset > value->max - 8 - (this_offset * 4)) {
                        if(last_place < temp->len) {
                                temp->len = last_place;
                                place = last_place;
                        }
                        break;
                }

                this_offset++;
                if(place >= temp->len) {
                        break;
                }
        }

        /* RRs we didn't account for above are discarded */
        if(place < temp->len) {
                temp->len = place;
        }
        /* Make sure string will fit in "value" */
        if(place + first_offset > value->max - 8 - (this_offset * 4)) {
                if(last_place < temp->len) {
                        temp->len = last_place;
                        this_offset--;
                }
        }

        dw_append(temp,value);
        dw_destroy(temp);

        /* Put offsets and an/ns/ar count at end of string */
        for(rdlength=0;rdlength<this_offset*2;rdlength++) {
                dw_put_u16(value, offsets[rdlength], -1);
        }
        dw_put_u16(value,this_offset,-1);/*ancount*/
        dw_put_u16(value,0,-1);/*nscount*/
        dw_put_u16(value,0,-1);/*arcount*/
        dw_put_u8(value,TYPE_ANSWER,-1);/* Answer to question */

}

/* If the answer at the end of a CNAME chain is not a full answer, handle it
 * thusly; this is used so we can give the correct reply when a CNAME points
 * to a SOA "not there" reply. */
dw_str *dwx_alt_cname_reply(dw_str *query, dw_str *action, dw_str *answer,
                int32_t ttl) {
        int len = 0, place = 0;
        dw_str *value = 0;

        /* We will just give the stub resolver our first CNAME link */
        value = dwx_make_one_cname_rr(query, 0, action, 2, ttl, &len, 260);
        place = dw_get_dn_end(value, 0);
        dw_put_u16(value,0,-1); /* First offset */
        dw_put_u16(value,place,-1); /* Second offset */
        dw_put_u16(value,1,-1); /* ANcount */
        dw_put_u16(value,0,-1); /* NScount */
        dw_put_u16(value,0,-1); /* ARcount */
        dw_put_u8(value,0,-1); /* Type */
        return value;
}

/* Create the actual reply to give the user */
dw_str *dwx_create_cname_reply(dw_str *query, dw_str *action, dw_str *answer,
                int32_t ttl) {
        dw_str *value = 0, *temp = 0;
        int32_t length = 0, final_offset = 0, current_offset = 0;
        int this_offset = 0, len = 0;
        uint16_t offsets[32];

        final_offset = dw_fetch_u16(action, -2);
        if(query == 0 || action == 0 || final_offset == -1 ||
                        dw_fetch_u8(action, -1) != TYPE_CNAME_REFER) {
                goto catch_dwx_create_cname_reply;
        }
        if(dw_fetch_u8(answer,-1) != TYPE_ANSWER) {
                return dwx_alt_cname_reply(query, action, answer, ttl);
        }

        /* First CNAME pointer... */
        value = dwx_make_one_cname_rr(query, 0, action, 2, ttl, &len, 1024);
        if(value == 0 || value->len > 1020) {
                dw_log_string("dwx_make_one_cname_rr problem",100);
                goto catch_dwx_create_cname_reply;
        }
        offsets[0] = 0;
        offsets[1] = len;
        this_offset = 1;

        /* Subsequent CNAME pointers... */
        while(current_offset < final_offset && this_offset < 12) {
                length = dw_fetch_u16(action, current_offset);
                if(length < 1) {
                        goto catch_dwx_create_cname_reply;
                }
                temp = dwx_make_one_cname_rr(action, current_offset + 2,
                                action, current_offset + length + 4, ttl,
                                &len, 260);
                if(temp == 0) {
                        goto catch_dwx_create_cname_reply;
                }
                offsets[this_offset * 2] = value->len;
                offsets[(this_offset * 2) + 1] = value->len + len;
                if(dw_append(temp, value) == -1 || value->len > 1020) {
                        dw_log_string("Append error making cname reply",100);
                        goto catch_dwx_create_cname_reply;
                }
                dw_destroy(temp);
                current_offset += length + 2;
                this_offset++;
        }

        /* Final answer after CNAME pointers... */
        dwx_add_final_answer(query, answer, value, offsets, this_offset);

        if(value->len > 1020) {
                dw_log_string("Final append error making cname reply",100);
                goto catch_dwx_create_cname_reply;
        }

        /* Make that a full answer to give the calling function */
        return value;

catch_dwx_create_cname_reply:
        if(value != 0) {
                dw_destroy(value);
        }
        if(temp != 0) {
                dw_destroy(temp);
        }
        return 0;
}

/* Gluless CNAME finished; send upstream.
 *
 * This is called from dwx_make_cname_reply() and is a private method for
 * that calling function.
 *
 * Input:
 *
 * conn_num: The connection number for the connection which just finished
 *      a glueless cname referral upstream
 *
 * c: The particular "local" connection number pointing to the upstream
 *      cname referral which needs a glueless CNAME finished
 *
 * depth: The recursion depth for dwx_make_cname_reply(); we have this to
 *      stop infinite loops
 *
 * uncomp: A pointer to a string with the uncompressed reply; the format
 *      for this reply is:
 *
 *              * raw DNS packets with answers combined together
 *
 *              * offsets for beginning of DNS packets; each DNS packet
 *                has two offsets (the beginning of the name followed by
 *                the end of the name/beginning of the type).  These are
 *                big-endian 16-bit numbers
 *
 *              * ancount, nscount, arcount.  Again big-endian 16-bit numbers
 *
 *              * a type of "0" (TYPE_ANSWER) to indicate this is an answer
 *                (as opposed to a NS referral or incomplete CNAME reply,
 *                 which have their own format)
 *
 * Variables used:
 *
 * * cname_cache: This is a pointer to a record in the cache with the
 *      CNAME referral which the upstream query got when trying to solve
 *      the query in question, such as binary data stating
 *      "The CNAME pointer for www.example.com".  The query type is 65394,
 *      which is a Deadwood internal query (we reserve queries 65392-65407
 *      for Deadwood's internal use, rejecting outside queries sent with
 *      these RRs) for a CNAME pointer (for security reasons, I'm not using
 *      the CNAME RR for this purpose)
 *
 * * child_action: This is the element we got from the cache which tells us
 *      the action done by the parent query which we finally solved.  It is
 *      a string with binary data which tells us something like
 *      "www.example.com is a CNAME for akamai.example.net" (the format of
 *      the data is generated by dwx_make_cname_refer() and the binary format
 *      is described there)
 *
 * * upstream: The connection number for the parent query which needed to
 *      solve an incomplete multi-link CNAME reply
 *
 */
void dwx_send_glueless_cname_upstream(int conn_num, int c, int depth,
                dw_str *uncomp) {
        dw_str *cname_cache = 0, *child_action = 0;
        int upstream = -1;

        upstream = rem[conn_num].local[c]->glueless_conn;
        cname_cache = dw_copy(rem[upstream].query);
        if(cname_cache == 0 || cname_cache->len < 3 ||
                dw_put_u16(cname_cache, 65394, -3) == -1) {
                        goto catch_dwx_send_glueless_cname_upstream;
        }
        child_action = dwh_get(cache, cname_cache, 0, 1);
        dwx_make_cname_reply(upstream, rem[upstream].query,
                        child_action, uncomp, depth + 1, 0);

catch_dwx_send_glueless_cname_upstream:
        if(cname_cache != 0) {
                dw_destroy(cname_cache);
        }
        if(child_action != 0) {
                dw_destroy(child_action);
        }
}

/* This is used for completing incomplete CNAME referrals.
 * What this does is create a reply to give to the user, then
 * send that reply out.
 */
int dwx_make_cname_reply(int conn_num, dw_str *query,
                dw_str *action, dw_str *answer, int depth, int here_max_ttl) {
        dw_str *uncomp = 0, *reply = 0, *comp = 0;
        int ret = -1, c = 0; /* c is for counter */
        int_fast32_t ttl = 3600;
        int ancount = 0;

        if(depth > 32) {
                 goto catch_dwx_make_cname_reply;
        }

        if(query == 0 || action == 0 || answer == 0) {
                goto catch_dwx_make_cname_reply;
        }

        ancount = dw_fetch_u16(answer,-6);
        if(ancount < 1) {
                goto catch_dwx_make_cname_reply;
        }
        ttl = dw_get_a_dnsttl(answer,0,31536000,ancount);
        if(ttl < 0) {
                dw_log_dwstr("Invalid TTL in answer ",answer,100);
                ttl = 3600;
        }
        if(ttl < 30) {
                ttl = 30;
        }
	if(ttl < min_ttl) {
		ttl = min_ttl;
	}
        if(ttl > max_ttl) {
                ttl = max_ttl;
        }
	if(here_max_ttl > 0 && ttl > here_max_ttl) {
                ttl = here_max_ttl;
        }
        /*ttl = 30; // DEBUG*/
        uncomp = dwx_create_cname_reply(query, action, answer, ttl);
        comp = dwc_compress(query, uncomp);

        /* Send a reply out for each "live" local connection */
        if(uncomp == 0 || comp == 0 || rem[conn_num].local == 0 ||
           rem[conn_num].num_locals < 1) {
                goto catch_dwx_make_cname_reply;
        }

        /* Put answer in cache as full answer */
        dwh_add(cache, query, uncomp, ttl, 1);

        /* Send answer from cache */
        for(c = 0; c < rem[conn_num].num_locals; c++) {
                if(rem[conn_num].local[c] == 0) {
                        goto catch_dwx_make_cname_reply;
                }
                if(rem[conn_num].local[c]->glueless_type == 2) {
                        dwx_send_glueless_cname_upstream(conn_num, c, depth,
                                        uncomp);
                        continue;
                }
                if(rem[conn_num].local[c]->glueless_type == 1) {
                        /* To do: Glueless NS */
                        continue;
                }
                if(rem[conn_num].local[c]->glueless_type == 3) {
                        dwx_cached_cname_done(query,conn_num,c,depth);
                        continue;
                }
                reply = make_dns_packet(query, comp,
                                rem[conn_num].local[c]->local_id);
                if(reply == 0) {
                        goto catch_dwx_make_cname_reply;
                }
                send_reply_from_cache(reply->str, reply->len, conn_num, c);
                dw_destroy(reply);
        }

        reset_rem(conn_num); /* Close finished query */
        closesocket(b_remote[conn_num]);
        b_remote[conn_num] = INVALID_SOCKET; /* Make remote available */
        reply = 0;

        /* Clean up */
catch_dwx_make_cname_reply:
        if(reply != 0) {
                dw_destroy(reply);
        }
        if(uncomp != 0) {
                dw_destroy(uncomp);
        }
        if(comp != 0) {
                dw_destroy(comp);
        }
        return ret;
}

/* Handle the case for when we get an incomplete CNAME referral */
int dwx_handle_cname_refer(int connection_number, dw_str *action,
                dw_str *query, int32_t ttl) {
        int32_t qtype = 0, offset = 0;
        dw_str *real_query = 0, *cname_cache = 0, *answer = 0;
        int ret = -1;

        /* Cache this CNAME referral */
        if(ttl < key_n[DWM_N_min_ttl_incomplete_cname]) {
                ttl = key_n[DWM_N_min_ttl_incomplete_cname];
        }
        if(ttl < 30) {
                ttl = 30;
        }
	if(ttl < min_ttl) {
		ttl = min_ttl;
	}
        if(ttl > max_ttl) {
                ttl = max_ttl;
        }
        cname_cache=dw_copy(query);
        if(cname_cache == 0 || cname_cache->len < 3 ||
                        dw_put_u16(cname_cache, 65394, -3) == -1) {
                goto catch_dwx_handle_cname_refer;
        }
        dwh_add(cache, cname_cache, action, ttl, 1);

        /* Determine what query the CNAME points to */
        if(action == 0 || query == 0 ||
                        dw_fetch_u8(action,-1) != TYPE_CNAME_REFER) {
                goto catch_dwx_handle_cname_refer;
        }
        offset = dw_fetch_u16(action, -2);
        offset += 2; /* Go past two-byte length */
        real_query = dw_get_dname(action->str, offset, 260, 0);
        dwc_lower_case(real_query);
        if(real_query == 0) {
                goto catch_dwx_handle_cname_refer;
        }
        qtype = dw_fetch_u16(query,-1);
        if(qtype == -1 || dw_put_u16(real_query, qtype, -1) == -1) {
                goto catch_dwx_handle_cname_refer;
        }

        /* See if we have the data already in the cache */
        answer = dwh_get(cache,real_query,0,1);
        if(answer != 0) { /* In cache */
                /* Only keep new cached item in cache slightly longer
                 * than cache item it depends on */
		int32_t the_most_ttl;
                the_most_ttl = dwh_get_ttl(cache,real_query) + 30;
                if(the_most_ttl > max_ttl) {
                        the_most_ttl = max_ttl;
                }
                if(the_most_ttl < 30) {
                        the_most_ttl = 30;
                }
                ret = dwx_make_cname_reply(connection_number, query,
                                action, answer,0,the_most_ttl);
                goto catch_dwx_handle_cname_refer;
        } else { /* Not in cache */
                ret = dwx_do_cname_glueless(real_query, connection_number);
        }

catch_dwx_handle_cname_refer:
        if(real_query != 0) {
                dw_destroy(real_query);
        }
        if(answer != 0) {
                dw_destroy(answer);
        }
        if(cname_cache != 0) {
                dw_destroy(cname_cache);
        }
        return ret;
}

/* Called from cache_dns_reply this determines whether the answer is
 * complete or not; if it's complete, we put it in the cache as-is; if
 * not, we put in the cache an incomplete DNS reply (NS referral),
 * and continue processing
 *
 * Input: Pointer to the cache, the query used, the reply upstream, the
 *      desired TTL for this reply
 * Output: The "type" of reply we got upstream, as follows:
 *      -1: Error
 *      Type  0: Positive answer
 *      Type  1: NXDOMAIN negative reply
 *      Type  2: Non-NXDOMAIN negative reply
 *      Type 16: NS referral
 *      Type 17: CNAME referral
 */
int dwx_cache_reply(dw_hash *cache, dw_str *query, dw_str *in, int32_t ttl,
                int connection_number) {
        dw_str *action = 0;
        dw_str *bailiwick = 0;
        int type;
        int ret = 0;

        if(query == 0 || in == 0) {
                ret = -1;
                goto catch_dwx_cache_reply;
        }

        if(rem[connection_number].ns == 0) {
                ret = -1;
                goto catch_dwx_cache_reply;
        }

        if(ttl < 30) {
                ttl = 30;
        }
	if(ttl < min_ttl) {
		ttl = min_ttl;
	}
        if(ttl > max_ttl) {
                ttl = max_ttl;
        }

        bailiwick = dw_get_dname(rem[connection_number].ns->str, 0, 260, 0);
        if(bailiwick == 0 || bailiwick->len > 256) {
                ret = -1;
                goto catch_dwx_cache_reply;
        }

        action = dwx_dissect_packet(in,query,bailiwick);
        if(action == 0) {
                ret = -1;
                goto catch_dwx_cache_reply;
        }
        type = dw_fetch_u8(action,-1);

        if(type == TYPE_ANSWER || type == TYPE_NXDOMAIN ||
                        type == TYPE_NOT_THERE) {
                dw_log_dwstr("Caching direct answer at ",query,100);
                dwh_add(cache,query,action,ttl,1);
                ret = 1;
                goto catch_dwx_cache_reply;
        }

        if(type == TYPE_NS_REFER && rem[connection_number].is_upstream == 0) {
                ret = TYPE_NS_REFER;
                dw_log_dwstr("Processing NS refer for ",query,100);
                dwx_handle_ns_refer(connection_number,action,query,ttl);
                goto catch_dwx_cache_reply;
        }

        if(type == TYPE_CNAME_REFER &&
                        rem[connection_number].is_upstream == 0) {
                ret = type;
                dw_log_dwstr("Processing incomplete CNAME for ",query,100);
                dwx_handle_cname_refer(connection_number,action,query,ttl);
                goto catch_dwx_cache_reply;
        }

        /* Anything else is an error */
        ret = -1;

catch_dwx_cache_reply:
        if(bailiwick != 0) {
                dw_destroy(bailiwick);
        }
        if(action != 0) {
                dw_destroy(action);
                action = 0;
        }
        return ret;
}

/* Convert a single IP from human-readable ("8.8.4.4",
 * "2001:db8:1:2::3:f") to raw binary format, returning the length of
 * the resulting IP
 */
int dwx_ns_convert_1ip(char *ip_human, uint8_t *ip_raw) {
        int ip_type = 0;

        if(inet_pton(AF_INET, ip_human, (uint8_t *)(ip_raw)) > 0) {
                ip_type = 4;
#ifndef NOIP6
        } else if(inet_pton(AF_INET6, ip_human, (uint8_t *)(ip_raw)) > 0) {
                ip_type = 16;
#endif /* NOIP6 */
        }

        return ip_type;
}

/* Convert a length of a given IP (ip_type) in to a number in a NS
 * referral; 4 -> 1; 16 -> 28; otherwise error */
int dwx_ns_convert_number(int in) {
        if(in == 4) {
                return 1;
        } else if(in == 16) {
                return 28;
        }
        return -1;
}

/* Add a single record (IP) to our converted NS */
int dwx_ns_add_1record(dw_str *out, int ip_type, uint8_t *ip_raw) {
        int num = 0, counter = 0;

        num = dwx_ns_convert_number(ip_type);
        if(num == -1 || dw_put_u8(out,num,-1) == -1) {
                return -1;
        }
        for(counter = 0; counter < ip_type; counter++) {
                if(dw_put_u8(out,ip_raw[counter],-1) == -1) {
                        return -1;
                }
        }
        return 1;
}

/* Create a new NS referral with the bailiwick at the top of the string */
dw_str *dwx_ns_convert_init(dw_str *bailiwick) {
        dw_str *out = 0, *dname = 0;

        if(bailiwick == 0) {
                out = dw_create(256);
                if(out == 0) {
                        return 0;
                }
                if(dw_put_u8(out,0,-1) == -1) /* One byte "dot" RR */ {
                        dw_destroy(out);
                        return 0;
                }
        } else {
                dname = dw_get_dname(bailiwick->str, 0, 260, 0);
                if(dname == 0) {
                        return 0;
                }
                if(dname->len > 256) {
                        dw_destroy(dname);
                        return 0;
                }
                out = dw_substr(dname,0,-1,256);
                dw_destroy(dname);
                if(out == 0) {
                        return 0;
                }
        }

        return out;
}

/* Remove trailing whitespace from a null-terminated string */
void dwx_zap_whitespace(char *in) {
        int counter = 0;

        if(in == 0) {
                return;
        }

        for(counter = 0; counter < 512; counter++) {
                if(*in == 0) {
                        return;
                }
                if(*in == ' ' || *in == '\t') {
                        *in = 0;
                        return;
                }
                in++;
        }
}

/* This is the engine for dwx_ns_convert; the "mangle" string is, well,
 * mangled */
dw_str *dwx_ns_convert_mangle(dw_str *mangle, int is_upstream, dw_str *b) {
        int counter = 0, ip_type = 0, a = 0;
        char *ip_human = 0;
        uint8_t ip_raw[24];
        uint16_t offsets[32];
        dw_str *out = 0;

        /* Initialize output string */
        out = dwx_ns_convert_init(b);
        if(out == 0) {
                goto clean_dwx_ns_convert_mangle;
        }

        /* Add IPs to output string */
        for(counter = 0; counter < 30; counter++) {
                ip_human = pop_last_item(mangle);
                dwx_zap_whitespace(ip_human);
                ip_type = dwx_ns_convert_1ip(ip_human,ip_raw);
                free(ip_human);
                if(ip_type == 0) {
                        break;
                }
                offsets[counter] = out->len;
                if(dwx_ns_add_1record(out, ip_type, ip_raw) == -1) {
                        goto clean_dwx_ns_convert_mangle;
                }
        }

        /* List of offsets */
        for(a = 0; a < counter && a < 31; a++) {
                if(dw_put_u16(out, offsets[a], -1) == -1) {
                        goto clean_dwx_ns_convert_mangle;
                }
        }

        /* Footer */
        if(dw_put_u8(out,counter,-1) == -1) { /* Number of offsets */
                goto clean_dwx_ns_convert_mangle;
        }
        if(is_upstream == 1 && dw_put_u8(out,TYPE_UPSTREAM_REFER,-1) == -1) {
                goto clean_dwx_ns_convert_mangle;
        } else if(is_upstream != 1 && dw_put_u8(out,TYPE_NS_REFER,-1) == -1) {
                goto clean_dwx_ns_convert_mangle;
        }

        return out;

clean_dwx_ns_convert_mangle:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

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
dw_str *dwx_ns_convert(dw_str *in, int is_upstream, dw_str *bailiwick) {
        /* This function is a wrapper for dwx_ns_convert_mangle; we create
         * a temporary "mangle" string because dwx_ns_convert_mangle modifies
         * the "mangle" string */
        dw_str *mangle = 0, *out = 0;

        mangle = dw_copy(in);
        if(mangle == 0) {
                goto clean_dwx_ns_convert;
        }

        out = dwx_ns_convert_mangle(mangle, is_upstream, bailiwick);
        if(out == 0) {
                goto clean_dwx_ns_convert;
        }

        if(mangle != 0) {
                dw_destroy(mangle);
        }
        return out;

clean_dwx_ns_convert:
        if(mangle != 0) {
                dw_destroy(mangle);
        }
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* Given a NS referral string and an offset, get the IPv4 address from that
 * string and return it
 */
ip_addr_T dwx_ns_getip_ipv4(dw_str *list, int offset) {
        ip_addr_T addr = {0, {0,0}, 0, 0};
        int counter = 0, temp = 0;

        if(list == 0 || dw_fetch_u8(list,offset) != RR_A) { /* Sanity check */
                return addr; /* Error */
        }

        for(counter = 0; counter < 4; counter++) {
                temp = dw_fetch_u8(list,offset + 1 + counter);
                if(temp < 0) {
                        return addr; /* Error */
                }
                addr.ip[counter] = temp;
        }

        addr.len = 4; /* IPv4 */

        return addr;
}

#ifndef NOIP6
/* Given a NS referral string and an offset, get the IPv6 address from that
 * string and return it
 */
ip_addr_T dwx_ns_getip_ipv6(dw_str *list, int offset) {
        ip_addr_T addr = {0, {0,0}, 0, 0};
        int counter = 0, temp = 0;

        if(list == 0 || dw_fetch_u8(list,offset) != RR_AAAA) { /* Sanity */
                return addr; /* Error */
        }

        for(counter = 0; counter < 16; counter++) {
                temp = dw_fetch_u8(list,offset + 1 + counter);
                if(temp < 0) {
                        return addr; /* Error */
                }
                addr.ip[counter] = temp;
        }

        addr.len = 16; /* IPv6 */

        return addr;
}
#endif /* NOIP6 */

/* Given an answer as it looks in the cache, choose a random A (or AAAA if
 * IPv6 support is compiled in) record from that answer and return it as
 * an IP; note that "answer" is mangled.
 */

ip_addr_T dwx_get_rr_from_answer(dw_str *answer) {
        ip_addr_T addr = {0, {0, 0}, 0, 0};
        int counter = 0, ancount = 0, stack[20], type = 0, place = 0, z = 0;

        if(answer == 0) {
                goto catch_dwx_get_rr_from_answer;
        }

        if(dw_fetch_u8(answer,-1) != TYPE_ANSWER) {
                goto catch_dwx_get_rr_from_answer;
        }

        answer->len--;

        if(dw_pop_u16(answer) == -1 || dw_pop_u16(answer) == -1) {
                goto catch_dwx_get_rr_from_answer;
        }
        ancount = dw_pop_u16(answer);

        for(counter = 0; counter < ancount && counter < 16; counter++) {
                z = dw_pop_u16(answer);
                if(z == -1 || dw_pop_u16(answer) == -1) {
                        goto catch_dwx_get_rr_from_answer;
                }
                /* See if it's an A/AAAA; if it is, add the
                 * offset to a stack and finally choose a random offset
                 * from the stack */
                type = dw_fetch_u16(answer,z);
                if(type == RR_A
#ifndef NOIP6
                        || type == RR_AAAA
#endif /* NOIP6 */
                ) {
                        stack[place] = z;
                        place++;
                }
        }

        if(place == 0) {
                goto catch_dwx_get_rr_from_answer;
        }
        place = dwr_rng(rng_seed) % place;
        type = dw_fetch_u16(answer,stack[place]);
        if(type == RR_A) {
                addr.len = 4;
                addr.ip[0] = *(answer->str + stack[place] + 10);
                addr.ip[1] = *(answer->str + stack[place] + 11);
                addr.ip[2] = *(answer->str + stack[place] + 12);
                addr.ip[3] = *(answer->str + stack[place] + 13);
        }
        /* We really should add IPv6 support...this will be done later */

catch_dwx_get_rr_from_answer:
        return addr;
}

/* Given a NS referral string and an offset, get the glueless NS referral
 * from the string and return it
 */
ip_addr_T dwx_ns_getip_glueless(dw_str *list, int offset) {
        ip_addr_T addr = {0, {0,0}, 0, 0};
        dw_str *query = 0, *answer = 0;
        int type = 1;

        if(list == 0 || *(list->str + offset) != 2) {
                goto catch_dwx_ns_getip_glueless;
        }
        type = key_n[DWM_N_ns_glueless_type];
        if(type != RR_A && type != RR_AAAA && type != RR_ANY) {
                type = RR_A; /* Sanity check */
        }

        /* See if it is in the cache */
        query = dw_get_dname(list->str + 3, offset, 256, 0);
        dwc_lower_case(query);
        if(query == 0 || dw_push_u16(type,query) == -1) {
                goto catch_dwx_ns_getip_glueless;
        }
        answer = dwh_get(cache,query,0,1);
        if(answer != 0) {
                addr = dwx_get_rr_from_answer(answer);
                if(addr.len != 0) { /* Return from cache if success */
                        goto catch_dwx_ns_getip_glueless;
                }
        }

        addr.glueless = dw_get_dname(list->str + 3, offset, 260, 0);
        dw_put_u16(addr.glueless, key_n[DWM_N_ns_glueless_type], -1);
        if(addr.glueless == 0) {
                goto catch_dwx_ns_getip_glueless;
        }
        addr.len = 127; /* Tell them this is a glueless NS referral */

catch_dwx_ns_getip_glueless:
        if(query != 0) {
                dw_destroy(query);
        }
        if(answer != 0) {
                dw_destroy(answer);
        }
        return addr;
}

/* Given a NS referral list and the NS record we want to look at, tell us
 * what type of record it is */
int dwx_nsref_type(int a, int *offset, dw_str *list) {
        if(list == 0 || offset == 0) {
                return -1;
        }

        *offset = -1 * (2 + (a * 2));
        *offset = *offset - 1;
        *offset = dw_fetch_u16(list, *offset);
        if(*offset < 0 || *offset > list->len) {
                return -1;
        }

        return dw_fetch_u8(list,*offset);
}

/* Choose which upstream NS server we will contact.  "b" is the connection
 * number; "count" is the number of upstream NS servers; we also point
 * to an active random number generator */
int dwx_choose_ns(int b, int count, dwr_rg *rng, dw_str *list) {
        int out = 0, offset = 0, a = 0, type = 0;

        if(count <= 1) {
                return 0;
        }

        /* Choose the first one randomly; otherwise cycle them using a
         * largeish prime number chosen to have good "jumps".  A jump is
         * how many name servers we jump past for a given number
         * of name servers.  I like 173 because it has the following jumps:
         * Number of name servers:  2  3  4  5  6  7  8  9 10 11 12 13 14
         * Jump for this number:    1 -1  1 -2 -1 -2 -3  2  3 -3  5  4  5
         *
         * The jump is not 1 or -1 for all small numbers (16 or less) where
         * it's possible to have a non 1/-1 relatively prime sequence; this
         * is the smallest prime with this condition (others are 283, 317,
         * 653, 787, and 907).  This bit of research was done with a small
         * awk script: 'BEGIN{for(prime=131;prime<1024;prime+=2){y=0;for(z
         * =3;z*z<=prime;z++){if(prime % z == 0){y=1}}if(y==0){score=0;for
         * (a=1;a<17;a++){b = prime % a; c = b - a; c = -c; if(b>1 && c>1)
         * {score++}; print a " " b }print score ":" prime}}}'
         */
        if(rem[b].current_ns < 0) {
                for(a = 0; a < 5; a++) { /* Favor glued records */
                        out = dwr_rng(rng) % count;
                        type = dwx_nsref_type(out,&offset,list);
                        if(type == RR_A
#ifndef NOIP6
                        || type == RR_AAAA
#endif /* NOIP6 */
                        ) {
                                break;
                        }
                }
        } else {
                out = rem[b].current_ns;
                out = (out + 173) % count;
        }
        rem[b].current_ns = out;

        return out;
}

/* Given a list of NS referrals (in dwx_make_ns_refer format), a pointer
 * to our random number generator, and the connection number we are on (b),
 * return either the IP or glueless hostname of a randomly chosen NS record
 */

ip_addr_T dwx_ns_getip(dw_str *list, dwr_rg *rng, int b) {
        ip_addr_T addr = {0, {0,0}, 0, 0};
        int type = 0, count = 0, offset = 0, a = 0, rr = 0;

        if(list == 0 || rng == 0) {
                goto catch_dwx_ns_getip;
        }

        /* See what kind of record this is and how many RRs we have */
        type = dw_fetch_u8(list,-1);
        if(type != TYPE_NS_REFER && type != TYPE_UPSTREAM_REFER) {
                goto catch_dwx_ns_getip;
        }
        count = dw_fetch_u8(list,-2);
        if(count <= 0 || count > 127) {
                goto catch_dwx_ns_getip;
        }

        /* Choose a RR at random */
        a = dwx_choose_ns(b, count, rng, list);
        rr = dwx_nsref_type(a, &offset, list);

        if(rr == RR_A) {
                addr = dwx_ns_getip_ipv4(list,offset);
#ifndef NOIP6
        } else if(rr == RR_AAAA) {
                addr = dwx_ns_getip_ipv6(list,offset);
#endif /* NOIP6 */
        } else if(rr == RR_NS) {
                addr = dwx_ns_getip_glueless(list,offset);
        } else {
                goto catch_dwx_ns_getip;
        }

        if(type == TYPE_UPSTREAM_REFER) {
                addr.flags = 1;
        }
        return addr;

catch_dwx_ns_getip:
        addr.len = 0;
        return addr;
}

/* Look for a given query, to see if it is already "in flight".  If it is,
 * we return the remote UDP connection with the inflight query; if we
 * do not find an inflight query, return -1. */
int dwx_find_inflight(dw_str *query) {
        dw_str *answer = 0;
        int ret = -1;

        answer = dwh_get(inflight, query, 0, 1);
        if(answer == 0) {
                return -1;
        }

        ret = dw_fetch_u16(answer,0);
        dw_destroy(answer);

        if(rem[ret].socket == INVALID_SOCKET) { /* Sanity check */
                return -1;
        }

        if(dw_issame(query,rem[ret].query) != 1) { /* Actually not same */
                dwh_zap(inflight,query, 0, 1); /* Remove corrupt data */
                return -1;
        }

        return ret;

}

/* Initialize all of the "local" elements of an already existing connection */
void dwx_init_conn_local(int32_t conn_number, int local_number) {
        if(rem[conn_number].local == 0 ||  /* Sanity check */
                        rem[conn_number].local[local_number] == 0) {
                return;
        }
        rem[conn_number].local[local_number]->from_socket = INVALID_SOCKET;
        rem[conn_number].local[local_number]->port = 0;
        rem[conn_number].local[local_number]->tcp_num = -1;
        rem[conn_number].local[local_number]->action = 0;
}

#ifdef XTRA_STUFF
/* Given an "address" with a NS referral (addr), a connection which needs to
 * process the glueless referral (conn_number), and an already existing
 * connection which we will attach to (already), connect our query to the
 * already existing connection
 */
int dwx_do_glueless_inflight(int32_t conn_number, int already, int type) {
        int max = 0, num_alloc = 0;

        if(already == conn_number || rem[conn_number].recurse_depth >= 83 ||
           rem[already].recurse_depth >= 83) {
                return -1;
        }

        rem[conn_number].recurse_depth++;
        rem[already].recurse_depth++;

        num_alloc = key_n[DWM_N_max_inflights];
        if(num_alloc < 1) {
                num_alloc = 1;
        } else if(num_alloc > 32000) {
                num_alloc = 32000;
        }
        num_alloc++; /* Stop off-by-one attacks */

        max = rem[conn_number].recurse_depth;
        if(rem[already].recurse_depth > max) {
                max = rem[already].recurse_depth;
        }
        rem[conn_number].recurse_depth = max + 1;
        rem[already].recurse_depth = max + 1;

        /* Add this glueless NS request to the already existing query */
        if(rem[already].num_locals >= num_alloc - 2) {
                return -2; /* No more inflights for this query; make new one */
        }
        rem[already].num_locals++;
        rem[already].local[rem[already].num_locals-1] =
                        dw_malloc(sizeof(local_T));
        if(rem[already].local[rem[already].num_locals-1] != 0) {
                rem[already].local[rem[already].num_locals-1]->orig_query = 0;
                rem[already].local[rem[already].num_locals-1]->action = 0;
        }
        dwx_init_conn_local(already,rem[already].num_locals - 1);
        if(rem[already].socket == INVALID_SOCKET ||
           rem[already].local[rem[already].num_locals - 1] == 0) {
                reset_rem(already);
                closesocket(b_remote[already]);
                b_remote[already] = INVALID_SOCKET;
                return -1;
        }
        rem[already].local[rem[already].num_locals - 1]->glueless_type = type;
        rem[already].local[rem[already].num_locals - 1]->glueless_conn =
                        conn_number;
        return 1; /* Success */

}
#endif /* XTRA_STUFF */

/* Create a new outgoing query to process a glueless request (NS or CNAME);
 * similiar to forward_local_udp_packet() and make_new_udp_connect()
 */
void dwx_do_glueless_new(dw_str *query, int32_t conn_number, int type) {
        int32_t new_conn_num = 0;
        int num_alloc = 0;
        int depth = 0;
        dw_str *packet = 0;
        int this_recurse_depth = 0;

        num_alloc = key_n[DWM_N_max_inflights];
        if(num_alloc < 1) {
                num_alloc = 1;
        } else if(num_alloc > 32000) {
                num_alloc = 32000;
        }
        num_alloc++; /* Stop off-by-one attacks */
        if(conn_number < 0 || conn_number > maxprocs ||
               rem[conn_number].recurse_depth >= 83) {
                return;
        }
        rem[conn_number].recurse_depth++;
        this_recurse_depth = rem[conn_number].recurse_depth;

        /* Make sure we "bubble up" the fact we have made a new query */
        new_conn_num = conn_number;
        depth = 0;
        while(rem[conn_number].num_locals > 0 &&
              rem[conn_number].local != 0 &&
              depth < 120) {
                if(rem[conn_number].local[0] != 0) {
                        conn_number = rem[conn_number].local[0]->glueless_conn;
                }
                if(conn_number == -1) {
                        break;
                }
                if(conn_number < 0 || conn_number > maxprocs) {
                        return;
                }
                if(rem[conn_number].recurse_depth > 83) {
                        return;
                }
                rem[conn_number].recurse_depth++;
                /* Make sure children and parent queries keep recurse_depth
                 * in sync with each other */
                if(rem[conn_number].recurse_depth < this_recurse_depth) {
                        rem[conn_number].recurse_depth = this_recurse_depth;
                } else {
                        this_recurse_depth = rem[new_conn_num].recurse_depth = 
                            rem[conn_number].recurse_depth;
                }
                depth++;
        }
        conn_number = new_conn_num;


        new_conn_num = find_free_remote();
        if(new_conn_num == -1) { /* No more remote pending connections */
                return;
        }

        reset_rem(new_conn_num);
        closesocket(b_remote[new_conn_num]);
        b_remote[new_conn_num] = INVALID_SOCKET;
        rem[new_conn_num].query = dw_copy(query);
        rem[new_conn_num].recurse_depth = rem[conn_number].recurse_depth + 1;
        rem[new_conn_num].socket = INVALID_SOCKET;
        rem[new_conn_num].remote_id = dwr_rng(rng_seed);
        /* Note that RD is always set to 0, even though the upstream server
         * may be an upstream, and not root, server.  This is a bug. */
        packet = make_dns_header(rem[new_conn_num].remote_id,0x0000,0,0,0);
        if(packet == 0 || dw_append(rem[new_conn_num].query,packet) == -1 ||
                        dw_put_u16(packet,1,-1) == -1 /* QCLASS: 1 */) {
                reset_rem(new_conn_num);
                closesocket(b_remote[new_conn_num]);
                b_remote[new_conn_num] = INVALID_SOCKET;
                goto catch_dwx_do_ns_glueless_new;
        }
        /* Connect to remote server... */
        rem[new_conn_num].local = dw_malloc(num_alloc * sizeof(local_T *));
        if(rem[new_conn_num].local == 0) {
                reset_rem(new_conn_num);
                closesocket(b_remote[new_conn_num]);
                b_remote[new_conn_num] = INVALID_SOCKET;
                goto catch_dwx_do_ns_glueless_new;
        }
        make_remote_connection(new_conn_num,(unsigned char *)packet->str,
                        packet->len,rem[new_conn_num].query,INVALID_SOCKET);
        rem[conn_number].die = get_time() + ((int64_t)timeout_seconds << 12);
        rem[conn_number].child_id = new_conn_num;
        /* Set new connection parameters */
        rem[new_conn_num].die = get_time() + ((int64_t)timeout_seconds << 8);
        rem[new_conn_num].num_locals = 1;
        rem[new_conn_num].local[0] = dw_malloc(sizeof(local_T));
        if(rem[new_conn_num].local[0] != 0) {
                rem[new_conn_num].local[0]->orig_query = 0;
                rem[new_conn_num].local[0]->action = 0;
        }
        dwx_init_conn_local(new_conn_num,0);
        if(rem[new_conn_num].socket == INVALID_SOCKET ||
           rem[new_conn_num].local[0] == 0) {
                reset_rem(new_conn_num);
                closesocket(b_remote[new_conn_num]);
                b_remote[new_conn_num] = INVALID_SOCKET;
                goto catch_dwx_do_ns_glueless_new;
        }
        rem[new_conn_num].local[0]->glueless_type = type;
        rem[new_conn_num].local[0]->glueless_conn = conn_number;

catch_dwx_do_ns_glueless_new:
        if(packet != 0) {
                dw_destroy(packet);
        }

}

/* Given an "address" with a NS referral (addr), and a connection which needs
 * to process the glueless referral (conn_number), create a new remote
 * connection to process the "child" glueless request while the parent
 * request waits (and has its timeout occasionally updated).
 *
 * Note that this function is responsible for freeing the allocated string
 * addr.glueless
 */

void dwx_do_ns_glueless(ip_addr_T addr, int32_t conn_number) {
        /* int already = 0; */

        if(addr.len != 127 || addr.glueless == 0) {
                goto clean_dwx_do_ns_glueless;
        }

        /* Do we connect to an already existing query? */
        /* Disabled because this code has not been tested */
        /*
        already = dwx_find_inflight(addr.glueless);
        rem[conn_number].child_id = already;
        if(already != -1) {
                if(dwx_do_glueless_inflight(conn_number, already, 1)
                                != -2) {
                        goto clean_dwx_do_ns_glueless;
                }
        }
        */

        /* If not, then we make a new query */
        dwc_lower_case(addr.glueless);
        dwx_do_glueless_new(addr.glueless, conn_number,1);

clean_dwx_do_ns_glueless:
        dw_destroy(addr.glueless);
}

/* Once a glueless part of a query is finished, we have to make sure the
 * query that had to spawn the glueless query gets the NS record we looked
 * for and goes on processing the query */

void dwx_glueless_done(dw_str *query, int32_t conn_num) {
        ip_addr_T addr = {0, {0,0}, 0, 0};
        dw_str *answer = 0, *packet = 0;
        sockaddr_all_T server;
        SOCKET s = INVALID_SOCKET;
        socklen_t inet_len = sizeof(struct sockaddr_in);

        if(rem[conn_num].recurse_depth > 83) {
                return;
        }
        rem[conn_num].recurse_depth++;

        /* Get answer from cache */
        answer = dwh_get(cache,query,0,1);
        if(answer == 0) {
                goto catch_dwx_glueless_done;
        }
        addr = dwx_get_rr_from_answer(answer);
        if(addr.len != 4
#ifndef NOIP6
                && addr.len != 16
#endif /* IP6 */
        ) {
                goto catch_dwx_glueless_done;
        }
        s = setup_server(&server,&addr);
        if(s == INVALID_SOCKET) {
                goto catch_dwx_glueless_done;
        }
#ifndef NOIP6
        if (server.Family == AF_INET6) {
                inet_len = sizeof(struct sockaddr_in6);
        }
#endif /* NOIP6 */
        rem[conn_num].remote_id = dwr_rng(rng_seed);
        /* Make sure the following does not leak */
        /* Yes, RD is 0.  Yes, this may very well be a bug */
        packet = make_dns_header(rem[conn_num].remote_id,0x0000,0,0,0);
        if(packet == 0 || dw_append(rem[conn_num].query,packet) == -1 ||
                        dw_put_u16(packet,1,-1) == -1 /* QCLASS: 1 */) {
                goto catch_dwx_glueless_done;
        }
        make_socket_nonblock(s); /* Linux kernel bug */
        if ((do_random_bind(s,addr.len) == -1) ||
            (connect(s, (struct sockaddr *)&server, inet_len) == -1) ||
            (send(s,packet->str,packet->len,0) < 0)) {
                closesocket(s);
                goto catch_dwx_glueless_done;
        }

        b_remote[conn_num] = s;
        if(rem[conn_num].socket != INVALID_SOCKET) {
                closesocket(rem[conn_num].socket);
        }
        rem[conn_num].socket = s;
        /* We should have now finished up updating this connection */

catch_dwx_glueless_done:
        if(answer != 0) {
                dw_destroy(answer);
        }
        if(packet != 0) {
                dw_destroy(packet);
        }
}

/* Create a child query to solve an incomplete CNAME referral */
int dwx_do_cname_glueless(dw_str *query, int conn_num) {
        /* int already = 0; */

        if(query == 0) {
                return -1;
        }

        /* Do we connect to an already existing query? */
        /* Disabled because this code has not been tested */
        /*
        already = dwx_find_inflight(query);
        rem[conn_number].child_id = already;
        if(already != -1) {
                if(dwx_do_glueless_inflight(conn_num, already, 2) != -2) {
                        return 1;
                }
        }
        */

        dwx_do_glueless_new(query, conn_num, 2);

        return 1;
}

/* Handle having an incomplete CNAME query finished upstream */
void dwx_incomplete_cname_done(dw_str *query, int child, int l) {
        int parent = 0;
        dw_str *cname_cache = 0, *action = 0, *answer = 0;

        /* Arguments: conn_num, query (conn_num->query),
         * action (from cache, make qtype 65394 via
         * dw_put_u16(cname_cache, 65394, -3)), answer (from cache, via
         * parent query)
         */
        if(rem[child].local == 0 || rem[child].local[l] == 0) {
                goto catch_dwx_incomplete_cname_done;
        }

        parent = rem[child].local[l]->glueless_conn;
        if(rem[parent].child_id != child) {
                goto catch_dwx_incomplete_cname_done;
        }
        cname_cache = dw_copy(rem[parent].query);
        if(cname_cache == 0 || cname_cache->len < 3 ||
                        dw_put_u16(cname_cache, 65394, -3) == -1) {
                goto catch_dwx_incomplete_cname_done;
        }
        action = dwh_get(cache, cname_cache, 0, 1);
        answer = dwh_get(cache, query, 0, 1);
        if(action == 0 || answer == 0) {
                goto catch_dwx_incomplete_cname_done;
        }

        dwx_make_cname_reply(parent, rem[parent].query, action, answer, 0, 0);

catch_dwx_incomplete_cname_done:
        if(cname_cache != 0) {
                dw_destroy(cname_cache);
        }
        if(action != 0) {
                dw_destroy(action);
        }
        if(answer != 0) {
                dw_destroy(answer);
        }
}

/* See if a CNAME referral is already cached; if so, chase the CNAME
 * Input:
 * orig_query: case-preserved version of query from client
 * query: lower-case version of query from client
 * client: Structure for sending info to client
 * from_ip: IP of client
 * local_id: Query ID of DNS query from client
 * sock: Socket ID of local client
 */
int dwx_cname_in_cache(dw_str *orig_query, dw_str *query,
                sockaddr_all_T *client, ip_addr_T *from_ip, int32_t local_id,
                SOCKET sock, uint16_t from_port) {
        dw_str *cname_cache = 0, *action = 0, *real_query = 0, *packet = 0;
        int ret = 0;
        int_fast32_t b = 0, offset = 0, num_alloc = 1, qtype = 0;

        num_alloc = key_n[DWM_N_max_inflights];
        if(num_alloc < 1) {
                num_alloc = 1;
        }
        if(num_alloc > 32000) {
                num_alloc = 32000;
        }

        if(orig_query == 0 || query == 0 || client == 0 || from_ip == 0) {
                return 0; /* Failed */
        }
        /* Look for CNAME of query */
        cname_cache=dw_copy(query);
        if(cname_cache == 0 || cname_cache->len < 3 ||
                        dw_put_u16(cname_cache, 65394, -3) == -1) {
                goto catch_dwx_cname_in_cache;
        }
        action = dwh_get(cache, cname_cache, 0, 1);
        if(action == 0) {
                goto catch_dwx_cname_in_cache;
        }
        dw_log_dwstr("Cached CNAME refer found for ",query,100);

        /* Create new remote for solving incomplete CNAME */
        offset = dw_fetch_u16(action, -2);
        offset += 2; /* Go past two-byte length */
        real_query = dw_get_dname(action->str, offset, 260, 0);
        dwc_lower_case(real_query);
        if(real_query == 0) {
                goto catch_dwx_cname_in_cache;
        }
        qtype = dw_fetch_u16(query,-1);
        if(qtype == -1 || dw_put_u16(real_query, qtype, -1) == -1) {
                goto catch_dwx_cname_in_cache;
        }

        b = find_free_remote();
        if(b == -1) { /* We're overloaded */
                goto catch_dwx_cname_in_cache;
        }
        reset_rem(b);
        rem[b].query = dw_copy(real_query);
        rem[b].remote_id = dwr_rng(rng_seed);
        rem[b].local = dw_malloc(num_alloc * sizeof(local_T *));
        if(rem[b].local == 0) {
                goto catch_dwx_cname_in_cache;
        }
        rem[b].local[0] = dw_malloc(sizeof(local_T));
        rem[b].num_locals = 0;
        if(rem[b].local[0] == 0) {
                reset_rem(b);
                goto catch_dwx_cname_in_cache;
        }
        rem[b].num_locals = 1;
        rem[b].die = get_time() + ((int64_t)timeout_seconds << 12);
        rem[b].local[0]->orig_query = dw_copy(orig_query);
        rem[b].local[0]->action = dw_copy(action);
        rem[b].local[0]->from_socket = sock;
        rem[b].local[0]->tcp_num = INVALID_SOCKET;
        rem[b].local[0]->port = from_port;
        rem[b].local[0]->local_id = local_id;
        rem[b].local[0]->glueless_type = 3;
        rem[b].local[0]->glueless_conn = -1;
        rem[b].local[0]->ip = *from_ip;

        /* Make packet to send upstream */
        packet = make_dns_header(rem[b].remote_id,0x0000,0,0,0);
        if(packet == 0 || dw_append(rem[b].query,packet) == -1 ||
                        dw_put_u16(packet,1,-1) == -1 /* QCLASS: 1 */) {
                reset_rem(b);
                goto catch_dwx_cname_in_cache;
        }
        /* Send packet upstream */
        make_remote_connection(b,(unsigned char *)packet->str,
                        packet->len,rem[b].query,INVALID_SOCKET);

        ret = 1;

catch_dwx_cname_in_cache:
        if(cname_cache != 0) {
                dw_destroy(cname_cache);
        }
        if(action != 0) {
                dw_destroy(action);
        }
        if(real_query != 0) {
                dw_destroy(real_query);
        }
        if(packet != 0) {
                dw_destroy(packet);
        }
        return ret;
}

void dwx_cached_cname_done(dw_str *query, int b, int l, int depth) {

        dw_str *answer = 0, *oquery = 0, *action = 0;

        if(rem[b].local == 0 || rem[b].local[l] == 0 || depth > 32) {
                return;
        }

        oquery = dw_copy(rem[b].local[l]->orig_query);
        dwc_lower_case(oquery);
        action = dw_copy(rem[b].local[l]->action);
        answer = dwh_get(cache, query, 0, 1);

        rem[b].local[l]->glueless_type = 0; /* For dwx_make_cname_reply */

        if(answer == 0 || oquery == 0 || action == 0) {
                goto catch_dwx_cached_cname_done;
        }

        dwx_make_cname_reply(b,oquery,action,answer,depth + 1,0);

catch_dwx_cached_cname_done:
        dw_destroy(answer);
        dw_destroy(oquery);
        dw_destroy(action);
}

