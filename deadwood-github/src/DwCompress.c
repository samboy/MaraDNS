/* Copyright (c) 2009-2014 Sam Trenholme
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

#include "DwStr.h"
#include "DwStr_functions.h"
#include "DwCompress.h"
#include "DwDnsStr.h"

/* Given a string with compressed DNS data, and an offset in the string
 * looking at a compression pointer, determine where to point to and in
 * what string (qlen is the length of the question).
 *
 * The return code is a little complicated.  -1 means error; -2 or lower
 * means an offset in the question string (-2 is beginning of question or
 * offset 12 in a DNS label, -3 is second byte in question, etc.)
 *
 * 0 or higher means an offset in the "answer" string or the string as
 * stored in the cache.
 */

int32_t dwc_decomp_offset(dw_str *in, int32_t offset, int32_t qlen) {
        int32_t t = 0;

        if(dw_assert_sanity(in) == -1) {
                return -1;
        }

        t = offset;
        if(t < 0 || t > in->len) {
                return -1;
        }
        if(*(in->str + t) < 64) { /* Not a compression pointer */
                return t;
        }
        offset = *(in->str + t) & 0x3f;
        offset <<= 8;
        offset += *(in->str + t + 1);

        offset -= 12; /* DNS header */
        if(offset < qlen && qlen > 0) { /* In question */
                return -2 - offset;
        }
        offset -= qlen;
        offset -= 2; /* CLASS part of question */
        if(offset < 0 || offset > in->len) { /* Invalid place */
                return -1;
        }
        return offset; /* In answer */
}

/* Finish up a name by putting the final '\0' at the end of the binary
 * dname, and adjusting the length for the relevant variables */
int32_t dwc_finish_name(dw_str *out, int32_t *delta, int32_t offset,
            int compress_followed, int32_t t) {

        if(dw_assert_sanity(out) == -1 || offset < 0) {
                return -1;
        }

        dw_addchar(0,out);
        if(compress_followed != 0) {
                *delta += 1;
        }
        if(compress_followed == 0) {
                t = offset + 1;
        }
        return t;
}

/* Given a string with the compressed DNS data, a string with the
 * uncompressed DNS data, a string with the DNS question, a pointer where
 * we will put how much longer the uncompressed string is
 * and an offset in the compressed string where the compressed dlabel begins,
 * we decompress the string
 *
 * We return -1 on error; on success, we return the offset in the source
 * string where the DNS name ends.
 */
int32_t dwc_decomp_dname(dw_str *in, dw_str *out, dw_str *q, int32_t *delta,
    int32_t where_dname) {
        int32_t counter = 0, offset = 0, t = 0;
        int compress_followed = 0, len = 0, use_q_string = 0;
        dw_str *tmp = 0;

        if(dw_assert_sanity(in) == -1 || dw_assert_sanity(out) == -1 ||
                        dw_assert_sanity(q) == -1 || delta == 0 ||
                        where_dname < 0) {
                return -1;
        }

        offset = where_dname;
        for(counter = 0 ; counter < 200; counter++) {
                if(use_q_string == 0) { /* Are we in question or answer? */
                        if(offset + 1 > in->len) { /* Sanity check */
                                return -1;
                        }
                        len = *(in->str + offset);
                } else {
                        if(offset + 1 > q->len) { /* Sanity check */
                                return -1;
                        }
                        len = *(q->str + offset);
                }
                if(len >= 192) { /* Compression pointer */
                        if(use_q_string == 1) { /* No comp pointers in Q */
                                return -1;
                        }
                        if(compress_followed == 0) { /* Mark orig length */
                                t = offset + 2;
                                *delta = -2;
                        }
                        offset = dwc_decomp_offset(in, offset, q->len);
                        if(offset == -1) {
                                return -1;
                        } else if(offset < 0) { /* In question, not answer */
                                use_q_string = 1;
                                offset = -2 - offset;
                        }
                        compress_followed = 1;
                } else if(len > 63 || len < 0) { /* Invalid length */
                        return -1;
                } else if(len == 0) { /* End of name */
                        t = dwc_finish_name(out,delta,offset,compress_followed,
                                t);
                        break;
                } else { /* Copy single label of dname over */
                        if(use_q_string == 0) { /* If we're in answer */
                                tmp = dw_substr(in,offset,len + 1, 1);
                        } else { /* otherwise, we're in question */
                                tmp = dw_substr(q,offset,len + 1, 1);
                        }
                        dw_append(tmp,out);
                        dw_destroy(tmp);
                        offset += len + 1;
                        if(compress_followed != 0) {
                                *delta += len + 1;
                        }
                }
        }
        return t;
}

/* Given a rr type number (1 for A, etc.), return a character that
 * describes the RR in question.  The format for this is simple; we only
 * care about whether we are to compress the data in question (this is
 * the first nybble, '1' means yes, compress, and '0' means no, don't
 * compress), how many bytes at the beginning of the label (0-9, second
 * nybble), how many "dname"s we have to compress (usually 1 but
 * sometimes 2, third nybble), and how many 16-bit words we have after the
 * final dname (usually 0 but is "10" or "a" for SOA records; 20 bytes)
 *
 * Sometimes, the RR will have data after the dnames; we treat this data
 * as a black box and keep it as-is.  We return 0 in that case.
 *
 */

int16_t dwc_type_desc(int32_t type) {
        switch(type) {
                case 15: /* MX */
                        return 0x1210; /* Compress, 2 bytes then 1 dname */
                case 2: /* NS */
                case 12: /* PTR */
                case 5: /* CNAME */
                        return 0x1010; /* Compress, 1 dname at beginning */
                case 6: /* SOA */
                        return 0x102a; /* Compress, 2 dnames at beginning,
                                          20 bytes after dnames */
                case 3: /* MD */
                case 4: /* MF */
                case 7: /* MB */
                case 8: /* MG */
                case 9: /* MR */
                        return 0x0010; /* Don't compress, 1 dname at start */
                case 14: /* MINFO */
                case 17: /* RP */
                        return 0x0020; /* Don't compress, 2 dnames at start */
                case 18: /* AFSDB */
                case 21: /* RT */
                        return 0x0210; /* Don't compress, 2 bytes, 1 dname */
                case 33: /* SRV */
                        return 0x0610; /* Don't compress, 6 bytes, 1 dname */
                default:
                        return 0;
        }
}

/* Decompress the rddata of a single record.
 *
 * Input: Description of RR to decompress (bytes in lead, number of DNS
 * names to decompress; 16-bit words in tail as a packed 12-bit value)
 * compressed string offset, input string location, output string location,
 * question string location
 *
 * Output: New compressed string offset
 */
int32_t dwc_decomp_rddata(int16_t desc, int32_t offset, dw_str *in,
                dw_str *out, dw_str *q) {
        dw_str *tmp = 0;
        int lead = 0, ndnames = 0, tail = 0;
        int32_t rdo = 0, rdlength = 0, delta = 0;

        if(dw_assert_sanity(in) == -1 || dw_assert_sanity(out) == -1 ||
                        dw_assert_sanity(q) == -1 || desc < 0 ||
                        offset < 0) {
                return -1;
        }

        lead = (desc & 0xf00) >> 8;
        ndnames = (desc & 0xf0) >> 4;
        tail = (desc & 0x0f) << 1;
        offset += 10;
        rdo = out->len - 2; /* Where RDLENGTH is in string */
        if(lead > 0) {
		if(in->len < offset + lead) { /* No truncated packets */
                        goto catch_dwc_decomp_rddata;
                }
                tmp = dw_substr(in,offset,lead,1);
                if(dw_append(tmp,out) == -1) {
                        goto catch_dwc_decomp_rddata;
                }
                dw_destroy(tmp);
                tmp = 0;
                offset += lead;
        }
        while(ndnames > 0) {
                delta = 0;
                offset = dwc_decomp_dname(in,out,q,&delta,
                          offset);
                if(offset < 0) {
                        goto catch_dwc_decomp_rddata;
                }
                rdlength = dw_fetch_u16(out,rdo);
                rdlength += delta;
                dw_put_u16(out,rdlength,rdo);
                ndnames--;
        }
        if(tail > 0) {
		if(in->len < offset + tail) { /* No truncated packets */
                        goto catch_dwc_decomp_rddata;
                }
                tmp = dw_substr(in,offset,tail,1);
                dw_append(tmp,out);
                dw_destroy(tmp);
                tmp = 0;
                offset += tail;
        }

        return offset;

catch_dwc_decomp_rddata:
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        return -1; /* Error */
}

/* Decompress a single DNS record.
 *
 * Input: input string, output string, question string, "stack" string for
 *        storing offsets of where RRs and RR's post-name data are, offset
 *
 * Output: New offset
 */
int32_t dwc_decomp_rr(dw_str *in, dw_str *out, dw_str *q, dw_str *stack,
                int32_t offset) {

        int32_t val = 0, delta = 0;
        int16_t desc = 0;
        dw_str *tmp = 0;

        if(dw_assert_sanity(in) == -1 || dw_assert_sanity(out) == -1 ||
                        dw_assert_sanity(q) == -1 ||
                        dw_assert_sanity(stack) == -1 || offset < 0) {
                return -1;
        }

        dw_push_u16(out->len,stack); /* Beginning of RR */

        /* DNS name at beginning of RR */
        offset = dwc_decomp_dname(in,out,q,&delta,offset);
        if(offset < 0 || offset > in->len - 7) {
                goto catch_dwc_decomp_rr;
        }

        dw_push_u16(out->len,stack); /* Part of RR after RR name */
        val = dw_fetch_u16(in,offset); /* RR type */
        if(val == -1) {
                goto catch_dwc_decomp_rr;
        }
        desc = dwc_type_desc(val); /* Description for compression purposes */

        /* Add data between name and RDdata */
        tmp = dw_substr(in,offset,10,1);
        dw_append(tmp,out);
        dw_destroy(tmp);
        tmp = 0;

        val = dw_fetch_u16(in,offset + 8); /* RDLENGTH */
        if(desc == 0) { /* No compression pointers */
		if(in->len < offset + 10 + val) { /* No truncated packets */
			goto catch_dwc_decomp_rr;
		}
                tmp = dw_substr(in,offset + 10,val,1);
                dw_append(tmp,out);
                dw_destroy(tmp);
                offset += val + 10;
        } else { /* Decompress compression pointers */
                offset = dwc_decomp_rddata(desc, offset, in, out, q);
        }

        return offset;

catch_dwc_decomp_rr:
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        return -1;
}

/* Given the question we are answering, and a packet as stored in the cache
 * (a DNS packet processed by dw_packet_to_cache() ) decompress the packet
 * and output the decompressed packet as a newly created DwStr() object
 */

dw_str *dwc_decompress(dw_str *q, dw_str *in) {
        dw_str *out = 0, *tmp = 0, *stack = 0;
        int32_t offset = 0;
        int rr = 0;

        if(dw_assert_sanity(in) == -1 || dw_assert_sanity(q) == -1) {
                return 0;
        }

        out = dw_create(2048);
        if(out == 0) {
                return 0;
        }
        stack = dw_create(2048); /* 1024 lengths or 512 dlabels */
        if(stack == 0) {
                goto catch_dwc_decompress;
        }

        for(rr = 0 ; rr < 1000 && offset < in->len - 7 ; rr++) {
                offset = dwc_decomp_rr(in, out, q, stack, offset);
                if(offset < 0 || offset > in->len - 7) {
                        goto catch_dwc_decompress;
                }
        }

        dw_append(stack,out);
        dw_destroy(stack);
        tmp = dw_substr(in,-7,-1,1);
        dw_append(tmp,out);
        dw_destroy(tmp);
        tmp = 0;
        return out;

catch_dwc_decompress:
        if(out != 0) {
                dw_destroy(out);
        }
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        if(stack != 0) {
                dw_destroy(stack);
        }
        return 0;
}

/* Determine whether two single dlabels are identical; 1 if they are, 0
 * if they are not, and -1 on error
 * Input: String with first label, offset of begining of dlabel in
 *        first string, string and offset for second label
 * 2013-07-13: Made search case-insensitive
 */
int dwc_label_same(dw_str *a, int32_t a_o, dw_str *b, int32_t b_o) {
        int c = 0, noloop = 0;
        uint8_t lc1, lc2;

        if(dw_assert_sanity(a) == -1 || dw_assert_sanity(b) == -1 ||
           a_o > a->len || b_o > b->len || a_o < 0 || b_o < 0) {
                return -1;
        }

        lc1 = *(a->str + a_o);
        lc2 = *(b->str + b_o);
        if(lc1 >= 'A' && lc1 <= 'Z') { lc1 += 32; }
        if(lc2 >= 'A' && lc2 <= 'Z') { lc2 += 32; }
        if(lc1 != lc2) {
                return 0;
        }

        c = *(a->str + a_o);

        if(c < 0 || c > 64 || (a_o + c > a->len) || (b_o + c > b->len)) {
                return -1;
        }

        for(noloop = 0; noloop < 128 && c > 0; noloop++) {
                lc1 = *(a->str + a_o + c);
                lc2 = *(b->str + b_o + c);
                if(lc1 >= 'A' && lc1 <= 'Z') { lc1 += 32; }
                if(lc2 >= 'A' && lc2 <= 'Z') { lc2 += 32; }
                if(lc1 != lc2) {
                        return 0;
                }
                c--;
        }

        return 1;
}

/* Determine whether two dlabels are the same, where one dlabel can
 * have compression pointers (the other doesn't)
 *
 * Input: String with uncompressed dname (u), offset to dname in that string,
 *        String with compressed dname (c), offset to dname in compressed
 *        string,
 *        pointer to string with question (q), since compression pointers
 *        sometimes point here
 *
 * Output: -1 if error, 0 if different, 1 if same
 */

int dwc_dname_same(dw_str *u, int32_t u_o, dw_str *c, int32_t c_o, dw_str *q) {
        int count = 0, in_q = 0, len = 0;
        int32_t place = 0;

        place = c_o;

        if(dw_assert_sanity(u) == -1 || dw_assert_sanity(c) == -1 ||
                        u_o < 0 || u_o > u->len || c_o < 0 || c_o > c->len) {
                return -1;
        }

        for(count = 0; count < 300; count++) {
                /* Follow any compression pointers as needed */
                if(in_q == 0) {
                        if(q != 0) {
                                place = dwc_decomp_offset(c, place, q->len);
                        } else {
                                place = dwc_decomp_offset(c, place, 0);
                        }
                        if(place == -1 || (q == 0 && place < 0)) {
                                return -1;
                        }
                        if(place < -1 && q != 0) {
                                in_q = 1;
                                place = -2 - place;
                        }
                }
                if(in_q == 0) {
                        if(dwc_label_same(u,u_o,c,place) != 1) {
                                return 0; /* Not same */
                        }
                } else {
                        if(dwc_label_same(u,u_o,q,place) != 1) {
                                return 0; /* Not same */
                        }
                }
                len = *(u->str + u_o);
                if(len == 0) {
                        return 1; /* Same */
                }
                if(len < 0 || len > 64 || (u_o + len >= u->len)) {
                        return -1;
                }
                if(in_q == 0 && (place + len >= c->len)) {
                        return -1;
                } else if(in_q == 1 && q != 0 && (place + len >= q->len)) {
                        return -1;
                }
                u_o += len + 1;
                place += len + 1;
        }
        return -1;
}

/* Determine whether a given uncompressed domain name (b) is the ending of
 * another, compressed domain name (h, which may also point back to the
 * question of the domain name).  If it is, we output a postive number
 * if the offset of where it is can be found in the compressed answer (0
 * if it's at the start of the answer); and a negative number -3 or higher
 * if it is in the question (-3 is start of question, -4 first byte in
 * question, etc.). -1 is a fatal error; -2 is "not found"
 *
 * Input: String with uncompressed name, offset in string of uncompressed
 *        name, String with compressed name, offset in string with compressed
 *        name, String with question.  If string with compressed name is
 *        zero, we look in the question for a match; if question is zero, we
 *        only look in the string with the compressed name for a match.
 *
 * Output: As described above; offset if found, -2 if not found
 *
 * Named "in_bailiwick" because we can use this for bailiwick tests, such
 * as dwc_in_bailiwick(bailiwick,0,hostname,0,0) and see if we get a
 * positive number or 0 (yes, we're in bailiwick), or a negative number
 * (no, we're not)
 *
 * In a loop, we follow the compression pointer of the hostname until we're
 * at a non-compression pointer.  We then see if the label is the same as
 * the first bailiwick label.
 *
 * If it is, we repeat the process until we're at the end of the
 * bailiwick label.
 *
 * If it isn't, then we look at the next label in the hostname
 * string and perform the same comparison until the hostname string
 * is zero-length.
 */

int32_t dwc_in_bailiwick(dw_str *b, int32_t b_o, dw_str *h,
        int32_t h_o, dw_str *q) {
        int count = 0, in_q_string = 0, len = 0;
        int32_t place = 0;

        if(dw_assert_sanity(b) == -1 || dw_assert_sanity(h) == -1 ||
                        b_o < 0 || b_o > b->len || h_o < 0 || h_o > h->len) {
                return -1;
        }
        place = h_o;
        for(count = 0; count < 300; count++) { /* Infinite loop protect */
                if(in_q_string == 0) { /* If not in question */
                        if(q != 0) { /* No segfault if question is unset */
                                place = dwc_decomp_offset(h, place, q->len);
                        } else {
                                place = dwc_decomp_offset(h, place, 0);
                        }
                        if(place == -1 || (q == 0 && place < 0)) { /* Sanity */
                                return -1;
                        }
                        if(place < 0 && q != 0) {
                                place = -2 - place;
                                in_q_string = 1;
                        }
                }
                if(in_q_string == 0) { /* Look in answer */
                        if(dwc_dname_same(b, b_o, h, place, q) == 1) {
                                return place;
                        }
                } else { /* Look in question */
                        if(dwc_dname_same(b, b_o, q, place, q) == 1) {
                                return -3 - place;
                        }
                }
                /* Move to next dlabel */
                if(in_q_string == 0) {
                        len = *(h->str + place);
                        if(len + place + 1 > h->len) {
                                return -1; /* Out of bounds */
                        }
                } else if(q != 0) {
                        len = *(q->str + place);
                        if(len + place + 1 > q->len) {
                                return -1; /* Out of bounds */
                        }
                } else {
                        return -1; /* Invalid */
                }
                if(len == 0) {
                        return -2; /* No match */
                }
                place += len + 1; /* Next part of name */
        }
        return -1; /* Error */
}

/* Look at a DNS name and put all of its non-compressed labels on
 * a stack (a dw_str object, since the dw_str library has support for
 * putting and reading 16-bit values there)
 *
 * Input: String with dname, offset of dname in string, string with
 *        stack, value to add to any number put on the stack
 *
 * Output: 0 on success, -1 on error
 */

int dwc_push_offsets(dw_str *dns, int32_t place, dw_str *stack, int32_t
                offset) {
        int len, count;

        if(dw_assert_sanity(dns) == -1 || dw_assert_sanity(stack) == -1) {
                return -1;
        }

        for(count = 0; count < 300; count++) { /* Infinite loop protection */
                if(place > dns->len || place < 0) {
                        return -1; /* Error */
                }
                len=*(dns->str + place);
                if(len >= 192 /* Comp marker */ || len == 0 /* End */) {
                        return 0; /* Done */
                }
                if(len >= 64) {
                        return -1; /* Invalid length field */
                }
                if(place < 0 || place >= 0x3fff ||
                   place + offset < 0 || place + offset > 0xffff) {
                        return -1; /* Invalid offset */
                }
                if(dw_push_u16(place + offset, stack) == -1) {
                        return -1;
                }
                place += len + 1;
        }
        return 0; /* Success */
}

/* Given an uncompressed string, an offset we're looking at in said
 * uncompressed string, a partially compressed string, a question string,
 * and a "stack" of offsets, determine if we should return a compression
 * pointer.  If so, where will the compression pointer point.
 *
 * Input: u (uncompressed string), u_o (offset in uncompressed string),
 * c (partially compressed string, just the answer part of the DNS packet),
 * q (question string), s (stack of offsets)
 *
 * Output: -2: Not found
 *         -1: Error
 *         0-16383: Have the compression pointer point this many bytes in to
 *                  the final compressed string
 */

int32_t dwc_seek_comp_pointer(dw_str *u, int32_t u_o, dw_str *c, dw_str *q,
                dw_str *s) {
        int32_t s_o = 0; /* Stack offset (which thingy we're looking at in
                          * the stack) */
        int32_t offset = 0;
        int in_q = 0; /* Whether we're in the question string or not */
        int count = 0; /* Infinite loop protection */

        if(dw_assert_sanity(u) == -1 || dw_assert_sanity(c) == -1 ||
                        u_o < 0 || u_o > u->len) {
                return -1;
        }

        for(count = 0; count < 1000 && s_o < s->len; count++) {
                offset = dw_fetch_u16(s, s_o);
                in_q = 0;
                if(offset < 0) {
                        return -1;
                }
                if(offset >= 0x8000) {
                        in_q = 1;
                }
                offset &= 0x3fff;
                if(in_q == 1) {
                        if(dwc_dname_same(u, u_o, q, offset, 0) == 1) {
                                return 12 + offset;
                        }
                } else {
                        if(dwc_dname_same(u, u_o, c, offset, q) == 1) {
                                return 12 + q->len + 2 + offset;
                        }
                }
                s_o += 2;
        }
        return -2;

}

/* Given the beginning of a DNS domain name (dname), and the number of dnames
 * we will look at, a pointer to the stack to add uncompressed labels, the
 * question string, and the partially compressed string (which we will append
 * to), compress part of the string.
 *
 * Input: Uncompressed string (u), uncompressed offset (u_o), partially
 *        compressed string (c; adding to end), number dlabels (num_dlabels),
 *        stack of uncompressed labels (s; which we will append to if the
 *        label can't be compressed), question string (q), recursion depth (d)
 *
 * Output: New uncompressed offset ; -1 on fatal error
 */

int32_t dwc_compress_dlabels(dw_str *u, int32_t u_o, dw_str *c,
                int num_dlabels, dw_str *s, dw_str *q, uint8_t d) {
        int32_t point = 0;
        int count = 0, len = 0;
        dw_str *tmp = 0;

        if(dw_assert_sanity(u) == -1 || dw_assert_sanity(c) == -1 ||
                        dw_assert_sanity(s) == -1 || u_o < 0 ||
                        u_o > u->len) {
                return -1;
        }

        if(d >= 20 || num_dlabels <= 0) {
                return u_o;
        }

        for(count = 0; count < 300; count++) {
                point = dwc_seek_comp_pointer(u,u_o,c,q,s);
                if(point > 0) { /* Compression pointer to be used */
                        point &= 0x3fff;
                        point |= 0xc000;
                        if(dw_push_u16(point,c) == -1) {
                                return -1;
                        }
                        point = dw_get_dn_end(u,u_o); /* End of uncomp label */
                        if(point == -1) {
                                return -1;
                        }
                        return dwc_compress_dlabels(u, point, c,
                                        num_dlabels - 1, s, q, d + 1);
                } else if(point == -2) { /* Not found */
                        /* Go to the next label */
                        len = *(u->str + u_o);
                        if(len > 63 || len < 0) {
                                return -1;
                        } else if(len == 0) { /* End of dname */
                                dw_addchar(0,c);
                                return dwc_compress_dlabels(u, u_o + 1, c,
                                        num_dlabels - 1, s, q, d + 1);
                        }
                        /* Add this label to stack of uncompressed dlabels */
                        if(dw_push_u16(c->len,s) == -1) {
                                return -1;
                        }
                        /* Copy label to compressed string */
                        tmp = dw_substr(u, u_o, len + 1, 1);
                        if(tmp == 0) {
                                return -1;
                        }
                        dw_append(tmp,c);
                        dw_destroy(tmp);
                        u_o += len + 1;

                } else { /* Error */
                        return -1;
                }
        }

        return -1; /* We should never get here */
}

/* Compress the rddata part of a record with dlabels
 *
 * Input: desc (description of rddata), u (unompressed string),
 * offset (offset in uncompressed string), c (partially compressed string),
 * s (stack of places compression pointer can point to), q (question string)
 *
 * Output: New offset
 */

int32_t dwc_comp_rddata(int16_t desc, dw_str *u, int32_t offset, dw_str *c,
                dw_str *s, dw_str *q) {

        dw_str *tmp = 0;
        int lead = 0, ndnames = 0, tail = 0;

        if(dw_assert_sanity(u) == -1 || dw_assert_sanity(c) == -1 ||
                        dw_assert_sanity(s) == -1 || desc < 0 ||
                        offset < 0 || offset > u->len) {
                return -1;
        }

        lead = (desc & 0xf00) >> 8;
        ndnames = (desc & 0xf0) >> 4;
        tail = (desc & 0x0f) << 1;

        /* The stuff in the rddata before the dlabels (such as the preference
         * for a MX record) */
        if(lead > 0) {
                tmp = dw_substr(u,offset,lead,1);
                if(dw_append(tmp,c) == -1) {
                        dw_destroy(tmp);
                        return -1;
                }
                dw_destroy(tmp);
                offset += lead;
        }

        offset = dwc_compress_dlabels(u,offset,c,ndnames,s,q,0);
        if(offset == -1) {
                return -1;
        }

        /* Anything in the RDDATA after the dlabel (the only RR type I know
         * of that does this is the SOA record */
        if(tail > 0) {
                tmp = dw_substr(u,offset,tail,1);
                if(dw_append(tmp,c) == -1) {
                        dw_destroy(tmp);
                        return -1;
                }
                dw_destroy(tmp);
                offset += tail;
        }

        return offset;
}

/* Given a pointer to a list of 16-bit offsets (we will use two of them),
 * a question string, a partially compressed string, and the uncompressed
 * string, add this particular DNS record to the partially compressed
 * string.
 *
 * Input: Pointer to 2 offsets used for this RR (o), uncompressed string (u),
 *        partially compressed string (c), question string (q), stack
 *        of pointers to dlabels (s)
 *
 * Output: -1 on error, 1 on success
 */

int dwc_compress_rr(uint16_t *o, dw_str *u, dw_str *c, dw_str *q, dw_str *s) {
        uint16_t name = 0, data = 0;
        int16_t desc = 0;
        int32_t offset = 0, rdplace = 0, type = 0, len = 0, rdold = 0;
        dw_str *tmp = 0;

        if(dw_assert_sanity(u) == -1 || dw_assert_sanity(c) == -1 ||
                        dw_assert_sanity(q) == -1 ||
                        dw_assert_sanity(s) == -1 || o == 0) {
                return -1;
        }

        name = o[0];
        data = o[1];
        offset = name;

        if(name > u->len || data > u->len || name > data) { /* Sanity check */
                return -1;
        }

        offset = dwc_compress_dlabels(u, offset, c, 1, s, q, 0); /* Name */
        if(offset == -1 || offset != data) {
                return -1;
        }

        /* Type, class, TTL, rdlength (which we will change) */
        tmp = dw_substr(u,offset,10,1);
        if(tmp == 0) {
                return -1;
        }
        dw_append(tmp,c);
        dw_destroy(tmp);

        type = dw_fetch_u16(u,offset);
        rdplace = offset + 8;
        offset += 10;
        desc = dwc_type_desc(type);
        if((desc & 0x1000) == 0) { /* Unknown/no dnames to compress */
                len = dw_fetch_u16(u,rdplace);
                tmp = dw_substr(u,offset,len,1);
                if(dw_append(tmp,c) == -1) {
                        dw_destroy(tmp);
                        return -1;
                }
                dw_destroy(tmp);
        } else {
                rdold = c->len;
                offset = dwc_comp_rddata(desc, u, offset, c, s, q);
                dw_put_u16(c,c->len - rdold,rdold - 2);
                if(offset == -1) {
                        return -1;
                }
        }

        return 1;
}

/* Compress all of the RR records in a string */

int dwc_compress_all_rrs(dns_string *unpack, dw_str *in, dw_str *out,
                dw_str *q, dw_str *stack) {
        int32_t seek = 0;

        if(dw_assert_sanity(in) == -1 || dw_assert_sanity(out) == -1 ||
                        dw_assert_sanity(q) == -1 ||
                        dw_assert_sanity(stack) == -1 || unpack == 0) {
                return -1;
        }

        /* AN section */
        for(seek = 0; seek < unpack->ancount * 2; seek += 2) {
                if(dwc_compress_rr(unpack->an + seek, in,out,q, stack) == -1) {
                        return -1;
                }
        }

        /* NS section */
        for(seek = 0; seek < unpack->nscount * 2; seek += 2) {
                if(dwc_compress_rr(unpack->ns + seek, in,out,q, stack) == -1) {
                        return -1;
                }
        }

        /* AR section */
        for(seek = 0; seek < unpack->arcount * 2; seek += 2) {
                if(dwc_compress_rr(unpack->ar + seek, in,out,q, stack) == -1) {
                        return -1;
                }
        }

        return 1;
}


/* Compress a DNS string, and return a newly created compressed string. */

dw_str *dwc_compress(dw_str *q, dw_str *in) {
        dw_str *stack = 0; /* Stack of uncompressed dlabels */
        dw_str *out = 0; /* Compressed string */
        dns_string *unpack = 0;

        if(dw_assert_sanity(q) == -1 || dw_assert_sanity(in) == -1) {
                return 0;
        }

        stack = dw_create(1024);
        out = dw_create(515);
        if(stack == 0) {
                goto catch_dwc_compress;
        }
        if(dwc_push_offsets(q,0,stack,0x8000) == -1) {
                goto catch_dwc_compress;
        }
        unpack = dwc_make_dns_str(in);
        if(unpack == 0) {
                goto catch_dwc_compress;
        }

        if(dwc_compress_all_rrs(unpack, in, out, q, stack) == -1) {
                goto catch_dwc_compress;
        }

        dw_push_u16(unpack->ancount,out);
        dw_push_u16(unpack->nscount,out);
        dw_push_u16(unpack->arcount,out);
        dw_addchar(unpack->type,out);
        dw_destroy(stack);
        dwc_zap_dns_str(unpack);
        return out;

catch_dwc_compress:
        if(stack != 0) {
                dw_destroy(stack);
        }
        if(out != 0) {
                dw_destroy(out);
        }
        if(unpack != 0) {
                dwc_zap_dns_str(unpack);
        }
        return 0;
}

#ifdef HAVE_MAIN
/* Question and answer for "example.com" to test (de)compression */
#define EXAMPLE_COM_Q "\x07\x65\x78\x61\x6D\x70\x6C\x65\x03\x63\x6F\x6D" \
                      "\x00\x00\x01" /* 15 bytes */
#define EXAMPLE_COM_A "\xC0\x0C\x00\x01\x00\x01\x00\x00\x46\x50\x00\x04\x0A" \
        "\x02\x04\x08\xC0\x0C\x00\x02\x00\x01\x00\x00\x46\x50\x00\x05\x02" \
        "\x6E\x73\xC0\x0C\xC0\x39\x00\x01\x00\x01\x00\x00\x46\x50\x00\x04" \
        "\x0A\x01\x02\x03\x00\x01\x00\x01\x00\x01\x00" /* 50 bytes */

#define PA "\300\014\000\005\000\001\000\011-]\000\027\014safebrowsing\005cache\001l\300\037\300;\000\001\000\001\000\000\001\000\000\004J}\245\047\300;\000\001\000\001\000\000\001\000\000\004J}\245\020\300;\000\001\000\001\000\000\001\000\000\004J}\245\021\300;\000\001\000\001\000\000\001\000\000\004J}\245\022\300;\000\001\000\001\000\000\001\000\000\004J}\245\023\300;\000\001\000\001\000\000\001\000\000\004J}\245\024\300;\000\001\000\001\000\000\001\000\000\004J}\245\025\300;\000\001\000\001\000\000\001\000\000\004J}\245\026\300;\000\001\000\001\000\000\001\000\000\004J}\245\027\300;\000\001\000\001\000\000\001\000\000\004J}\245\030\300;\000\001\000\001\000\000\001\000\000\004J}\245\031\300;\000\001\000\001\000\000\001\000\000\004J}\245\032\300;\000\001\000\001\000\000\001\000\000\004J}\245\033\300;\000\001\000\001\000\000\001\000\000\004J}\245\034\300;\000\001\000\001\000\000\001\000\000\004J}\245\035\300;\000\001\000\001\000\000\001\000\000\004J}\245\036\300;\000\001\000\001\000\000\001\000\000\004J}\245\037\300;\000\001\000\001\000\000\001\000\000\004J}\245 \300;\000\001\000\001\000\000\001\000\000\004J}\245!\300;\000\001\000\001\000\000\001\000\000\004J}\245\042\300;\000\001\000\001\000\000\001\000\000\004J}\245#\300;\000\001\000\001\000\000\001\000\000\004J}\245$\300;\000\001\000\001\000\000\001\000\000\004J}\245\045\300;\000\001\000\001\000\000\001\000\000\004J}\245&\000\031\000\000\000\000\000" /* 426 bytes */
#define PQ "\022safebrowsing-cache\006google\003com\000\000\001" /* 33 bytes */
void show_str(dw_str *u) {
        int c = 0;
        for(c = 0; c < u->len; c++) {
                printf("%d %x %c\n",c,*(u->str + c),*(u->str + c));
        }
}

int main() {
        dw_str *q = 0, *a = 0, *u = 0, *c = 0;
        q = dw_create(256);
        a = dw_create(512);
        dw_cstr_append((uint8_t *)PQ,33,q);
        dw_cstr_append((uint8_t *)PA,426,a);
        u = dwc_decompress(q,a);
        c = dwc_compress(q,u);
        dw_stdout(q);
        dw_stdout(a);
        dw_stdout(u);
        dw_stdout(c);
        dw_destroy(q);
        dw_destroy(a);
        dw_destroy(u);
        dw_destroy(c);
        return 0;
}
#endif /* HAVE_MAIN */
