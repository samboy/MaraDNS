/* Copyright (c) 2002-2006 Sam Trenholme
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

/* uncompress a query compressed with the RFC1035 compression algorithm
   (section 4.1.4)
   input: pointer to compressed udp data, pointer to uncompressed udp data
   output: JS_ERROR on error, JS_SUCCESS on success
   note: When in multithreaded mode, this is the only operation that
         needs to be done on data with a mutex on it.  Place a mutex on
         the compressed data, copy it over to uncompressed data, then
         release the mutex.  Have the one "parent" listen for UDP
         packets again while the "child" processes the packet
*/
int decompress_data(js_string *compressed, js_string *uncompressed);

/* Determine the length of a domain-name label
   Input: the js_string obejct with the domain label in question,
          the offset from the beginning of the js_string object
          with the domain label
   Output: The length of the label, JS_ERROR on error
*/
int dlabel_length(js_string *raw, unsigned int offset);

/* Compress an uncompressed RFC1035 query/answer according to section 4.1.4.
   input: pointer to uncompressed udp data, pointer to compressed udp data
   output: JS_ERROR on error, JS_SUCCESS on success
*/
int compress_data(js_string *uncompressed, js_string *compressed);

/* Zero-copy implemention of converting a human-readable host name in to the
   raw RFC1035 UDP data for a domain.
   Input:  pointer to js_string object we modify "in place"
   Output: -1 on error, numeric type of query on success, -2 on
           unsupported query type, -3 on 'U' query type (which
           then has to be specified by the user elsewhere)
*/
int hname_2rfc1035(js_string *hostname);

/* Starwhitis: 0: Stars *not* allowed at end of host name
 *                1: Stars are allowed at host name ends */
int hname_2rfc1035_starwhitis(js_string *hostname, int starwhitis);

/* Zero-copy implemention of converting a human-readable email address in to
   the raw RFC1035 UDP data for a domain.
   Input:  pointer to js_string object we modify "in place" (needs a
           one-octet 'prefix' which can be be any character
   Output: -1 on error, JS_SUCCESS on success
*/
int email_2rfc1035(js_string *hostname);

/* Given a q_header structure, initialize the values of the structure
   to sane values */
void init_header(q_header *header);

/* Given a q_header structure, and a js object to put the raw UDP data
   in, convert a q_header structure to raw UDP data.
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, JS_SUCCESS on success
*/
int make_hdr(q_header *header, js_string *js);

/* Given a domain-label, change this label in-place so that the first domain
   label is lopped off of it.  Eg. '\003www\007example\003com\000" becomes
   "\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           zero-length already
*/
int bobbit_label(js_string *js);

/* Given a q_header structure, and a js object with the raw UDP data,
   convert raw UDP data to a q_header structure.
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, JS_SUCCESS on success
*/
int read_hdr(js_string *js, q_header *header);

/* Man, RFC1035 decompression is a pain to implement.  This routine
   decompresses a domain string in the string "compressed" in to
   the string "uncompressed".
   Input: compressed: Pointer to the js_string we are decompressing
          uncompressed: Pointer to the string we are decompressing to
          place: Where we are looking in the compressed string right now
          uplace: pointer to where we are looking at in the decompression
                  string right now
   output: JS_ERROR on error, length of uncompressed poiner on success
*/
int decompress_dname(js_string *compressed, js_string *uncompressed,
                     int *place, int *uplace);

/* Man, RFC1035 compression is a pain to implement.  This routine
   compresses a domain string in the string "uncompressed" in to
   the string "compressed".
   Input: compressed: Pointer to the js_string we are decompressing
          uncompressed: Pointer to the string we are decompressing to
          place: Where we are looking in the uncompressed string right now
          cplace: pointer to where we are looking at in the compression
                  string right now
          points: A pointer to a uint16 array which is a list of pointers
   output: JS_ERROR on error, length of uncompressed poiner on success
*/
int compress_dname(js_string *uncompressed, js_string *compressed,
                     int *place, int *cplace, uint16 *points);

/* Process the header of a RR record as described in section 4.1.3 of
   RFC1035.  This converts the contents of a RFC1035 header in to an
   q_rr structure.
   input: js_string obejct with the raw UDP data, q_rr struct to put data
          in, offset form beginning of string to look at data for
   output: number of bytes in rr header on success, JS_ERROR on error
*/
int read_rr_h (js_string *js, q_rr *hdr, int offset);

/* read_soa: Read a SOA record.
   input: Pointer to js_string, pointer to rr_soa structure, offset
   output: JS_ERROR on error, bytes in SOA record on success
*/
int read_soa(js_string *js, rr_soa *soa, int offset);

/* Zero-copy implemention of converting the raw UDP data for a domain in
   to a human-readable host name.
   Input:  pointer to js_string object we modify "in place", query type
           (-2 if we wish to make it show a pipe)
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
int hname_translate(js_string *hostname, int qtype);

/* Zero-copy implemention of converting the raw UDP data for a domain in
   to a human-readable email address
   Input:  pointer to js_string object we modify "in place"
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
int email_translate(js_string *hostname);

/* Initialize the decompression code; set up the RRs, and set the
   log_level global variable in the decompression code.
   Input: The desired log_level for all of the decompression code
   Output: JS_SUCCESS on success, JS_ERROR on error
   Global variables affected:
   rr_formats (indirectly via decomp_add_rrdesc)
   log_level
*/
int decomp_init(int alog_level);

/* Given a js string object and a q_question structure, place the raw UDP
   format of the query at the end of the js_string object
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, JS_SUCCESS on success
*/
int make_question(q_question *question, js_string *js);

/* Given a js string object and an offset (where we begin reading our
   question), in addition to a q_question structure, read the raw UDP
   format of the query in to the q_question structure
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, number of bytes in question on success
*/
int read_question(js_string *js, q_question *question, int offset);

/* Read a NS (or any other <domain-name>) record
   input: js_string object with raw UDP data, js_string object to have just
          the NS record, offset from beginning of raw UDP data to get RR
   output: JS_ERROR on ERROR, bytes in <domain-name> on success
*/
int read_ns(js_string *in, js_string *out, int offset);

/* Process the RR portion of a TXT record.
   Input: pointer to string of uncompressed UDP data, pointer of string to
          put txt record in, offset from beginning of UDP data
   Output: JS_ERROR on error, byes in TXT record on success
*/
int read_txt(js_string *in, js_string *out, int offset);

/* This function is designed to make a packet which compresses to a size
 * greater than 512 bytes smaller.  The input is an uncompressed DNS packet;
 * the output is the same packet with the last DNS record removed from the
 * packet.  As per RFC2181 9, if we are removing a DNS record from the NS
 * or AN section of a reply, the TC bit is not set.  Otherwise (as a
 * reasonable interpretation of the wishes in RFC2181 9), we remove all DNS
 * information except the header and mark the DNS packet truncated.
 *
 * Input: A js_string object with a full uncompressed raw DNS packet.
 *
 * Output: A point to the above js_string object on success; 0 on error */

js_string *squeeze_to_fit(js_string *packet);

