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

/* --- Outside of this space --- */

/* --- MaraBigHash.c --- */

int starrecord_to_meta(js_string *rr, int recursive);
int add_rr_to_bighash(mhash *bighash, js_string *query,
                js_string *data, uint32 ttl, js_string *zone, perm_t perms);

/* --- MaraDNS.c --- */
int fold_case(js_string *js);

/* --- Csv2_esc_txt.c --- */

/* Generate Csv2-compatible output for TXT record from raw js_string
 * Quote ASCII sequences printed to standard output
 * Make listeral ' \'
 * Make \xXX (hex number) sequences of anything else
 */
int escape_stdout_csv2(js_string *js);

/* Given a raw DNS query, show them the query in qtype:qname format, where
 * qname is a human-readable dns query */
void human_readable_dns_query(js_string *query, int hide_qtype);

/* --- Csv2_database.c --- */

/* Function to initialize the csv2_add_state for a new zone
 * Input: The zone in Alabel format.
 * Output: The initialized csv2 add state
 */
csv2_add_state *csv2_init_add_state(js_string *zone);

/* This function releases the memory resources that the csv2_add_state
 * x is using up */
void csv2_zap_add_state(csv2_add_state *x);

/* Function to set the big hash we point to
 * Input: Pointer to hash
 * Output: JS_ERROR on error; JS_SUCCESS on success */
int csv2_set_bighash(csv2_add_state *state, mhash *bighash);

/* Function to set the method we use to process sucessfully parsed
 * records.  Input: numeric method process
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int csv2_set_add_method(csv2_add_state *state, int method);

/* Function that closes out the state for processing parsed records;
 * JS_ERROR on error, JS_SUCCESS on success */
int csv2_close_state(csv2_add_state *state);

/* Function that uses stat() to determine the timestamp to put in the
 * SOA serial for when we synthesize the SOA record;
 * JS_ERROR on error, JS_SUCCESS on success */
int csv2_set_soa_serial(csv2_add_state *state, js_string *filename);

/* Function that converts an ASCII zone file in to a udpzone,
 * returning the new zone as a string on stdout
 * This converts an Alabel to a Blabel */
js_string *csv2_zone_to_udpzone(js_string *zone);

/* Function that just shows the rr we would have added; this is mainly
 * for debugging purposes
 * Input: The csv2_add_state, the query (Blabel),
 * the rtype, the ttl, and the data.
 * Output: JS_ERROR on error, JS_SUCCESS on success
 */

int csv2_add_rr_debug(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data);

/* Function to add an rr to the big hash;
 * Input: The csv2_add_state,
 * the query (Blabel), the rtype, the ttl, and the data.
 * Output: JS_ERROR on error; JS_SUCCESS on success
 */

int csv2_add_rr_bighash(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data, int32 starwhitis);

/* Function to process an rr for the zone server;
 * Input: The csv2_add_state,
 * the query (Blabel), the rtype, the ttl, and the data.
 * Output: JS_ERROR on error; JS_SUCCESS on success
 */

int csv2_add_rr_zoneserver(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data);

/* Create a synthetic query
 * Input: the csv2_add_state
 * Output: A query (from the state's zone name) suitable for passing
 *         csv2_add_rr_w (in binary rfc1035/1983 format--Blabel) */
js_string *csv2_synth_query(csv2_add_state *state);

/* If needed, synthesize a soa record for this zone */
int csv2_synthesize_soa(csv2_add_state *state);

/* Make a single synthetic A record, given a certain IP.
 * Input: The state (since we store the record), the ip address, whether
 *        we actually make the record (1) or just the blabel (0)
 * Output: The Blabel with the record in question.
 */
js_string *csv2_synth_ip(csv2_add_state *state, uint32 ip,
                int actually_make_record);

/* Make a single synthetic NS record */
int csv2_make_synth_ns(csv2_add_state *state, uint32 ip);

/* tell us if we are looking at a private IP (rfc1918 or localhost)
 * 0: No, we're not looking at one
 * 1: Yes, we're are looking at one */
int csv2_is_private_ip(uint32 ip);

/* tell us if we are looking at a localhost IP
 * 0: Nope
 * 1: yep */
int csv2_is_localhost_ip(uint32 ip);

/* If needed, synthesize NS records for this zone; this code
 * assumes that people without NS records are on ipv4 addresses */
int csv2_synthesize_ns(csv2_add_state *state);

/* Create a copy of a csv2_rr; this will *not* copy the entire
 * chain, but only the record at the top of the chain */
csv2_rr *copy_csv2_rr(csv2_rr *source);

/* Push an RR to the state's buffer
 * Input: The query, rtype, etc. of what we will add.
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int csv2_push_buffer(csv2_add_state *state, js_string *query, int rtype,
                                int32 ttl, js_string *data);

/* Get the soa in a state.
 * Input: The raw js_string query and data; the ttl
 * Output: JS_ERROR on error; JS_SUCCESS on success */

int csv2_set_soa(csv2_add_state *state, js_string *query, js_string *data,
                int32 ttl);
/* Check to see if the query is the same as the zone in state
 * Input: the state, a query
 * Output: 1 if they are the same, 0 otherwise */
int csv2_is_zonetop(csv2_add_state *state, js_string *query);

/* Pop the top record from the state's buffer of records, adding it to
 * the cache (or doing whatever processing we're doing) */
int csv2_pop_buffer(csv2_add_state *state);

/* Add the SOA record in the state to the zone in question */
int csv2_add_soa(csv2_add_state *state);

/* Routine that simply makes a copy of a js_string object,
 * returning the copy of that object. */
js_string *csv2_copy_js(js_string *s);

/* Wrapper to make sure all of the authoritative
 * stuff for the zone is setup (regardless of whether said authoritative
 * data is in the actual zone file) before adding the SOA record */
int csv2_add_rr(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data);

/* Function to add an rr in general */
int csv2_add_rr_w(csv2_add_state *state, js_string *query,
                int rtype, int32 ttl, js_string *data);

/* --- Csv2_rr_txt.c --- */

/* Get a TXT record from the stream.
 * Input: A pointer to the stream we are reading
 * Output: A js_string object with the raw rddata we want */
js_string *csv2_get_txt(csv2_read *stream, int numchunks);

/* Get a RAW record from the stream.
 * Input: A pointer to the stream we are reading
 * Output: A js_string object with the raw rddata we want */
js_string *csv2_get_raw(csv2_read *stream);

/* This returns true for [\#] */
int csv2_is_hash(int32 in);

/* --- Csv2_main.c --- */

/* The main function for parsing a csv2_zone for putting stuff
 * in the big hash */
int csv2_parse_main_bighash(mhash *main_table, int32 starwhitis);

/* The function we call from the zoneserver; this lets us put the contents
 * of the zone in question available over the TCP socket specified by
 * the calling program (zoneserver)
 * Input: The name of the zone (example.com., etc.) in Alabel format
 *        The name of the file with the zone
 *        The tcp connection socket (connect)
 *        Whether the zone transfer client asked for an SOA recrd (soa_q)
 * Output: JS_SUCCESS if we were able to send the zone over the connection
 *         socket
 */

int csv2_parse_zone_zoneserver(js_string *zone,
                int connect, int soa_q, q_header *header);

/* The following was semi-automatically generated */

js_string *process_1stchar(csv2_read *stream, int (*is_ok)(int32 in),
                char *pre);
int csv2_parse_zone_bighash(js_string *zone, js_string *filename,
                mhash *bighash, int32 starwhitis);
int csv2_parse_zone(js_string *filename, csv2_add_state *state,
                int32 starwhitis);
int csv2_see_char(int32 in, char *list);
int csv2_is_number(int32 in);
int csv2_is_upper(int32 in);
int csv2_is_lower(int32 in);
int csv2_is_hibit(int32 in);
int csv2_is_delimiter(int in);
int32 csv2_get_utf8(csv2_read *stream);
int32 csv2_read_unicode(csv2_read *stream);
int csv2_append_utf8(js_string *toappend, int32 in);
int csv2_get_1st(csv2_read *stream, int (*is_ok)(int32 in), int options);
int csv2_is_alpha(int32 in);
int csv2_is_alphanum(int32 in);
int csv2_is_text(int32 in);
int csv2_is_dchar(int32 in);
int csv2_is_starwhitis(int32 in);
int csv2_numeric_rtype(js_string *text_rtype);
int32 csv2_get_rtype(csv2_read *stream);
int32 csv2_get_num(csv2_read *stream);
int csv2_read_rr(csv2_add_state *state, csv2_read *stream, int32 starwhitis);
void process_comment(csv2_read *stream);
js_string *process_something(csv2_read *stream, int (*is_ok)(int32 in));
js_string *process_number(csv2_read *stream);
js_string *process_textlabel(csv2_read *stream);
js_string *process_dname(csv2_read *stream, int starwhitis);
js_string *js_append_dname(js_string *o, csv2_read *stream, int starwhitis);
js_string *csv2_get_hostname(csv2_read *stream, js_string *zonename,
                int starwhitis);
js_string *csv2_get_dname(csv2_read *stream);
js_string *csv2_get_soa(csv2_read *stream, js_string *zone,
        csv2_add_state *state);
js_string *csv2_convert_percent(js_string *in, js_string *psub);
int csv2_close(csv2_read *file);
int csv2_readchar(csv2_read *file);
int csv2_justread(csv2_read *file);
int csv2_error(csv2_read *file, char *why);
int32 csv2_get_unicode(csv2_read *file);
int csv2_set_unicode(csv2_read *file, int32 in);
csv2_read *csv2_open(js_string *filename);
int csv2_is_hex(int32 in);
int csv2_is_hex_or_colon(int32 in);
js_string *process_aaaa(csv2_read *stream);
int csv2_is_number_or_dot(int32 in);
js_string *process_ipv4_ddip(csv2_read *stream);
js_string *csv2_get_a(csv2_read *stream);
int csv2_b4_at(int32 in);
js_string *process_mbox(csv2_read *stream);

csv2_add_state *csv2_init_add_state(js_string *zone);

js_string *csv2_get_aaaa(csv2_read *stream);
js_string *csv2_get_string(csv2_read *stream, int datatype, int post_txt);

/* Csv2_rr_wks.c */

int csv2_is_wks(int32 in);
int csv2_is_alphanum_ordot(int32 in);
js_string *csv2_get_wks(csv2_read *stream);
js_string *csv2_get_mbox(csv2_read *stream, js_string *zone, int count);
js_string *csv2_get_hex(csv2_read *stream);
js_string *csv2_get_loc(csv2_read *stream);
js_string *csv2_get_naptr(csv2_read *stream);

/* Some more Csv2_read.c functions */
int csv2_push_file(csv2_read *file, js_string *filename);
int csv2_pop_file(csv2_read *file);
void csv2_allow_tilde(csv2_read *file);
void csv2_forbid_tilde(csv2_read *file);
void csv2_allow_leftbrace(csv2_read *file);
void csv2_forbid_leftbrace(csv2_read *file);
int csv2_tilde_seen(csv2_read *file);
void csv2_reset_tilde_seen(csv2_read *file);

