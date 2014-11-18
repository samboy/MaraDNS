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

/* Determine if a given IP is on a given ipv4pair ACL
 * Input: The ip, the ACL list
 * Output: 0 if they do not have authority, 1 if they do
 */
int check_ipv4_acl(uint32 ip, ipv4pair *list);

/* Determine if a given IP has authority to perform recursive DNS lookups
   Input: IP of where they come from
   Ouput: 0 if they do not have authority, 1 if they do
   Global variables used: The recurse_acl array
*/

int check_recursive_acl(uint32 ip);

/* Initialize a rr data structure
   Input: Pointer to the rr
   Output: none
 */
void init_rr(rr *data);

/* Routine which prepares the launch of a detached thread which will
   recursivly look for the DNS name in question
   Input:  id of query, socket of query, sockaddr struct of query,
           js_string with host name they are looking for
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
#ifndef MINGW32
int launch_thread(int id, int sock,
                  struct sockaddr_in client, js_string *query);
#else
int launch_thread();
#endif

/* Populate the main assosciative array (the one where the raw UDP query is
   the key and the value is the answer) with the data from the various
   csv1 files.
   Input: A pointer to the hash to populate, a pointer to the string to
          put an error message in, whether MaraDNS is being recursive or
          not
   Ouput: JS_ERROR on error, -2 on parsing error, 0 if we don't
          put anything in the csv hash, JS_SUCCESS on success
   Global vars used: The kvars and dvars
 */
int populate_main(mhash *maintable, js_string *error, int recursive);

/* Check to see if the IP in question is a ddip (e.g.
   "<03>127<01>0<01>0<03>1<00>"), and, if so, convert it in to
   a bare A record
   input: Pointer to js_string object with the query
   output: JS_ERROR on fatal error, 0 on non-ddip query,
           JS_SUCCESS if it was a ddip
*/
int ddip_check(int id, int sock, conn *ect, js_string *query);

/* Convert a domain-name query in to its lower-case equivalent
   Input: Pointer to the js string object with the query
   Output: JS_ERROR on error, JS_SUCCESS on sucess, 0 on
           success if no change was made to the string
*/
int fold_case(js_string *js);

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, and the desired new record number for
   that data type, convert the record type to the new number.
   Input: js_string object with raw UDP data, the desired new record type
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
int change_rtype(js_string *js, int newtype);

/* Add a resource record to the big hash of RRs.
   Input: Pointer to the main table
          Binary form of query (dname followed by two-byte type)
          Answer to query
          Ttl for query in question
          Zone this record is in (to determine whether to flag it as
                                  authoritative or a "glue" record)
          We will do the following to determine if the data is
          authoritative:
          1) If the query is the same as the zone name (for all records)
             then the data is authoritative
          2) If the query is <single label>.<zone.name> (for example:
             If the zone is example.com, then anything.example.com
             fits, but some.thing.example.com does not fit), then
             the data is data for all RR types except NS and SOA.
          3) If this data is authoritative, overwrite any non-authoritative
             data in the database.  If it is authoritative, and authoritative
             data is there, do nothing.

          perms: What IPs are allowed to view a given record

   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int add_rr_to_bighash(mhash *bighash,
                      js_string *query, js_string *data, uint32 ttl,
                      js_string *zone, perm_t perms);

/* Make pointers in MX, NS, and CNAME records so we can have A records in the
   AR section (AN section with CNAMEs)
   Input: A pointer to the hash to populate, a pointer to the string to
          put an error message input an error message in
   Output: JS_ERROR on error, -2 on non-fatal error, JS_SUCCESS on success
*/
int add_an(mhash *bighash, js_string *error);

/* Give the RR type and a pointer to a js_string object we will put
   data in, make the corresponding A query for the data in question
   Input:  The query type this is (as an int), a pointer to the
           js string with the answer, a pointer to a js string
           which we will place the corresponding A record in question
   Output: JS_ERROR on fatal error, otherwise JS_SUCCESS
*/
int answer_ip_query(int qtype, js_string *qu, js_string *ar);

/* Given a js_string object containing a raw UDP dname followed by a
   16-bit big-endian record type, get the query type for the string in
   question.
   Input: js_string object with raw UDP data
   Output: JS_ERROR on error, record type (0-65535) on success */
int get_rtype(js_string *js);

/* Tell a function calling this function the number of threads currently
   running; used for debugging purposes
   Input: None
   Output: An integer which tells us the number of threads currently running
*/
int how_many_threads();

/* Tell a function calling this function how many elements are in the
   DNS cache
   Input: None
   Output: An integer which tells us the number of elements in the
           DNS cache
*/
int cache_elements();

/* Set the minimim TTLs
   Input: The minimum TTL for non-CNAME records, the minimum TTL for
          CNAME records
   Output: JS_ERROR on fail, 1 on success
*/
int set_min_ttl(int norm, int cname);

/* Initialize the cache hash for general use
   Input: maximum number of elements the cache can have,
          maximum number of threads we are allowed to run
   Output: less than 0 on error, JS_SUCCESS on success
   Global variables used: max_cache, etc.
   Error return values:
    -1: Max cache elements is too big
    -2: We have already run init_cache
    -3: Failure to create a js_string object (shouldn't happen)
    -4: Failure to create a js_string object (shouldn't happen)
    -5: Failure to make a string a js_string object (shouldn't happen)
    -6: Failure to make a string a js_string object (shouldn't happen)
    -7: The root_servers["."] element does not exist
    -8: Failure to make a string a js_string object (shouldn't happen)
    -9: Failure to make "A." a binary hostname (shouldn't happen)
   -10: Failure to add a 16-bit integer to a js_string (shouldn't happen)
   -11: The elements of the root_servers["."] are invalid
   -12: Too many elements in the root_servers ACL (shouldn't happen)
   -13: Problem adding a root nameserver to the cache proper (shoudn't
        happen);
*/
int init_cache(int max_cache_elements, int max_threads, int max_glueless,
               int max_q_total, int timeout, int verbose_query_value);

/* Initialize the list of spam-friendly DNS servers which we will refuse
   to obtain DNS information from.
   Input: Pointer to js_string object with list of spammers
   Output: JS_SUCCESS on success, JS_ERROR on error
   Global Variables used: ipv4pair spammers[512]
*/
int init_spammers(js_string *spam_list);

/* Initialize the secure psudo-random-number generator
   Input: pointer to string that has the filename with the PRNG seed
   Whether we are re-keying the PRNG or not (rekey, 0 we aren't, 1 we are)
   Output: JS_SUCCESS.  On failure:
           -1 (JS_ERROR): Generalized error which means there is a bug in
                          MaraDNS
           -2: We could not open up the random seed file
           -3: We could not read 16 bytes from the random seed file
*/
int init_rng(js_string *seedfile, int rekey);

/* Set the level of logging of messages
   Input: Log level desired
   Output: js_success
   Global variables used: rlog_level
*/
int init_rlog_level(int verbose_level);

/* Debug routine that shows an IP in dotted decimal format on the
   standard output.
   Input:  A uint32 ip
   Output: none
*/
void debug_show_ip(uint32 ip);

/* Add a host (domain) name to an already existing element in the big hash
   Input: Pointer to hash, host name, host ttl, authoritative flag,
          expire (currently always 0)
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
int mhash_add_rr(mhash *hash, js_string *query, js_string *value, uint32 ttl,
                 uint32 authoritative, uint32 expire, perm_t perms);

/* Add a PTR pointer to the first record in a given chain of records
   (if it does not already have a PTR record)
   This is used by the recursive code, hence we need to be careful that
   we don't make the data inconsistant
   Input: Pointer to hash, host name, pointer to string with value
          of PTR record
   Output: JS_ERROR on error, JS_SUCCESS on success
*/
int mhash_add_ptr(mhash *hash, js_string *query, js_string *value);


/* Given a query, a record type to query, and whether we have
   already found a record in question, do an ANY lookup for
   the query in question
*/
int starwhitis_seek_any(js_string *query, int rr_type, int found,
                        q_header *head, rr **w, int *a,
                        js_string *most, js_string *ns, js_string *ar);

/* Add an element to the ANY chain in the big hash
 * Input: Pointer to the bighash, the query to point to, the data being
 * pointed to
 * Output: JS_SUCCESS on success, JS_ERROR on error
 */
int any_add_rr(mhash *hash, js_string *query, rr *data);

/* Remove an element from the ANY chain in the big hash
 * Input: Pointer to the big hash
 *        Pointer to data which we are now removing, query with this
 *        data
 * Output: JS_ERROR on error, JS_SUCCESS on success */
int any_zap_rr(mhash *hash, js_string *query, rr *data);

/* Handler to handle fatal errors.
   Input: Pointer to null-terminalted string with fatal error
   Output: MaraDNS exits
*/
void harderror(char *why);

/* In recursive.c: Set how we handle the case of not being able to
   contact any remote servers when making a recursive query.  0: Drop
   the packet on the floor.  1: Send the client a "server fail" error.
   2: Send the client a "this host does not exist" reply. */
int init_handle_noreply(int value);

#ifndef AUTHONLY
/* Lock the writing of log messages */
void log_lock();
void log_unlock();
#endif /* AUTHONLY */

/* Given a domain-label without a star record ('_'), change the first
   domain label in to a star record ('_') Eg. "\003www\007example\003com\000"
   becomes "_\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           a star record already
*/
int make_starlabel(js_string *js);

/* Given a domain-label ending with (or without) a star record ('_'),
   change the label
   in-place so that the first domain label before the star record is lopped
   off of it.  Eg. "\003name\007example\003com\000\000\001" becomes
   "\003name\007example\003com_\000\001", and
   "\003name\007example\003com_\000\001" becomes "\003name\007example_\000\001"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, 0 if the label is
           zero-length already, number of labels including star otherwise
           (130 if we don't know how many labels there are)
*/
int bobbit_starlabel_end(js_string *js);

/* Given a domain-label starting with a star record ('_') change this label
   in-place so that the first domain label after the star record is lopped
   off of it.  Eg. '_\003sub\007example\003com\000" becomes
   "_\007example\003com\000"
   input: A pointer to the js_string object in question
   output: JS_ERROR on error, JS_SUCCESS on success, 0 if the label is
           zero-length already
*/
int bobbit_starlabel(js_string *js);

#ifndef AUTHONLY
int init_retry_cycles(int in);
#endif /* AUTHONLY */

/* Set the upstream_port; the port we use to contact to remote DNS
 * servers */
int set_upstream_port(int num);

/* Set the range of ports that the recursive resolver will bind to
 * when making requests to other DNS servers */
int set_port_range(int a, int b);

/* Calculate the TTL age given the expire time (absolute time) and
 * the ttl (relative time)
 * Input: Exprire time, TTL in question
 * Output: The TTL we should give, taking TTL aging in to account
 */

uint32 determine_ttl(qual_timestamp expire,uint32 ttl);

/* This function takes a conn *ect (a MaraDNS-specific description of a
 * connection that can be the IP and port of either a ipv4 or ipv6
 * connection), a socket number, and a js_string to send, and sends
 * a message over the 'net */
int mara_send(conn *ect, int sock, js_string *reply);

/* Return a packet indicating that there was an error in the received
   packet
   input: socket number,
          a js_string object that we get the data from the first two
          bytes from, a sockaddr of who to send the error to,
          the question the error-generating query asked, the error
          to give them in the RCODE part of the header,
          the reason for the error, the minimim log_level to log this
          error (with reason) with
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int udperror(int sock,js_string *raw, struct sockaddr_in *from,
             js_string *question, int error,
             char *why,int min_log_level, int rd_val, conn *ect,int log_msg);
/* If we successfully found a record, spit out that record on the
   udp packet.
   Input: Where a pointer to the rr in question is, the id of the
          query they sent us, the socket the
          UDP bind is on, the sockaddr of the client who sent us the message,
          a js_string containing the query (dname + type), whether to show
          an A record along with a CNAME record (this is no longer used),
          rd_val (which to set the RD flag in the headers), ect: A
          description of the connection to send the reply to,
          force_authoritative: A boolean.  If 0, the value of the
          authoritative bit is determined by looking at the data in where.
          If 1, the record is always marked in the DNS headers as
          "authoritative".
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udpsuccess(rr *where, int id, int sock, struct sockaddr_in *client,
               js_string *query, void **rotate_point, int show_cname_a,
               int rd_val, conn *ect, int force_authoritative, int
               ra_value);
