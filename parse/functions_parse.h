/* Copyright (c) 2002,2003 Sam Trenholme
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

/* Put the value of the Kiwi variable with the name name in the value value.
   input: name, value
   output: JS_SUCCESS or JS_ERROR, depending on error/success
   global vars used: kvar[], keywords[]
*/
int read_kvar(js_string *name, js_string *value);

/* Read /etc/mararc, and set the appropriate symbols
   input: location of rc file, place to put error string (if needed),
          place to put error number (0 if no error, -1 if the error
          does not have a line number)
   output: JS_ERROR on error, JS_SUCCESS on success
   global vars: dvar
*/
int read_mararc(js_string *fileloc,js_string *errorstr,int *errorret);

/* Find the mararc file we are supposed to read
   input: js_string to place mararc file in
   output: JS_ERROR on error, JS_SUCCESS on success
*/
int find_mararc(js_string *out);

/* Point to the hash that dvar[arg] points to
   input: index of dvar to look at
   ouput: pointer to mhash object on success, 0 on failure
*/
mhash *dvar_raw(int index);

/* Put the value of the Kiwi variable with the name the value.
   input: name, key, value
   output: JS_SUCCESS or JS_ERROR, depending on error/success
   global vars used: dvar[], keywords[]
*/
int read_dvar(js_string *name, js_string *key, js_string *value);

/* Make a list of ip addresses and netmasks that are allowed to connect to
   the zone server.
   Input: Pointer to object containing a list of either ip/netmask
          pairs (10.1.1.1/24 or 10.1.1.1/255.255.255.0 form) or
          an alias (e.g. ipv4_alias["foo"] = "10.1.1.1/24"
                         ipv4_alias["bar"] = "10.2.2.2/24"
                    followed by zone_transfer_acl = "foo,bar"),
          Pointer to list of ipv4pair objects (ip, mask),
          maximum number of ipv4objects allowed in "out"
          array,
          pointer to where from beginning of string to put the
          next ipv4object (allows recursion),
          recursion depth (stops loops)
   Output: JS_SUCCESS on success, JS_ERROR on error
*/
int make_ip_acl(js_string *in, ipv4pair *out, int max, int depth);

/* Parse a single line of a csv1 data file
   input: pointer to line of data, place to put the domain name (with
          class as a 2-byte siffix), place to put the domain data, place
          to put the TTL for this record
   output: 0 on blank or hashed lines, the type of RR on lines where
           we need to add the RR in question, JS_ERROR on fatal error.
           On non-fatal error, we return -2
*/
int parse_csv1_line(js_string *line, js_string *name, js_string *data,
                    uint32 *ttl);

/* pre-process a line.  In addition to making domain labels lower-case,
   this converts \ characters in the line in to other values.  \\ is
   backslash, \nnn is an octal value for a character.
   input: pointer of line to process, pointer to place to put
          processed data, pointer to string to substitute % with
          (if 0, no substitution is performed)
   ouput: JS_ERROR on error, JS_SUCCESS on success
*/
int bs_process(js_string *in, js_string *out, js_string *sub);

/* Parse a single line of a csv1 data file
   input: pointer to line of data, place to put the domain name (with
          class as a 2-byte siffix), place to put the domain data, place
          to put the TTL for this record
   output: 0 on blank or hashed lines, the type of RR on lines where
           we need to add the RR in question, JS_ERROR on fatal error.
           On non-fatal error, we return -2
*/
int parse_csv1_line(js_string *line, js_string *name, js_string *data,
                    uint32 *ttl);

/* Convert a dotted-decimal IP (in a js_string object) in to a raw IP
   (another js_string object)
   input: pointer to dotted decimal data, pointer to js_string object to
          place raw IP in to, offset from top to start looking
   output: JS_ERROR on error, pointer to first non-ip byte on SUCCESS
           (-2 if no non-ip byte was found)
*/
int ddip_2_ip(js_string *ddip, js_string *ip, int offset);

/* pre-process a line.  In addition to making domain labels lower-case,
   this converts \ characters in the line in to other values.  \\ is
   backslash, \nnn is an octal value for a character.
   input: pointer of line to process, pointer to place to put
          processed data, pointer to string to substitute % with
          (if 0, no substitution is performed)
   ouput: JS_ERROR on error, JS_SUCCESS on success
*/
int bs_process(js_string *in, js_string *out, js_string *sub);

/* Convert a null-terminated string (like "csv1") to a number (0, in this case)
   input: A null-terminated string with the keyword
   output: The number of the keyword (starting at 0), JS_ERROR on error,
           -2 on no match
*/
int dq_keyword2n(char *in);

/* Determine if a given js_string object is a valid string for use in the Kiwi
   internals
   input: Pointer to js_string object to test
   ouput: JS_ERROR if bad, JS_SUCCESS if good
*/
int mara_goodjs(js_string *test);

