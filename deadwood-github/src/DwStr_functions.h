/* Copyright (c) 2007-2010 Sam Trenholme
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

/* Make sure a dw_str object is sane.
 * Input: Pointer to dw_str
 * Output: 0 if sane; -1 if not */
int dw_assert_sanity(dw_str *object);

/* Create a new dw_str object.
 * Input: Maximum length allowed for the string
 * Output: Pointer to newly created string
 */
dw_str *dw_create(uint32_t size);

/* Destroy a dw_str object.
 * Input: Pointer to string to destroy
 * Output: 0 on success; -1 on failure
 */
int dw_destroy(dw_str *object);

/* Add a single character to the DwStr */
int dw_addchar(uint8_t add, dw_str *object);

/* Add a C-string (which may have NULL characters) to a DwStr object.
 * Input: Pointer to string; number of characters we will add to DwStr
 * object; pointer to dw_str object.  Output: -1 on error; 0 on success */
int dw_cstr_append(uint8_t *add, int32_t len, dw_str *obj);

/* Add a null-terminated string to a DwStr; should the null-terminated string
 * have the character specified in 'nope', don't append that character and
 * stop appending to the string. Input: String to append; DwStr to append
 * to; 'nope' character we're not allowed to add (make this 0 if you want
 * to allow all non-NULL characters) */
int dw_qrappend(uint8_t *add, dw_str *object, char nope);

/* Add an arbitrary binary string of length "len" to a DwStr object */
int dw_bin_append(uint8_t *add, int len, dw_str *object);

/* Add a null-terminated string to a DwStr; if the DwStr is non-0 length,
 * first add a comma.  If the null-terminated string has a comma, stop
 * appending the string.
 * Input: C string to add; DwStr to add string to
 * Output: 0 on success; -1 on failure */
int dw_qspush(uint8_t *add, dw_str *object);

/* For debug purposes: Output a dw_str object on the standard output. */
void dw_stdout(dw_str *object);

/* Take some of, or all, of a dw_str, and copy it in to a new dw_str object.
 * return 0 (NULL) if there is an error copying the string.  The parameters
 * are:
 * 1) The dw_string we want to copy
 * 2) The first character we starting copying from.  If this value has
 *    a value of 0, then we start copying from the start of the
 *    string.  If this has a value of -1, then we start copying at
 *    the end of the string (meaning, we can only copy the very last
 *    character). -2 is the second-to-last character in the string; 1 is
 *    the second character in the string (c indexes, ugh)
 * 3) The number of characters we copy.  0 means no characters (making
 *    a zero-length string); 1 means 1 character, etc.  If this is negative
 *    then we copy relative to the end of the string.  In other words, if
 *    the length has a value of -1, we copy until the end of the string;
 *    if length has a value of -2, we copy until the second to last character
 *    in the string, etc.
 * 4) The maximum allowed length for the string.  Should this have a positive
 *    value or 0, the string is allowed to add that many characters to the end
 *    of the string (0: The string can not grow; 1: the string can grow by
 *    one character, etc).  If it has a value of -1, then the string has the
 *    same maximum permitted size as the string we are copying.  Otherwise,
 *    we return an error.
 *
 * Output: We create a new dw_str object, which has the copied substr.
 *
 * Some common parameters: dw_substr(str,0,-1,-1): Copies the entire string
 */

dw_str *dw_substr(dw_str *obj, int32_t begin, int32_t amount, int32_t max);

/* Read a 16-bit big-endian string that is in a dw_str as a number.  DNS
 * commonly has these kinds of numbers (can you say 1983?)
 * Input: Pointer to dw_str object; offset where we will look for number
 * (0 is top of string; -1 is last two bytes of string)
 * Output: The number; -1 on error */
int32_t dw_fetch_u16(dw_str *object, int32_t offset);

/* Read a 16-bit big-endian number at the end of a dw_str object, and
 * remove the string from the string object.  -1 on error */
int32_t dw_pop_u16(dw_str *object);

/* Read an 8-bit number at the end of a dw_str object, and
 * remove the string from the string object.  -1 on error */
int32_t dw_pop_u8(dw_str *object);

/* Read an 8-bit big-endian string that is in a dw_str as a number.
 * Input: Pointer to dw_str object; offset where we will look for number
 * (0 is top of string)
 * Output: The number; -1 on error */
int32_t dw_fetch_u8(dw_str *object, int32_t offset);

/* Put a 16-bit big-endian number (the argument "value") in a dw_str object.
 * Offset can be either a positive or negative number; should offset be
 * a positive number, then we put that byte in that many bytes from
 * the beginning of the string.  Should offset be a negative number, then
 * we put the number that many bytes from the end of the string.  This
 * function will, in certain cases make the string one or two bytes longer.
 * If offset is -1, then the number is added to the end of the string.
 * If offset is -2, then the number replaces the last byte of the string,
 * and adds a byte the the end of the string.  Should offset be 0, the
 * number replaces the first two numbers in the string (adding numbers
 * if needed)
 *
 * Should this function succeed, it will return a 0.  Otherwise, it
 * will return a -1 */
int dw_put_u16(dw_str *obj, uint16_t value, int32_t offset);

/* Put an 8-bit (the argument "value") in a dw_str object.
 * Offset can be either a positive or negative number; should offset be
 * a positive number, then we put that byte in that many bytes from
 * the beginning of the string.  Should offset be a negative number, then
 * we put the number that many bytes from the end of the string.  This
 * function will, in certain cases make the string one byte longer.
 * If offset is -1, then the number is added to the end of the string.
 *
 * Should offset be 0, the number replaces the first number in the string
 * (adding numbers if needed)
 *
 * Should this function succeed, it will return a 0.  Otherwise, it
 * will return a -1
 */
int dw_put_u8(dw_str *obj, uint8_t value, int32_t offset);

#ifdef OTHER_STUFF
/* Read a single bit from a dw_str object.  The way we choose the bit is
 * to first choose the byte with the desired bit, then to choose the
 * bit in that byte.  0 is the least significant (rightmost) bit; 7 is the
 * most significant bit.
 * We return -1 on error, 0 if the bit is 0, and 1 if the bit is 1 */
int dw_get_bit(dw_str *obj, int32_t byte, int8_t bit);
#endif /* OTHER_STUFF */

/* Compare two dw_string objects to see if they are the same (different max
 * lengths are allowed).  -1 on error, 0 if not the same, and 1 if they are
 * the same */
int dw_issame(dw_str *a, dw_str *b);

/* Append one dw_string object to another dw_string.
 * Input: The two dw_string objects
 * Output: 0 on success, -1 on error */
int dw_append(dw_str *toappend, dw_str *target);

/* Append a substring of one dw_string object to another dw_string.
 * Input: String we splice from, where we start cutting from that string,
 *        how many bytes to cut from said string, the string to append to
 * Output: 0 on success, -1 on error
 */
int dw_substr_append(dw_str *splice, int32_t begin, int32_t amount,
                dw_str *target);

/* Copy a dw_string object in to a null-terminated C-string.
 * Input: The string to convert
 * Output: A pointer to a newly created C-string; 0 on error */

uint8_t *dw_to_cstr(dw_str *obj);

/* Find the last instance of a given character in a DwStr object.
 * Input: The dw_str object, the character we are seeking
 * Output: The index in the string with the character in question
 * -1 on error; -2 on "not found"
 */

int32_t dw_rfind(dw_str *obj, unsigned char rx);

/* Take the last element of a comma-separated DwStr object, remove it
 * from said string, and create a new string with the popped comma-separated
 * object.  Should the source string not have a comma in it, then we take
 * the entire source string, blank it (make it 0-length) and copy it over
 * to the newly created string.  The final comma is removed from the
 * source string, but is *not* included in the destination string.
 * Input: The source string
 * Output: A newly created string with the last comma separated object */

dw_str *dw_qspop(dw_str *in);

/* Create a copy of a dw_str object with any leading whitespace in the
 * original object removed in the copy.  If the original is nothing
 * but whitespace, the copy will be a 0-length string.
 * Input: dw_str object we want to remove leading whitespace from
 * Output: Newly created dw_str object without the leading whitespace */

dw_str *dw_zap_lws(dw_str *obj);

/* Convert a dw_str object with a number in to an integer.  Leading
 * whitespace is ignored; anything that is not a number or letter stops
 * processing.
 * Input:
 *      obj: The dw_str object we convert in to a number
 *      index: How far in to the string we begin conversion (0 is
 *              beginning of string)
 *      base: The base we work in (2 is binary, 10 is decimal, 16 is
 *            hex; this can be up to 36)
 * Output:
 *      The number the string represents; -1 on error
 */

int32_t dw_atoi(dw_str *obj, int32_t index, int base);

/* This extracts just a DNS DNAME (without TYPE) from a raw c-string (with
 * ASCII nulls, since DNS packets have those) and puts it in a newly
 * created string.
 * Input: Pointer to raw string; offset where we look for DNS DNAME,
 *        maximum length of raw string
 * Output: A pointer to a new dw_str with NAME
 */
dw_str *dw_get_dname(uint8_t *raw, int offset, int max);

/* This extracts a DNS DNAME, followed by a two-byte TYPE (the type of RR)
 * from a raw c-string (with ASCII nulls, since DNS packets have those)
 * and puts it in a newly created offset.
 * Input: Pointer to raw string; offset where we look for DNS DNAME + CLASS,
 *        maximum length of raw string
 * Output: A pointer to a new dw_str with NAME + CLASS
 */
dw_str *dw_get_dname_type(uint8_t *raw, int offset, int max);

/* Given a raw pointer to a c-string (which can have NULLs), and a length
 * for that string, extract a dw_str object that is a cachable form of
 * the packet.  Basically:
 *      * Everything after the question is put at the beginning
 *        of the packet
 *      * This is followed by, in order, ancount, nscount, then
 *        arcount
 */

dw_str *dw_packet_to_cache(uint8_t *raw, int len, uint8_t type);

/* Get a TTL that is buried in a DNS string.  We start at the beginning of
 * the DNS name, figure out how long the name is (ugh), then skip past
 * type and class to get the TTL; return -1 on error.  We don't support
 * TTLs longer than 31,536,000: One year (0x01E13380)
 *
 * Input: String we will get TTL from; offset from where we will get TTL,
 *        maximum allowed TTL (which should be 31536000 when called from
 *        another part of Deadwood), recursion depth (to stop infinite loops)
 *        Note that depth is a positive number that decrements.
 */
int32_t dw_get_a_dnsttl(dw_str *in, int offset, int32_t max, int depth);

/* Make sure a filename is sanitized; only lowercase letters, the '_',
 * the '-', and the '/' are allowed in file names; anything else becomes
 * a '_' */
int dw_filename_sanitize(dw_str *obj);

/* Given a packet in the form put in the DNS cache (with things like type,
 * ancount, nscount, and arcount at the end of the string), tell the user how
 * many answers are in the packet. */
int32_t dw_cachepacket_to_ancount(dw_str *packet);

/* See if a given ASCII name ends in a '.'; if it doesn't return -1, if
 * there is an unexpected error, return 0, and if it does end with '.', return
 * 1 */
int dw_ends_in_dot(dw_str *in);

/* Convert an ASCII name, like "www.samiam.org." in to the DNS form of the
 * same name (\003www\006samiam\003org\000).  Output, as a new string, the
 * newly created DNS string; 0 if there is any error */
dw_str *dw_dnsname_convert(dw_str *in);

/* Chop off the first label of a DNS name; for example, the raw DNS form
 * of www.example.com. (\003www\007example\003com\000) becomes example.com
 * (\007example\003com\000).  This will also work with strings having data
 * after the end of the DNS name.
 *
 * This function creates a new string which needs to be freed by its caller
 */
dw_str *dw_dnslabel_chop(dw_str *in);

/* Determine where the end of a <domain-name> at offset in the string
 * is (ugh, DNS is ugly); -1 on error */
int32_t dw_get_dn_end(dw_str *in, int offset);

/* Rotate data in a string: Given a start point and a pivot point, take all of
 * the string between the pivot point to the end, and put it where the start
 * point is.  Take all the data from the start point to the pivot point, and
 * put it at the end of the string.
 *
 * For example, if we have the string "0123456789", and the start is 3, and
 * the pivot 5, we would have the string "0125678934" after running
 * this function
 */
int dw_rotate(dw_str *in, int32_t start, int32_t pivot, int32_t end);

