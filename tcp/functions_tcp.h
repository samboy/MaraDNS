/* Copyright (c) 2002-2004 Sam Trenholme
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


/* --- libtcp.c --- */

/* Create a bind address list
 * Input: None
 * Output: JS_SUCCESS on success; JS_ERROR on error */

int libtcp_create_bind_addrs();

/* Obtain a bind address from the kvars.
 * This is used to determine the IPs the zoneserver will bind to
 * Input: type: 1: the bind address
 *               2: the address to synthesize for NS records
 * Output: an ipv4pair containing the bind address. */
ipv4pair *libtcp_bind_address(int type);

void set_soa_origin(js_string *in);
void set_soa_serial(int in);

