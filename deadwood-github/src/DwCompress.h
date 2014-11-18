/* Copyright (c) 2009 Sam Trenholme
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

/* Given a packet as stored in the cache (a DNS packet processed by
 * dw_packet_to_cache() ) decompress the packet and output the decompressed
 * packet as a newly created DwStr() object
 */

dw_str *dwc_decompress(dw_str *q, dw_str *in);

/* Compress a DNS string, and return a newly created compressed string. */

dw_str *dwc_compress(dw_str *q, dw_str *in);

