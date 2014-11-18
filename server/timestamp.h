/* Copyright (c) 2004 Sam Trenholme
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

/* Set the type of timestamp that we will display.
   Input:  The type of timestamp they want.
           0: "Timestamp: " followed by UNIX timestemp
           1: Just the UNIX timestamp
           2: A GMT timestamp in the Spanish language
           3: A local timestamp in the Spanish language
           4: A timestamp using asctime(gmtime()); usually in the English language
           5: No timestamp whatsoever is shown
           6: ISO GMT timestamp is shown
           7: ISO local timestamp is shown
   Output: JS_SUCCESS on success; JS_ERROR on error
*/

int set_timestamp(int type);

/* Display the timestamp based on the timestamp type above
   Input: None
   Output: JS_ERROR on error, JS_SUCCESS on success
   Outputs to standard output timestamp w/o carriage return
*/

int show_timestamp();


