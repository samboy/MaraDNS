/* Copyright (c) 2002-2005 Sam Trenholme
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

/* Give an application a timestamp in a non-blocking manner */

qual_timestamp qual_get_time();

/* Set the time; this should be run once a second or so.
 *    Return code: JS_ERROR or JS_SUCCESS, depending */

int qual_set_time();


