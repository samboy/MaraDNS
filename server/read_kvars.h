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

/* Routine which reads a numeric kvar from the database of values set
   in the mararc file (this can not be used for dictionary variables).

   Input: A null-terminated string with the desired variable name,
          the default value for the kvar in question (if not set)

   Output: The numeric value in question (always positive or zero)
           -1 (JS_ERROR) if a fatal error happened

 */

int read_numeric_kvar(char *name,int default_value);

/* Routine which reads a string kvar from the database of values set
   in the mararc file (this can not be used for dictionary variables).

   Input: A null-terminated string with the desired variable name,

   Output: A pointer to the string with the value in question.  This
           string will be blank if the kvar is not set; 0 (NULL) if
           there was an error

 */

js_string *read_string_kvar(char *name);

