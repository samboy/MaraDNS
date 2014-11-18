/* Place in the public domain by Sam Trenholme 2000 */
/* js_string routines that depend on the code page (encoding) that we
   are in */

#include "JsStr.h"

/* js_newline_chars: returns a set of newline characters for a given
                     encoding
   input: an empty js_string object we look at the codepage of
   output: JS_ERROR (-1) on error, JS_SUCCESS (1) on success */

int js_newline_chars(js_string *js) {

    /* Sanity check */
    if(js_has_sanity(js) == -1)
        return -1;

    /* Handle different encodings differently */
    switch(js->encoding) {
        case JS_BINARY:
            js->unit_count = 0;
            return JS_SUCCESS;
        case JS_US_ASCII:
        case JS_ISO_8859_1:
            if(js->unit_size != 1)
                return -1; /* This string is not sane */
            if(js_octets(js) < 2)
                return -1; /* No overflows ever */
            *(js->string) = '\r';
            *(js->string + 1) = '\n';
            js->unit_count = 2;
            return JS_SUCCESS;
        }

     /* We only get here if it is an unhandled encoding */
     return JS_ERROR;

     }

/* js_space_chars: returns a set of whitespace characters for a given
                   encoding
   input: an empty js_string object we look at the codepage of
   output: JS_ERROR (-1) on error, JS_SUCCESS (1) on success */

int js_space_chars(js_string *js) {

    /* Sanity check */
    if(js_has_sanity(js) == -1)
        return -1;

    /* Handle different encodings differently */
    switch(js->encoding) {
        case JS_BINARY:
            js->unit_count = 0;
            return JS_SUCCESS;
        case JS_US_ASCII:
        case JS_ISO_8859_1:
            if(js->unit_size != 1)
                return -1; /* This string is not sane */
            if(js_octets(js) < 3)
                return -1; /* No overflows ever */
            *(js->string) = ' ';
            *(js->string + 1) = '\t';
            if(js->encoding != JS_US_ASCII) {
                *(js->string + 2) = 160; /* Non-breaking space */
                js->unit_count = 3;
                }
            else
                js->unit_count = 2;
            return JS_SUCCESS;
        }

     /* We only get here if it is an unhandled encoding */
     return JS_ERROR;

     }

/* js_atoi: Convert a number, starting at a given offset, into an integer
   input: js_string object to look at, place in string to start looking at
   output: integer we find at the given point, 0 on error (ugh) */
unsigned int js_atoi(js_string *js, int offset) {

   int value, sign;

   if(js_has_sanity(js) == JS_ERROR)
       return 0;

   /* Return 0 if encoding unsupported */
   if(js->encoding != JS_US_ASCII && js->encoding != JS_ISO_8859_1)
       return 0;
   /* All supported encodings use the same codes for numerical digits */
   else {
       if(offset >= js->unit_count)
           return 0;
       value = 0;
       sign = 1;
       while(offset < js->unit_count && *(js->string + offset) >= '0'
             && *(js->string + offset) <= '9') {
           value *= 10;
           value += *(js->string + offset) - '0';
           offset++;
           }
       value *= sign;
       return value;
       }

   return 0; /* We should never get here */
   }

/* js_tolower: Convert a js_string object in to all lower case letters.
   input: js_string object to convert
   output: JS_ERROR on error, JS_SUCCESS on success */
int js_tolower(js_string *js) {
    int counter;

    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;

    if(js->unit_size != 1) /* All supported encodings have one octet
                              per character */
        return JS_ERROR;

    if(js->encoding == JS_US_ASCII) {
        for(counter = 0; counter < js->unit_count; counter++)
            if(*(js->string + counter) >= 'A' &&
               *(js->string + counter) <= 'Z')
                *(js->string + counter) += 32;
        }
    else if(js->encoding == JS_ISO_8859_1) {
        for(counter = 0; counter < js->unit_count; counter++) {
            if(*(js->string + counter) >= 'A' &&
               *(js->string + counter) <= 'Z')
                *(js->string + counter) += 32;
            if(*(js->string + counter) >= 192 /*  */ &&
               *(js->string + counter) <= 214 /*  */)
                *(js->string + counter) += 32;
            /* Why they had to put  and the corresponding  smack dab in
               the middle of the international letters is a mystery to me */
            if(*(js->string + counter) >= 216 /*  */ &&
               *(js->string + counter) <= 222 /*  */)
                *(js->string + counter) += 32;
            }
         }
    /* Return 0 if encoding unsupported */
    else
        return 0;

    return JS_SUCCESS;
    }

/* js_anq_chars: Give a list of alpha(numeric) characters for a given
                encoding.
   input: js_string object to fill with the data in question,
          whether or not we include numbers and the _ symbol
          (0 = no, 1 = yes, 2 = only numbers)
   output: pointer to js_string obejct on success, 0 on error
*/

js_string *js_anq_chars(js_string *js, int do_nums) {
    int place = 0,do_lets = 1;
    unsigned char counter;

    /* Sanity check */
    if(js_has_sanity(js) == JS_ERROR)
        return 0;

    /* If we are doing only numbers, then we don't use letters */
    if(do_nums == 2)
        do_lets = 0;

    /* Action is based on encoding */
    switch(js->encoding) {
        case JS_ISO_8859_1:
            if(js_octets(js) < 192)
                return 0; /* No overflows ever */
            if(do_lets == 1) {
                /*  to  */
                for(counter=192;counter<=214;counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                /*  to  */
                for(counter=216;counter<=246;counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                /*  to  */
                for(counter=248;counter<255;counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                /*  ( We do it this way because counter is always <= 255 ) */
                *(js->string + place) = 255;
                place++;
            }
        case JS_US_ASCII:
            if(js_octets(js) < 96)
                return 0;
            if(do_lets == 1) {
                /* A to Z */
                for(counter='A';counter<='Z';counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                /* a to z */
                for(counter='a';counter<='z';counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                }
            if(do_nums == 1 || do_nums == 2) {
                /* 0 to 9 */
                for(counter='0';counter<='9';counter++) {
                    *(js->string + place) = counter;
                    place++;
                    }
                /* _ */
                if(do_nums != 2) /* If not numbers only */ {
                    *(js->string + place) = '_';
                    place++;
                    }
                }
            js->unit_count = place;
            break;
        default:
            return 0;
        }

    return js;

    }

/* js_alpha_chars: Give a list of alphabetic characters for a given
                   encoding. (not including _)
   input: js_string object to fill with the data in question,
   output: pointer to js_string obejct on success, 0 on error
*/

js_string *js_alpha_chars(js_string *js) {
    return js_anq_chars(js,0);
    }

/* js_an_chars: Give a list of alphanumeric characters for a given
                encoding. (including _)
   input: js_string object to fill with the data in question,
   output: pointer to js_string obejct on success, 0 on error
*/

js_string *js_an_chars(js_string *js) {
    return js_anq_chars(js,1);
    }

/* js_numbers: Give a list of numeric characters for a given
                encoding. (no _)
   input: js_string object to fill with the data in question,
   output: pointer to js_string obejct on success, 0 on error
*/

js_string *js_numbers(js_string *js) {
    return js_anq_chars(js,2);
    }


