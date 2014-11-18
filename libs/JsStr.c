/* Public domain code by Sam Trenholme 2000 */
/* Routines in the string library not dependent on the underlying OS */
/* Nor dependent on the encoding of the data in the string--all of these
   work on the underlying binary data in the string */

/* Headers for the string routines */
#include "JsStr.h"

/* js_octets: Number of allowed octets in a given string
   input: Pointer to the string in question
   output: Number of allowed octets */
int js_octets(js_string *js) {
    return js->max_count * js->unit_size;
    }

/* js_create: Create a new string object
   input: The maximum unit count and unit size of the new string object
   output: A pointer to the new string object, 0 on error */

js_string *js_create(unsigned int max_count, unsigned int unit_size) {
    js_string *new;

    if((new = js_alloc(1,sizeof(js_string))) == 0)
        return 0;

    /* Initial values for the new string object */
    new->unit_size = unit_size;
    new->unit_count = 0;
    new->max_count = max_count;
    new->is_good = JS_SANE_NUMBER;
    new->encoding = JS_BINARY;
    /* Allocate memory for character string, return on error */
    /* The 3 is a security margin */
    if((new->string = js_alloc(max_count + 3,unit_size)) == (void *)0) {
        js_dealloc(new);
        return (js_string *)0;
        }

    return new;
    }

#ifdef DEBUG
/* js_create_DEBUG: Create a new string object, keeping track of the
                    memory we allocate
   input: The maximum unit count and unit size of the new string object,
          A string which explains where we allocate the memory
   output: A pointer to the new string object, 0 on error */

js_string *js_create_DEBUG(unsigned int max_count, unsigned int unit_size,
                           char *whence) {
    js_string *new;

    if((new = js_alloc_DEBUG(1,sizeof(js_string),whence)) == 0)
        return 0;

    /* Initial values for the new string object */
    new->unit_size = unit_size;
    new->unit_count = 0;
    new->max_count = max_count;
    new->is_good = JS_SANE_NUMBER;
    new->encoding = JS_BINARY;
    /* Allocate memory for character string, return on error */
    /* The 3 is a security margin */
    if((new->string = js_alloc_DEBUG(max_count + 3,unit_size,whence))
       == (void *)0) {
        js_dealloc(new);
        return (js_string *)0;
        }

    return new;
    }
#else  /* DEBUG */
#define js_create_DEBUG(x,y,z) js_create(x,y)
#endif /* DEBUG */

/* js_set_encode: Change the encoding of a js_string object
   input: Pointer to js_string object, desired encoding
   output: -1 on error, otherwise 0
*/
int js_set_encode(js_string *js, int encoding) {
    /* Make sure we are sane */
    if(js_has_sanity(js) == -1)
        return -1;

    /* Return error if encoding value is out of bounds */
    if(encoding < JS_MIN_ENCODE || encoding > JS_MAX_ENCODE)
        return -1;

    js->encoding = encoding;

    return 0;
    }

/* js_get_encode: Get the encoding of a js_string object
   input: Pointer to js_string object
   output: -1 on error, otherwise encoding
*/
int js_get_encode(js_string *js) {
    /* Make sure we are sane */
    if(js_has_sanity(js) == -1)
        return -1;

    /* Return error if encoding value is out of bounds */
    if(js->encoding < JS_MIN_ENCODE || js->encoding > JS_MAX_ENCODE)
        return -1;

    return js->encoding;

    return 0;
    }

/* js_length: tell them the length (in units) of a given js_string object
   input: A pointer to the js_string object in question
   output: The length of the string, in units, or JS_ERROR on error. */
int js_length(js_string *js) {
    /* Sanity check */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;

    return js->unit_count;
    }

/* js_set_chsize: Change the size of a character in a js_string object
   input: Pointer to js_string object, desired character size
   output: -1 on error, otherwise 0
   NOTE: This funciton is depricated; I never used it and it, according
   to one email I received is buggy.  *Do not use this function*
*/
int js_set_chsize(js_string *js, int size) {
    /* Make sure we are sane */
    if(js_has_sanity(js) == -1)
        return -1;

    /* Return error if size value is out of bounds */
    if(size < 1)
        return -1;

    /* You are only allowed to change the unit size if the string is a
       0-length string */
    if(js->unit_count != 0)
        return -1;

    /* Change the size of the unit, resetting max_count accordingly.

       The algebra here was complicated enough that I had to work it out
       with pencil and paper before coding, so I will document here:

       Given the values s1 (current unit size), s2 (new unit size),
       u1 (current maximum unit count) and u2 (new maximum unit count),
       we know that the following equation needs to be true:

       s1 * u1 = s2 * u2

       In this equation, the only unknown value is u2.  Solving the above for
       u2, we get:

       u2 = (s1 * u1) / s2

       The following code sets up u2, based on s1, s2, and u1.

      */

    /* I am not going to deal with fractions */
    if((js->max_count * js->unit_size) % size != 0)
        return -1;
    js->max_count = js->max_count * js->unit_size;
    js->max_count /= size;

    /* Now that the max_count has been reset, change the size */
    js->unit_size = size;

    return 0;
    }

/* js_destroy: Destroy a new string object
   input: Pointer to the string object to destroy
   output: -1 on error, 1 on success*/
int js_destroy(js_string *object) {
    if(js_has_sanity(object) != -1)
        return js_destroy_force(object);
    else
        return -1;
    }

/* js_destroy_force: Destroy a new string object (forcibly, may segfault)
   input: Pointer to the string object to destroy
   output: 1 on success */
int js_destroy_force(js_string *object) {
    /* Deallocate the character string in the string object */
    js_dealloc(object->string);
    /* Deallocate the object itself */
    js_dealloc(object);
    /* Bye bye */
    return 1;
    }

/* js_has_sanity: Make sure a js_string object is sane
   input: pointer to js_string object
   output: JS_ERROR if insane, otherwise 1
*/
int js_has_sanity(js_string *object) {

    /* Is it a null pointer? */
    if(object == 0)
        return JS_ERROR;

    /* Is the sane value sane? */
    if(object->is_good != JS_SANE_NUMBER)
        return JS_ERROR;

    /* Is the length not greater than the max length? */
    if(object->unit_count > object->max_count)
        return JS_ERROR;

    /* If the encoding is ASCII, make sure unit size is one */
    if(object->encoding == JS_US_ASCII && object->unit_size != 1)
        return JS_ERROR;

    return 1;
    }

/* js_str2js: Convert a 'normal' C-lang string to a js_string object
   input: pointer to js object, string to convert, units to convert, size
          of each unit in octets
   output: -1 on error */
int js_str2js(js_string *js, char *string, int count, int size) {
    int counter = 0;
    /* int max = (count > js->max_count ? js->max_count : count); */
    int max = count;

    /* If we are out of bounds, return error */
    if(count > js->max_count)
        return -1;

    /* Sanity checks */
    if(js_has_sanity(js) == -1)
        return -1;
    if(size != js->unit_size)
        return -1;
    if(string == 0)
        return -1;

    while(counter < (max * size)) {
        *(js->string + counter) = *(string + counter);
        counter++;
        }

    /* Reset the count of characters in the string */
    js->unit_count = count;

    return 1;
    }

/* js_js2str: Convert a js_string object to a 'normal' C-lang string
   input: pointer to js object, string to convert, max number of characters
          to convert;
   output: -1 on error */
int js_js2str(js_string *js, char *string, int max) {
    int counter = 0;

    /* Sanity checks */
    if(js_has_sanity(js) == -1)
        return -1;
    if(js->unit_size * js->unit_count >= max)
        return -1;

    while(counter < js->unit_size * js->unit_count) {
        *(string + counter) = *(js->string + counter);
        counter++;
        }

    *(string + counter) = 0;

    return 1;
    }

/* js_issame: Determine if two js_string objects are identical
   input: Pointers to the two string objects
   output: 1 if they are the same, 0 otherwise, -1 on error */
int js_issame(js_string *js1, js_string *js2) {
    int counter = 0;
    int max;

    /* Sanity checks */
    if(js_has_sanity(js1) == -1)
        return -1;
    if(js_has_sanity(js2) == -1)
        return -1;

    /* They are not the same if they have different sizes for a character */
    if(js1->unit_size != js2->unit_size)
        return 0;
    /* Nor are they the same if they have different lengths */
    if(js1->unit_count != js2->unit_count)
        return 0;
    /* They both have to use the same encoding */
    /*if(js1->encoding != js2->encoding)
        return 0; */ /* This requirement disabled because this just
                        causes annoyances */

    max = js1->unit_count;

    /* If any characters in the actual string differer, they are different */
    while(counter < (max * js1->unit_size)) {
        if(*(js1->string + counter) != *(js2->string + counter))
            return 0;
        counter++;
        }

    /* Otherwise, they are identical */
    return 1;
    }

/* js_fgrep: Determine if the contents of one js_string object is
             embedded in another js_string object
   input: Object with string to look for, string object to look in
   output: number of units from beginning of string grepped string is
           at if found, 0 otherwise, -1 on error */
int js_fgrep(js_string *exp, js_string *js) {
    return js_fgrep_offset(exp,js,0);
    }

/* js_fgrep_offset: Determine if the contents of one js_string object is
             embedded in another js_string object, but we only check
             starting at offset (0 to look at entire string)
   input: Object with string to look for, string object to look in, offset of
          where we first do the match (in units)
   output: number of units from beginning of string grepped string is
           at if found, -2 otherwise, -1 on error */
int js_fgrep_offset(js_string *exp, js_string *js, int offset) {
    int counter = 0;
    int place = 0;
    int match = -2;
    int max;

    /* Sanity checks */
    if(js_has_sanity(exp) == -1)
        return -1;
    if(js_has_sanity(js) == -1)
        return -1;

    /* Make sure offset has an OK value; error if it is longer then string */
    if(offset > js->unit_count)
        return -1;

    /* If offset is less than zero, mark it from end of string */
    if(offset < 0)
        offset = js->unit_count + offset;

    /* If offset is still less than zero, error condition */
    if(offset < 0)
        return -1;

    /* They are not the same if they have different sizes for a character */
    if(exp->unit_size != js->unit_size)
        return -2;

    /* They do not match if the grep expression is longer than the string
       to grep from */
    if(exp->unit_count > js->unit_count)
        return -2;

    /* In the case of an empty grep expression, they match (at the top) */
    if(exp->unit_count <= 0)
        return 0;

    /* Max here is the last letter a matching expression can start at
       in the string we are looking for the expression in */
    max = js->unit_count - exp->unit_count;

    match = -2;

    /* Here is the actual grepping core; we match the leftmost instance */
    while(counter <= (max * js->unit_size) && match == -2) {
        /* If we match at the beginning of a letter */
        if(*(exp->string) == *(js->string + counter) &&
          counter % js->unit_size == 0 && counter >= offset * js->unit_size) {
            /* We make sure we match for each letter in the expression */
            match = counter / js->unit_size;
            place = 0;
            while(place < (exp->unit_count * exp->unit_size) &&
              place + counter < (js->unit_count * js->unit_size)) {
                if(*(exp->string + place) !=
                  *(js->string + place + counter))
                    match = -2;
                place++;
                }
            }
        counter++;
        }

    /* Return whether they matched or not */
    return match;

    }

/* js_match: Match one of a list of characters
   input: list of characters to match against, string to look in,
   output: -2 if no match, -1 error, otherwise characters form beginning
           match is at */

int js_match(js_string *exp, js_string *js) {
    return js_match_offset(exp,js,0);
    }

/* js_match_offset: Match one of a list of characters
   input: list of characters to match against, string to look in,
          offset (first character to match from)
   output: -2 if no match, -1 error, otherwise characters from beginning
           match is at */

int js_match_offset(js_string *exp, js_string *js, int offset) {
    int counter = 0;
    int place = 0;
    int pexp = 0;
    int match = -2;

    /* Sanity checks */
    if(js_has_sanity(exp) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;

    /* If offset is less than zero, mark it from end of string */
    if(offset < 0)
        offset = js->unit_count + offset;

    /* If offset is still less than zero, error condition */
    if(offset < 0)
        return -1;

    /* They are not the same if they have different sizes for a character */
    if(exp->unit_size != js->unit_size)
        return -2;

    /* In the case of an empty grep expression, they do not match */
    if(exp->unit_count <= 0)
        return -2;

    /* Here is the actual grepping core; we match the leftmost instance */
    while(counter < (js->unit_count * js->unit_size) && match == -2) {
        /* Point to first letter in expression */
        pexp = 0;
        /* If we are where a match is allowed (after offset) and the
           pexp guy (Pointer to where we are looking in the expression
           right now) is in the expression string */
        while(counter >= offset && pexp < (exp->unit_count * exp->unit_size)
              && match == -2) {
            /* If the octet we are looking at in the expression matches
               of the octet we are looking at in the string; and the octet
               we are looking at is the first character of a possible
               multioctet set; and we are in bounds... */
            if(*(exp->string + pexp) == *(js->string + counter) &&
              pexp % exp->unit_size == 0 && pexp < js_octets(exp)) {
                /* ... then we tenatively match */
                match = counter / exp->unit_size;
                place = 1;
                /* For multioctet characters, we have to make sure
                   we match for all the octets in the character */
                while(place < exp->unit_size) {
                    /* If we do not match for any of the octets...
                       (and are in bounds) */
                    if(*(exp->string + pexp + place) !=
                      *(js->string + counter + place) &&
                      pexp + place < js_octets(exp) &&
                      counter + place < js_octets(js))
                        /* ... Disregard the match */
                        match = -2;
                    place++;
                    }
                }
            /* Continue looking at all the characters in the expression */
            pexp++;
            }
        /* And continue looking at all the characters in the string we are
           looking at */
        counter++;
        }

    /* Return whether they matched or not */
    return match;

    }

/* js_notmatch: Match the first character not on a list of characters
   input: list of characters to not match against, string to look in,
   output: -2 if no match, -1 error, otherwise characters form beginning
           match is at */

int js_notmatch(js_string *exp, js_string *js) {
    return js_notmatch_offset(exp,js,0);
    }

/* js_notmatch_offset: Match one of anything besides a list of characters
   input: list of characters to notmatch against, string to look in,
          offset (first character to match from)
   output: -2 if no match, -1 error, otherwise characters from beginning
           match is at */

int js_notmatch_offset(js_string *exp, js_string *js, int offset) {
    int counter = 0;
    int place = 0;
    int pexp = 0;
    int match = -2;

    /* Sanity checks */
    if(js_has_sanity(exp) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;

    /* If offset is less than zero, mark it from end of string */
    if(offset < 0)
        offset = js->unit_count + offset;

    /* If offset is still less than zero, error condition */
    if(offset < 0)
        return -1;

    /* They are not the same if they have different sizes for a character */
    if(exp->unit_size != js->unit_size)
        return -2;

    /* In the case of an empty grep expression, they do not match */
    if(exp->unit_count <= 0)
        return -2;

    /* Here is the actual grepping core; we match the leftmost instance */
    while(counter < (js->unit_count * js->unit_size) && match == -2) {
        /* Point to first letter in expression */
        pexp = 0;
        /* If we are where a match is allowed (after offset) and the
           pexp guy (Pointer to where we are looking in the expression
           right now) is in the expression string */
        while(counter >= offset && pexp < (exp->unit_count * exp->unit_size)) {
            if(pexp % exp->unit_size == 0)
                match = counter / exp->unit_size;
            /* If the octet we are looking at in the expression match
               of the octet we are looking at in the string; and the octet
               we are looking at is the first character of a possible
               multioctet set; and we are in bounds... */
            if(*(exp->string + pexp) == *(js->string + counter) &&
              pexp % exp->unit_size == 0 && pexp < js_octets(exp)) {
                /* ... then we tenatively notmatch */
                match = -2;
                place = 1;
                /* For multioctet characters, we have to make sure
                   we don't match for any the octets in the character */
                while(place < exp->unit_size) {
                    /* If we do not match for any of the octets...
                       (and are in bounds) */
                    if(*(exp->string + pexp + place) !=
                      *(js->string + counter + place) &&
                      pexp + place < js_octets(exp) &&
                      counter + place < js_octets(js))
                        /* ... Disregard the match */
                        match = counter / exp->unit_size;
                    place++;
                    }
                if(match == -2)
                    break;
                }
            /* Continue looking at all the characters in the expression */
            pexp++;
            }
        /* And continue looking at all the characters in the string we are
           looking at */
        counter++;
        }

    /* Return whether they matched or not */
    return match;

    }

/* js_insert: insert one string inside another string
   input: A pointer of the string obj to insert, the target to insert in,
          and the place we insert the string (in units, unit 0 is beginning
          of string, negative number is units from the end of the string;
           -1 is one from end of string; -2 two from end of string and so on)
   output: -1 on error, 0 on success
*/

int js_insert(js_string *toinsert, js_string *target, int where) {
    int place = 0;
    int counter;
    char *temp_str; /* temporary string for properly performing insertion */

    /* Check to make sure things are sane */
    if(js_has_sanity(toinsert) == -1)
        return -1;
    if(js_has_sanity(target) == -1)
        return -1;
    /* Both the source and dest must have same unit size */
    if(toinsert->unit_size != target->unit_size)
        return -1;
    /* Where must be before the end of the string */
    if(where > target->unit_count)
        return -1;

    /* If where is precisely at the end, do the more efficient append */
    if(where == target->unit_count)
        return js_append(toinsert,target);

    /* So we don't have to deal with it, bail if the resulting string is
       longer than the maximum allowed target string */
    if(toinsert->unit_count + target->unit_count > target->max_count)
        return -1;

    /* Allocate temporary string; Return on allocation error */
    if((temp_str = js_alloc(target->unit_size,target->unit_count)) ==
       (void *)-1)
        return -1;

    /* Copy over the target string to temp */
    while(place < (target->unit_size * target->unit_count)) {
        *(temp_str + place) = *(target->string + place);
        place++;
        }

    /* If where is less than zero, offset it from the end of the string */
    if(where < 0)
        where = target->unit_count + where;

    /* If where is still less than zero, return error */
    if(where < 0) {
        js_dealloc(temp_str);
        return -1;
        }

    /* Change the actual target string */
    place = 0;
    counter = 0;
    while(place < (target->unit_size * target->unit_count)) {
        /* If we are where to insert toinsert string, do so */
        if(place == where * target->unit_size)
            while(counter < toinsert->unit_size * toinsert->unit_count) {
                /* If we are in the bounds of the string... */
                if(place + counter < (target->unit_size * target->max_count))
                    /* ...then add an octet of the string to insert */
                    *(target->string + place + counter) =
                      *(toinsert->string + counter);
                counter++;
                }
        /* If we are in the bounds of the string... */
        if(place + counter < (target->unit_size * target->max_count))
            /* Then add an octet of the original string */
            *(target->string + place + counter) = *(temp_str + place);
        place++;
        }

    /* Increase the size of the string */
    target->unit_count += toinsert->unit_count;

    /* Free that string */
    js_dealloc(temp_str);

    return 0;
    }


/* js_append: add one string to the end of another string
   input: A pointer of the string obj to append, the target to append to,
   output: -1 on error, 0 on success
*/

int js_append(js_string *toappend, js_string *target) {
    int counter = 0;

    /* Check to make sure things are sane */
    if(js_has_sanity(toappend) == -1)
        return -1;
    if(js_has_sanity(target) == -1)
        return -1;
    /* Both the source and dest must have same unit size */
    if(toappend->unit_size != target->unit_size)
        return -1;

    /* So we don't have to deal with it, bail if the resulting string is
       longer than the maximum allowed target string */
    if(toappend->unit_count + target->unit_count >= target->max_count)
        return -1;

    /* Append the toappend string to the actual target string */
    while(counter < (toappend->unit_size * toappend->unit_count)) {
        *(target->string + target->unit_size * target->unit_count + counter) =
          *(toappend->string + counter);
        counter++;
        }

    /* Increase the size of the string */
    target->unit_count += toappend->unit_count;

    return 0;
    }

/* js_substr: Copy a substring of the first string in to the second string
   input: The source string, the destination string, the first character to
          copy from, the length of the string to copy (in units, possibly
          multi-octet)
   output: 1 on success, -1 on error */
int js_substr(js_string *source, js_string *dest, int start, int count)
    {
    int counter;

    /* Sanity Checks */
    if(js_has_sanity(source) == -1)
        return -1;
    if(js_has_sanity(dest) == -1)
        return -1;
    if(source->unit_size != dest->unit_size)
        return -1;

    /* Make sure the passed parameters are in bounds */
    if(count < 0)
        return -1;
    if(start >= source->unit_count || start >= source->max_count)
        return -1;
    if(start + count > source->unit_count)
        return -1;
    if(start + count > source->max_count)
        return -1;
    if(count >= dest->max_count)
        return -1;

    /* Do the actual copying */
    counter = 0;
    while(counter < count * source->unit_size && counter < js_octets(dest) &&
          counter + start * source->unit_size < js_octets(source)) {
        *(dest->string + counter) =
          *(source->string + counter + start * source->unit_size);
        counter++;
        }

    dest->unit_count = count;

    return JS_SUCCESS;
    }

/* js_copy: copy one js_string over to another js_string
   input: src, dest strings (copy from src to dest)
   output: JS_ERROR (-1) on error, JS_SUCCESS (1) on success */
int js_copy(js_string *src, js_string *dest) {
    int counter = 0;

    /* Sanity checks */
    if(js_has_sanity(src) == -1 || js_has_sanity(dest) == -1)
        return -1;
    /* unit_size has to be the same on both */
    if(src->unit_size != dest->unit_size)
        return -1;
    /* We can not overflow the destination string */
    if(src->unit_size * src->unit_count >= js_octets(dest))
        return -1;

    /* Copy over the string */
    while(counter < src->unit_size * src->unit_count &&
          counter < js_octets(dest) && counter < js_octets(src)) {
        *(dest->string + counter) = *(src->string + counter);
        counter++;
        }

    /* Copy over all of the other attributes of the string */
    dest->unit_count = src->unit_count;
    dest->encoding = src->encoding;

    return JS_SUCCESS;
    }

/* js_val: Return the big-endian numeric value of a given character in
           a js_string object
   input: Pointer to js_string object, offset (in units) from beginning
          of string (0 is string begin)
   output: interger value of string character on success, JS_ERROR on error
*/

int js_val(js_string *js, int offset) {

    int value, point;

    /* Sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(offset >= js->unit_count)
        return JS_ERROR;

    /* The return value has to fit! */
    if(js->unit_size >= sizeof(int))
        return JS_ERROR;

    value = point = 0;

    while(point < js->unit_size) {
        value *= 256;
        value += *(js->string + (offset * js->unit_size) + point);
        point++;
        }

    return value;

    }

/* js_qappend: "Quick" version of js_append routine
   input: NULL-terminated string to append, pointer to js object
   output: JS_ERROR on failure, JS_SUCCESS on success
*/

int js_qappend(char *toappend, js_string *target) {

    js_string *temp = 0;
    int return_value;

    /* Sanity test */
    if(js_has_sanity(target) == JS_ERROR)
        return JS_ERROR;

    /* Allocate memory for the appending string if necessary */
    if(temp == 0)
        /* We really should make 1024 here strlen(toappend)
           That would necessitate moving this to JsStrOS.c */
        if((temp = js_create(1024,target->unit_size)) == 0)
            return JS_ERROR;

    if(js_qstr2js(temp,toappend) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    return_value = js_append(temp,target);

    js_destroy(temp);

    return return_value;

    }

/* js_qprepend: "Quick" version of js_append routine which
                prepends the NULL-terminated string in question
   input: NULL-terminated string to prepend, pointer to js object
   output: JS_ERROR on failure, JS_SUCCESS on success
*/

int js_qprepend(char *toprepend, js_string *target) {

    js_string *temp = 0;
    int return_value;

    /* Sanity test */
    if(js_has_sanity(target) == JS_ERROR)
        return JS_ERROR;

    /* Allocate memory for the appending string if necessary */
    if(temp == 0)
        /* We really should make 1024 here
           strlen(toappend) + js_octets(target)
           That would necessitate moving this to JsStrOS.c */
        if((temp = js_create(1024,target->unit_size)) == 0)
            return JS_ERROR;

    if(js_qstr2js(temp,toprepend) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    /* Preseve the encoding of this string */
    temp->encoding = target->encoding;

    if(js_append(target,temp) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    return_value = js_copy(temp,target);

    js_destroy(temp);

    return return_value;

    }

/* js_qissame: "Quick" version of js_issame routine
   input: NULL-terminated string to look for, pointer to js object
   output: JS_ERROR on failure, JS_SUCCESS on success
*/

int js_qissame(char *expression, js_string *target) {

    js_string *temp = 0;
    int return_value;

    /* Sanity test */
    if(js_has_sanity(target) == JS_ERROR)
        return JS_ERROR;

    /* Allocate memory for the appending string if necessary */
    if(temp == 0)
        /* We really should make 1024 here strlen(toappend)
           That would necessitate moving this to JsStrOS.c */
        if((temp = js_create(1024,target->unit_size)) == 0)
            return JS_ERROR;

    if(js_qstr2js(temp,expression) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    temp->unit_size = target->unit_size;
    temp->encoding = target->encoding;
    return_value = js_issame(temp,target);

    js_destroy(temp);

    return return_value;

    }

/* js_qfgrep: "Quick" version of js_fgrep routine
   input: NULL-terminated string to look for, pointer to js object
   output: JS_ERROR on failure, JS_SUCCESS on success
*/

int js_qfgrep(char *expression, js_string *target) {

    js_string *temp = 0;
    int return_value;

    /* Sanity test */
    if(js_has_sanity(target) == JS_ERROR)
        return JS_ERROR;

    /* Allocate memory for the appending string if necessary */
    if(temp == 0)
        /* We really should make 1024 here strlen(toappend)
           That would necessitate moving this to JsStrOS.c */
        if((temp = js_create(1024,target->unit_size)) == 0)
            return JS_ERROR;

    if(js_qstr2js(temp,expression) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    return_value = js_fgrep(temp,target);

    js_destroy(temp);

    return return_value;

    }

/* js_addbyte: Add a single byte at the end of a js_string obejct,
               where the js->unit_size is one.
   input: pointer to js_string object, byte to add
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int js_addbyte(js_string *js, unsigned char byte) {

    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    /* No buffer overflows */
    if(js->unit_count + 1 >= js->max_count)
        return JS_ERROR;

    /* Add the byte to the end of the string */
    *(js->string + js->unit_count) = byte;
    js->unit_count++;

    return JS_SUCCESS;
    }

/* js_changebyte: Change a single byte in a js_string obejct,
                  where the js->unit_size is one.
   input: pointer to js_string object, byte to add, place to add byte
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int js_changebyte(js_string *js, unsigned char byte, int offset) {

    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    /* No buffer overflows */
    if(offset >= js->unit_count)
        return JS_ERROR;

    /* Change the byte */
    *(js->string + offset) = byte;

    return JS_SUCCESS;
    }

/* js_adduint16: Add a 16-bit number to the end of a js_string obejct
                 in big-endian format, where the js->unit_size is one.
   input: pointer to js_string object, number to add
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int js_adduint16(js_string *js, int number) {

    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(number < 0 || number > 65535)
        return JS_ERROR;
    /* No buffer overflows */
    if(js->unit_count + 2 >= js->max_count)
        return JS_ERROR;

    /* Add the uint16 to the end of the string */
    *(js->string + js->unit_count) = (number >> 8) & 0xff;
    *(js->string + js->unit_count + 1) = number & 0xff;
    js->unit_count += 2;

    return JS_SUCCESS;
    }

/* js_readbyte: Read a single byte from a js_string object
   input: pointer to js_string object, offset from beginning
          of string (0 is beginning of string, 1 second byte, etc.)
   output: JS_ERROR on error, value of byte on success
*/

int js_readbyte(js_string *js, unsigned int offset) {

    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(offset > (js->unit_count - 1) || offset < 0)
        return JS_ERROR;

    return *(js->string + offset);

    }

/* js_readuint16: Read a single uint16 (in big-endian format)
                  from a js_string object
   input: pointer to js_string object, offset from beginning
          of string (0 is beginning of string, 1 second byte, etc.)
   output: JS_ERROR on error, value of uint16 on success
*/

int js_readuint16(js_string *js, unsigned int offset) {

    int ret;
    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(offset > (js->unit_count - 2) || offset < 0)
        return JS_ERROR;

    ret = ((*(js->string + offset) << 8) & 0xff00) |
           (*(js->string + offset + 1) & 0xff);

    return ret;

    }

/* js_substr_append: Append a substring of one js_string object to
   the end of another js_string object.

   Input: The js_string object with the desired substring, the
   string to append to, the offset in the source string, the
   length (in bytes) to append

   Output: JS_ERROR, JS_SUCCESS on success

 */

int js_substr_append(js_string *source, js_string *dest, int offset,
                     int length) {

    js_string *temp;
    if((temp = js_create(length + 2,1)) == 0) {
        return JS_ERROR;
        }

    if(source->unit_count < offset + length) {
       js_destroy(temp);
       return JS_ERROR;
       }

    if(js_substr(source,temp,offset,length) != JS_SUCCESS) {
       js_destroy(temp);
       return JS_ERROR;
       }

    if(js_append(temp,dest) == JS_ERROR) {
        js_destroy(temp);
        return JS_ERROR;
        }

    js_destroy(temp);
    return JS_SUCCESS;
    }


