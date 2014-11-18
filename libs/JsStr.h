/* Placed in the public domain in 2000 by Sam Trenholme */
/* js_strings  -- This is my library for handling string manuipulations
   in a secure manner.  In order to make things secure, we have a more
   complicated structure for the string.  In addition to a pointer to the
   beginning of the actual character string, we have an indiction of how
   long the string currently is (ascii nulls should be allowed in strings.
   period), how long the string is allowed to be (it will truncate any attempt
   to overflow the string), and how long each character in the string is
   (can you say unicode?  I thought so.  Also use for things like using
    JsStr objects to store IPs, etc.) */

/* Make sure this isn't included multiple times */
#ifndef JS_STRING_INCLUDED
#define JS_STRING_INCLUDED

/* Needed for uint32_t */
#include <stdint.h>

typedef struct {
    unsigned char *string;   /* Actual physical string */
    unsigned int unit_size;  /* The size of a single character in the string */
    unsigned int unit_count; /* The length of the string, in units */
    unsigned int max_count;  /* The maximum allowable size of the string,
                               also in units */
    int encoding;   /* The type of language/encoding the string is in */
    int is_good;    /* This is checked to make sure the data structure is
                       sane */
    } js_string;

typedef struct {
    int filetype;
    int file_desc;
    /* Some values so we can have buffered i/o */
    js_string *buffer;
    int number;
    int eof;
    } js_file;

/* Some constants */
/* Sane number for is_good structure element */
#define JS_SANE_NUMBER 3124
/* Some encoding numbers */
/* Minimum encoding number */
#define JS_MIN_ENCODE 1
/* encoding values */
#define JS_BINARY 1
#define JS_US_ASCII 2
#define JS_ISO_8859_1 3
#define JS_8859_1 3 /* Shortcut */
#define JS_UTF8 4
/* Max encoding number */
#define JS_MAX_ENCODE 3
/* File types */
/* UNIX-style open/read/write file (in section 2 of the man pages) */
#define JS_OPEN2 1
/* Error and success */
#define JS_ERROR -1
#define JS_SUCCESS 1
/* Size of buffer in file i/o buffering options (getline, mainly) */
#define JS_BUFSIZE 1024

/* Function Prototypes */

/* JsStr.c functions */
int js_octets(js_string *js);
js_string *js_create(unsigned int max_count, unsigned int unit_size);
int js_set_encode(js_string *js, int encoding);
int js_get_encode(js_string *js);
int js_set_chsize(js_string *js, int size);
int js_destroy(js_string *object);
int js_destroy_force(js_string *object);
int js_has_sanity(js_string *object);
int js_str2js(js_string *js, char *string, int count, int size);
int js_js2str(js_string *js, char *string, int max);
int js_issame(js_string *js1, js_string *js2);
int js_fgrep(js_string *exp, js_string *js);
int js_fgrep_offset(js_string *exp, js_string *js, int offset);
int js_match(js_string *exp, js_string *js);
int js_match_offset(js_string *exp, js_string *js, int offset);
int js_insert(js_string *toinsert, js_string *target, int where);
int js_append(js_string *toappend, js_string *target);
int js_copy(js_string *src, js_string *dest);
int js_substr(js_string *source, js_string *dest, int start, int count);
int js_notmatch_offset(js_string *exp, js_string *js, int offset);
int js_notmatch(js_string *exp, js_string *js);
int js_qappend(char *toappend, js_string *target);
int js_qprepend(char *toprepend, js_string *target);
int js_qfgrep(char *expression, js_string *target);
int js_val(js_string *js, int offset);
int js_adduint16(js_string *js, int number);
int js_addbyte(js_string *js, unsigned char byte);
int js_length(js_string *js);
int js_readuint16(js_string *js, unsigned int offset);
int js_changebyte(js_string *js, unsigned char byte, int offset);
int js_qissame(char *expression, js_string *target);

/* JsStrOS.c functions */
void *js_alloc(int unit_count, int unit_size);
int js_dealloc(void *pointer);
int js_show_stdout(js_string *js);
void js_open(js_string *filename, js_file *desc, int flags);
int js_open_write(js_string *filename, js_file *desc);
int js_open_read(js_string *filename,js_file *desc);
int js_read(js_file *desc, js_string *js, int count);
int js_write(js_file *desc, js_string *js);
int js_close(js_file *desc);
int js_buf_eof(js_file *desc);
int js_buf_read(js_file *desc);
int js_buf_getline(js_file *desc, js_string *js);
int js_qstr2js(js_string *js, char *string);
int js_adduint32(js_string *js, uint32_t number);
int js_substr_append(js_string *source, js_string *dest, int offset,
                     int length);
uint32_t js_readuint32(js_string *js, unsigned int offset);
int js_strnlen(char *s, uint32_t limit);
int js_tell_memory_allocated();
int show_esc_stdout(js_string *js);
int safe_esc_stdout(js_string *js);

/* JsStrCP.c functions */
int js_newline_chars(js_string *js);
int js_tolower(js_string *js);
unsigned int js_atoi(js_string *js, int offset);
int js_space_chars(js_string *js);
js_string *js_an_chars(js_string *js);
js_string *js_numbers(js_string *js);

#endif /* JS_STRING_INCLUDED */
