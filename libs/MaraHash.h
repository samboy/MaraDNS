/* Released to the public domain 2001 by Sam Trenholme */

/* MaraHash: A series of functions to make assosciative arrays using
   js_string objects as keys and values.

   This is done with a hash that grows as needed for the data in question */

#ifndef MARAHASH_INCLUDED
#define MARAHASH_INCLUDED
#ifndef JS_STRING_INCLUDED
#include "JsStr.h"
#endif

/* Some definitions of data types */
/* Offset from the beginning of the hash table */
#define mhash_offset unsigned int

/* Tuple (immutable) list of js_string elements */
typedef struct {
    int elements;
    js_string **tuple_list;
    } mara_tuple;

/* Single element of an assosciative array (key,value) */
typedef struct mhash_spot {
    js_string *key;
    void *value;
    int datatype;
    struct mhash_spot *next;
    } mhash_spot;

/* Structure used to return two values in mhash_get function */
typedef struct {
    void **point; /* Used so we can change what the hash elements points
                     to (userful for round-robin rotates and the like) */
    void *value;
    int datatype;
    } mhash_e;

/* The actual assosciative array object */
typedef struct {
    int hash_bits; /* Bits in the hash */
    mhash_spot **hash_table; /* the actual hash table */
    mhash_offset spots; /* NUmber of elements in the table */
    } mhash;

/* Some data types for mhash_spot->datatype field */
#define MARA_JS 1 /* js_string object */
#define MARA_TUPL 2 /* mara_tuple object */
#define MARA_TUPLE 2 /* mara_tuple object */
#define MARA_DNSRR 3 /* DNS RR object used by MaraDNS */
#define MARA_DNS_NS 4 /* DNS record "closer" to what we are looking for */
#define MARA_DNS_NEG 5 /* A cached instance of "this host is not there" */
#define MARA_DNS_LIST 6 /* A list of RRs that share a given name */

/* Function prototypes */
/* mhash (assosciative array) objects */
mhash *mhash_create();
mhash_offset mhash_js(js_string *tohash, int hash_bits);
mhash_offset mhash_inc(mhash_offset old, int hash_bits);
int mhash_put(mhash *hash, js_string *key, void *value, int datatype);
mhash_e mhash_get(mhash *hash, js_string *key);
int mhash_put_js(mhash *hash, js_string *key,js_string *value);
js_string *mhash_get_js(mhash *hash, js_string *key);
int mhash_firstkey(mhash *hash, js_string *key);
int mhash_nextkey(mhash *hash, js_string *key);

/* mara_tuple (immutable list) objects */
mara_tuple *mtuple_new(int elements);
int mtuple_put(mara_tuple *tuple, js_string *js, int element);
js_string *mtuple_get(mara_tuple *tuple, int element);
mhash_e mhash_offset2val(mhash *hash, mhash_offset offset);
js_string *mhash_get_immutable_key(mhash *hash, js_string *key);

/* More function prototypes */
#include "functions_MaraHash.h"

#endif /* MARAHASH_INCLUDED */
