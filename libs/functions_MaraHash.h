/* Function to remove a js_string object from a mhash structure
   input: Hash to fondle, key
   output: JS_SUCCESS or JS_ERROR, depending on success/failure */

int mhash_undef_js(mhash *hash, js_string *key);

/* Function to resize a hash table.
   input: pointer to mhash object (assosciative array), desired size of
          new hash table
   output: JS_SUCCESS on success, JS_ERROR on error
*/

int mhash_resize(mhash *hash,int new_bits);

/* Function to, if needed, automatically grow a hash table
   Input: pointer hash table
   Output: JS_ERROR if something bad happened, 1 if the table did not grow,
           2 if the table grew.
*/

int mhash_autogrow(mhash *hash);

/* Convert a hash offset to a pointer to js data for the key
   input: pointer to hash, offset of element we are looking at
   output: pointer to js_String object if success, otherwise 0
*/
js_string *mhash_offset2key(mhash *hash, mhash_offset offset);

/* Convert a hash offset to a pointer to js data for the value
   input: pointer to hash, offset of element we are looking at
   output: pointer to js_String object if success, otherwise 0
*/
js_string *mhash_offset2js(mhash *hash, mhash_offset offset);

/* Remove an element from the assosciative array (hash)
   input: Hash to change, element to remove
   output: Pointer to value of array element to remove (which
           you will probably want to deallocate), 0 on error
*/
void *mhash_undef(mhash *hash, js_string *key);

/* Read four bytes from a filename and use that as a secret add constant */
int mhash_set_add_constant(char *filename);
