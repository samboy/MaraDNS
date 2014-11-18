/* Copyright (c) 2005 Sam Trenholme
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

#include "../MaraDns.h"
#include "../libs/MaraHash.h"
#ifndef MINGW32
#include <netinet/in.h>
#else
#include <winsock.h>
#include <wininet.h>
#endif
#include "functions_server.h"

/* Add an element to the ANY chain in the big hash
 * Input: Pointer to the bighash, the query to point to, the data being
 * pointed to
 * Output: JS_SUCCESS on success, JS_ERROR on error
 */

int any_add_rr(mhash *hash, js_string *query, rr *data) {
        int rrtype;
        int a;
        js_string *copy;
        rr_list *point;
        rr_list *new;
        mhash_e get;

        rrtype = get_rtype(query);
        /*printf("%d ",rrtype);show_esc_stdout(query);printf("\n");*//*DEBUG*/
        if(rrtype == JS_ERROR) {
                return JS_ERROR;
        }
        if(rrtype < 0 || rrtype > 65535) {
                return JS_ERROR;
        }

        /* Make the "copy" string be the "ANY" form of the query in question
         */
        if((copy = js_create(256,1)) == 0) {
                return JS_ERROR;
        }
        if(js_copy(query,copy) == JS_ERROR) {
                js_destroy(copy);
                return JS_ERROR;
        }
        if(change_rtype(copy,RR_ANY) == JS_ERROR) {
                js_destroy(copy);
                return JS_ERROR;
        }

        /* Make the new rr_list be where we will put this data */
        new = js_alloc(1,sizeof(rr_list));
        if(new == 0) {
                js_destroy(copy);
                return JS_ERROR;
        }
        /* Initialize the new rr_list */
        new->rr_type = rrtype;
        new->data = data;
        new->next = 0;

        /* Look for the "ANY" query in the big hash */
        get = mhash_get(hash,copy);
        /*printf("DEBUG 72: %p %d\n",get.value,get.datatype);*/

        /* If nothing was found, create a new entry in the big hash */
        if(get.value == 0 && get.datatype == 0) {
                mhash_put(hash,copy,(void *)new,MARA_DNS_LIST);
                js_destroy(copy);
                return JS_SUCCESS;
        }

        js_destroy(copy);

        /* Otherwise, put the new data at the end of the in-place linked
         * list */
        if(get.datatype != MARA_DNS_LIST) {
                harderror("Data not MARA_DNS_LIST in ANY query in bighash");
        }

        point = (rr_list *)get.value;
        if(point == 0) {
                return JS_ERROR;
        }

        /* Find the end of the list */
        for(a = 0; a < 65000; a++) {
                /*printf("96: %p %p\n",point,point->next);*//*DEBUG*/
                if(point->next == 0) {
                        break;
                }
                point = point->next;
        }

        if(point->next != 0) {
                return JS_ERROR;
        }

        /* Add this data to the end of the list */
        point->next = new;
        new->next = 0;
        new->data = data;
        return JS_SUCCESS;
}

/* Add an ANY element to the big hash, as long as the rtype of the element
 * is *not* RR_CNAME */
int any_add_c_rr(mhash *hash, js_string *query, rr *data) {
        int rrtype;
        rrtype = get_rtype(query);
        if(rrtype == RR_CNAME) {
                return JS_ERROR;
        }
        return any_add_rr(hash,query,data);
}

/* Remove an element from the ANY chain in the big hash
 * Input: Pointer to the big hash
 *        Pointer to data which we are now removing, query with this
 *        data
 * Output: JS_ERROR on error, JS_SUCCESS on success */

int any_zap_rr(mhash *hash, js_string *query, rr *data) {
        int a;
        js_string *copy;
        mhash_e get;
        rr_list *point;
        rr_list *last;

        /* Make the "copy" string be the "ANY" form of the query in question
         */
        if((copy = js_create(256,1)) == 0) {
                return JS_ERROR;
        }
        if(js_copy(query,copy) == JS_ERROR) {
                js_destroy(copy);
                return JS_ERROR;
        }
        if(change_rtype(copy,RR_ANY) == JS_ERROR) {
                js_destroy(copy);
                return JS_ERROR;
        }

        /* Look for the query in the big hash */
        get = mhash_get(hash,copy);

        if(get.value == 0 || get.datatype == 0) {
                js_destroy(copy);
                return JS_SUCCESS;
        }

        point = (rr_list *)get.value;
        last = 0;
        /* If the first link is the link we're removing, and it's also
         * the last link... */
        if(point->data == data && point->next == 0) {
                last = (rr_list *)mhash_undef(hash,copy);
                if(last != point) {
                        harderror("Line 166; mail the mailing list");
                }
                js_dealloc(last);
                js_destroy(copy);
                return JS_SUCCESS;
        }
        /* If the first link is the link we're removing, and it isn't the
         * last link, then we repoint the data in the hash */
        if(point->data == data && point->next != 0) {
                last = (rr_list *)mhash_undef(hash,copy);
                if(last != point) {
                        harderror("Line 177; mail the mailing list");
                }
                point = point->next;
                js_dealloc(last);
                mhash_put(hash,copy,point,MARA_DNS_LIST);
                js_destroy(copy);
                return JS_SUCCESS;
        }

        js_destroy(copy);

        /* OK, look for the link in the list */
        for(a=0;a<65000;a++) {
                if(point->next == 0) {
                        return -2; /* Not found */
                }
                last = point;
                point = point->next;
                /* If element to remove is found */
                if(point->data == data) {
                        last->next = point->next;
                        js_dealloc(point);
                        return JS_SUCCESS;
                }
        }

        return JS_ERROR; /* Chain far too long */
}

