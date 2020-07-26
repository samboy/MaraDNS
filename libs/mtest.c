/* Given in to the public domain 2000,2001 by Sam Trenholme */
/* This is a series of regression tests for the js_string library */

#include "MaraHash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int mhash_firstkey();
extern int mhash_nextkey();

int main() {
    js_string *s1,*s2,*get;
    mhash *dict;
    mhash_e e;
    char strn[256];
    mhash_offset counter = 0;
    int see_ret;

    /* creation of strings */
    s1 = js_create(256,1);
    s2 = js_create(256,1);

    printf("\n");

    /* Test the ability to put and get info from a dictionary */
    /* First, create the dictionary */
    printf("Interactive session: create dictionary\n");
    printf("Number of bits in hash (default 8): ");
    fgets(strn,200,stdin);
    if(strn[strlen(strn) - 1] == '\n')
        strn[strlen(strn) - 1] = '\0';
    if(atoi(strn) >= 8 && atoi(strn) < 31)
        dict = (mhash *)mhash_create(atoi(strn));
    else
        dict = (mhash *)mhash_create(8);
    if(dict == 0) {
        printf("Fatal: Couldn't make Dictionary!\n");
        exit(1);
        }
    /* Add some elements to the dictionary */
    js_qstr2js(s1,"key");
    js_qstr2js(s2,"value");
    mhash_put_js(dict,s1,s2);
    js_qstr2js(s1,"otherkey");
    js_qstr2js(s2,"hihihi");
    mhash_put_js(dict,s1,s2);
    get = mhash_get_js(dict,s1);
    printf("%s\n","You should see:\nhihihi\nvalue\n\n");
    js_show_stdout(get);
    printf("\n");
    js_qstr2js(s1,"key");
    get = mhash_get_js(dict,s1);
    js_show_stdout(get);
    printf("\n");

    /* Some more hash testing */
    printf("Interactive session: add/remove/view mhash elements\n");
    printf("key = value, otherkey = hihihi, otherwise empty mhash\n");
    for(;;) {
        printf("a to add, v to view, d to delete, s to see the entire ");
        printf("hash, r to resize,\n");
        printf("g to add element with autogrow check,and q to quit\n");
        printf("Enter command: ");
        fgets(strn,200,stdin);
        if(strn[strlen(strn) - 1] == '\n')
            strn[strlen(strn) - 1] = '\0';
        if(*strn == 'r') {
            printf("New size of hash (in hash_bits): ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            if(atoi(strn) >= 8 && atoi(strn) < 31)
                see_ret = mhash_resize(dict,atoi(strn));
            else
                see_ret = mhash_resize(dict,atoi(strn));
            printf("mhash_resize returned %d\n",see_ret);
            }
        if(*strn == 's') {
            printf("Viewing the assosciative array\n");
            mhash_firstkey(dict,s1);
            do {
                printf("Hash: %d\n",mhash_js(s1,dict->hash_bits));
                printf("Key: ");
                js_show_stdout(s1);
                printf(" Value: ");
                e = mhash_get(dict,s1);
                if(e.datatype == MARA_JS)
                    js_show_stdout(e.value);
                else
                    printf("pointer to %p",
                           dict->hash_table[counter]->value);
                printf("\n\n");
                } while(mhash_nextkey(dict,s1) != 0);
            }
        else if(*strn == 'a') {
            printf("Element to add: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s1,strn);
            printf("Value of element: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s2,strn);
            printf("mhash_put_js returned %d\n",mhash_put_js(dict,s1,s2));
            }
        else if(*strn == 'g') {
            printf("Element to add: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s1,strn);
            printf("Value of element: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s2,strn);
            printf("mhash_put_js returned %d\n",mhash_put_js(dict,s1,s2));
            printf("mhash_autogrow returned %d\n",mhash_autogrow(dict));
            }
        else if(*strn == 'v') {
            printf("Element to view: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s1,strn);
            get = mhash_get_js(dict,s1);
            printf("mhash_get_js returned %p\n",get);
            printf("Viewing element %s: ",strn);
            js_show_stdout(get);
            printf("\n");
            }
        else if(*strn == 'd') {
            printf("Element to delete: ");
            fgets(strn,200,stdin);
            if(strn[strlen(strn) - 1] == '\n')
                strn[strlen(strn) - 1] = '\0';
            js_qstr2js(s1,strn);
            printf("mhash_undef_js returned %d\n",mhash_undef_js(dict,s1));
            }
        else if(*strn == 'q')
            break;
        }

    return 0;
    }
