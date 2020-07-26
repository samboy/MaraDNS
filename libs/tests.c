/* Given in to the public domain 2000 by Sam Trenholme */
/* This is a series of regression tests for the js_string library */

#include "MaraHash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main() {
    js_string *s1,*s2,*s3,*get;
    js_file *f1;
    mhash *dict;
    char c;
    char strn[256];
    int counter,place,number;

    /* Test creation of the string */
    s1 = js_create(256,1);
    printf("%s\n","Test: String creation");
    printf("%s%p\n","The following number should be a valid address: ",s1);

    printf("\n");

    /* Put the string 'What's up doc?' in the js_string object */
    /* Test conversion of classicsal C null-terminated string to
       js_ String object */

    printf("%s\n","Test: String conversion from null-terminated string");
    js_str2js(s1,"What's up doc?",14,1);
    printf("%s\n",
           "The following line should have the string \"What's up doc?\"");
    js_show_stdout(s1);
    printf("\n");

    printf("\n");

    /* Test appending to a string */
    printf("%s\n","Test: Appending one string to another");
    s2 = js_create(256,1);
    js_str2js(s2," is what the bunny said.",24,1);
    /* Append the contents of s2 to s1 */
    js_append(s2,s1);
    printf("%s\n","You should see \"What's up doc? is what the bunny said.\"");
    js_show_stdout(s1);

    /* test the hash function */
    printf("\n");
    printf("%s","Test: the MaraHash library\n");
    for(counter=8;counter<24;counter++)
        printf("s1 Hash: %d\n",mhash_js(s1,counter));
    for(counter=8;counter<24;counter++)
        printf("s2 Hash: %d\n",mhash_js(s2,counter));
    printf("\n");

    /* Test the ability to put and get info from a dictionary */
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
        printf("a to add, v to view, d to delete, and q to quit\n");
        printf("Enter command: ");
        fgets(strn,200,stdin);
        if(strn[strlen(strn) - 1] == '\n')
            strn[strlen(strn) - 1] = '\0';
        if(*strn == 'a') {
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
    printf("Continuing with ks_String tests.....\n");

    /* Test qappend function -- fast string appending */
    printf("%s\n","Test: js_qappend and js_qstr2js functions");
    js_qstr2js(s1,"What's up doc");
    printf("%s\n","You should see \"What's up doc is what the bunny said\"");
    js_qappend(" is what the bunny said",s1);
    js_show_stdout(s1);
    printf("\n");

    printf("\n");

    /* Test qprepend function -- fast string prepending */
    printf("%s\n","Test: js_qprepend and js_qstr2js functions");
    js_qstr2js(s1," what's up doc");
    printf("%s\n","You should see \"is what the bunny said what's up doc\"");
    js_qprepend("is what the bunny said",s1);
    js_show_stdout(s1);
    printf("\n");

    printf("\n");

    /* Test qfgrep function -- fast string fgrepping */
    printf("%s\n","Test: js_qfgrep function");
    printf("%s\n","You should see 12");
    printf("%d\n",js_qfgrep("bunny",s1));
    printf("\n");

    printf("\n");

    /* Test inserting in a string */
    printf("%s\n","Test: Inserting one string inside another");
    for(counter=0;counter<=10;counter++) {
        js_destroy(s1);
        js_destroy(s2);
        s1 = js_create(256,1);
        s2 = js_create(256,1);
        js_str2js(s1,"1234567890",10,1);
        js_str2js(s2,"insert",6,1);
        js_insert(s2,s1,counter);
        printf("%s","You should see \"");
        place = 1;
        while(place <= counter) {
            printf("%d",place % 10);
            place++;
            }
        printf("%s","insert");
        while(place <= 10) {
            printf("%d",place % 10);
            place++;
            }
        printf("%s","\"\n");
        js_show_stdout(s1);
        printf("%s","\n");
        }

    printf("%s","\n");

    /* Test fgreping a string */
    printf("%s\n","Test: Fgrepping one string inside another");
    printf("%s\n","You should see \"0 1 2 3 4 5 6 7 8 9 10 \"");
    for(counter=0;counter<=10;counter++) {
        js_destroy(s1);
        js_destroy(s2);
        s1 = js_create(256,1);
        s2 = js_create(256,1);
        js_str2js(s1,"1234567890",10,1);
        js_str2js(s2,"insert",6,1);
        js_insert(s2,s1,counter);
        printf("%d ",js_fgrep(s2,s1));
        }

    printf("%s","\n");
    printf("%s","\n");

    /* Test fgreping a string with offset */
    printf("%s\n","Test: Fgrepping one string inside another with offset");
    for(counter=1;counter<=10;counter++) {
        printf("%s","You should see \"");
        for(place=0;place<counter;place++)
            printf("%s","-2 ");
        for(;place<=10;place++)
            printf("%d ",place);
        printf("%s","\"\n");
        for(place=0;place<=10;place++) {
            js_destroy(s1);
            js_destroy(s2);
            s1 = js_create(256,1);
            s2 = js_create(256,1);
            js_str2js(s1,"1234567890",10,1);
            js_str2js(s2,"insert",6,1);
            js_insert(s2,s1,place);
            printf("%d ",js_fgrep_offset(s2,s1,counter));
            }
        printf("%s","\n");
        }

    printf("%s","\n");

    /* Test matching one string inside another */
    printf("%s\n","Test: Matching one string against another");
    printf("%s\n","You should see \"0 1 2 3 4 5 6 7 8 9 \"");
    js_destroy(s1);
    js_destroy(s2);
    s1 = js_create(256,1);
    s2 = js_create(256,1);
    js_str2js(s1,"1234567890",10,1);
    for(counter=1;counter<=10;counter++) {
        c = '0' + counter % 10;
        js_str2js(s2,&c,1,1);
        printf("%d ",js_match(s2,s1));
        }
    printf("%s","\n");

    printf("%s","\n");

    /* Test matching one string inside another with offset */
    printf("%s\n","Test: Matching one string against another with offset");
    for(place=1;place<10;place++) {
        printf("%s","You should see \"");
        for(counter=0;counter<place;counter++)
            printf("%s","-2 ");
        for(;counter<10;counter++)
            printf("%d ",counter);
        printf("%s","\"\n");
        js_destroy(s1);
        js_destroy(s2);
        s1 = js_create(256,1);
        s2 = js_create(256,1);
        js_str2js(s1,"1234567890",10,1);
        for(counter=1;counter<=10;counter++) {
            c = '0' + counter % 10;
            js_str2js(s2,&c,1,1);
            printf("%d ",js_match_offset(s2,s1,place));
            }
        printf("%s","\n");
        }

    printf("%s","\n");

    /* Test matching one string inside another (multichar expression)*/
    printf("%s\n","Test: Matching one string against another (multichar expression)");
    for(place=1;place<=10;place++) {
        printf("%s","You should see \"");
        for(counter=0;counter<10;counter++)
            printf("%d ",place - 1);
        printf("%s","\"\n");
        s3 = js_create(1,1);
        for(number=1;number<=10;number++) {
            js_destroy(s1);
            js_destroy(s2);
            js_destroy(s3);
            s1 = js_create(256,1);
            s2 = js_create(256,1);
            s3 = js_create(256,1);
            js_str2js(s1,"1234567890",10,1);
            for(counter=1;counter<=10;counter++) {
                if(counter==number)
                    c = '0' + place % 10;
                else
                    c = 'a' + counter;
                js_str2js(s3,&c,1,1);
                js_append(s3,s2);
                }
            printf("%d ",js_match(s2,s1));
            }
        printf("%s","\n");
        }

    printf("%s","\n");

    /* Test matching one string inside another (multichar expression 2) */
    printf("%s\n","Test: Matching one string against another (multichar expression 2)");
    for(place=1;place<=10;place++) {
        printf("%s","You should see \"");
        for(counter=0;counter<10;counter++)
            printf("%d ",counter);
        printf("%s","\"\n");
        for(number=1;number<=10;number++) {
            js_destroy(s1);
            js_destroy(s2);
            js_destroy(s3);
            s1 = js_create(256,1);
            s2 = js_create(256,1);
            s3 = js_create(256,1);
            js_str2js(s1,"1234567890",10,1);
            for(counter=1;counter<=10;counter++) {
                if(counter==number)
                    c = '0' + place % 10;
                else
                    c = 'a' + counter;
                js_str2js(s3,&c,1,1);
                js_append(s3,s2);
                }
            printf("%d ",js_match(s1,s2));
            }
        printf("%s","\n");
        }

    printf("%s","\n");

    /* Test match with multioctet chars */
    printf("%s\n","Test: Match with multioctet chars");
    js_destroy(s1);
    js_destroy(s2);
    js_destroy(s3);
    s1 = js_create(128,2);
    s2 = js_create(128,2);
    js_str2js(s1,"timokutokita",6,2);
    js_str2js(s2,"mmkkkkkikktt",6,2);
    printf("%s","You should see 3\n");
    printf("%d\n",js_match(s1,s2));
    js_str2js(s2,"mmkukkkxkktt",6,2);
    printf("%s","You should see 1\n");
    printf("%d\n",js_match(s1,s2));
    js_str2js(s2,"mokukkkxkktt",6,2);
    printf("%s","You should see 0\n");
    printf("%d\n",js_match(s1,s2));
    js_str2js(s2,"zxkzkukukuto",6,2);
    printf("%s","You should see 2\n");
    printf("%d\n",js_match(s1,s2));
    js_str2js(s2,"xxkzkqkxkztb",6,2);
    printf("%s","You should see -2\n");
    printf("%d\n",js_match(s1,s2));

    js_destroy(s1);
    js_destroy(s2);
    printf("%s","\n");

    /* Test js_substr function */
    s1 = js_create(256,1);
    s2 = js_create(256,1);
    js_str2js(s1,"1234567890",10,1);
    js_substr(s1,s2,2,3);
    printf("%s","You should see \"345\"\n");
    js_show_stdout(s2);
    printf("%s","\n");

    /* Test "not"matching one string inside another */
    printf("%s\n","Test: NotMatching one string against another");
    printf("%s\n","You should see \"1 2 3 4 5 6 7 8 9 -2\"");
    js_destroy(s1);
    js_destroy(s2);
    s1 = js_create(256,1);
    s2 = js_create(256,1);
    s3 = js_create(256,1);
    js_str2js(s1,"1234567890",10,1);
    for(counter=1;counter<=10;counter++) {
        c = '0' + counter % 10;
        js_str2js(s2,&c,1,1);
        js_append(s2,s3);
        printf("%d ",js_notmatch(s3,s1));
        }
    printf("%s","\n");

    printf("%s","\n");

    /* Test reading a file line by line */
    js_str2js(s1,"testdata",8,1);
    f1 = js_alloc(1,sizeof(js_file));
    js_open_read(s1,f1);
    js_set_encode(s1,JS_US_ASCII); /* Mandatory for line-by-line reading */
    while(!js_buf_eof(f1)) {
        printf("%s","Reading a line from file:\n");
        js_buf_getline(f1,s1);
        js_show_stdout(s1);
        }

    /* Test js_atoi */
    js_qstr2js(s1,"12345");
    printf("%s","\nTest: js_atoi\n");
    printf("%s","You should see: 12345 2345 345 45 5 0\n");
    for(counter=0; counter<=5; counter++)
        printf("%d ",js_atoi(s1,counter));
    printf("\n");

    /* Test js_val */
    printf("%s","\nTest: js_val\n");
    printf("%s","You should see: 49 50 51 52 53\n");
    for(counter=0;counter<5;counter++)
        printf("%d ",js_val(s1,counter));
    printf("\n");

    return 0;
    }
