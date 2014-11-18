/* Copyright (c) 2002 Sam Trenholme
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

#include "../libs/JsStr.h"
#include "../MaraDns.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifndef DARWIN
#include <sys/resource.h>
#endif
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

/* A define */
#define BUFSIZE 65000

/* Test zone server which does the following:

   * Bind on port 53

   * Wait for someone to connect

   * When someone connects, they will send a two-byte big-endian number
     followed by that number fo bytes

   * After this packet is sent, this program will open up a file
     called "test_zonedata.txt".  It will convert each line, which is
     an octal-escaped JS-string sequence, in to a binary js-string object.
     Each line will be sent as the same two-octet length followed by the
     raw binary data in question.

   * After it is done, it will close the connection on port 53.

 */

/* Bind to TCP port 53 on IP address 127.0.0.99
   Input: pointer to socket to bind on
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int tcpbind(int *sock) {
    int len_inet; /* Length */
    struct sockaddr_in dns_tcp;
    char *ip = "127.0.0.99";

    /* Sanity checks */
    if(sock == 0)
        return JS_ERROR;

    /* Create a raw TCP socket */
    if((*sock = socket(PF_INET,SOCK_STREAM,0)) == -1) {
        return JS_ERROR;
        }

    /* Choose an IP and port to bind to */
    memset(&dns_tcp,0,sizeof(dns_tcp));
    dns_tcp.sin_family = AF_INET;
    dns_tcp.sin_port = htons(53);
    if((dns_tcp.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
        return JS_ERROR;

    len_inet = sizeof(dns_tcp);

    /* Bind to the socket.  Note that we usually have to be root to do this */
    if(bind(*sock,(struct sockaddr *)&dns_tcp,len_inet) == -1)
        return JS_ERROR;

    /* Set up an active listen on the socket */
    if(listen(*sock,250) == -1)
        return JS_ERROR;

    /* We are now on TCP port 53.  Leave */
    return JS_SUCCESS;
    }

/* Start a TCP connection on socket sock.
   Input: pointer to socket
   Output: Integer value of TCP connection on success, JS_ERROR on error
           (or permission denied)
*/

int gettcp(int *sock) {
    int ret, counter;
    struct sockaddr_in adr_clnt;
    int len_inet;
    uint32 ip;

    len_inet = sizeof(adr_clnt);
    ret = accept(*sock, (struct sockaddr *)&adr_clnt,&len_inet);
    if(ret == -1)
        return JS_ERROR;

    return ret;
    }

/* Given the output of show_esc_stdout, create a binary js_string
   object.
   Input: js_string object to convert escape sequences in to binary
          sequences
   Output: Pointer to newly created js_string object which contains
           the binary sequence; 0 if any problems happened
 */

js_string *decode_esc_sequence(js_string *esc) {
    js_string *ret;
    int iplace, oplace, counter, inescape, octal_value;
    unsigned char octet;
    iplace = oplace = 0;

    if(js_has_sanity(esc) != JS_SUCCESS) {
        return 0;
        }

    /* Find out how big to make the output string */
    for(counter = 0 ; counter < esc->unit_count ; counter++) {
        octet = *(esc->string + counter);
        if(octet == '\\') {
            counter++;
            if(counter >= esc->unit_count) {
                return 0;
                }
            octet = *(esc->string + counter);
            /* Anything besides a number is a single character escaped */
            if(octet < '0' || octet > '7') {
                oplace++;
                }
            else {
                for(inescape = 0; inescape < 3 ; inescape++) {
                    octet = *(esc->string + counter);
                    /* We only accept three-digit octal sequences */
                    if(octet < '0' || octet > '7') {
                        return 0;
                        }
                    if(inescape < 2)
                        counter++;
                    if(counter >= esc->unit_count) {
                        return 0;
                        }
                    }
                oplace++;
                }
            }
        /* Normal non-escape character */
        else if(octet >= 32) {
            oplace++;
            }
        }

    /* oplace now has the number of octets the outputted string should
       have; if there was anything unusual in the escape sequences,
       we will not have gotten to here */
    if((ret = js_create(oplace + 2,1)) == 0) {
        return 0;
        }

    ret->unit_count = oplace;

    /* Now, copy over the escaped string to the unescaped return string */
    oplace = 0;
    for(counter = 0 ; counter < esc->unit_count ; counter++) {
        octet = *(esc->string + counter);
        if(octet == '\\') {
            counter++;
            if(counter >= esc->unit_count) {
                js_destroy(ret);
                return 0;
                }
            octet = *(esc->string + counter);
            /* Anything besides a number is a single character escaped */
            if(octet < '0' || octet > '7') {
                *(ret->string + oplace) = *(esc->string + counter);
                oplace++;
                }
            else {
                octal_value = 0;
                for(inescape = 0; inescape < 3 ; inescape++) {
                    octal_value *= 8;
                    octet = *(esc->string + counter);
                    /* We only accept three-digit octal sequences */
                    if(octet < '0' || octet > '7') {
                        js_destroy(ret);
                        return 0;
                        }
                    octal_value += octet - '0';
                    if(inescape < 2)
                        counter++;
                    if(counter >= esc->unit_count) {
                        js_destroy(ret);
                        return 0;
                        }
                    }
                *(ret->string + oplace) = octal_value;
                oplace++;
                }
            }
        /* Normal non-escape character */
        else if(octet >= 32) {
            *(ret->string + oplace) = *(esc->string + counter);
            oplace++;
            }
        }

    return ret;
    }

/* The core of the test zoneserver */

int main() {
    int sock;

    /* Bind to port 53 */
    if(tcpbind(&sock) == JS_ERROR) {
        printf("Binding problem.\n");
        exit(1);
        }

    /* Drop root privileges */
    if(setuid(99) != 0) {
        printf("Could not drop root privileges\n");
        exit(1);
        }

    /* Old Linux kernel bug */
    if(setuid(0) == 0) {
        printf("We're still root!\n");
        exit(1);
        }

    /* Listen for data on the TCP socket */
    for(;;) {
        int connect;
        pid_t pid;
        connect = gettcp(&sock);
        if(connect == JS_ERROR)
            continue;

        printf("Someone has connected...\n");

        /* Fork off to handle the connection */
        pid = fork();
        if(!pid) { /* Child */
            js_string *line, *gotit;
            FILE *in;
            unsigned char getline[BUFSIZE];
            unsigned char get[2];
            int length;

            /* Get the two byte length header */
            if(recv(connect,get,2,MSG_WAITALL) != 2) {
                close(connect); /* Close connection on error */
                exit(0); /* End child */
                }

            /* Determine how long the query will be */
            length = (get[0] & 0xff) << 8 | (get[1] & 0xff);
            if(length > BUFSIZE - 100) {
                close(connect); /* Close connection on error */
                exit(0); /* End child */
                }
            if(recv(connect,getline,length,MSG_WAITALL) != length) {
                close(connect); /* Close connection on error */
                exit(0); /* End child */
                }
            /* Now, send them the reply */
            if((in = fopen("test_zonedata.txt","rb")) == NULL) {
                printf("No test_zonedata.txt file\n");
                close(connect); /* Close connection on error */
                exit(0);
                }

            gotit = js_create(BUFSIZE,1);
            if(gotit == 0) {
                close(connect); /* Close connection on error */
                exit(0);
                }

            /* Get a line */
            while(fgets(getline,BUFSIZE - 100,in) != NULL) {
                /* And process it */
                if(js_qstr2js(gotit,getline) == JS_ERROR) {
                    close(connect); /* Close connection on error */
                    exit(0);
                    }
                line = decode_esc_sequence(gotit);
                /* Determine the length of the response to send */
                get[0] = (line->unit_count & 0xff00) >> 8;
                get[1] = line->unit_count & 0xff;
                if(write(connect,get,2) == -1) {
                    close(connect); /* Close connection on error */
                    exit(0);
                    }
                if(write(connect,line->string,line->unit_count) == -1) {
                    close(connect); /* Close connection on error */
                    exit(0);
                    }
                js_destroy(line);
                }
            close(connect); /* Close connection */
            exit(0);
            }

        /* Hackish way to clean up child processes without needlessly slowing
           the program */
        while(waitpid(0,NULL,WNOHANG) > 0);
        }
    }
