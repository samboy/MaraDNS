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

/* This is the core DNS server */

#include "../MaraDns.h"
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* A list of the IP addresses we bind MaraDNS to (the netmask portion is
   ignored) */
ipv4pair bind_addresses[512];

/* Bind to IPV4 UDP port 53. (or DNS_PORT if debugging MaraDNS on a
                              system where I do not have root, and
                              theirfore can not bind to a low port number)

   Input:  pointer to socket to bind on, js_string with the dotted-decimal
           ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udp_ipv4_bind(int *sockets, ipv4pair *addresses) {
    int len_inet; /* Length */
    struct sockaddr_in dns_udp;
    int counter;

    /* Sanity checks */
    if(sockets == 0)
        return JS_ERROR;

    counter = 0;

    /* Create a socket address to use with bind() */
    while(counter < 500 && addresses[counter].ip != 0xffffffff) {
        /* Create a raw UDP socket */
        if((sockets[counter] = socket(AF_INET,SOCK_DGRAM,0)) == -1) {
            return JS_ERROR;
            }

        memset(&dns_udp,0,sizeof(dns_udp));
        dns_udp.sin_family = AF_INET;
        /* DNS_PORT is usually 53, but can be another port.  Defined in
           MaraDNS.h */
        dns_udp.sin_port = htons(DNS_PORT);
        if((dns_udp.sin_addr.s_addr = htonl(addresses[counter].ip))
           == INADDR_NONE)
            return JS_ERROR;

        len_inet = sizeof(dns_udp);

        /* Bind to the socket.  Note that we usually have to be root to
           do this */
        if(bind(sockets[counter],(struct sockaddr *)&dns_udp,len_inet) == -1)
            return JS_ERROR;

        counter++;
        }

    /* We are now bound to UDP port 53. (Or whatever DNS_PORT is) Leave */
    return JS_SUCCESS;
    }

/* We don't allow both recursive and ipv6 support, since the recursive
 * resolver is ipv4-only */

#ifdef AUTHONLY
/* Bind to IPV6 UDP port 53. (or DNS_PORT if debugging MaraDNS on a system
                         where I do not have root, and theirfore can not
                         bind to a low port number)
   Input:  pointer to socket to bind on, js_string with the dotted-decimal
           ip address to bind to
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int udp_ipv6_bind(int *sock, int splace, js_string *ipv6_address) {
    int len_inet; /* Length */
    struct sockaddr_in6 dns_udp;
    int counter;
    char ascii_ipv6[128];

    if(js_js2str(ipv6_address,ascii_ipv6,100) == JS_ERROR) {
            return JS_ERROR;
    }
    if(splace >= 501) {
            return JS_ERROR;
    }

    /* Sanity checks */
    if(socket == 0)
        return JS_ERROR;

    counter = 0;

    if((sock[splace] = socket(AF_INET6,SOCK_DGRAM,0)) == -1) {
            return JS_ERROR;
            }

    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin6_family = AF_INET6;
    /* DNS_PORT is usually 53, but can be another port.  Defined in
       MaraDNS.h */
    dns_udp.sin6_port = htons(DNS_PORT);
    inet_pton(AF_INET6,ascii_ipv6,&(dns_udp.sin6_addr));

   /* if((dns_udp.sin6_addr = htonl(addresses[counter].ip))
         == INADDR_NONE)
            return JS_ERROR; */

    len_inet = sizeof(dns_udp);

    /* Bind to the socket.  Note that we usually have to be root to
       do this */
    if(bind(sock[splace],(struct sockaddr *)&dns_udp,len_inet) == -1)
            return JS_ERROR;

    /* We are now bound to UDP port 53. (Or whatever DNS_PORT is) Leave */
    return JS_SUCCESS;
    }
#endif /* AUTHONLY */

/* Get information from a previously binded UDP socket
   Input:  list of UDP bound sockets, list of addresses we are bound to,
           pointer to sockaddr structure that will contain
           the IP of the system connecting to us, pointer to js_string
           object that will have the data in question, maximum allowed
           length of data we receive
   Output: JS_ERROR on error, socket we got packet from on success
*/

int getudp(int *sock,ipv4pair *addr,conn *ect,
           js_string *data, int max_len, int have_ipv6_address) {
    int len_inet, counter, len;
    fd_set rx_fd;
    int select_output;
    int max_socket;
    struct timeval timeout;
    struct sockaddr_in *ipv4_client;
#ifdef AUTHONLY
    struct sockaddr_in6 *ipv6_client;
#endif

    /* Sanity checks */
    if(ect == 0 || data == 0) {
        printf("172\n");
        return JS_ERROR;
    }
    if(js_has_sanity(data) == JS_ERROR) {
        printf("176\n");
        return JS_ERROR;
    }
    if(data->unit_size != 1) {
        printf("180\n");
        return JS_ERROR;
    }
    if(max_len < 0 || max_len >= data->max_count) {
        printf("184\n");
        return JS_ERROR;
    }

    len_inet = sizeof(struct sockaddr);
    ect->addrlen = len_inet;

    FD_ZERO(&rx_fd);
    counter = 0;
    max_socket = 0;
    while(counter < 500 && addr[counter].ip != 0xffffffff) {
        FD_SET(sock[counter],&rx_fd);
        if((sock[counter] + 1) > max_socket) {
            max_socket = sock[counter] + 1;
            }
        counter++;
        }
#ifdef AUTHONLY
    if(have_ipv6_address == 1) {
        FD_SET(sock[counter],&rx_fd);
        if((sock[counter] + 1) > max_socket) {
            max_socket = sock[counter] + 1;
            }
        }
#endif
    if(max_socket == 0) /* No sockets */ {
        printf("209\n");
        return JS_ERROR;
        }

    timeout.tv_sec = 1; /* Check for HUP signal every second */
    timeout.tv_usec = 0;

    /* OK, wait for activity on any of those sockets */
    select_output = select(max_socket,&rx_fd,NULL,NULL,&timeout);

    if(select_output <= 0) { /* 0: Timeout; less than 0: error */
        /*printf("220\n");*/
        return JS_ERROR;
        }

    /* Figure out which socket gave us something */
    counter = 0;
    while(counter < 500 && addr[counter].ip != 0xffffffff) {
        if(FD_ISSET(sock[counter],&rx_fd)) {
            int a; unsigned char *b; /*DEBUG*/
            ipv4_client = js_alloc(1,sizeof(struct sockaddr_in));
            if(ipv4_client == 0) {
                    printf("231\n");
                    return JS_ERROR;
                    }

#ifdef SELECT_PROBLEM
            fcntl(sock[counter], F_SETFL, O_NONBLOCK);
#endif
            b=ipv4_client;for(a=0;a<sizeof(struct sockaddr_in);a++){*b = 0;b++;}/*DEBUG*/
            len = recvfrom(sock[counter],data->string,max_len,0,
                           (struct sockaddr *)ipv4_client,&(ect->addrlen));
            if(len < 0) {
                js_dealloc(ipv4_client);
                printf("243\n");
                return JS_ERROR;
                }
            printf("You should see 7f 00 00 03 or 7f 00 00 04 in the next bytes\n");
            b=ipv4_client;for(a=0;a<len;a++){printf("%02x ",*b++);}/*DEBUG*/
            printf("3411: %x\n",ipv4_client->sin_addr.s_addr);
            ect->type = 4;
            ect->d = ipv4_client;

            data->unit_count = len;

            return sock[counter];
            }
        counter++;
        }
#ifdef AUTHONLY
    if(have_ipv6_address == 1) {
        if(FD_ISSET(sock[counter],&rx_fd)) {
            ipv6_client = js_alloc(1,sizeof(struct sockaddr_in6));
            if(ipv6_client == 0) {
                    printf("262\n");
                    return JS_ERROR;
            }

#ifdef SELECT_PROBLEM
            fcntl(sock[counter], F_SETFL, O_NONBLOCK);
#endif
            len = recvfrom(sock[counter],data->string,max_len,0,
                           (struct sockaddr *)ipv6_client,&(ect->addrlen));
            if(len < 0) {
                js_dealloc(ipv6_client);
                printf("273\n");
                return JS_ERROR;
                }

            ect->type = 6;
            ect->d = ipv6_client;

            data->unit_count = len;

            return sock[counter];
            }
        }
#endif /* AUTHONLY */

    /* "JS_ERROR" means "nobody talked to us in the last second" */
    ect->type = 0;
    ect->d = 0;
    return JS_ERROR;

    }

/* The core of the DNS server */

int main(int argc, char **argv) {

    js_string *mararc_loc, *errors,
              *kvar_query, *bind_address, *ipv6_bind_address,
              *incoming, *uncomp, *verbstr;
    unsigned char chroot_zt[255];
    uid_t uid;
    gid_t gid;
    int errorn, value, maxprocs, counter;
    int sock[514];
    int cache_size;
    int min_ttl_n = 300, min_ttl_c = 300;
    int timestamp_type = 0; /* Type of timestamp */
    int recursion_enabled = 0; /* Whether we have recursion */
#ifndef AUTHONLY
    int max_glueless; /* Maximum allowed glueless level */
    int max_q_total; /* Maximum total queries in attempt to resolve hostname */
    int timeout; /* Maximum time to wait for a remote server when performing
                    a recursive query */
#endif
    int verbose_query = 0;
    struct sockaddr client;
    struct sockaddr_in *clin; /* So we can log the IP */
#ifndef DARWIN
    struct rlimit rlim;
#endif
    int have_ipv6_address = 0;

    clin = (struct sockaddr_in *)&client;


        for(counter = 0; counter < 512 ; counter++) {
            bind_addresses[counter].ip = 0xffffffff;
            sock[counter] = 0;
            }
        bind_addresses[0].ip = 0x7f000003; /* 127.0.0.3 */
        bind_addresses[1].ip = 0x7f000004; /* 127.0.0.4 */
        if(udp_ipv4_bind(sock,bind_addresses) == JS_ERROR)
            exit(123); /* "Problem binding to port 53.\nMost likely, another process is already listening on port 53" */

        if(0 >= 1) {
                for(counter = 0; counter < 502; counter++) {
                        if(sock[counter] == 0)
                            break;
                }
                if(counter >= 501) {
                        exit(124);
                }
                if(udp_ipv6_bind(sock,counter,ipv6_bind_address) == JS_ERROR) {
                        exit(125);
                }
                have_ipv6_address = 1;
        }

        /* Set the ID */
        setgid(99);
        setuid(99);

    incoming = js_create(1034,1);
    uncomp = js_create(1034,1);

    printf("This server is listening on port 53 with the IPs 127.0.0.3 and 127.0.0.4\n");

    for(;;) {
        int sock_num;
        conn ect; /* The space is not a typo */
        ect.type = 0;
        ect.d = (void *)0;
        ect.addrlen = 0;
        sock_num = getudp(sock,bind_addresses,&ect,incoming,512,
                          have_ipv6_address);
        if(sock_num == JS_ERROR)
            continue;
        if(decompress_data(incoming,uncomp) == JS_ERROR) {
            if(5 >= 4) {
                clin = (struct sockaddr_in *)(ect.d);
                show_timestamp();
                printf("%s ","Query from");
                if(ect.type == 4) {
                    printf(" ipv4 ");
                } else {
                    printf(" ipv6 ");
                }
                printf("has decompression error: ");
                show_esc_stdout(incoming);
                printf("\n");
                }
            continue;
            }
            show_timestamp();
            printf("Decompressed packet: ");
            show_esc_stdout(uncomp);
            printf("\n");
        if(uncomp->unit_count > 12) {
            /* Show them the query */
            counter = dlabel_length(uncomp,12);
            value = js_readuint16(uncomp,12+counter);
            if(js_substr(uncomp,incoming,12,counter) != JS_ERROR) {
                clin = (struct sockaddr_in *)(ect.d);
                hname_translate(incoming,value);
                /* Yes, I know, put these in the "to localize" header file */
                show_timestamp();
                printf("%s: ","Query from");
                if(ect.type == 4) {
                    printf(" ipv4");
                } else {
                    printf(" ipv6");
                }
                printf(" ");
                js_show_stdout(incoming);
                printf("\n");
                }
            }
        /* Free the memory used by the ect structure */
        if(ect.d != 0) {
                js_dealloc(ect.d);
            }
        }

    /* We should never end up here */

    exit(7); /* Exit code 7: Broke out of loop somehow */

    }

void debug_show_ip(){printf("debug_show_ip\n");}
void fold_case(){printf("fold_case\n");}
void get_bind_addr_list(){printf("get_bind_addr_list\n");}
void log_level(){printf("log_level\n");}
void proc_query(){printf("proc_query\n");}
void pthread_create(){printf("pthread_create\n");}
void udpany(){printf("udpany\n");}
void udperror(){printf("udperror\n");}
void udpnotfound(){printf("udpnotfound\n");}
void udpsuccess(){printf("udpsuccess\n");}
