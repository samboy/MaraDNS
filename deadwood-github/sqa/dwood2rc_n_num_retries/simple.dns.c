/* Copyright (c) 2009 Sam Trenholme
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

/* Simple UDP DNS server; this sends "10.11.12.13" as an IP as a reply
 * to any DNS packet; to test handle_noreply this only answers every
 * third packet */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

/* This is the IP "10.11.12.13" added to their question */
char p[17] =
"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x0a\x0b\x0c\x0d";

main() {
        int a, b, len_inet, sock;
        struct sockaddr_in dns_udp;
        char in[512];
        int foo = sizeof(in);
        int localhost = 0x7f000001; /* 127.0.0.1 */
        int leni = sizeof(struct sockaddr);

        /* Bind to 127.0.0.1 port 53 */
        sock = socket(AF_INET,SOCK_DGRAM,0);
        if(sock == -1) {printf("socket error\n");exit(0);}
        memset(&dns_udp,0,sizeof(dns_udp));
        dns_udp.sin_family = AF_INET;
        dns_udp.sin_port = htons(53);
        dns_udp.sin_addr.s_addr = htonl(localhost);
        if(dns_udp.sin_addr.s_addr == INADDR_NONE) {
                printf("htonl error\n");exit(0);}
        len_inet = sizeof(dns_udp);
        if(bind(sock,(struct sockaddr *)&dns_udp,len_inet) == -1) {
                printf("bind error\n");exit(0);}

        /* Linux kernel bug */
        /* fcntl(sock, F_SETFL, O_NONBLOCK); */

        for(b=0;;b++) {
          /* Get data from UDP port 53 */
          len_inet = recvfrom(sock,in,255,0,(struct sockaddr *)&dns_udp,&foo);
          /* Roy Arends check: We only answer questions */
          if(len_inet < 3 || (in[2] & 0x80) != 0x00) {
                continue;
          }
          if(len_inet > 12) {
                /* Make this an answer */
                in[2] |= 0x80;
                /* We add an additional answer */
                in[7]++;
          }
          for(a=0;a<16;a++) {
                in[len_inet + a] = p[a];
          }

          if(b % 3 == 2) {
                /* Send the reply */
                sendto(sock,in,len_inet + 16,0,
                       (struct sockaddr *)&dns_udp,leni);
                printf("Packet sent\n");
          } else {
                printf("Packet not sent\n");
          }

        }

}

