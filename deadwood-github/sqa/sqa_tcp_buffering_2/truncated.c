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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* We use a special SOCKET type for easier Windows porting */
#define SOCKET int

/* microdns: This is a tiny DNS server that does only one thing: It
 * always sends a "truncated" reply to any and all queries sent to the server.
 */

/* Based on command-line arguments, set the IP we will bind to */
uint32_t get_ip(int argc, char **argv) {

        uint32_t ip;

        /* Set the IP we bind to (default is "0", which means "all IPs) */
        ip = 0;
        if(argc >= 2) {
                ip = inet_addr(argv[1]);
        }
        /* Return the IP we bind to */
        return ip;
}

/* Get port: Get a port locally and return the socket the port is on */
SOCKET get_port(uint32_t ip, char **argv, struct sockaddr_in *dns_udp) {
        SOCKET sock;
        int len_inet;

        /* Bind to port 53 */
        sock = socket(AF_INET,SOCK_DGRAM,0);
        if(sock == -1) {
                perror("socket error");
                exit(0);
        }
        memset(dns_udp,0,sizeof(struct sockaddr_in));
        dns_udp->sin_family = AF_INET;
        dns_udp->sin_port = htons(53);
        dns_udp->sin_addr.s_addr = ip;
        if(dns_udp->sin_addr.s_addr == INADDR_NONE) {
                printf("Problem with bind IP %s\n",argv[2]);
                exit(0);
        }
        len_inet = sizeof(struct sockaddr_in);
        if(bind(sock,(struct sockaddr *)dns_udp,len_inet) == -1) {
                perror("bind error");
                exit(0);
        }

        /* Linux kernel bug */
        /* fcntl(sock, F_SETFL, O_NONBLOCK); */

        return sock;
}

int main(int argc, char **argv) {
        int len_inet;
        SOCKET sock;
        char in[512];
        socklen_t foo = sizeof(in);
        struct sockaddr_in dns_udp;
        uint32_t ip = 0; /* 0.0.0.0; default bind IP */
        int leni = sizeof(struct sockaddr);

        ip = get_ip(argc, argv);
        sock = get_port(ip,argv,&dns_udp);

        /* Now that we know the IP and are on port 53, process incoming
         * DNS requests */
        for(;;) {
                /* Get data from UDP port 53 */
                len_inet = recvfrom(sock,in,255,0,(struct sockaddr *)&dns_udp,
                        &foo);
                /* Roy Arends check: We only answer questions */
                if(len_inet < 3 || (in[2] & 0x80) != 0x00) {
                        continue;
                }

                /* Prepare the reply */
                if(len_inet > 12) {
                        /* Make this an answer */
                        in[2] |= 0x80;
                        /* Mark this as truncated */
                        in[2] |= 0x02;
                }

                /* Send the reply */
                sendto(sock,in,len_inet + 16,0, (struct sockaddr *)&dns_udp,
                        leni);
        }

}

