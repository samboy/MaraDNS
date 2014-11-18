/* Copyright (c) 2009-2010 Sam Trenholme
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

/* This is the header placed before the 4-byte IP; we change the last four
 * bytes to set the IP we give out in replies */
char p[17] =
"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x7f\x7f\x7f";

/* microdns: This is a tiny DNS server that does only one thing: It
   always sends a given IPv4 IP to any and all queries sent to the server.
   The IP to send the user is given in the first argument; the second optional
   argument is the IP of this tiny DNS server.  If the second argument is not
   given, microdns binds to "0.0.0.0": All the IP addresses the server has.

   For example, to have micrdns always give the IP address 10.1.2.3 on the
   IP 127.0.0.1:

        microdns 10.1.2.3 127.0.0.1

 */

/* Based on command-line arguments, set the IP we will bind to and the
   IP we send over the pipe */
uint32_t get_ip(int argc, char **argv) {

        uint32_t ip;

        /* Set the BIND ip and the IP we give everyone */
        if(argc < 2 || argc > 3) {
                printf(
                "Usage: microdns {ip to give out} [{ip of microdns server}]\n"
                );
                exit(1);
                }

        /* Set the IP we give everyone */
        ip = inet_addr(argv[1]);
        ip = ntohl(ip);
        p[12] = (ip & 0xff000000) >> 24;
        p[13] = (ip & 0x00ff0000) >> 16;
        p[14] = (ip & 0x0000ff00) >>  8;
        p[15] = (ip & 0x000000ff);

        /* Set the IP we bind to (default is "0", which means "all IPs) */
        ip = 0;
        if(argc == 3) {
                ip = inet_addr(argv[2]);
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
        int a, len_inet;
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
                        if(in[11] == 0) { /* EDNS not supported */
                                /* We add an additional answer */
                                in[7]++;
                        } else {
                                in[3] &= 0xf0; in[3] |= 4; /* NOTIMPL */
                        }
                }
                if(in[11] == 0) { /* Again, EDNS not supported */
                        for(a=0;a<16;a++) {
                                in[len_inet + a] = p[a];
                        }
                }

                /* Send the reply */
                sendto(sock,in,len_inet + 16,0, (struct sockaddr *)&dns_udp,
                        leni);
        }

}

