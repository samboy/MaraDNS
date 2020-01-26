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

/* This is the DNS question we send up the pipe; this is a request for the
 * A record for example.com. */
#define PACKET_LEN 29
char p[PACKET_LEN] =
        "\x6d\xe4\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07"
        /*  e   x   a   m   p   l   e   .   c   o   m   . */
        "\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

/* sendpacket: This is a simple DNS client; this sends over UDP port 53
   the above packet, waits seven seconds for a reply, then timeouts if it
   doesn't get the packet, otherwise it shows on standard output the packet
   in hex format.  This program takes one argument: The IP to send the packet
   to */

/* Based on command-line arguments, set the IP we will send to */
uint32_t get_ip(int argc, char **argv) {

        uint32_t ip;

        /* Set the BIND ip and the IP we give everyone */
        if(argc < 2 || argc > 3) {
                printf(
                "Usage: sendpacket {ip} {Roy Arends bit}\n"
                );
                exit(1);
                }

        if(argc == 3) {
                p[2] |= 0x80; /* Mark this as an "answer" which should be
                               * ignored (The "Roy Arends" bit) */
        }

        /* Set the IP we bind to (default is "0", which means "all IPs) */
        ip = inet_addr(argv[1]);
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
        memset(dns_udp,0,sizeof(dns_udp));
        dns_udp->sin_family = AF_INET;
        dns_udp->sin_port = htons(53);
        dns_udp->sin_addr.s_addr = ip;
        if(dns_udp->sin_addr.s_addr == INADDR_NONE) {
                printf("Problem with bind IP %s\n",argv[2]);
                exit(0);
        }
        len_inet = sizeof(struct sockaddr_in);

        /* Linux kernel bug */
        /* fcntl(sock, F_SETFL, O_NONBLOCK); */

        return sock;
}

/* Send the packet above, then show them the reply */
int main(int argc, char **argv) {
        int a, len_inet;
        SOCKET sock;
        char in[512];
        socklen_t foo = sizeof(in);
        struct sockaddr_in dns_udp;
        uint32_t ip = 0; /* 0.0.0.0; default bind IP */
        int leni = sizeof(struct sockaddr);
        fd_set rx_set; /* Using select() because if its timeout option */
        int maxd;      /* select() */
        struct timeval tv;  /* select() */
        int n; /* Select() return value */

        ip = get_ip(argc, argv);
        sock = get_port(ip,argv,&dns_udp);

        /* Now that we know the IP and are sending on port 53, send the
         * packet */
        /* Get data from UDP port 53 */
        len_inet = sizeof(dns_udp);
        sendto(sock,p,PACKET_LEN,0,(struct sockaddr *)&dns_udp,len_inet);

        /* Wait to get a reply from them */
        FD_ZERO(&rx_set);
        FD_SET(sock,&rx_set);
        maxd = sock + 1;
        tv.tv_sec = 7; /* 7 seconds */
        tv.tv_usec = 0;
        n = select(maxd,&rx_set,0,0,&tv);
        if(n < 0) {
                printf("Select() failed\n");
                exit(1);
        }
        if(n == 0) {
                printf("Timeout\n");
                exit(1);
        }

        /* Tell us the packet we got from them */
        leni = recvfrom(sock,in,255,0,(struct sockaddr *)&dns_udp,
                &foo);
        for(a=0;a<leni;a++) {
                printf("\\x%02x",in[a] & 0xff);
        }
        printf("\n");
}
