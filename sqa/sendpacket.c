/* Copyright (c) 2009-2016 Sam Trenholme
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

/* This is a tool for sending a RAW UDP packet to MaraDNS for "gremlin"
 * testing. This program receives the UDP packet on standard input (which,
 * yes, can have NULLs in it); once standard input is closed, this
 * program sends the packet to the IP specified on the command line.
 * E.g. let's make 32 random bytes:
 *
 * dd if=/dev/urandom of=foo bs=32 count=1
 *
 * And send them to the DNS server on port 53:
 *
 * cat foo | ./sendpacket 127.0.0.1
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
#define PACKET_LEN 256
char p[PACKET_LEN];

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
                "Usage: cat some_binary_dns_packet | ./sendpacket {ip}\n"
                );
                exit(1);
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
        int z,y;

        ip = get_ip(argc, argv);
        sock = get_port(ip,argv,&dns_udp);

        /* Now that we know the IP and are sending on port 53, send the
         * packet */
        /* Get data from UDP port 53 */
        len_inet = sizeof(dns_udp);

        /* Get packet to send */
        z = 0;
        while(!feof(stdin)) {
                y = getc(stdin);
                if(!feof(stdin) && z < PACKET_LEN) {
                        p[z] = y;
                        z++;
                }
        }

        printf("%d\n",z);

        y = sendto(sock,p,z,0,(struct sockaddr *)&dns_udp,len_inet);

        if(y >= 0) {
                printf("Packet sent\n");
        } else {
                printf("Error sending packet\n");
        }
}
