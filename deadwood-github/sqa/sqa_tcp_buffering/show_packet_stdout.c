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

/* This is a simple DNS-over-TCP server that reads a DNS packet over
 * port 53 TCP, then outputs that packet on the standard input.  Then
 * the program reads standard input and outputs the DNS packet on
 * standard input */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* We use a special SOCKET type for easier Windows porting */
#define SOCKET int

/* Get port: Get a port locally and return the socket the port is on */
SOCKET get_port(uint32_t ip, struct sockaddr_in *dns) {
        SOCKET sock;
        int len_inet;

        /* Bind to port 53 */
        sock = socket(AF_INET,SOCK_STREAM,0);
        if(sock == -1) {
                perror("socket error");
                exit(0);
        }
        memset(dns,0,sizeof(struct sockaddr_in));
        dns->sin_family = AF_INET;
        dns->sin_port = htons(53);
        dns->sin_addr.s_addr = ip;
        if(dns->sin_addr.s_addr == INADDR_NONE) {
                perror("Problem with bind");
                exit(0);
        }
        len_inet = sizeof(struct sockaddr_in);
        if(bind(sock,(struct sockaddr *)dns,len_inet) == -1) {
                perror("bind error");
                exit(0);
        }

        /* Linux kernel bug */
        /* fcntl(sock, F_SETFL, O_NONBLOCK); */

        return sock;
}

#define calc_dns_len(a) ((a[0] & 0xff) << 8) | (a[1] & 0xff)

/* Get a single nibble from stdin in hex */
int8_t get_nibble() {
        char nib;

        while((nib = (getc(stdin)))) {

                /* We allow pauses to test TCP buffering */
                if(nib == '-') {
                        sleep(1);
                        return -2;
                /* Hex-ASCII to bin conversion */
                } else if(nib >= '0' && nib <= '9') {
                        return nib - '0';
                } else if(nib >= 'A' && nib <= 'F') {
                        return nib - 'A' + 10;
                } else if(nib >= 'a' && nib <= 'f') {
                        return nib - 'a' + 10;
                }
        }
        return -1;

}

/* Get a single byte from stdin in hex */
int16_t get_stdin_hex() {
        char low;
        char high;

        high = get_nibble();
        if(high == -2) {
                return -2;
        }
        low = get_nibble();
        if(low == -2) {
                return -2;
        }

        return (high << 4) | low;
}

int main(int argc, char **argv) {
        uint32_t ip;
        int a;
        SOCKET sock;
        SOCKET local;
        uint32_t dns_l, place;
        struct sockaddr_in dns;
        uint8_t buffer[1512], id1, id2;
        ssize_t len;
        int16_t get;

        if(argc >= 2) {
                ip = inet_addr(argv[1]);
        } else {
                ip = 0; /* All IP addresses */
        }
        sock = get_port(ip,&dns);
        if(listen(sock, 250) == -1) {
                perror("listen error");
                exit(0);
        }
        len = sizeof(struct sockaddr_in);
        local = accept(sock,(struct sockaddr *)&dns,(void *)&len);
        if(local == -1) {
                perror("accept error");
                exit(0);
        }
        /* Blocking: Get 2-byte length header */
        len = recv(local, buffer, 2, MSG_WAITALL);
        if(len == -1) {
                perror("recv error show");
        }
        for(a=0; a < len; a++) {
                printf("%02X",buffer[a]);
        }
        dns_l = calc_dns_len(buffer);
        /* Blocking: Get DNS packet */
        len = recv(local, buffer, dns_l, MSG_WAITALL);
        for(a=0; a < len; a++) {
                printf("%02X ",buffer[a]);
        }
        id1 = buffer[0];
        id2 = buffer[1];
        printf("\n");
        /* Now, send a packet back from stdin */
        buffer[0] = get_stdin_hex();
        buffer[1] = get_stdin_hex();
        dns_l = calc_dns_len(buffer);
        if(send(local, buffer, 2, MSG_WAITALL) == -1) {
                perror("send error len");
                exit(0);
        }
        place = 0;
        for(a=0; a < dns_l; ) {
                get = get_stdin_hex();
                if(get == -2) {
                        if(send(local,buffer + place, a - place, MSG_WAITALL)
                           == -1) {
                                perror("send error pause");
                                exit(0);
                        }
                        printf("%d bytes sent\n",a - place);
                        place = a;
                } else {
                        buffer[a] = get;
                        buffer[0] = id1;
                        buffer[1] = id2;
                        a++;
                }
        }
        if(send(local,buffer + place,dns_l - place, MSG_WAITALL) == -1) {
                perror("send error");
                exit(0);
        }
        printf("%d bytes sent\n",dns_l - place);
        return 0;
}
