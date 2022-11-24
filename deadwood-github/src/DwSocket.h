/* Copyright (c) 2007-2022 Sam Trenholme
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

#ifndef __DW_SOCKET_DEFINED__
#define __DW_SOCKET_DEFINED__

/* This is the root server list as of 2017-11-11; the IPv4 root servers were
 * last changed 2017-10 */
#define ROOT_SERVERS "198.41.0.4"       /* a.root-servers.net (VeriSign) */ \
                     ",199.9.14.201"    /* b.root-servers.net (ISI) */ \
                     ",192.33.4.12"     /* c.root-servers.net (Cogent) */ \
                     ",199.7.91.13"     /* d.root-servers.net (UMaryland) */ \
                     ",192.203.230.10"  /* e.root-servers.net (NASA Ames) */ \
                     ",192.5.5.241"     /* f.root-servers.net (ISC) */ \
                     ",192.112.36.4"    /* g.root-servers.net (DOD NIC) */ \
                     ",198.97.190.53"   /* h.root-servers.net (ArmyRU) */ \
                     ",192.36.148.17"   /* i.root-servers.net (NORDUnet) */ \
                     ",192.58.128.30"   /* j.root-servers.net (VeriSign) */ \
                     ",193.0.14.129"    /* k.root-servers.net (Reseaux) */ \
                     ",199.7.83.42"     /* l.root-servers.net (IANA) */ \
                     ",202.12.27.33        "    /* m.root-servers.net (WIDE) */
/* I'm putting some whitespace at the end so it is possible to change the root
 * servers without needing to recompile Deadwood if that is ever needed */

/* https://github.com/samboy/MaraDNS/issues/56 Deadwood 3.3 has transitioned
 * to using the https://quad9.net/ servers as the default upstream DNS
 * servers */
#define UPSTREAM_SERVERS "9.9.9.9,149.112.112.112                 "

#include "DwStr.h"
#include "DwMararc.h"
#include "DwStr_functions.h"
#include "DwRadioGatun.h"
#include "DwHash.h"

#ifdef __CYGWIN__
#define MSG_DONTWAIT 0
#endif /* __CYGWIN__ */
#ifndef MINGW
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#else  /* MINGW */
/* Maximum number of open sockets; make this big like it is in *NIX */
#ifndef FD_SETSIZE
#define FD_SETSIZE 512
#endif /* FD_SETSIZE */
#include <winsock.h>
#include <wininet.h>
#endif /* MINGW */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#ifdef MINGW
#define NO_INET_PTON
#define sa_family_t uint16_t
#define socklen_t int32_t
#define EINPROGRESS WSAEWOULDBLOCK
/* This has a strange name because winsock.h defines SOCKET_ERROR */
#define SCKT_ERR WSAGetLastError()
/* This actually isn't supported in winsock but we do the ioctl thing
 * to make the socket non-blocking, so this should be a non-issue */
#define MSG_DONTWAIT 0
#define make_socket_nonblock(a) dont_block=1;ioctlsocket(a,FIONBIO,&dont_block)
#else /* MINGW */ /* The following are defined for *NIX */
#define SCKT_ERR errno
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket(a) close(a)
#define make_socket_nonblock(a) fcntl(a,F_SETFL,O_NONBLOCK)
#endif /* MINGW */

/* Parameter that is currently hardcoded in the source code */
#define DW_MAXIPS 128 /* Maximum number of bind addresses or upstream IPs */

/* Structures for storing IP addresses */
typedef struct {
        uint8_t len; /* 0: Error; 4: IPv4; 16: IPv6; 127: Glueless name */
#ifndef NOIP6
        uint8_t ip[17];
#else /* NOIP6 */
        uint8_t ip[5];
#endif /* NOIP6 */
        dw_str *glueless; /* Used for glueless NS referrals */
        uint8_t flags;
} ip_addr_T;

#include "DwSys.h" /* DwSys.h needs ip_addr_t */

/* Structure for storing an IP address *and* a netmask; note that the
 * beginning of the structure *must* have the exact same form as the
 * ip_addr_T structure above */
typedef struct {
        uint8_t len;
#ifndef NOIP6
        uint8_t ip[17];
        uint8_t mask[17];
#else /* NOIP6 */
        uint8_t ip[5];
        uint8_t mask[5];
#endif /* NOIP6 */
} ip_mask_T;

/* storage for both sockaddr_in and sockaddr_in6; note that this needs
 * to be in that format that system calls like bind() and what not use
 * for the sockaddr format (16-bit family, followed by the IP) */
typedef struct {
        union {
                sa_family_t family;
                struct sockaddr_in v4;
#ifndef NOIP6
                struct sockaddr_in6 v6;
#endif
        } u;
} sockaddr_all_T;

/* shortcuts for above struct */
#define V4 u.v4
#define V6 u.v6
#define Family u.v4.sin_family

/* The part of a remote connection describing a single local connection */
typedef struct {
        SOCKET from_socket;
        int tcp_num; /* If this is a UDP connection, this has a value of
                      * 0; if this is a TCP connection, this is the number
                      * of the TCP connection in question */
        uint16_t local_id; /* Query ID generated by DNS server connecting
                            * to Deadwood */
        ip_addr_T ip; /* IP local request came from */
        uint16_t port; /* Port local request came from */
        uint8_t glueless_type;
        int glueless_conn; /* Remote connection number needing glueless */
        dw_str *orig_query; /* Case-preserved form of query */
        dw_str *action; /* Used for (cached) incomplete CNAMEs */
} local_T;

/* A pending remote connection */
typedef struct {
        SOCKET socket; /* Socket for connection upstream */
        int64_t die;
        uint16_t remote_id; /* Query ID generated by Deadwood */
        int retries; /* Number of times to retry connection */
        dw_str *ns; /* List of nameservers for this connection */
        uint8_t is_upstream; /* Whether this is an upstream or root NS */
        dw_str *query;
        uint8_t recurse_depth;
        int8_t current_ns;
        int child_id;
        dw_str *glueless;
        uint16_t num_locals; /* Number of local connections to send replies
                              * to once we get an answer from upstream */
        local_T **local; /* Array of local connections connected to this
                          * connection */
} remote_T;

/* A pending TCP remote connection */
typedef struct {
        SOCKET local;
        SOCKET remote;
        char *buffer;
        SOCKET buffer_socket;
        ssize_t buffer_len;
        int64_t die;
} tcp_remote_T;

/* A pending TCP connection */
typedef struct {
        SOCKET local;
        SOCKET upstream; /* For TCP queries after getting truncated packets */
        char *buffer;
        int32_t wanted; /* Bytes wanted from TCP connection */
        int32_t got;    /* Bytes received from TCP connection */
        int32_t sent;   /* Bytes sent downstream from TCP connection */
        int state;      /* What is the connection doing right now? */
        int64_t die;
} tcp_pend_T;

/* Initialize a pending TCP connection */
#define init_tcp_pend(a) tcp_pend[a].local = INVALID_SOCKET; \
                         tcp_pend[a].upstream = INVALID_SOCKET; \
                         tcp_pend[a].buffer = 0; \
                         tcp_pend[a].wanted = 0; \
                         tcp_pend[a].got = 0; \
                         tcp_pend[a].sent = 0; \
                         tcp_pend[a].state = 0; \
                         tcp_pend[a].die = 0;

/* Initialize a pending TCP remote connection */
#define init_tcp_rem(a)  tcp_rem[a].local = INVALID_SOCKET; \
                         tcp_rem[a].remote = INVALID_SOCKET; \
                         tcp_rem[a].buffer = 0; \
                         tcp_rem[a].buffer_socket = INVALID_SOCKET; \
                         tcp_rem[a].buffer_len = 0; \
                         tcp_rem[a].die = 0;

/* Reset a pending TCP connection */
#define reset_tcp_pend(a) tcp_pend[a].local = INVALID_SOCKET; \
                         tcp_pend[a].upstream = INVALID_SOCKET; \
                         if(tcp_pend[a].buffer != 0) { \
                                free(tcp_pend[a].buffer); \
                                tcp_pend[a].buffer = 0; } \
                         tcp_pend[a].wanted = 0; \
                         tcp_pend[a].got = 0; \
                         tcp_pend[a].sent = 0; \
                         tcp_pend[a].state = 0; \
                         tcp_pend[a].die = 0;

/* Reset a TCP remote connection */
#define reset_tcp_rem(a) tcp_rem[a].local = INVALID_SOCKET; \
                         tcp_rem[a].remote = INVALID_SOCKET; \
                         if(tcp_rem[a].buffer != 0) { \
                                free(tcp_rem[a].buffer); \
                                tcp_rem[a].buffer = 0; } \
                         tcp_rem[a].buffer_socket = INVALID_SOCKET; \
                         tcp_rem[a].buffer_len = 0; \
                         tcp_rem[a].die = 0;

/* Function for removing inflight data about a connection */
void zap_inflight(dw_str *query);

#define tcp_remote2local(a,b,c) tcp_local2remote(a,b,c)

/* Function parameters */

/* The following functions are private, and should only be called from
 * DwUdpSocket.c and DwTcpSocket.c */

/* In DwSocket.c */

/* Reset the values for a remote connection */
void reset_rem(int_fast32_t a);

/* Given a "client" that recvfrom/accept gave us (which has the IP and port
 * number hidden in it), extract the IP and port from that "client", put the
 * IP information in from_ip, and return a 16-bit number that has the port
 * the query came from */
uint16_t get_from_ip_port(ip_addr_T *from_ip, sockaddr_all_T *client);

/* See if a given ip is a permitted IP in the recursive_acl list.  Input:
 * IP we are checking.  Output: -1 on error; 0 if not permitted; 1 if
 * permitted */
int check_ip_acl(ip_addr_T *ip);

/* Configure the dns_do local bind structure.  Given an IP we
 * want to bind to, fill up the dns_udp structure with that IP
 * and set things up to bind to the dns_port port (normally 53, DNS).
 * Establish a socket for binding to, and return the value of the
 * socket.  type is SOCK_DGRAM for a UDP socket; SOCK_STREAM for TCP */
SOCKET bind_set_dns(ip_addr_T *ip, sockaddr_all_T *dns_do, int type);

/* Given an IP address to bind to, and a type of port it is (SOCK_DGRAM for
 * a UDP port; SOCK_STREAM for a TCP port), bind to that port and return the
 * socket number corresponding to that port */
SOCKET do_bind(ip_addr_T *ip,int type);

/* Get an upstream IP address (Not thread safe w/o locking) */
ip_addr_T get_upstream_ip();

/* Find a free remote pending connection */
int_fast32_t find_free_remote();

/* In DwUdpSocket.c */
/* Get and process a local DNS request */
void get_local_udp_packet(SOCKET sock);

/* Get and process a remote DNS request */
void get_remote_udp_packet(int b, SOCKET sock);

/* Here are all of the public functions in this program; anything else
 * is private and should not be called outside of DwSocket.c */

/* Read mararc parameters and set global variables based on those
 * parameters */
void process_mararc_params();

/* Read and process the ip4 mararc parameter */
int process_ip4_params();

/* Read and process the ip6 mararc parameter */
int process_ip6_params();

/* Initialize the inflight hash */
void init_inflight_hash();

/* Bind to all IP addresses we are to bind to and return the number of
 * IP addresses we got */
int bind_all_udp();

/* Initialize the list of pending remote replies */
void init_b_remote();

/* Main loop: Recieve from bound sockets, forward those on to upstream, and
 *            forward replies from upstream to bound sockets */
int bigloop();

/* The following functions are private functions, and should only be called
 * from DwSocket.c, DwUdpSocket.c, and DwTcpSocket.c */

/* Create a DNS header suitable for giving back to the client */
dw_str *make_dns_header(int32_t id, int16_t flags, int32_t ancount,
                        int32_t nscount, int32_t arcount);

/* Given two dw_strings with the question and answer, make a DNS packet
 * we can give back to the client; this will multilate answer so be
 * careful */
dw_str *make_dns_packet(dw_str *question, dw_str *answer, int32_t id);

/* Given a remote number, a C-string with the packet to send them, and
 * the length of that string, make a connection to a remote server */
int make_remote_connection(int32_t n, unsigned char *packet, int len,
        dw_str *query, SOCKET x_socket_num);

/* Forward a remote reply back to the client */
void forward_remote_reply(unsigned char *packet, size_t len, remote_T *r_ip,
        int local_num);

/* Send a server failure back to the client when there is no reply from
 * the upstream server.  Input: The pending remote connection number. */
void server_fail_noreply(int a, int local_num);

/* Process the root_servers and upstream_servers values, using
 * default root servers if needed
 */
void process_root_upstream();

/* Used in DwUdpSocket.c and DwRecurse.c: Given an IP address, create a
 * socket */
SOCKET setup_server(sockaddr_all_T *server, ip_addr_T *addr);

/* Bind to random source port (security) */
int do_random_bind(SOCKET s, int len);

#ifdef NO_INET_PTON
/* Wrapper function for systems that don't have inet_pton (Windows, etc.) */
int inet_pton(int z, char *c, uint8_t *ip);
#endif /* NO_INET_PTON */

/* Make the actual answer for a synthetic "not there" reply */
unsigned char *make_synth_not_there_answer(unsigned char *a, int *count,
                int type);
/* Make a synthetic RFC8482 answer */
unsigned char *make_synth_rfc8482_answer(unsigned char *a, int *count,
                int type);

#endif /* __DW_SOCKET_DEFINED__ */
