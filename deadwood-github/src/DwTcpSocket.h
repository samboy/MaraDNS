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

/* Allocate the memory for the list of the open remote TCP connections.
 * This memory is never freed once allocated, because this data is always
 * used by the program */
void malloc_tcp_pend();

/* Initialize the values of all the open remote TCP connections */
void init_tcp_b_pend();

/* TCP bind to all IP addresses we are to bind to and return the number of
 * IP addresses we got */
int bind_all_tcp();

/* Given a tcp socket s, accept the connection on that socket, then
 * open up a TCP connection to the upstream server, and assign a
 * tcp_rem with the socket numbers for the accepted local connection
 * and the connection to the upstream server */
void local_tcp_accept(SOCKET s);

/* Attempt to flush buffered data for a given pending TCP connection */
int tcp_flush_buffer(int r);

/* Disconnect idle TCP connections */
void kill_tcp_expired();

/* For a given pending TCP connection, see if we have all the bytes we
 * want.  If we don't, try to get the data we want */
void tcp_get_wanted(int b);

/* For a given TCP connection, if we have all the bytes we want, do the
 * next thing */
void tcp_process_data(int b);

/* This code sends back buffered data to the client who sent us the original
 * TCP request */
void tcp_send_wanted(int b);

/* Called from the "UDP" code, this tells Deadwood to buffer a TCP
 * packet to send back to the client */
void tcp_return_reply(int b, char *packet, int len);

/* Convert a TCP packet on a connection in to a reply we either get from
 * the cache or send upstream via UDP */
void tcp_to_udp(int b);

/* Functions in DwUdpSocket.c that we use in DwTcpSocket.c */

/* See if a given reply is in the cache; if so, send them the reply
 * from the cache */
int get_reply_from_cache(dw_str *query, sockaddr_all_T *client,
                         SOCKET sock, int32_t id, int resurrect,
                         int tcp_num, dw_str *orig_query, ip_addr_T *from_ip);

/* Given a connection we will send on, try and send the connection on.
   If we're unable to send the connection on, see if we have an
   expired element with the data we want. */
void try_forward_local_udp_packet(SOCKET sock, int32_t local_id,
     ip_addr_T *from_ip, uint16_t from_port, unsigned char *packet,
     int len, sockaddr_all_T *client,dw_str *query, int tcp_num,
     dw_str *orig_query);

/* Send a local DNS request to the upstream (remote) server; this
 * requires a few parameters having to do with the connection
 * to be passed to the function */
int forward_local_udp_packet(SOCKET sock, int32_t local_id,
     ip_addr_T *from_ip, uint16_t from_port, unsigned char *a,
     int len, int tcp_num, dw_str *orig_query);

/* Handle all TCP connections with data pending to be sent */
void tcp_handle_all(int b);

/* If we get a "truncated" UDP DNS packet upstream, and have connected via
 * TCP to make our original DNS query, connect via TCP to the upstream
 * server to try and get the non-truncated reply */
void tcp_truncated_retry(int b, dw_str *query, int id, int udp_id, int is_up);

