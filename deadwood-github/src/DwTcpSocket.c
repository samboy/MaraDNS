/* Copyright (c) 2007-2012 Sam Trenholme
 * IPv6 code contributed by Jean-Jacques Sarton in 2007
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

#include "DwSocket.h"
#include "DwTcpSocket.h"
#include "DwDnsStr.h"
#include <signal.h>
#include <errno.h>

/* One parameter that may eventually become a dwood2rc parameter */
#define TCP_BUFFERSIZE 1024

/* Mararc parameters that are set in DwMararc.c */
extern dw_str *key_s[];
extern dw_str *key_d[];
extern int32_t key_n[];

/* Parameters set in DwSys.c */
extern int64_t the_time;
extern dwr_rg *rng_seed;

/* List of addresses we will bind to */
extern ip_addr_T bind_address[];
extern ip_addr_T upstream_address[];

/* Some global variables */
extern int max_tcp_procs;
extern int timeout_seconds;
extern int timeout_seconds_tcp;
extern int dns_port;
extern int upstream_port;
extern int num_retries;

tcp_pend_T *tcp_pend;
SOCKET tcp_b_local[DW_MAXIPS + 1]; /* Local sockets */

/* The following is needed because Winsock's "make this socket non-blocking"
 * uses a pointer to a number as one of its arguments */
#ifdef MINGW
extern u_long dont_block;
extern void windows_socket_start();
#endif /* MINGW */

/* The upstream server we will connect to (round robin rotated) */

/* Allocate the memory for the list of the open remote TCP connections.
 * This memory is never freed once allocated, because this data is always
 * used by the program */
void malloc_tcp_pend() {
        tcp_pend = dw_malloc((max_tcp_procs + 1) * sizeof(tcp_pend_T));
        if(tcp_pend == 0) {
                dw_alog_3strings("Fatal: Could not allocate tcp_pend","","");
                exit(1);
        }
}

/* Initialize the values of all the open remote TCP connections */
void init_tcp_b_pend() {
        int a = 0;
        for(a = 0; a < max_tcp_procs; a++) {
                init_tcp_pend(a);
        }
}

/* TCP bind to all IP addresses we are to bind to and return the number of
 * IP addresses we got */
int bind_all_tcp() {
        int a = 0;
        int count = 0;
        if(key_n[DWM_N_tcp_listen] != 1) {
                return 0;
        }
        for(a = 0; a < DW_MAXIPS; a++) {
                if(bind_address[a].len != 0) {
                        tcp_b_local[a] = do_bind(&bind_address[a],SOCK_STREAM);
                        if(tcp_b_local[a] != -1) {
                                count++;
                        } else {
                                return -1;
                        }
                } else {
                        tcp_b_local[a] = -1;
                }
        }
        return count;
}

/* Find a free pending TCP connection to use; return -1 if
 * there isn't one (we're overloaded) */
int32_t find_free_tcp_pend() {
        int32_t a = 0;
        for(a = 0; a < max_tcp_procs; a++) {
                if(tcp_pend[a].local == INVALID_SOCKET) {
                        return a;
                }
        }
        return -1; /* None available (we're overloaded) */
}

/* Set up a TCP server that we will use to connect to a remote host */
SOCKET setup_tcp_server(sockaddr_all_T *server, dw_str *query, int b) {
        SOCKET remote = INVALID_SOCKET;
        ip_addr_T rem_ip = {0,{0,0},0,0};

        rem_ip = get_upstream_ip(query,b);
        if(rem_ip.glueless != 0) {
                dw_destroy(rem_ip.glueless);
        }
        if(rem_ip.len == 4) {
                server->V4.sin_family = AF_INET;
                server->V4.sin_port = htons(upstream_port);
                memcpy(&(server->V4.sin_addr),rem_ip.ip,4);
                remote = socket(AF_INET,SOCK_STREAM,0);
#ifdef IPV6
        } else if(rem_ip.len == 16) {
                server->V6.sin6_family = AF_INET6;
                server->V6.sin6_port = htons(upstream_port);
                memcpy(&(server->V6.sin6_addr),rem_ip.ip,16);
                remote = socket(AF_INET6,SOCK_STREAM,0);
#endif /* IPV6 */
        } else {
                return INVALID_SOCKET;
        }
        return remote;
}

/* Given a tcp socket s, accept the connection on that socket, then
 * prepare things so we can get <len><DNS packet>, send the query in their
 * packet upstream, then send <len><DNS reply> back to the TCP client
 */
void local_tcp_accept(SOCKET s) {
        sockaddr_all_T client;
        SOCKET local = 0;
        socklen_t len = sizeof(struct sockaddr_in);
        int b = 0;
        ip_addr_T from_ip;

        b = find_free_tcp_pend();
        if(b == -1) { /* Out of active TCP connections */
                return;
        }

        len = sizeof(client);
        local = accept(s,(struct sockaddr *)&client,&len);
        make_socket_nonblock(local);

        if(local == INVALID_SOCKET) { /* accept() error */
                return;
        }

        /* This is where we do ip-based packet rejection */
        get_from_ip_port(&from_ip,&client);
        if(check_ip_acl(&from_ip) != 1) {
                closesocket(local);
                return;
        }

        /* At this point, we want to get the 2-byte
         * length of the DNS packet, followed by getting the DNS packet;
         * we then want to be able to send UDP queries upstream to get
         * the information we want, then we went to send the reply back
         * over TCP */
        init_tcp_pend(b);
        tcp_pend[b].buffer = dw_malloc(3); /* To put the two bytes we want */
        if(tcp_pend[b].buffer == 0) {
                closesocket(local);
                reset_tcp_pend(b);
                return;
        }
        tcp_pend[b].local = local;
        tcp_pend[b].wanted = 2; /* We want to get the two-byte DNS length
                                 * header from the client */
        tcp_pend[b].die = get_time() + ((int64_t)timeout_seconds_tcp << 8);
}

/* For a given pending TCP connection, see if we have all the bytes we
 * want.  If we don't, try to get the data we want */
void tcp_get_wanted(int b) {
        char *buffer = 0;
        ssize_t len = 0;
        int toget = 0;
        toget = tcp_pend[b].wanted - tcp_pend[b].got;
        if(toget > 0 && tcp_pend[b].state == 0) {
                buffer = dw_malloc(toget + 1);
                if(buffer == 0) {
                        return;
                }
                len = recv(tcp_pend[b].local,buffer,toget,MSG_DONTWAIT);
                /* Add the bytes we get to the end of the buffer of wanted
                 * bytes */
                if(len > toget || len < 0) {
                        free(buffer);
                        return;
                }
                memcpy(tcp_pend[b].buffer + tcp_pend[b].got, buffer, len);
                tcp_pend[b].got += len;
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
                free(buffer);
        }
}

/* For a given TCP connection, if we have all the bytes we want, do the
 * next thing */
void tcp_process_data(int b) {
        int32_t wanted = 0;
        if(tcp_pend[b].wanted != tcp_pend[b].got || tcp_pend[b].buffer == 0
           || tcp_pend[b].state != 0) {
                return;
        }
        if(tcp_pend[b].wanted == 2) { /* If we wanted the length of the DNS
                                       * packet */
                /* Based on the length of the DNS packet wanted, we next
                 * try to get the DNS packet */
                tcp_pend[b].got = 0;
                wanted = tcp_pend[b].buffer[0];
                wanted <<= 8;
                wanted |= tcp_pend[b].buffer[1];
                free(tcp_pend[b].buffer);
                tcp_pend[b].buffer = 0;
                if(wanted < 12) {
                        closesocket(tcp_pend[b].local);
                        reset_tcp_pend(b);
                        return;
                }
                tcp_pend[b].wanted = wanted;
                tcp_pend[b].buffer = dw_malloc(wanted + 1);
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
        } else if(tcp_pend[b].wanted >= 12) {
                tcp_to_udp(b);
        }

}

/* Convert a TCP packet on a connection in to a reply we either get from
 * the cache or send upstream via UDP */
void tcp_to_udp(int b) {
        int32_t local_id = -1;
        dw_str *query = 0, *orig_query = 0;

        local_id = get_dns_qid((void *)tcp_pend[b].buffer, tcp_pend[b].wanted,
                        2);
        if(local_id == -1) {
                closesocket(tcp_pend[b].local);
                reset_tcp_pend(b);
                return;
        }

        /* See if the data is cached */
        query = dw_get_dname_type((void *)tcp_pend[b].buffer,12,
                tcp_pend[b].wanted);
        if(query == 0) {
                closesocket(tcp_pend[b].local);
                reset_tcp_pend(b);
                return;
        }
        orig_query = dw_copy(query);
        dwc_lower_case(query);

        if(get_reply_from_cache(query,0,0,local_id,0,b,orig_query,0) != 1) {
                /* If not cached, make the buffer a UDP connection upstream */
                forward_local_udp_packet(1,local_id,0,0,
                        (void *)tcp_pend[b].buffer,tcp_pend[b].wanted,b,
                                orig_query);
                tcp_pend[b].state = 1; /* Awaiting UDP reply */

                /* "<< 10" instead of "<< 8" because we need more time to
                 * get a reply upstream */
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 10);
        }

        dw_destroy(query);
        dw_destroy(orig_query);
}

/* Called from the "UDP" code, this tells Deadwood to buffer a TCP
 * packet to send back to the client */
void tcp_return_reply(int b, char *packet, int len) {
        if(tcp_pend[b].buffer != 0) {
                free(tcp_pend[b].buffer);
                tcp_pend[b].buffer = 0;
        }
        tcp_pend[b].state = 2; /* Send TCP reply back to client */
        tcp_pend[b].buffer = dw_malloc(len + 3);
        /* 2-byte length header */
        tcp_pend[b].buffer[0] = ((len & 0xff00) >> 8);
        tcp_pend[b].buffer[1] = (len & 0xff);
        memcpy(tcp_pend[b].buffer + 2, packet, len);
        tcp_pend[b].wanted = len + 2;
        tcp_pend[b].got = 0;
        tcp_pend[b].die = get_time() + ((int64_t)timeout_seconds_tcp << 8);
}

/* This code sends back buffered data to the client who sent us the original
 * TCP request */
void tcp_send_wanted(int b) {
        ssize_t len = 0;
        int tosend = 0;
        if(tcp_pend[b].state != 2) { /* Data to return to client */
                return;
        }
        tosend = tcp_pend[b].wanted - tcp_pend[b].got;
        if(tosend > 0 && tcp_pend[b].state == 2) {
                len = send(tcp_pend[b].local,tcp_pend[b].buffer +
                           tcp_pend[b].got,tosend,MSG_DONTWAIT);
                tcp_pend[b].got += len;
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
        } else {
                closesocket(tcp_pend[b].local);
                reset_tcp_pend(b);
        }
}

/* Create a DNS query packet, given a raw DNS query, as a dw_string object */
dw_str *make_dns_query_packet(dw_str *query, int id, int is_upstream) {
        dw_str *out = 0;

        /* Convert the query in to a DNS packet to send */
        /* 0x0180: QR = 0; Opcode = 0; AA = 0; TC = 0; RD = 1; RA = 1;
         *         Z = 0; RCODE = 0 ; 0x0080: Same but RD = 0 */
        if(is_upstream == 1) {
                out = make_dns_header(id,0x0180,0,0,0); /* Header */
        } else {
                out = make_dns_header(id,0x0080,0,0,0); /* Header */
        }
        if(out == 0) {
                goto catch_make_dns_query_packet;
        }
        if(dw_append(query,out) == -1) /* Question */ {
                goto catch_make_dns_query_packet;
        }
        if(dw_put_u16(out,1,-1) == -1) /* "class" (internet) */ {
                goto catch_make_dns_query_packet;
        }

        return out;

catch_make_dns_query_packet:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* If we get a "truncated" UDP DNS packet upstream, and have connected via
 * TCP to make our original DNS query, connect via TCP to the upstream
 * server to try and get the non-truncated reply */
void tcp_truncated_retry(int b, dw_str *query, int id, int udp_id, int is_up) {
        dw_str *tmp = 0;
        sockaddr_all_T server;
        socklen_t len = sizeof(struct sockaddr_in);

        if(tcp_pend[b].buffer != 0) {
                free(tcp_pend[b].buffer);
                tcp_pend[b].buffer = 0;
        }

        /* Prepare packet to send */
        tmp = make_dns_query_packet(query,id,is_up);
        if(tmp == 0) {
                goto catch_tcp_truncated_retry;
        }
        tcp_pend[b].buffer = dw_malloc(tmp->len + 3);
        if(tcp_pend[b].buffer == 0) {
                goto catch_tcp_truncated_retry;
        }
        tcp_pend[b].buffer[0] = (tmp->len & 0xff00) >> 8; /* Header byte 1 */
        tcp_pend[b].buffer[1] = tmp->len & 0xff; /* Header byte 2 */
        memcpy(tcp_pend[b].buffer + 2, tmp->str, tmp->len); /* DNS query */
        tcp_pend[b].state = 3; /* Send buffer upstream */
        tcp_pend[b].got = 0; /* No bytes sent */
        tcp_pend[b].wanted = tmp->len + 2; /* Send entire packet */

        /* Connect to upstream server over TCP */
        tcp_pend[b].upstream = setup_tcp_server(&server,query,udp_id);
        if(tcp_pend[b].upstream == INVALID_SOCKET) {
                goto catch_tcp_truncated_retry;
        }
        make_socket_nonblock(tcp_pend[b].upstream);
#ifdef IPV6
        if (server.Family == AF_INET6)
                len = sizeof(struct sockaddr_in6);
#endif /* IPV6 */
        if(connect(tcp_pend[b].upstream,(struct sockaddr *)&server,len) == -1
           && SCKT_ERR != EINPROGRESS) {
                closesocket(tcp_pend[b].upstream);
                goto catch_tcp_truncated_retry;
        }

        /* Clean-up */
        dw_destroy(tmp);
        return;

catch_tcp_truncated_retry:
        if(tmp != 0) {
                dw_destroy(tmp);
        }
        closesocket(tcp_pend[b].local);
        reset_tcp_pend(b);
}

/* Send data via TCP to upstream DNS server */
void tcp_upstream_send(int b) {
        ssize_t len = 0;

        if(tcp_pend[b].state != 3) {
                return;
        }

        if(tcp_pend[b].wanted < tcp_pend[b].got) {
                closesocket(tcp_pend[b].local);
                closesocket(tcp_pend[b].upstream);
                reset_tcp_pend(b);
        }

        len = send(tcp_pend[b].upstream,tcp_pend[b].buffer + tcp_pend[b].got,
                   tcp_pend[b].wanted - tcp_pend[b].got,MSG_DONTWAIT);

        if(len == -1) { /* Nothing sent, try later */
                return;
        }

        tcp_pend[b].got += len;
        tcp_pend[b].die = get_time() + ((int64_t)timeout_seconds << 8);
        if(tcp_pend[b].got >= tcp_pend[b].wanted) { /* All sent, get ready
                                                     * for reply */
                free(tcp_pend[b].buffer);
                tcp_pend[b].buffer = 0;
                tcp_pend[b].state = 4; /* Get packet length from upstream */
        }
}

/* Prepare things to get the length upstream */
void tcp_prepare_upstream_len(int b) {
        if(tcp_pend[b].state != 4) {
                return;
        }
        tcp_pend[b].buffer = dw_malloc(3);
        if(tcp_pend[b].buffer == 0) {
                closesocket(tcp_pend[b].local);
                closesocket(tcp_pend[b].upstream);
                reset_tcp_pend(b);
        }
        tcp_pend[b].wanted = 2;
        tcp_pend[b].got = 0;
        tcp_pend[b].state = 5; /* Getting length from upstream */
}

/* Get the two-byte length packet from upstream and allocate memory
 * to store the up-and-coming packet */
void tcp_get_upstream_len(int b) {
        int32_t wanted = 0;
        int32_t toget = 0;
        ssize_t len = 0;

        if(tcp_pend[b].state != 5) {
                return;
        }
        toget = tcp_pend[b].wanted - tcp_pend[b].got;
        if(toget > 0) {
                len = recv(tcp_pend[b].upstream,
                                tcp_pend[b].buffer + tcp_pend[b].got,
                                toget, MSG_DONTWAIT);
                if(len <= 0) {
                        return;
                }
                tcp_pend[b].got += len;
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
        } else if(toget == 0) {
                wanted = tcp_pend[b].buffer[0] & 0xff;
                wanted <<= 8;
                wanted |= tcp_pend[b].buffer[1] & 0xff;
                free(tcp_pend[b].buffer);
                tcp_pend[b].buffer = 0;
                tcp_pend[b].wanted = wanted;
                tcp_pend[b].buffer = dw_malloc(wanted + 3);
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
                tcp_pend[b].state = 6;
                tcp_pend[b].buffer[0] = (wanted & 0xff00) >> 8;
                tcp_pend[b].buffer[1] = (wanted & 0xff);
                tcp_pend[b].got = 0;
        }
}

/* Forward data from upstream DNS server locally; nearly identical to
 * Deadwood 2.3's tcp_local2remote */
void tcp_downstream_forward(int b) {
        ssize_t len = 0;
        ssize_t actual = 0;

        if(tcp_pend[b].state != 6) {
                return;
        }

        if(tcp_pend[b].got >= tcp_pend[b].wanted ||
           tcp_pend[b].buffer == 0 ||
           tcp_pend[b].sent >= tcp_pend[b].wanted + 2) {
                closesocket(tcp_pend[b].local);
                closesocket(tcp_pend[b].upstream);
                reset_tcp_pend(b);
                return;
        }

        /* The "2" you see is the 2-byte length header */
        len = recv(tcp_pend[b].upstream,
                tcp_pend[b].buffer + 2 + tcp_pend[b].got,
                tcp_pend[b].wanted - tcp_pend[b].got,MSG_DONTWAIT);

        if(len != (tcp_pend[b].wanted - tcp_pend[b].got)) {
                if(len <= 0) {
                        return; /* Try again later */
                } else {
                        tcp_pend[b].die = get_time() +
                                ((int64_t)timeout_seconds_tcp << 8);
                }
        }

        tcp_pend[b].got += len;

        /* Again, the '2' is the 2-byte length header */
        actual = send(tcp_pend[b].local,tcp_pend[b].buffer + tcp_pend[b].sent,
                        tcp_pend[b].got - tcp_pend[b].sent + 2,
                        MSG_DONTWAIT);

        if(actual <= 0) {
                return;
        } else if(actual != len) { /* Partial sends not supported */
                tcp_pend[b].die = get_time() +
                        ((int64_t)timeout_seconds_tcp << 8);
                tcp_pend[b].sent += actual;
                return;
        } else if(actual == len && tcp_pend[b].wanted == tcp_pend[b].got) {
                /* All data sent, success */
                closesocket(tcp_pend[b].local);
                closesocket(tcp_pend[b].upstream);
                reset_tcp_pend(b);
                return;
        }

        tcp_pend[b].sent += actual;

}

/* Handle all TCP connections with data pending to be sent */
void tcp_handle_all(int b) {
        if(key_n[DWM_N_tcp_listen] == 1) {
                tcp_get_wanted(b);
                tcp_process_data(b);
                tcp_send_wanted(b);
                tcp_upstream_send(b);
                tcp_prepare_upstream_len(b);
                tcp_get_upstream_len(b);
                tcp_downstream_forward(b);
        }
}

/* Disconnect idle TCP connections */
void kill_tcp_expired() {
        int a = 0;
        for(a = 0; a < max_tcp_procs; a++) {
                if(tcp_pend[a].die > 0 && tcp_pend[a].die < get_time()) {
                        closesocket(tcp_pend[a].local);
                        reset_tcp_pend(a);
                }
        }
}

/* Process any pending connections which select() caught */
void tcp_process_results(int a, fd_set *rx_fd) {
        int b = 0, z = 0;

        /* Find the pending connection */
        while(a > 0 && z < 10000) {
                /* Handle new connections */
                for(b = 0; b < DW_MAXIPS; b++) {
                        if(tcp_b_local[b] != INVALID_SOCKET &&
                           FD_ISSET(tcp_b_local[b],rx_fd)) {
                                local_tcp_accept(tcp_b_local[b]);
                                a--;
                                if(a <= 0) {
                                        return;
                                }
                        }
                }
                z++;
        }
}

