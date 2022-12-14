/* Copyright (c) 2007-2022 Sam Trenholme and others
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
#include "DwCompress.h"
#include "DwDnsStr.h"
#include "DwRecurse.h"
#include "DwBlockHash.h"

/* Mararc parameters that are set in DwMararc.c */
extern dw_str *key_s[];
extern dw_str *key_d[];
extern int32_t key_n[];

/* Parameters set in DwSys.c */
extern int64_t the_time;
extern dwr_rg *rng_seed;
extern dw_hash *cache;
extern blockHash *blocked_hosts_hash;

/* List of addresses we will bind to */
extern ip_addr_T bind_address[];
extern ip_addr_T upstream_address[];

/* List of active sockets */
extern SOCKET b_local[];
extern SOCKET *b_remote;

/* The list of pending remote connections */
extern remote_T *rem;

/* The list of active in-flight connections */
dw_hash *inflight;

/* The numeric mararc parameters */
extern int_fast32_t maxprocs;
extern int timeout_seconds;
extern int dns_port;
extern int upstream_port;
extern int handle_overload;
extern int resurrections;
extern int min_bind;
extern int num_ports;
extern int num_retries;
extern int_fast32_t max_ttl;
extern int_fast32_t min_ttl;
extern int rfc8482;

/* Other mararc parameters */
extern dwd_dict *blocklist_dict;
#ifndef MINGW
extern in_addr_t global_source_ip4;
#else
extern u_long global_source_ip4;
#endif

#ifdef MINGW
/* Needed for the Windows way of making a socket non-blocking */
extern u_long dont_block;
#endif /*MINGW*/

/* Initialize the inflight hash */
void init_inflight_hash() {
        inflight = 0;
        if(key_n[DWM_N_max_inflights] < 2) {
                return; /* No inflight merge desired */
        }
        inflight = dwh_hash_init(key_n[DWM_N_maxprocs] + 10);
}

/* The upstream server we will connect to (round robin rotated) */

/* Bind to all IP addresses we are to bind to and return the number of
 * IP addresses we got or INVALID_SOCKET on error */
int bind_all_udp() {
        int a = 0;
        int count = 0;
        for(a = 0; a < DW_MAXIPS; a++) {
                if(bind_address[a].len != 0) {
                        b_local[a] = do_bind(&bind_address[a],SOCK_DGRAM);
                        if(b_local[a] != INVALID_SOCKET) {
                                count++;
                        }
                } else {
                        b_local[a] = INVALID_SOCKET;
                }
        }
        return count;
}

/* Create a sockaddr_in that will be bound to a given port; this is
 * used by the code that binds to a randomly chosen port */
void setup_bind(sockaddr_all_T *dns_udp, uint16_t port, int len) {
        if(dns_udp == 0) {
                return;
        }
        memset(dns_udp,0,sizeof(*dns_udp));
        if(len == 4) {
                dns_udp->V4.sin_family = AF_INET;
                dns_udp->V4.sin_addr.s_addr = global_source_ip4;
                dns_udp->V4.sin_port = htons(port);
#ifndef NOIP6
        } else if(len == 16) {
                dns_udp->V6.sin6_family = AF_INET6;
                dns_udp->V6.sin6_addr = in6addr_any;
                dns_udp->V6.sin6_port = htons(port);
#endif
        } else { /* Bad ip */
                return;
        }
        return;
}

/* This tries to bind to a random port up to 10 times; should it fail
 * after 10 times, it returns a -1 */
int do_random_bind(SOCKET s, int len) {
        sockaddr_all_T dns_udp;
        int a = 0;
        int success = 0;
        socklen_t len_inet = sizeof(struct sockaddr_in);

        for(a = 0; a < 10; a++) {
                /* Set up random source port to bind to */
                setup_bind(&dns_udp,
                           min_bind + (dwr_rng(rng_seed) & num_ports), len);
#ifndef NOIP6
                if (dns_udp.Family == AF_INET6)
                        len_inet = sizeof(struct sockaddr_in6);
#endif
                /* Try to bind to that port */
                if(bind(s, (struct sockaddr *)&dns_udp,
                   len_inet) != -1) {
                        success = 1;
                        break;
                }
        }
        if(success == 0) { /* Bind to random port failed */
                return -1;
        }
        return 1;
}

/* Create a sockaddr_in that will connect to a given address; -1 on fail;
 * this is used by the code that "connects" to the remote DNS server */
SOCKET setup_server(sockaddr_all_T *server, ip_addr_T *addr) {
        int s = INVALID_SOCKET;
        if(server == 0 || addr == 0) {
                return INVALID_SOCKET;
        }

        memset(server,0,sizeof(*server));
        if ( addr->len == 4 ) {
                server->V4.sin_family = AF_INET;
                server->V4.sin_port = htons(upstream_port);
                memcpy(&(server->V4.sin_addr),addr->ip,4);
                s = socket(AF_INET,SOCK_DGRAM,0);
#ifndef NOIP6
        } else if ( addr->len == 16 ) {
                server->V6.sin6_family = AF_INET6;
                server->V6.sin6_port = htons(upstream_port);
                memcpy(&(server->V6.sin6_addr),addr->ip,16);
                s = socket(AF_INET6,SOCK_DGRAM,0);
#endif
        } else {
                return INVALID_SOCKET;
        }
        return s;
}

/* Given a remote number, a C-string with the packet to send them, and
 * the length of that string, make a connection to a remote server */
int make_remote_connection(int32_t n, unsigned char *packet, int len,
     dw_str *query, SOCKET x_socket_num) {
        sockaddr_all_T server;
        SOCKET s = 0;
        int_fast32_t rnum = -1;
        ip_addr_T addr = {0,{0,0},0,0};
        int counter = 0;
        socklen_t inet_len = sizeof(struct sockaddr_in);

        if(rem[n].socket != x_socket_num || /* Already used (sanity check) */
           rem[n].recurse_depth > 83) { /* Infinite recursion protection */
                return -1;
        }

        rem[n].recurse_depth++;

        /* Get a random query ID to send to the remote server */
        rnum = set_dns_qid(packet,len,dwr_rng(rng_seed));
        if(rnum == -1) {
                return -1;
        }

        /* Get IP of remote server and open a socket to them */
        for(counter = 0; counter < 7; counter++) { /* Don't stop on bad IP */
                addr = get_upstream_ip(query,n);
                /* Make sure RD is appropriately set or clear */
                if(rem[n].is_upstream == 1) {
                        packet[2] |= 0x01; /* Set RD */
                } else {
                        packet[2] &= 0xfe; /* Clear RD */
                }
                if(addr.len > 0) {
                        break;
                }
        }
        dw_log_ip("Making connection to IP",&addr,128);
        if(addr.len == 0) { /* Failed to get upstream IP */
                return -1;
        } else if(addr.len == 4 || addr.len == 16) { /* IPv4/IPv6 IP */
                s = setup_server(&server,&addr);
        } else if(addr.glueless != 0) { /* Glueless NS referral */
                dwx_do_ns_glueless(addr,n);
                return 2;
        }
        if(s == INVALID_SOCKET) { /* Failed to make socket */
                return -1;
        }

#ifndef NOIP6
        if (server.Family == AF_INET6)
                 inet_len = sizeof(struct sockaddr_in6);
#endif

        make_socket_nonblock(s); /* Linux kernel bug */

        /* Bind to source port; "connect" to remote server; send packet */
        if ((do_random_bind(s,addr.len) == -1) ||
            (connect(s, (struct sockaddr *)&server, inet_len) == -1) ||
            (send(s,packet,len,0) < 0)) {
                closesocket(s);
                return -1;
        }

        /* OK, now note the pending connection */
        b_remote[n] = s;
        if(rem[n].socket != INVALID_SOCKET) {
                closesocket(rem[n].socket);
        }
        rem[n].socket = s;
        rem[n].remote_id = rnum;
        return 1;
}

/* Send a server failure back to the client when the server is overloaded.
 * This is a bit of a hack; we just take the client's DNS packet, and send
 * it as-is with QR set to 1 (a response) and RCODE set to 2 (server
 * failure) */
void send_server_fail(sockaddr_all_T *client,unsigned char *a, int len,
                      SOCKET sock, int tcp_num) {
        socklen_t c_len = sizeof(struct sockaddr_in);

        if(len < 12) {
                return;
        }

#ifndef NOIP6
        if (client->Family == AF_INET6)
                c_len = sizeof(struct sockaddr_in6);
#endif
        a[2] |= 0x80; /* Set QR (reply, not question) */
        a[3] &= 0xf0; a[3] |= 0x02; /* Set RCODE */

        if(tcp_num == -1) {
                sendto(sock,(void *)a,len,0,(struct sockaddr *)client, c_len);
        }

}

/* See if there is a "inflight" query already handling the query we
 * are processing.  If not (or if we don't merge inflights), return -1.
 * If so, return the UDP connection number of the already-inflight query
 */

int find_inflight_query(unsigned char *a, int len) {
        dw_str *query = 0, *answer = 0;
        int ret = -1;

        if(len < 12 || a == 0 || key_n[DWM_N_max_inflights] < 2) {
                goto catch_find_inflight_query;
        }

        query = dw_get_dname_type(a,12,len);
        dwc_lower_case(query);
        if(query == 0) {
                goto catch_find_inflight_query;
        }

        answer = dwh_get(inflight, query, 0, 1);
        if(answer == 0) { /* Nothing in-flight */
                goto catch_find_inflight_query;
        }

        ret = dw_fetch_u16(answer,0);

        if(rem[ret].socket == INVALID_SOCKET) { /* Not valid query */
                ret = -1;
                goto catch_find_inflight_query;
        }

        if(dw_issame(query,rem[ret].query) != 1) { /* Actually not same */
                dwh_zap(inflight,query, 0, 1); /* Remove corrupt data */
                ret = -1;
        }

catch_find_inflight_query:
        if(query != 0) {
                dw_destroy(query);
        }
        if(answer != 0) {
                dw_destroy(answer);
        }
        return ret;
}

void zap_inflight(dw_str *query) {
        if(key_n[DWM_N_max_inflights] > 1) {
                dwh_zap(inflight,query, 0, 1);
        }
}

/* Make a new UDP connection on remote pending connection b */
int make_new_udp_connect(int b, unsigned char *a, int len, int num_alloc) {
        dw_str *answer = 0, *check = 0;
        int counter = 0, z = 0;

        /* Make a new remote connection */
        if(rem[b].socket != INVALID_SOCKET) { /* Sanity check */
                return -1;
        }
        rem[b].query = dw_get_dname_type(a,12,len);
        dwc_lower_case(rem[b].query);
        rem[b].local = dw_malloc(num_alloc * sizeof(local_T *));
        if(rem[b].local == 0) {
                return -1;
        }
        z = make_remote_connection(b,a,len,rem[b].query,INVALID_SOCKET);
        if(z != 1) {
                return z;
        }

        for(counter = 0; counter < num_alloc; counter++) {
                rem[b].local[counter] = 0;
        }
        rem[b].num_locals = 1;
        if(key_n[DWM_N_max_inflights] > 1) {
                answer = dw_create(3);
                check = dwh_get(inflight, rem[b].query, 0, 1);
                if(check == 0) { /* Mark query in inflight hash */
                        dw_put_u16(answer,b,0);
                        dwh_add(inflight, rem[b].query, answer, 120, 1);
                } else { /* This query is already inflight */
                        dw_destroy(check);
                }
                dw_destroy(answer);
        }
        return 1;
}

/* Send a local DNS request to the upstream (remote) server; this
 * requires a few parameters having to do with the connection
 * to be passed to the function. */
int forward_local_udp_packet(SOCKET sock, int32_t local_id,
     ip_addr_T *from_ip, uint16_t from_port, unsigned char *a,
     int len, int tcp_num, dw_str *orig_query) {
        int32_t b = 0;
        int num_alloc = 0;
        ip_addr_T null_addr = {0,{0,0},0,0};

        num_alloc = key_n[DWM_N_max_inflights];
        if(num_alloc < 1) {
                num_alloc = 1;
        } else if(num_alloc > 32000) {
                num_alloc = 32000;
        }
        num_alloc++; /* Stop off-by-one attacks */

        b = find_inflight_query(a,len);
        if(b == -1) {
                b = find_free_remote();
                if(b == -1) { /* We're out of remote pending connections */
                        return -1;
                } else { /* Create new connection */
                        reset_rem(b);
                        if(make_new_udp_connect(b,a,len,num_alloc) == 2) {
                                return 0;
                        }
                }
        } else { /* Add new local to already inflight connection */
                if(rem[b].num_locals >= num_alloc - 2) {
                        return -1; /* No more inflights for this query */
                }
                rem[b].num_locals++;
#ifdef INFLIGHT_VERBOSE
                printf("Connection %d has %d locals\n",b,rem[b].num_locals);
                fflush(stdout);
#endif /* INFLIGHT_VERBOSE */
        }

        if(rem[b].num_locals == 0) {
                reset_rem(b);
                return -1;
        }
        rem[b].local[rem[b].num_locals - 1] = dw_malloc(sizeof(local_T));
        if(rem[b].local[rem[b].num_locals - 1] != 0) {
                rem[b].local[rem[b].num_locals - 1]->orig_query = 0;
                rem[b].local[rem[b].num_locals - 1]->action = 0;
        }
        if(rem[b].socket == INVALID_SOCKET ||
           rem[b].local[rem[b].num_locals - 1] == 0) {
                reset_rem(b);
                return -1;
        }
        rem[b].local[rem[b].num_locals - 1]->from_socket = sock;
        rem[b].local[rem[b].num_locals - 1]->tcp_num = tcp_num;
        if(from_ip != 0) {
                rem[b].local[rem[b].num_locals - 1]->ip = *from_ip;
        } else {
                rem[b].local[rem[b].num_locals - 1]->ip = null_addr;
        }
        rem[b].local[rem[b].num_locals - 1]->port = from_port;
        rem[b].local[rem[b].num_locals - 1]->local_id = local_id;
        rem[b].local[rem[b].num_locals - 1]->glueless_type = 0;
        rem[b].local[rem[b].num_locals - 1]->glueless_conn = -1;
        rem[b].local[rem[b].num_locals - 1]->orig_query = dw_copy(orig_query);
        rem[b].die = get_time() + ((int64_t)timeout_seconds << 8);
        return 0;
}

/* Create a DNS header suitable for giving back to the client */
dw_str *make_dns_header(int32_t id, int16_t flags, int32_t ancount,
                        int32_t nscount, int32_t arcount) {
        dw_str *out = 0;

        if(id < 0 || ancount < 0 || nscount < 0 || arcount < 0) {
                return 0; /* Sanity check */
        }

        /* Destroyed after giving the client the reply */
        out = dw_create(515);

        /* Query ID; echo from client */
        if(dw_put_u16(out, id, -1) == -1) {
                goto catch_make_dns_header;
        }

        /* QR; Opcode; AA; TC; RD; RA; Z; RCODE */
        if(dw_put_u16(out, flags, -1) == -1) {
                goto catch_make_dns_header;
        }

        /* QDCOUNT = 1 */
        if(dw_put_u16(out,1,-1) == -1) {
                goto catch_make_dns_header;
        }

        /* And, finally, ANCOUNT, NSCOUNT, and ARCOUNT */
        if(dw_put_u16(out,ancount,-1) == -1 ||
           dw_put_u16(out,nscount,-1) == -1 ||
           dw_put_u16(out,arcount,-1) == -1) {
                goto catch_make_dns_header;
        }

        return out;

catch_make_dns_header:
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;
}

/* Given two dw_strings with the question and answer, make a DNS packet
 * we can give back to the client; this will multilate answer so be
 * careful */
dw_str *make_dns_packet(dw_str *question, dw_str *answer, int32_t id) {
        int32_t ancount = 0, nscount = 0, arcount = 0;
        int is_nxdomain = 0;
        dw_str *out = 0;

        is_nxdomain = dw_pop_u8(answer);
        if(is_nxdomain != TYPE_TRUNCATED &&
                        is_nxdomain != TYPE_TRUNCATED_NXDOMAIN) {
                arcount = dw_pop_u16(answer);
                nscount = dw_pop_u16(answer);
                ancount = dw_pop_u16(answer);
        }

        if(is_nxdomain == 0 || is_nxdomain == 2) {
                /* 0x8180: QR = 1; Opcode = 0; AA = 0; TC = 0; RD = 1; RA = 1;
                 * Z = 0; RCODE = 0 */
                out = make_dns_header(id,0x8180,ancount,nscount,arcount);
        } else if(is_nxdomain == 1) {
                /* Same header as before, but with RCODE of "name error" */
                out = make_dns_header(id,0x8183,ancount,nscount,arcount);
        } else if(is_nxdomain == TYPE_TRUNCATED) {
                /* Set TC to 1 */
                out = make_dns_header(id,0x8380,0,0,0);
        } else if(is_nxdomain == TYPE_TRUNCATED_NXDOMAIN) {
                /* TC 1; RCODE "name error" */
                out = make_dns_header(id,0x8383,0,0,0);
        } else {
                goto catch_make_dns_packet;
        }

        if(dw_append(question,out) == -1 ||
           dw_put_u16(out,1,-1) == -1 /* QCLASS: 1 */ ) {
                goto catch_make_dns_packet;
        }
        if(is_nxdomain != TYPE_TRUNCATED &&
                        is_nxdomain != TYPE_TRUNCATED_NXDOMAIN &&
                        dw_append(answer,out) == -1) {
                goto catch_make_dns_packet;
        }

        return out;

catch_make_dns_packet:
        if(out != 0) {
                dw_destroy(out);
                out = 0;
        }
        return 0;
}

/* See if a given reply is in the cache; if so, send them the reply
 * from the cache */
int get_reply_from_cache(dw_str *query, sockaddr_all_T *client,
                         SOCKET sock, int32_t id, int resurrect,
                         int tcp_num, dw_str *orig_query,
                         ip_addr_T *from_ip, unsigned char *orig_packet,
                         int orig_len) {
        dw_str *value = 0; /* Element in cache */
        dw_str *comp = 0; /* Compressed DNS packet */
        dw_str *packet = 0;
        socklen_t c_len = sizeof(struct sockaddr_in);
        int ret = -1, type = 0, cache_type = 0, blocklisted = 0;

        if(client == 0) {
                goto catch_get_reply_from_cache;
        }

#ifndef NOIP6
        if (client->Family == AF_INET6) {
               c_len = sizeof(struct sockaddr_in6);
        }
#endif

        dwc_lower_case(query);/* https://github.com/samboy/MaraDNS/issues/30 */
        dw_log_dwstr("Looking in cache for query ",query,100);
        type = dw_fetch_u16(query,-1);
        if(type == RR_MX && key_n[DWM_N_reject_mx] != 0) {
                dw_log_ip(
        "Attempt to get MX record (possible spam zombie) from IP",from_ip,3);
                return 1;
        } else if(type == RR_AAAA) { /* Blocklist affects both IPv4 and IPv6 */
                dw_str *value_ipv4 = 0; /* IPv4 record in cache (A record */
                if(dw_put_u16(query, RR_A, -3) == -1) {
                        goto catch_get_reply_from_cache;
                }
                value_ipv4 = dwh_get(cache,query,resurrect,1);
                if(value_ipv4 != 0) {
                        if(dw_fetch_u8(value_ipv4,-1) == TYPE_BLOCKLIST_ENTRY){
                                blocklisted = 1;
                        }
                        dw_destroy(value_ipv4);
                }
                if(dw_put_u16(query, RR_AAAA, -3) == -1) {
                        goto catch_get_reply_from_cache;
                }
        }

        if(blocklisted == 0) {
                dwc_process(cache,query,3); /* RR rotation, TTL aging, etc. */
                value = dwh_get(cache,query,resurrect,1);
                if(value == 0) {
                        dw_log_dwstr("Nothing found for ",query,100);
                        goto catch_get_reply_from_cache;
                }
                cache_type = dw_fetch_u8(value,-1);
        }
        if(cache_type == TYPE_BLOCKLIST_ENTRY || blocklisted == 1) {
                if(tcp_num != -1 || orig_packet == 0) {
                        ret = 2;
                        goto catch_get_reply_from_cache;
                }

                /* This is a copy paste from get_local_udp_packet */
                unsigned char *answer;
                answer = make_synth_not_there_answer(orig_packet,&orig_len,0);

                /* Flag this as an answer */
                answer[2] |= 0x80;

                /* Flag RA bit because, well, recursion is available */
                answer[3] |= 0x80;

                /* One "NS" record; no other records */
                answer[9] = 1;
                answer[6] = answer[7] = answer[8] = answer[10] = answer[11] =0;
                /* Copy over ID */
                sendto(sock,(void *)answer,
                                orig_len+40,0,(struct sockaddr *)client,
                                c_len);
                free(answer);
                /* END copy paste */
                ret = 1;
                goto catch_get_reply_from_cache;
        }
        if(cache_type != TYPE_TRUNCATED &&
                        cache_type != TYPE_TRUNCATED_NXDOMAIN) {
                comp = dwc_compress(query,value);
        } else {
                /* Immediately zap truncated from cache when fetched */
                dwh_zap(cache,query,0,1);
                if(client == 0) { /* DNS-over-TCP */
                        ret = 2;
                        goto catch_get_reply_from_cache;
                }
                comp = dw_copy(value);
        }

        if(comp == 0) {
                goto catch_get_reply_from_cache;
        }

        if(comp->len == 7) { /* Empty packet; workaround */
                dw_log_string("Warning: Removing empty packet from cache",11);
                dwh_zap(cache,query,0,1);
                goto catch_get_reply_from_cache;
        }

        dw_log_dwstr_str("Fetching ",query," from cache",100);
        packet = make_dns_packet(orig_query,comp,id);
        if(packet == 0) {
                goto catch_get_reply_from_cache;
        }

        if(tcp_num == -1) {
                sendto(sock,(void *)packet->str,packet->len,0,
                       (struct sockaddr *)client, c_len);
        } else if(key_n[DWM_N_tcp_listen] == 1) {
                tcp_return_reply(tcp_num,(void *)packet->str,packet->len);
        }

        ret = 1;

catch_get_reply_from_cache:
        if(value != 0) {
                dw_destroy(value);
        }
        if(packet != 0) {
                dw_destroy(packet);
        }
        if(comp != 0) {
                dw_destroy(comp);
        }
        return ret;
}

/* Given a connection we will send on, try and send the connection on.
   If we're unable to send the connection on, see if we have an
   expired element with the data we want. */
void try_forward_local_udp_packet(SOCKET sock, int32_t local_id,
     ip_addr_T *from_ip, uint16_t from_port, unsigned char *packet,
     int len, sockaddr_all_T *client,dw_str *query, int tcp_num,
     dw_str *orig_query) {

        unsigned char p0 = 0, p1 = 0, p2 = 0;

        if(packet == 0 || len < 12) { /* Sanity check */
                return;
        }
        p0 = packet[0];
        p1 = packet[1];
        p2 = packet[2];

        /* If not cached, get a reply that we will cache and send back to
         * the client */
        if(forward_local_udp_packet(sock,local_id,from_ip,from_port,
                                    packet,len,tcp_num,orig_query) != -1) {
                return; /* Success! */
        }

        /* OK, at this point it failed so we'll see if we get a
         * "resurrected" cache entry */
        if(resurrections == 1 &&
           get_reply_from_cache(query, client, sock, local_id, 1, tcp_num,
                        orig_query, from_ip, 0, 0) == 1) {
                dw_log_string("Resurrected from cache",11);
                return; /* Resurrected entry; we're done */
        }

        if(handle_overload == 1) {
                packet[0] = p0;
                packet[1] = p1;
                packet[2] = p2;
                send_server_fail(client,packet,len,sock,tcp_num);
        }
}

/* Get and process a local DNS request */
void get_local_udp_packet(SOCKET sock) {
        unsigned char packet[522];
        int len = 0;
        sockaddr_all_T client;
        socklen_t c_len = 0;
        ip_addr_T from_ip = {0,{0,0},0,0};
        uint16_t from_port = 0;
        int32_t local_id = -1;
        dw_str *query = 0, *orig_query = 0;
        int_fast32_t qtype = 0;
        int in_blocked_hosts_hash = 0;
#ifdef VALGRIND_NOERRORS
        memset(packet,0,522);
#endif /* VALGRIND_NOERRORS */

        c_len = sizeof(client);
        make_socket_nonblock(sock); /* Linux bug workaround */
        len = recvfrom(sock,(void *)packet,520,0,(struct sockaddr *)&client,
                       &c_len);

        if(len < 12) {
                goto catch_get_local_udp_packet;
        }

        from_port = get_from_ip_port(&from_ip,&client);

        if(check_ip_acl(&from_ip) != 1) { /* Drop unauthorized packets */
                goto catch_get_local_udp_packet;
        }

        local_id = get_dns_qid(packet, len, 2);
        if(local_id == -2) { /* Immediate NOTIMPL for EDNS requests w/ OPT */
#ifdef STRICT_RFC2671_COMPLIANCE
                packet[2] = 0x81; /* QR = 1; Op = 0; AA = 0; TC = 0; RD = 1 */
                packet[3] = 0x84; /* RA = 1; Z = 0; RCODE = "notimpl" (4) */
                sendto(sock,(void *)packet,len,0,(struct sockaddr *)&client,
                                c_len);
                goto catch_get_local_udp_packet;
#else /* STRICT_RFC2671_COMPLIANCE */
                query = dw_get_dname_type(packet,12,len);
                if(query == 0) {
                        goto catch_get_local_udp_packet;
                }
                len = query->len + 14;
                packet[11] = 0; /* We no longer have final question */
                dw_destroy(query);
                local_id = get_dns_qid(packet, len, 2);
#endif /* STRICT_RFC2671_COMPLIANCE */
        }
        if(local_id < 0 || len < 13) { /* Invalid remote packet */
                goto catch_get_local_udp_packet;
        }

        /* See if we have something in the cache; destroyed at end of
         * function */
        query = dw_get_dname_type(packet,12,len);
        qtype = dw_fetch_u16(query,-1);
        orig_query = dw_copy(query);
        dwc_lower_case(query);

        if(query != 0 && query->len > 2 && blocked_hosts_hash != 0) {
		if(DBH_BlockHasString(blocked_hosts_hash,query->str,
		   query->len-2) == 1) {
                	in_blocked_hosts_hash = 1;
                	dw_log_dwstr("DNS query in block hash: ",query,110); 
		} else {
			int label1 = 0, label2 = 0, label3 = 0;
			int point = 0;
			while(point < query->len - 2) {
				int len = *(query->str + point);
				if(len < 1 || len > 63) { break; }
				label3 = label2;
				label2 = label1;
				label1 = point;
				point = point + len + 1;
			}
			if(label1 > 0 && label1 < query->len-2 && 
			   DBH_BlockHasString(blocked_hosts_hash,
					query->str+label1,
					query->len-label1-2) == 1) {
				in_blocked_hosts_hash = 1;
                		dw_log_dwstr(
			    "DNS query in block hash (wildcard1): ",query,110); 
			} else if(label2 > 0 && label2 < query->len-2 &&
			   DBH_BlockHasString(blocked_hosts_hash,
					query->str+label2,
					query->len-label2-2) == 1) {
				in_blocked_hosts_hash = 1;
                		dw_log_dwstr(
			    "DNS query in block hash (wildcard2): ",query,110); 
			} else if(label3 > 0 && label3 < query->len-2 &&
                           DBH_BlockHasString(blocked_hosts_hash,
                                        query->str+label3,
                                        query->len-label3-2) == 1) {
                                in_blocked_hosts_hash = 1;
                		dw_log_dwstr(
			    "DNS query in block hash (wildcard3): ",query,110); 
			}
		}
        }

        /* Reject PTR or AAAA queries if not wanted; implement RFC8482 (ANY) */
        if((qtype == 28 /* AAAA */ && key_n[DWM_N_reject_aaaa] == 1) ||
           (qtype == 12 /* PTR */ && key_n[DWM_N_reject_ptr] == 1) ||
	   ((qtype == 255 || qtype == 13) && rfc8482 == 1) ||
           in_blocked_hosts_hash == 1) {
                unsigned char *answer;

		if(qtype == 255 || qtype == 13) { /* ANY or HINFO */
                	answer = make_synth_rfc8482_answer(packet,&len,0);
		} else {
                	answer = make_synth_not_there_answer(packet,&len,0);
		}

		if(answer == 0) {
                	goto catch_get_local_udp_packet;
		}

                /* Flag this as an answer */
                answer[2] |= 0x80;

                /* Flag RA bit because, well, recursion is available */
                answer[3] |= 0x80;

                /* One "NS" record; no other records */
                answer[9] = 1;
                answer[6] = answer[7] = answer[8] = answer[10] = answer[11] =0;
                /* Copy over ID */
                sendto(sock,(void *)answer,len+40,0,(struct sockaddr *)&client,
                                c_len);
                free(answer);
                goto catch_get_local_udp_packet;
        }

        dw_log_dwstr("Got DNS query for ",query,100); /* Log it */
        if(query == 0) {
                goto catch_get_local_udp_packet;
        }
        /* Is answer in cache? */
        if(get_reply_from_cache(query, &client, sock, local_id, 0, -1,
                        orig_query, &from_ip, packet, len) == 1) {
                goto catch_get_local_udp_packet; /* In cache; we're done */
        }
        if(dwx_cname_in_cache(orig_query, query, &client, &from_ip, local_id,
                        sock, from_port) == 1) { /* CNAME refer in cache? */
                goto catch_get_local_udp_packet;
        }

        /* Nothing in cache; lets try sending the packet upstream */
        try_forward_local_udp_packet(sock,local_id,&from_ip,from_port,
                        packet,len,&client,query,INVALID_SOCKET,
                        orig_query);

catch_get_local_udp_packet:
        if(query != 0) {
                dw_destroy(query);
                query = 0;
        }
        if(orig_query != 0) {
                dw_destroy(orig_query);
                query = 0;
        }
}

/* Forward a remote reply back to the client over UDP */
void forward_remote_reply(unsigned char *packet, size_t len, remote_T *r_ip,
                int local_num) {
        sockaddr_all_T client;
        socklen_t len_inet = 0;

        if(r_ip == 0) {
                return;
        }
        if(r_ip->local[local_num]->from_socket == INVALID_SOCKET ||
                        r_ip->local[local_num]->glueless_type != 0) {
                return;
        }
        memset(&client,0,sizeof(client));
        len_inet = sizeof(client);

        if (r_ip->local[local_num]->ip.len == 4) {
                client.V4.sin_family = AF_INET;
                client.V4.sin_port = htons(r_ip->local[local_num]->port);
                memcpy(&client.V4.sin_addr, r_ip->local[local_num]->ip.ip, 4);
                len_inet = sizeof(struct sockaddr_in);
#ifndef NOIP6
        } else if(r_ip->local[local_num]->ip.len == 16) {
                client.V6.sin6_family = AF_INET6;
                client.V6.sin6_port = htons(r_ip->local[local_num]->port);
                memcpy(&client.V6.sin6_addr, r_ip->local[local_num]->ip.ip,
                        16);
                len_inet = sizeof(struct sockaddr_in6);
#endif
        } else {
                return;
        }
        sendto(r_ip->local[local_num]->from_socket,(void *)packet,len,0,
               (struct sockaddr *)&client,len_inet);

        /* Sometimes, especially if we use DNS-over-TCP, we will have a case
         * where some local IPs have been handled and others haven't.
         * "forward_remote_reply" finishes up a local connection to UDP and
         * is only sent once, so we close the socket to make it invalid */
        r_ip->local[local_num]->from_socket = INVALID_SOCKET;
}

/* Add a reply we have received from the remote (upstream) DNS server to
 * the cache */
int cache_dns_reply(unsigned char *packet, int count, int b, int truncated) {
        int32_t ttl = 60;
        int32_t ancount = 0;
        int is_nxdomain = 0;
        dw_str *question = 0, *answer = 0;
        dw_str *decomp = 0;
        int ret = -1;

        question = dw_get_dname_type(packet,12,count);
        dwc_lower_case(question);
        dw_log_dwstr("Caching a reply for query ",question,1000);
        if((packet[3] & 0x0f) == 2) { /* Server FAIL */
                ret = -1; /* Bad return value; do not cache */
                goto catch_cache_dns_reply;
        } else if((packet[3] & 0x0f) == 3) { /* Name error/NXDOMAIN */
                is_nxdomain = 1;
        }
        if(truncated == 1) {
                is_nxdomain += 3;
                answer = dw_create(2);
                if(dw_put_u8(answer, is_nxdomain, 0) == -1) {
                        goto catch_cache_dns_reply;
                }
                dwh_add(cache,question,answer,7,1);
                ret = 1;
        } else {
                answer = dw_packet_to_cache(packet,count,is_nxdomain);
                decomp = dwc_decompress(question,answer);
                if(decomp == 0) {
                        goto catch_cache_dns_reply;
                }
                if(dwc_has_bad_ip(decomp,blocklist_dict)) {
                        ret = -2; /* Tell caller we need synth "not there" */
                        goto catch_cache_dns_reply;
                }
                ancount = dw_cachepacket_to_ancount(answer);
                if(ancount == 0) {
                        ancount = 32; /* Correct negative answer caching */
                }

                if(question == 0 || answer == 0 || ancount == -1) {
                        goto catch_cache_dns_reply;
                }

                ttl = dw_get_a_dnsttl(answer,0,31536000,ancount);
                if(ttl == -1 && decomp != 0 && decomp->len == 7) {
                        ttl = 30; /* Special case: Blank reply upstream */
                }
                if(ttl == -1) {
                        goto catch_cache_dns_reply;
                }
                if(ttl < 30) {
                        ttl = 30;
                }
                if(ttl > max_ttl) {
                        ttl = max_ttl;
                }
                if(ttl < min_ttl) {
                        ttl = min_ttl;
                }

                /* Routines in DwRecurse.c process the packet and let us know
                 * what kind of packet we got upstream (so we know how to
                 * continue)
                 */
                ret = dwx_cache_reply(cache,question,decomp,ttl,b);
        }

catch_cache_dns_reply:
        if(question != 0) {
                dw_destroy(question);
        }
        if(answer != 0) {
                dw_destroy(answer);
        }
        if(decomp != 0) {
                dw_destroy(decomp);
        }
        return ret;
}

/* Verify that a given DNS packet is good (The Query ID is correct, the
   query in the "question" section of the DNS header is good) */
int verify_dns_packet(int b, unsigned char *packet, int len) {
        int ret = 0;
        dw_str *question = 0;

        /* Make sure the ID we got is the same as the one we originally
         * sent them */
        if(get_dns_qid(packet,len,0) != rem[b].remote_id) {
                goto catch_verify_dns_packet;
        }

        question = dw_get_dname_type(packet,12,len);
        if(question == 0) {
                goto catch_verify_dns_packet;
        }

        dwc_lower_case(question); /* Case-insensitive comparison */
        if(dw_issame(question,rem[b].query) != 1) {
                goto catch_verify_dns_packet;
        }

        ret = 1;

catch_verify_dns_packet:
        if(question != 0) {
                dw_destroy(question);
                question = 0;
        }
        return ret;
}

/* Make the actual answer for a synthetic reply */
unsigned char *make_synth_answer(unsigned char *a, int *count,
                int type, unsigned char *synth, int slen) {
        unsigned char *answer = 0;
        int counter = 0;

        answer = dw_malloc(*count + slen + 3);
        if(answer == 0) {
                return 0;
        }

        if(type == 1) { /* Special case: Return just synth "not there" */
                for(counter = 0; counter < slen; counter++) {
                        answer[counter] = synth[counter];
                }
                return answer;
        }

        /* Copy the header they sent us to our reply */
        for(counter = 0; counter < 12 && counter < *count; counter++) {
                answer[counter] = a[counter];
        }

        /* Copy the question over to the reply */
        for(;counter < 520 && counter < *count; counter++) {
                if(a[counter] == 0) {
                        break; /* Quick and dirty "end of name"; yes, I
                                * check in dw_get_dname_type() to make sure
                                * there is no ASCII NULL in names */
                }
                answer[counter] = a[counter];
        }
        if(*count < counter + 5 || counter > 512) { /* Sanity check */
                free(answer);
                return 0;
        }

        /* Add the rest of the question */
        *count = counter + 5;
        for(;counter < *count; counter++) {
                answer[counter] = a[counter];
        }

        /* Add the SOA reply to the answer */
        for(counter = 0; counter < slen; counter++) {
                answer[*count + counter] = synth[counter];
        }

        /* Return the answer */
        return answer;
}

unsigned char *make_synth_not_there_answer(unsigned char *a, int *count,
                int type) {
        /* This is the answer for a "not there" reply */
        unsigned char not_there[41] =
        "\xc0\x0c" /* Name */
        "\0\x06" /* Type */
        "\0\x01" /* Class */
        "\0\0\0\0" /* TTL (don't cache) */
        "\0\x1c" /* RDLENGTH */
        "\x01\x7a\xc0\x0c" /* Origin */
        "\x01\x79\xc0\x0c" /* Email */
        "\0\0\0\x01\0\0\0\x01\0\0\0\x01\0\0\0\x01\0\0\0\x01" /* 5 numbers */;
	return make_synth_answer(a, count, type, not_there, 40);
}

unsigned char *make_synth_rfc8482_answer(unsigned char *a, int *count, 
		int type) {
	unsigned char AnyAnswer[22] = 
            "\xc0\x0c\x00\x0d\x00\x01\x00\x00\x00\x00\x00\x09\x07RFC8482\x00";
	return make_synth_answer(a, count, type, AnyAnswer, 21);
}
/* Make a synthetic "not there" reply */
void make_synth_not_there(int b, SOCKET sock, unsigned char *a, int count) {
        unsigned char *answer = 0;
        int local_num = 0;

        if(a == 0 || count < 12 || rem[b].local == 0) {
                return;
        }

        /* Copy original header and question in to answer */
        answer = make_synth_not_there_answer(a,&count,0);
        if(answer == 0) {
                return;
        }

        /* Flag this as an answer */
        answer[2] |= 0x80;

        /* One "NS" record; no other records */
        answer[9] = 1;
        answer[6] = answer[7] = answer[8] = answer[10] = answer[11] = 0;

        /* Send the reply(s) */
        for(local_num = 0; local_num < rem[b].num_locals; local_num++) {
                if(rem[b].local[local_num]->glueless_type != 0) {
                        continue;
                }
                /* Copy ID over */
                answer[0] = (rem[b].local[local_num]->local_id >> 8) & 0xff;
                answer[1] = (rem[b].local[local_num]->local_id) & 0xff;
                /* Send this reply */
                if(rem[b].local[local_num]->tcp_num == -1) {
                        forward_remote_reply(answer,count + 40, &rem[b],
                                local_num);
                } else {
                        tcp_return_reply(rem[b].local[local_num]->tcp_num,
                                (void *)answer, count);
                }
        }

        /* Reset the pending remote connection */
        closesocket(b_remote[b]);
        b_remote[b] = INVALID_SOCKET;
        reset_rem(b);

        /* Free allocated memory */
        free(answer);
}

/* Given a query, a socket, a remote connection_number (b), and a
 * local connection number for that remote connection (l), we get
 * a reply from the cache to send to the client in question.
 *
 * Don't confuse this with get_reply_from_cache, which does the same
 * thing with different arguments; this is a wrapper for
 * get_reply_from_cache() which is called from get_rem_udp_packet_core()
 */
int send_reply_from_cache(unsigned char *a, ssize_t count, int b, int l) {
        dw_str *query = 0;
        sockaddr_all_T client;
        int conn_num = 0;
        int ret = 1;

        query = dw_get_dname_type(a,12,count);
        if(query == 0 || rem[b].local == 0 || rem[b].local[l] == 0) {
                goto catch_send_reply_from_cache;
        }
        memset(&client,0,sizeof(client));
        if (rem[b].local[l]->glueless_type != 0) {
                conn_num = rem[b].local[l]->glueless_conn;
                if(rem[b].local[l]->glueless_type == 1) { /* Glueless NS */
                        if(rem[conn_num].child_id == b) { /* Sanity check */
                                dwx_glueless_done(query, conn_num);
                        }
                        ret = 4; /* Yes, we want to end the connection */
                } else if(rem[b].local[l]->glueless_type == 2) { /* CNAME */
                        dwx_incomplete_cname_done(query, b, l);
                        ret = 4; /* End connection */
                } else if(rem[b].local[l]->glueless_type == 3) {/* Saw CNAME */
                        dwx_cached_cname_done(query, b, l, 0);
                        ret = 4; /* End connection */
                }
                goto catch_send_reply_from_cache;
        } else if (rem[b].local[l]->ip.len == 4) {
                client.V4.sin_family = AF_INET;
                client.V4.sin_port = htons(rem[b].local[l]->port);
                memcpy(&client.V4.sin_addr, rem[b].local[l]->ip.ip, 4);
#ifndef NOIP6
        } else if(rem[b].local[l]->ip.len == 16) {
                client.V6.sin6_family = AF_INET6;
                client.V6.sin6_port = htons(rem[b].local[l]->port);
                memcpy(&client.V6.sin6_addr, rem[b].local[l]->ip.ip,
                        16);
#endif
        } else {
                ret = 1;
                goto catch_send_reply_from_cache;
        }

        get_reply_from_cache(query,&client,rem[b].local[l]->from_socket,
                        rem[b].local[l]->local_id, 0,-1,
                        rem[b].local[l]->orig_query, 0, 0, 0);

catch_send_reply_from_cache:
        if(query != 0) {
                dw_destroy(query);
        }
        return ret;
}

/* Core part of code that gets and processes remote DNS requests */

int get_rem_udp_packet_core(unsigned char *a, ssize_t count,
                int b, SOCKET sock, int l) {

        int cache_dns_reply_return_value = -1;
        int z = 0, y = 0, x = 0;

        if(count < 12) {
                return -1; /* Not a DNS packet at all */
        }

        if(rem[b].local[l] == 0) {
                return -1;
        }

        /* answers.yahoo.com hack: A truncated reply upstream with
         * answers will be treated as if it has only one answer */
        if((a[2] & 0x02) != 0x00 && a[7] > 0 &&
                        key_n[DWM_N_truncation_hack] == 1) {
                a[6] = a[8] = a[9] = a[10] = a[11] = 0;
                a[7] = 1;
                /* Cut off answer after first reply */
                for(z=12;z<count;z++) {
                        if(y == 0) { /* Question Length label */
                                y = 1;
                                x = a[z];
                                if(x > 63) {
                                        return -1; /* funny packet */
                                }
                                if(x == 0) {
                                        x = 4;
                                        y = 7;
                                }
                        } else if(y == 1) { /* In question label */
                                x--;
                                if(x == 0) {
                                        y = 0;
                                }
                        } else if(y == 7) { /* Type/class of question */
                                x--;
                                if(x == 0) {
                                        y = 2;
                                }
                        } else if(y == 2) { /* First part of name */
                                if(a[z] != 0xc0) {
                                        return -1; /* funny packet */
                                }
                                y = 3;
                        } else if(y == 3) { /* Second part of name */
                                if(a[z] != 0x0c) {
                                        return -1; /* funny packet */
                                }
                                y = 4;
                                x = 8;
                        } else if(y == 4) { /* Answer Type, class, or TTL */
                                x--;
                                if(x == 0) {
                                        y = 5;
                                }
                        } else if(y == 5) {
                                if(a[z] != 0) {
                                        return -1; /* RDLENGTH too long */
                                }
                                y = 6;
                        } else if(y == 6) {
                                if(z + a[z] + 1> count) {
                                        return -1; /* shouldn't happen */
                                }
                                count = z + a[z] + 1;
                                y = 8; /* We're done */
                        }
                }
                a[2] &= 0xfd;
        }

        if((a[2] & 0x02) == 0x00) { /* If not truncated */
                fflush(stdout);
                cache_dns_reply_return_value = cache_dns_reply(a,count,b,0);
                if(cache_dns_reply_return_value == -2) { /* Make synth NX */
                        make_synth_not_there(b,sock,a,count);
                        return -1; /* Bad reply and they got a Synth NX */
                }
                if(cache_dns_reply_return_value < 0) {
                        return -1; /* Bad reply */
                }
                if(cache_dns_reply_return_value >= 16) { /* Don't forward */
                        return 3; /* Don't forward to end user; cache
                                   * and next step */
                }
        } else if(rem[b].local[l]->tcp_num != -1 &&
                        key_n[DWM_N_tcp_listen] == 1) {
                /* Send a DNS-over-TCP packet to handle a truncated reply */
                tcp_truncated_retry(rem[b].local[l]->tcp_num, rem[b].query,
                        rem[b].local[l]->local_id,b,rem[b].is_upstream);
                /* Give the UDP connection more time before timeout, so
                 * we can fully process the TCP connection */
                rem[b].die = get_time() + ((int64_t)timeout_seconds << 11);
                return 2; /* Don't kill pending UDP connection */
        } else { /* Truncated over UDP; just given them a blank "truncated"
                  * reply */
                if(key_n[DWM_N_tcp_listen] != 1) {
                        /* EasyDNS sometimes has given out packets marked
                         * "truncated" that, in violation of RFC1035 section
                         * 4.1.1, do not mean that "[the] message was
                         * truncated due to length greater than that
                         * permitted on the transmission channel.", but mean
                         * "our UDP server is broken, try using our TCP
                         * server".
                         *
                         * This in mind, if we got a truncated packet and
                         * can not extract any useful information from the
                         * packet, unless Deadwood is using DNS-over-TCP,
                         * it's better to completely ignore the reply (when
                         * EasyDNS has had this issue, only some of their
                         * DNS servers have been affected)
                         */
                        return -1;
                }
                cache_dns_reply(a,count,b,1);
        }

        /* Now make sure the ID is the same as the one the client
         * originally sent us */
        set_dns_qid(a,count,rem[b].local[l]->local_id);

        /* Send the answer we just cached over appropriate local connection */
        if(rem[b].local[l]->tcp_num == -1 ||
                        rem[b].local[l]->glueless_type != 0) {
                return send_reply_from_cache(a,count,b,l);
        } else if(key_n[DWM_N_tcp_listen] == 1) {
                tcp_return_reply(rem[b].local[l]->tcp_num,(void *)a,count);
        }

        return 1;
}

/* Get and process a remote DNS packet (one sent upstream to us) */
void get_remote_udp_packet(int b, SOCKET sock) {
        ssize_t count;
        unsigned char a[520];
        int l = 0, kill = 1, core_ret = 0;

        count = recv(sock,a,514,0);
        if(count < 12 || count > 512) {
                return;
        }
        a[2] |= 0x80; /* Flag this as an answer (just in case they didn't) */

#ifdef SHOWPACKET
        dw_str *hack = 0;
        hack = dw_malloc(sizeof(dw_str));
        hack->max = count + 1;
        hack->len = count;
        hack->str = (uint8_t *)a;
        hack->sane = 114;
        dw_log_dwstr("Packet received ",hack,0);
        free(hack);
#endif /* SHOWPACKET */

        /* Make reasonably sure this is the reply to their question */
        if(verify_dns_packet(b,a,count) != 1) {
                return;
        }

        /* Having this be able to handle multiple in-flight requests
         * is hairy because we have to handle both DNS-over-UDP and
         * DNS-over-TCP */

        for(l = 0; l < rem[b].num_locals; l++) {
                core_ret = get_rem_udp_packet_core(a,count,b,sock,l);
                if(core_ret == -1) {
                        return;
                } else if(core_ret == 2 || core_ret == 3) {
                        kill = 0;
                }
        }

        /* Reset this pending remote connection if needed */
        if(kill == 1) {
                closesocket(b_remote[b]);
                b_remote[b] = INVALID_SOCKET;
                reset_rem(b);
        }
}

/* Send a server failure back to the client when there is no reply from
 * the upstream server.  Input: The pending remote connection number. */
void server_fail_noreply(int a, int local_num) {
        dw_str *packet = 0;

        if(rem[a].local[local_num] == 0 ||
           rem[a].local[local_num]->glueless_type != 0) {
                return;
        }

        /* 0x8182: QR = 1; Opcode = 0; AA = 0; TC = 0; RD = 1; RA = 1;
         *         Z = 0; RCODE = "server fail" (2) */
        packet = make_dns_header(rem[a].local[local_num]->local_id,0x8182,
                        0,0,0);

        dw_log_dwstr("Sending SERVER FAIL for query ",rem[a].query,100);

        if(dw_append(rem[a].query,packet) == -1 ||
           dw_put_u16(packet,1,-1) == -1 /* QCLASS: 1 */) {
                goto catch_server_fail_noreply;
        }

        if(rem[a].local[local_num]->tcp_num == -1 ||
                        rem[a].local[local_num]->glueless_type != 0) {
                forward_remote_reply((unsigned char *)packet->str,
                        packet->len,&rem[a],0);
        } else if(key_n[DWM_N_tcp_listen] == 1) {
                tcp_return_reply(rem[a].local[local_num]->tcp_num,
                        (void *)packet->str,packet->len);
        }

catch_server_fail_noreply:
        if(packet != 0) {
                dw_destroy(packet);
                packet = 0;
        }
}

