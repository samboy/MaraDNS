/* Copyright (c) 2007-2012 Sam Trenholme
 * IPv6 code by Jean-Jacques Sarton
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
#include "DwSys.h"
#include "DwRecurse.h"

/* Mararc parameters that are set in DwMararc.c */
extern dw_str *key_s[];
extern dw_str *key_d[];
extern int32_t key_n[];

/* Parameters set in DwSys.c */
extern int64_t the_time;
extern dwr_rg *rng_seed;

/* Parameters from DwTcpSocket.c */
extern tcp_pend_T *tcp_pend;
extern SOCKET tcp_b_local[]; /* Local TCP sockets */

/* List of addresses we will bind to */
ip_addr_T bind_address[DW_MAXIPS + 1];
ip_addr_T upstream_address[DW_MAXIPS + 1];

/* List of who is allowed to use Deadwood */
ip_mask_T recursive_acl[DW_MAXIPS + 1];

/* List of active sockets */
SOCKET b_local[DW_MAXIPS + 1];
SOCKET *b_remote;

/* The list of pending remote connections */
remote_T *rem;

/* The cache */
extern dw_hash *cache;

/* Some dwood3rc parameters */
int maxprocs = 32;
int max_tcp_procs = 8;
#ifndef FALLBACK_TIME
int timeout_seconds = 1;
int timeout_seconds_tcp = 4;
#else /* FALLBACK_TIME */
int timeout_seconds = 2;
int timeout_seconds_tcp = 4;
#endif /* FALLBACK_TIME */
int dns_port = 53;
int upstream_port = 53;
int handle_overload = 1;
int handle_noreply = 1;
int resurrections = 1;
int32_t min_bind = 15000;
int32_t num_ports = 4096;
int32_t maradns_uid = 99;
int32_t maradns_gid = 99;
int32_t max_ttl = 86400;
int num_retries = 5;
dwd_dict *blacklist_dict = 0;

#ifdef MINGW
u_long dont_block = 0;
#endif /* MINGW */

#ifdef NO_INET_PTON
/* Wrapper function for systems that don't have inet_pton (Windows, etc.) */
int inet_pton(int z, char *c, uint8_t *ip) {
        uint32_t ipt = 0xffffffff;
        if(c != 0 && *c != 0) {
                ipt = inet_addr(c);
        } else {
                return -1;
        }
        ipt = htonl(ipt);
        ip[0] = (ipt & 0xff000000) >> 24;
        ip[1] = (ipt & 0x00ff0000) >> 16;
        ip[2] = (ipt & 0x0000ff00) >>  8;
        ip[3] = (ipt & 0x000000ff);
        if(ipt != 0xffffffff) {
                return 1;
        } else {
                return -1;
        }
}
#endif /* NO_INET_PTON */

/* Reset the values for a remote connection */
void reset_rem(int_fast32_t a) {
        if(rem[a].socket != INVALID_SOCKET) {
                closesocket(rem[a].socket);
                rem[a].socket = INVALID_SOCKET;
        }
        rem[a].die = 0;
        rem[a].remote_id = 0;
        rem[a].retries = num_retries;
        if(rem[a].ns != 0) {
                dw_destroy(rem[a].ns);
                rem[a].ns = 0;
        }
        rem[a].is_upstream = 0;
        if(rem[a].query != 0) {
                zap_inflight(rem[a].query);
                dw_destroy(rem[a].query);
                rem[a].query = 0;
        }
        rem[a].recurse_depth = 0;
        rem[a].current_ns = -1;
        rem[a].child_id = -1;
        if(rem[a].glueless != 0) {
                dw_destroy(rem[a].glueless);
                rem[a].glueless = 0;
        }
        if(rem[a].local != 0) {
                int qq;
                for(qq = 0; qq < rem[a].num_locals; qq++) {
                        if(rem[a].local[qq] != 0) {
                                dw_destroy(rem[a].local[qq]->orig_query);
                                dw_destroy(rem[a].local[qq]->action);
                                free(rem[a].local[qq]);
                                rem[a].local[qq] = 0; }
                }
                free(rem[a].local);
        }
        rem[a].local = 0;
        rem[a].num_locals = 0;
}

/* Configure the dns_do local bind structure.  Given an IP we
 * want to bind to, fill up the dns_udp structure with that IP
 * and set things up to bind to the dns_port port (normally 53, DNS).
 * Establish a socket for binding to, and return the value of the
 * socket.  type is SOCK_DGRAM for a UDP socket; SOCK_STREAM for TCP */
SOCKET bind_set_dns(ip_addr_T *ip, sockaddr_all_T *dns_do, int type) {
        SOCKET sock = INVALID_SOCKET;

        if(ip == 0 || dns_do == 0) {
                return INVALID_SOCKET;
        }

        memset(dns_do,0,sizeof(sockaddr_all_T));

        /* Copy IP, set port, and create socket */
        if ( ip->len == 4 ) { /* IPV4 */
                dns_do->V4.sin_family = AF_INET;
                memcpy(&(dns_do->V4.sin_addr.s_addr), ip->ip, ip->len);
                dns_do->V4.sin_port = htons(dns_port);
                sock = socket(AF_INET,type,0);
#ifdef IPV6
        } else if( ip->len == 16) { /* IPV6 */
                dns_do->V6.sin6_family = AF_INET6;
                memcpy(&(dns_do->V6.sin6_addr), ip->ip, ip->len);
                dns_do->V6.sin6_port = htons(dns_port);
                sock = socket(AF_INET6,type,0);
#endif
        }

        if(sock != INVALID_SOCKET) {
                make_socket_nonblock(sock);
        }

        return sock;
}

/* Given an IP address to bind to, and a type of port it is (SOCK_DGRAM for
 * a UDP port; SOCK_STREAM for a TCP port), bind to that port and return the
 * socket number corresponding to that port */
SOCKET do_bind(ip_addr_T *ip,int type) {
        int on = 1;
        SOCKET sock = INVALID_SOCKET;
        sockaddr_all_T dns_do;
        unsigned int len_inet = sizeof(struct sockaddr_in);

        sock = bind_set_dns(ip,&dns_do,type);
        if(sock == INVALID_SOCKET) {
                return INVALID_SOCKET;
        }

        if (setsockopt(sock, SOL_SOCKET,
                       SO_REUSEADDR, (char *) &on, sizeof (on)))
        {
                closesocket(sock);
                return INVALID_SOCKET;
        }

#ifdef IPV6
        if (ip->len == 16)
                len_inet = sizeof(struct sockaddr_in6);
#endif

        if(bind(sock,(struct sockaddr *)&dns_do,len_inet) == -1) {
                closesocket(sock);
                return INVALID_SOCKET;
        }

        if(type == SOCK_STREAM && listen(sock,250) == -1) {
                closesocket(sock);
                return INVALID_SOCKET;
        }

        return sock;
}

/* This function, given a dw_str with a comma-separated list of IP
 * addresses, removes the last IP from the comma-separated list, and
 * converts it in to an IP (what *ip points to) */
void pop_ip_core(dw_str *list, ip_addr_T *ip,char *c) {
        if(c == 0 || ip == 0) { /* Sanity check */
                return;
        }
        ip->len = 0;
        if( inet_pton(AF_INET, c, (uint8_t *)(ip->ip)) > 0 ) {
                ip->len = 4;
#ifdef IPV6
        } else {
                if ( inet_pton(AF_INET6, c, (uint8_t *)(ip->ip)) > 0 ) {
                        ip->len = 16;
                }
#endif /* IPV6 */
        }
}

/* This is the version of pop_ip that deallocates the string that
 * pop_ip_core creates */
void pop_ip(dw_str *list, ip_addr_T *ip) {
        char *c = 0;

        c = pop_last_item(list);
        pop_ip_core(list,ip,c);

        if(c != 0) {
                free(c);
                c = 0;
        }
}

/* This converts an ip_addr_T in to a dw_str object */
dw_str *make_ip_str(ip_addr_T *in) {
        dw_str *out = 0;
        int counter = 0;

        if(in == 0) {
                goto catch_make_ip_str;
        }

        if(in->len != 4 && in->len != 16) {
                goto catch_make_ip_str;
        }

        out = dw_create(in->len + 1);

        if(out == 0) {
                goto catch_make_ip_str;
        }

        out->len = in->len;

        for(counter = 0; counter < in->len; counter++) {
                *(out->str + counter) = in->ip[counter];
        }

        return out;

catch_make_ip_str:
        if(out != 0) {
                dw_destroy(out);
        }
        return 0;
}

/* This converts a dw_str with a list of IPs in to a dwd_dict obejct.  This
 * is destructive for "in" */
dwd_dict *make_ip_dict(dw_str *in) {
        dwd_dict *out = 0;
        dw_str *key = 0, *value = 0;
        int counter = 0;
        ip_addr_T ip;

        if(in == 0) {
                return 0;
        }

        value = dw_create(2);
        if(value == 0) {
                return 0;
        }

        value->len = 1;
        *(value->str) = 'y'; /* Yes, this has a value */

        out = dwd_init();

        ip.len = 1;
        for(counter = 0; counter < 1000 && ip.len != 0; counter++) {
                pop_ip(in, &ip);
                if(ip.len != 0) {
                        key = make_ip_str(&ip);
                        if(key != 0) {
                                dwd_add(out, key, value);
                                dw_destroy(key);
                                key = 0;
                        }
                }
        }

        dw_destroy(value);
        return out;
}

/* This function, given a dw_str with a comma-separated list of IP
 * address/netmask pairs (currently, the netmask can not have a form
 * like /255.255.255.0; it *has* to have a form like /24), removes
 * the last IP/netmask from the comma-separated list, and converts
 * it in to an IP/netmask pair pointed to by ip_mask */
void pop_ip_mask(dw_str *list, ip_mask_T *ip_mask) {
        char *c = 0;
        char *q = 0; /* Not free()d; uses same memory as c */
        int n;

        c = pop_last_item(list);
        if(c == 0) {
                goto catch_pop_ip_mask;
        }

        q = strchr(c,'/');
        if(q == 0 || *q != '/') {
                pop_ip_core(list,(ip_addr_T *)ip_mask,c);
                make_netmask(ip_mask->len * 8,ip_mask->mask,ip_mask->len);
                goto catch_pop_ip_mask;
        }
        *q = 0; /* pop_ip_core can't take an IP ending with a slash */
        pop_ip_core(list,(ip_addr_T *)ip_mask,c);
        *q = '/';

        q++;
        if(*q == 0) {
                goto catch_pop_ip_mask;
        }

        n = atoi(q);
        if(ip_mask->len != 4 && ip_mask->len != 16) {
                goto catch_pop_ip_mask;
        }
        if(n < 0 || n > (ip_mask->len * 8)) {
                n = ip_mask->len * 8;
        }
        make_netmask(n,ip_mask->mask,ip_mask->len);

catch_pop_ip_mask:
        if(c != 0) {
                free(c);
                c = 0;
        }
}

/* Set a list of IPs based on the contents of a dw_str object that
 * we give to the program. */
void set_ip_list(ip_addr_T *list, dw_str *str) {
        int a = 0;

        if(list == 0 || str == 0) {
                return;
        }

        /* Get the IPs from "str" and make them IPs in the list */
        while(a < DW_MAXIPS - 1) {
                pop_ip(str, &list[a]);
                if(list[a].len == 0) {
                        break;
                }
                a++;
        }
        /* Fill the rest of the list with "not set" values */
        while(a < DW_MAXIPS) {
                list[a].len = 0;
                a++;
        }
}

/* Set a list IP/Mask pairs based on the contents of a dw_str object
 * that we give to the program; almost identical to set_ip_list() */
void set_ipmask_list(ip_mask_T *list, dw_str *str) {
        int a = 0;

        if(list == 0 || str == 0) {
                return;
        }

        /* Get the IP + masks from "str" and make them IPs in the list */
        while(a < DW_MAXIPS - 1) {
                pop_ip_mask(str, &list[a]);
                if(list[a].len == 0) {
                        break;
                }
                a++;
        }
        /* Fill the rest of the list with "not set" values */
        while(a < DW_MAXIPS) {
                list[a].len = 0;
                a++;
        }
}

/* Given a "client" that recvfrom gave us (which has the IP and port
 * number hidden in it), extract the IP and port from that "client", put the
 * IP information in from_ip, and return a 16-bit number that has the port
 * the query came from */
uint16_t get_from_ip_port(ip_addr_T *from_ip, sockaddr_all_T *client) {
        uint16_t from_port = 0;

        if(from_ip == 0 || client == 0) {
                return 0;
        }

        if(client->Family == AF_INET) {
                from_ip->len = 4;
                /* Copy over the IP the query is from */
                memcpy(from_ip->ip,&(client->V4.sin_addr.s_addr),4);
                /* Copy over the port the query is from */
                from_port = ntohs(client->V4.sin_port);
#ifdef IPV6
        } else if (client->Family == AF_INET6) {
                from_ip->len = 16;
                /* Copy over the IP the query is from */
                memcpy(from_ip->ip, &(client->V6.sin6_addr),16);
                /* Copy over the port the query is from */
                from_port = ntohs(client->V6.sin6_port);
#endif
        }
        return from_port;
}

/* See if a given ip is a permitted IP in the recursive_acl list.  Input:
 * IP we are checking.  Output: -1 on error; 0 if not permitted; 1 if
 * permitted */
int check_ip_acl(ip_addr_T *ip) {
        int a = 0;
        int b = 0;
        uint8_t m;

        for(a = 0; a < DW_MAXIPS; a++) {
                if(recursive_acl[a].len == 0) {
                        return 0;
                }
                if(ip->len != recursive_acl[a].len) {
                        continue;
                }
                for(b = 0; b < ip->len; b++) {
                        m = recursive_acl[a].mask[b];
                        if((recursive_acl[a].ip[b] & m) != (ip->ip[b] & m)) {
                                break;
                        }
                }
                if(b == ip->len) {
                        return 1;
                }
        }
        return 0;
}

/* Process numeric mararc parameters.  The last three arguments for
 * get_key_n are "minimum possible value", "maximum possible value",
 * and "fallback", which we use if the value they gave us is out of
 * range (if fallback is -1, we use min when below min and max
 * when above max).  Default values for numeric parameters are
 * in dwm_init_mararc() in the file DwMararc.c */
void process_numeric_mararc_params() {

        maxprocs =        get_key_n(DWM_N_maxprocs,       8,16384,-1);
        max_tcp_procs =   get_key_n(DWM_N_max_tcp_procs,  4,1024,-1);
#ifndef FALLBACK_TIME
        timeout_seconds = get_key_n(DWM_N_timeout_seconds,1,300,-1);
        timeout_seconds_tcp = get_key_n(DWM_N_timeout_seconds_tcp,1,300,-1);
#else /* FALLBACK_TIME */
        timeout_seconds = get_key_n(DWM_N_timeout_seconds,2,300,-1);
        timeout_seconds_tcp = get_key_n(DWM_N_timeout_seconds_tcp,2,300,-1);
#endif /* FALLBACK_TIME */
        dns_port =        get_key_n(DWM_N_dns_port,       1,65535,53);
        upstream_port =   get_key_n(DWM_N_upstream_port,  1,65535,53);
        handle_overload = get_key_n(DWM_N_handle_overload,0,1,1);
        handle_noreply  = get_key_n(DWM_N_handle_noreply,0,1,1);
        min_bind = get_key_n(DWM_N_recurse_min_bind_port,1025,32767,15000);
        num_ports = get_key_n(DWM_N_recurse_number_ports,256,32768,4096);
        maradns_uid = get_key_n(DWM_N_maradns_uid,10,65535,99);
        maradns_gid = get_key_n(DWM_N_maradns_gid,10,65535,99);
        resurrections = get_key_n(DWM_N_resurrections,0,1,1);
        num_retries = get_key_n(DWM_N_num_retries,0,32,5);
        max_ttl = get_key_n(DWM_N_max_ttl,
                300 /* 5 minutes */,
                7776000 /* 90 days */,
                86400 /* One day */);

        if((num_ports & (num_ports - 1)) != 0) {
                dw_fatal("num_ports must be a power of 2");
        }
        num_ports--;

}

/* Read and handle the upstream_servers dictionary variable */
int process_root_upstream_servers(int param, int is_upstream, char *bad) {
        dw_str *q = 0, *r = 0, *s = 0, *ns_refer = 0, *check = 0;
        int a = 0, out = 0;

        q = 0;
        /* Add upstream server elements to the main cache */
        for(a=0;a<20000;a++) {
                r = dwm_dict_nextkey(param,q);
                dw_destroy(q);
                if(r == 0) {
                        break;
                }
                out = 1;
                s = dwm_dict_fetch(param,r);
                q = dw_dnsname_convert(r);
                ns_refer = dwx_ns_convert(s,is_upstream,q);
                if(q == 0 || ns_refer == 0 || ns_refer->len < 4) {
                        dw_log_dwstr_str(bad,r,"\"]",0);
                        dw_fatal("Please fix this line");
                }
                dw_put_u16(q, 65395, -1); /* NS refer private RR */
#ifndef TINY_BINARY
                /* Forbid duplicate lines to minimize chance of user
                 * confusion */
                check = dwh_get(cache,q,1,1);
                if(check != 0) {
                        dw_log_dwstr_str(bad,r,
                     "\"] (used in both root_servers and upstream_servers)",0);
                        dw_fatal("Same entry can not be in both");
                        }
#endif /* TINY_BINARY */
                dwh_add(cache,q,ns_refer,1,2);
                dw_destroy(q);
                dw_destroy(s);
                dw_destroy(ns_refer);
                q = dw_copy(r);
                dw_destroy(r);
        }
        if(a == 20000) {
                dw_fatal("Too many upstream servers, limit 20,000");
        }

        return out;

}

/* Process the root_servers and upstream_servers values, using
 * default root servers if needed
 */
void process_root_upstream() {
        int elements_in_cache = 0;
        dw_str *s = 0, *q = 0, *ns_refer = 0;

        elements_in_cache +=
                process_root_upstream_servers(DWM_D_upstream_servers,1,
                        "Bad dwood3rc line looks like:\nupstream_servers[\"");
        elements_in_cache +=
                process_root_upstream_servers(DWM_D_root_servers,0,
                        "Bad dwood3rc line looks like:\nroot_servers[\"");

        if(elements_in_cache == 0) { /* Use default root servers */
                dw_log_3strings("Using default ICANN root servers:"," ",
                        ROOT_SERVERS,1);
                s = dw_create(256);
                q = dw_create(16);
                dw_qrappend((uint8_t *)ROOT_SERVERS,s,0);
                ns_refer = dwx_ns_convert(s,0,0);
                dw_put_u8(q,0,-1); /* Root server (".") */
                dw_put_u16(q,65395,-1); /* NS refer private RR */
                dwh_add(cache,q,ns_refer,1,2);
                dw_destroy(q);
                dw_destroy(s);
                dw_destroy(ns_refer);
        }
}

/* Read mararc parameters and set global variables based on those
 * parameters */
void process_mararc_params() {
        dw_str *bind = 0, *r_acl = 0;
        int a;

        bind = get_bind_addrs();
        if(bind == 0) {
                dw_fatal("Could not bind");
        }
        set_ip_list(bind_address,bind);

        r_acl = dw_copy(key_s[DWM_S_recursive_acl]);
        if(r_acl == 0) {
                dw_fatal("Could not get recursive_acl");
        }
        set_ipmask_list(recursive_acl,r_acl);

#ifndef TINY_BINARY
        /* Harlan's issue: Make sure all bind addresses are in the recursive
         * ACL */
        for(a = 0; a < DW_MAXIPS; a++) {
                if(bind_address[a].len == 0) {
                        break;
                }
                if(check_ip_acl(&(bind_address[a])) != 1) {
                        dw_log_ip("This IP is not in recursive_acl: ",
                                  &(bind_address[a]),0);
                        dw_fatal("All bind_address values must be in"
                                 " recursive_acl");
                }
        }
        if(DW_MAXIPS == a) {
                dw_fatal("Too many bind_address IPs");
        }
#endif /* TINY_BINARY */

        process_numeric_mararc_params();

        /* These two items are allocated once and never freed;
         * they are used while the program is running */
        b_remote = dw_malloc((maxprocs + 1) * sizeof(int));
        rem = dw_malloc((maxprocs + 1) * sizeof(remote_T));

        /* Make sure we got that memory */
        if(b_remote == 0) {
                dw_fatal("Could not allocate b_remote!");
        }
        if(rem == 0) {
                dw_fatal("Could not allocate rem!");
        }

        blacklist_dict = make_ip_dict(key_s[DWM_S_ip_blacklist]);

        if(bind != 0) {
                dw_destroy(bind);
                bind = 0;
        }
        if(r_acl != 0) {
                dw_destroy(r_acl);
                r_acl = 0;
        }
}

/* Initialize the list of pending remote replies */
void init_b_remote() {
        int a = 0;
        for(a = 0; a < maxprocs; a++) {
                b_remote[a] = INVALID_SOCKET;
                rem[a].socket = INVALID_SOCKET;
                rem[a].query = 0;
                rem[a].glueless = 0;
                rem[a].local = 0;
                rem[a].ns = 0;
                reset_rem(a);
        }
}

/* Search for the highest socket number in a list of sockets */
SOCKET find_max(int *list, int max) {
        int a = 0;
        int ret = -1;
        for(a = 0; a < max ; a++) {
                if(list[a] > ret) {
                        ret = list[a];
                }
        }
        return ret;
}

/* Get maximum socket number from either the local or remote socket
 * lists; add one to the result so it can be used by select() */
SOCKET get_max() {
        int a = 0;
        int b = 0;
        int c = 0;
        int max = 0;

        /* UDP */
        c = find_max(b_local,DW_MAXIPS);
        b = find_max(b_remote,maxprocs);
        if(c > b) {
                max = c;
        } else {
                max = b;
        }

        /* There might be a TCP socket with a bigger number */
        for(a = 0; a < DW_MAXIPS; a++) {
                if(tcp_b_local[a] > max) {
                        max = tcp_b_local[a];
                }
        }

        /* Socket lib quirk: Select uses max + 1, not max */
        return max + 1;
}

/* Set the rx_fd list (A list used by select() ) */
void set_rx_fd(fd_set *rx_fd) {
        int a = 0;
        FD_ZERO(rx_fd);

        /* UDP */
        for(a = 0; a < DW_MAXIPS; a++) {
                if(b_local[a] != -1) {
                        FD_SET(b_local[a],rx_fd);
                }
        }
        for(a = 0; a < maxprocs; a++) {
                if(b_remote[a] != -1) {
                        FD_SET(b_remote[a],rx_fd);
                }
        }

        /* TCP */
        if(key_n[DWM_N_tcp_listen] == 1) {
                for(a = 0; a < DW_MAXIPS; a++) {
                        if(tcp_b_local[a] != -1) {
                                FD_SET(tcp_b_local[a],rx_fd);
                        }
                }
        }

}

/* Find a free remote pending connection */
int32_t find_free_remote() {
        int32_t a = 0;
        for(a = 0; a < maxprocs; a++) {
                if(rem[a].socket == INVALID_SOCKET &&
                                rem[a].local == 0) { /* Available for use */
                        return a;
                }
        }
        return -1; /* None are available (We're overloaded) */
}

/* Get an upstream NS delegation */
dw_str *get_upstream_ns(dw_str *query, int connection_number) {
        dw_str *q = 0, *r = 0;
        int a = 0;

        /* Convert query in to a form where we can look for it in our list
         * of upstream servers */
        r = dw_copy(query);
        dw_pop_u16(r);
        dw_put_u16(r, 65395, -1); /* Special "NS refer" RR type */

        /* Figure out which upstream server to use */
        for(a=0; q == 0 && a < 260; a++) {
                q = dwh_get(cache,r,0,1);
                if(q == 0) {
                        q = dw_dnslabel_chop(r);
                        dw_destroy(r);
                        r = 0;
                        r = dw_copy(q);
                        dw_destroy(q);
                        q = 0;
                }
                if(r == 0) {
                        break;
                }
        }

        dw_destroy(r);
        r = 0;

        /* Is this an upstream referral? */
        if(dw_fetch_u8(q,-1) == TYPE_UPSTREAM_REFER) {
                rem[connection_number].is_upstream = 1;
        }

        /* Return the list of NS servers */
        return q;
}

/* Given a UDP remote connection, decide on an IP to send a query to
 * (or, if needed, a gluless NS record); if the list of nameservers
 * to contact is empty, fill it up using get_upstream_ns */
ip_addr_T get_upstream_ip(dw_str *query, int b) {
        ip_addr_T addr = {0,{0,0},0,0};

        if(rem[b].ns == 0) {
                rem[b].ns = get_upstream_ns(query,b);
        }

        if(rem[b].ns == 0) {
                return addr; /* Error; returns invalid addr */
        }

        return dwx_ns_getip(rem[b].ns,rng_seed,b);

}

/* This bit of code is used five times in process_results() to see if
 * we have processed all of the pending connections and leaves
 * process_results() if we have */
#define dec_a() a--; if(a <= 0) { return; }

/* If we have a pending connection, process the pending connection */
void process_results(int a, fd_set *rx_fd) {
        int b = 0, z = 0;

        /* Find the pending connection */
        while(a > 0 && z < 50000) {
                /* New UDP connections */
                for(b = 0; b < DW_MAXIPS; b++) {
                        if(b_local[b] != -1 && FD_ISSET(b_local[b],rx_fd)) {
                                get_local_udp_packet(b_local[b]);
                                dec_a();
                        }
                }
                /* UDP upstream replies */
                for(b = 0; b < maxprocs; b++) {
                        if(b_remote[b] != -1 && FD_ISSET(b_remote[b],rx_fd)) {
                                get_remote_udp_packet(b, b_remote[b]);
                                dec_a();
                        }
                }
                /* New TCP connections */
                for(b = 0; b < DW_MAXIPS; b++) {
                        if(tcp_b_local[b] != INVALID_SOCKET &&
                           FD_ISSET(tcp_b_local[b],rx_fd)) {
                                local_tcp_accept(tcp_b_local[b]);
                                dec_a();
                        }
                }
                z++;
        }
}

/* Try to give the user an expired record, if we have it */
int handle_resurrections(int a) {
        dw_str *value = 0;
        dw_str *packet = 0;
        int ret = 0;
        int local_num = 0;

        value = dwh_get(cache,rem[a].query,1,1);
        if(value == 0) {
                goto catch_handle_resurrections;
        }

        for(local_num = 0; local_num < rem[a].num_locals; local_num++) {
                if(rem[a].local[local_num]->glueless_type != 0) {
                        continue;
                }
                packet = make_dns_packet(rem[a].query,value,
                                rem[a].local[local_num]->local_id);
                if(packet == 0) {
                        goto catch_handle_resurrections;
                }

                if(rem[a].local[local_num]->tcp_num == -1) {
                        forward_remote_reply((unsigned char *)packet->str,
                                packet->len, &rem[a], local_num);
                } else {
                        tcp_return_reply(rem[a].local[local_num]->tcp_num,
                                (void *)packet->str, packet->len);
                }
                if(packet != 0) {
                        dw_destroy(packet);
                        packet = 0;
                }
        }

        ret = 1;

catch_handle_resurrections:
        if(value != 0) {
                dw_destroy(value);
                value = 0;
        }
        if(packet != 0) {
                dw_destroy(packet);
                packet = 0;
        }
        return ret;
}

/* If a given connection has timed out:
 *  1) Try connecting to upstream server again if retries hasn't run out
 *  2) If enabled, try to give them an expired record
 *  3) If enabled, give them a server fail or whatever
 */
int handle_expired(int a) {
        dw_str *packet = 0;
        int ret = 0, t = 0, local_num = 0;

        if(rem[a].retries > 0) {
                /* Try connecting to remote server again */
                rem[a].retries--;
                closesocket(rem[a].socket);
                rem[a].socket = INVALID_SOCKET;
                /* 0x0180: QR = 0; Opcode = 0; AA = 0; TC = 0; RD = 1; RA = 1;
                 *         Z = 0; RCODE = 0; 0x080 is same but with RD = 0 */
                rem[a].remote_id = dwr_rng(rng_seed);
                if(rem[a].is_upstream == 1) {
                        packet = make_dns_header(rem[a].remote_id,0x180,0,0,0);
                } else {
                        packet = make_dns_header(rem[a].remote_id,0x080,0,0,0);
                }
                if(dw_append(rem[a].query,packet) == -1 ||
                   dw_put_u16(packet,1,-1) == -1 /* QCLASS: 1 */) {
                        goto catch_handle_expired;
                }
                dw_log_dwstr_str("Connection for query ",rem[a].query,
                                " did not respond; trying again",128);
                make_remote_connection(a,(unsigned char *)packet->str,
                                packet->len,rem[a].query,INVALID_SOCKET);
                rem[a].die = get_time() + ((int64_t)timeout_seconds << 8);
                ret = 1; /* Do not kill; we're trying again */
                goto catch_handle_expired;
        }
        if(resurrections == 1) {
                if(handle_resurrections(a) == 1) {
                        goto catch_handle_expired;
                }
        }
        for(local_num = 0; local_num < rem[a].num_locals; local_num++) {
                if(handle_noreply == 1) {
                        server_fail_noreply(a, local_num);
                } else if(rem[a].local[local_num]->tcp_num != -1) {
                        t = rem[a].local[local_num]->tcp_num;
                        /* Close the TCP socket */
                        closesocket(tcp_pend[t].local);
                        reset_tcp_pend(t);
                }
        }

catch_handle_expired:
        if(packet != 0) {
                dw_destroy(packet);
                packet = 0;
        }
        return ret;
}

/* Kill any pending remote connections that have timed out */
void kill_expired() {
        int a = 0;
        for(a = 0; a < maxprocs; a++) {
                if(rem[a].die > 0 && rem[a].die < get_time()) {
                        if(handle_expired(a) == 1) {
                                continue;
                        }
                        closesocket(rem[a].socket);
                        b_remote[a] = INVALID_SOCKET;
                        reset_rem(a);
                }
        }
}

/* Signal handler flag so we know when to write the cache to disk */
#ifndef MINGW
extern int got_signal;
#else /* MINGW */
extern int run_loop;
extern FILE *LOG;
#endif /* MINGW */

/* Main loop: Recieve from bound sockets, forward those on to upstream, and
 *            forward replies from upstream to bound sockets */
int bigloop() {
        int a = 0, b = 0;
        int max = 0;
        fd_set rx_fd;
        struct timeval timeout;
#ifndef MINGW
        for(;;) {
#else /* MINGW */
        while(run_loop == 1) {
#endif /* MINGW */
                set_time();
                max = get_max();
                set_rx_fd(&rx_fd);
                timeout.tv_sec = 0;
                timeout.tv_usec = 50000; /* 20 times a second */
                a = select(max,&rx_fd,NULL,NULL,&timeout);

                /* If we have results, process them */
                if(a > 0) {
                        process_results(a,&rx_fd);
#ifdef MINGW
                } else {
                        fflush(LOG);
#endif /* MINGW */
                }
                /* Kill off expired pending connections */
                /* Get data from any pending TCP connections */
                for(b = 0; b < max_tcp_procs; b++) {
                        tcp_handle_all(b);
                }
                kill_expired();
                kill_tcp_expired();
#ifndef MINGW
                /* Process any signals received */
                if(got_signal != 0) {
                        dw_log_number("Got signal ",
                           got_signal," to process...",1);
                        process_signal(got_signal);
                }
#endif /* MINGW */
        }
#ifdef MINGW
        process_signal(1);
#endif /* MINGW */
        return 0; /* We only get here in Windows */
}

