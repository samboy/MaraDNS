/* Copyright (c) 2007-2010 Sam Trenholme
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

#include <stdio.h>
#include <signal.h>
#include "DwSocket.h"
#include "DwTcpSocket.h"
#include "DwSys.h"
#include "version.h"

extern int32_t key_n[];

#ifdef MINGW
void windows_socket_start() {
        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2,2);
        WSAStartup( wVersionRequested, &wsaData);
}
#ifdef IPV6
ipv6_not_supported_on_windows_build;
#endif /* IPV6 */
#endif /* MINGW */

void usage() {
        printf("Usage: Deadwood [-f dwood3rc]\n");
        exit(1);
}

/* Show the name of the program */
void dw_show_programname() {
#ifdef IPV6
        dw_log_string(
        "Deadwood: A DNS UDP non-recursive cache (IPv6 supported)",1);
#else /* IPV6 */
        dw_log_string(
        "Deadwood: A DNS UDP non-recursive cache (IPv4-only)",1);
#endif /* IPV6 */
}

/* Parse command-line arguments given to server */
void dw_parse_args(int argc, char **argv) {
        if(argc != 1 && argc != 3) {
                usage();
        } else if(argc == 3) {
                if(argv[1] == 0 || argv[2] == 0) {
                        usage();
                } if(*(argv[1]) != '-' || *(argv[1] + 1) != 'f' ||
                     *(argv[1] + 2) != 0) {
                        usage();
                }
                process_mararc(argv[2]);
        } else {
#ifndef MINGW
                process_mararc("/etc/dwood3rc");
#else /* MINGW */
                process_mararc("dwood3rc.txt");
#endif /* MINGW */
        }
}

/* DNS non-recursive caching server */
int dw_udp_main(int argc, char **argv) {
        int bind_count = 0; /* Number of IPs we bound to */
        set_add_constant(); /* Has to be done before processing mararc */
        dw_parse_args(argc,argv);
        dw_show_programname();
        process_mararc_params();
#ifdef MINGW
        windows_socket_start();
#else
        setup_signals();
        signal(SIGPIPE, SIG_IGN); /* *NIX security bug workaround */
#endif /* MINGW */
        dw_log_number("Verbose_level set to ",key_n[DWM_N_verbose_level]
                      ,"",4);
        /* Bind to all UDP sockets */
        bind_count = bind_all_udp();
        if(bind_count > 0) {
                dw_log_number("We bound to ",bind_count," addresses",1);
        } else {
                dw_fatal("Unable to bind to any IP addresses (UDP)");
        }
        /* Bind to all TCP sockets */
        bind_count = bind_all_tcp();
        if(bind_count <= 0 && key_n[DWM_N_tcp_listen] == 1) {
                dw_fatal("Unable to bind to any IP addresses (TCP)");
        }
        /* Initialize "inflight" hash */
        init_inflight_hash();
#ifdef MINGW
        fflush(stdout);
#endif /* MINGW */
        init_rng();
        sandbox();
        init_cache();
        process_root_upstream();
        malloc_tcp_pend();
        init_tcp_b_pend();
        init_b_remote();
        bigloop();
        return 0;
}

/* Make -Wall happy */
extern int dw_tcp_main(int argc, char **argv);
/* Combined binary: Have DwUdp and DwTcp be the same program */

#ifndef MINGW
int main(int argc, char **argv) {
#else /* MINGW */
int dw_svc_main(int argc, char **argv) {
#endif /* MINGW */
        char *a = 0, *b = 0;
        int c = 0;
        dw_alog_3strings("Deadwood version ",VERSION,"");
        if(argv[0] == 0) {
                dw_alog_3strings("Don't invoke this program without ",
                        "argv[0] ","set");
                exit(1);
        }
        a = argv[0];

        /* Have 'a' point to the first character in the basename */
        while(*a != 0 && c < 250) {
                if(*a == '/' || *a == '\\') {
                        b = a;
                }
                a++;
                c++;
        }
        if(b != 0) {
                a = b + 1;
        } else {
                a = argv[0];
        }

        if((*a == 'D' || *a == 'd') && *(a+1) == 'w' && (*(a+2) == 'T' ||
           *(a+2) == 't')) {
                printf("Deadwood now has TCP support; DwTcp isn't needed\n");
                exit(1);
        }
        dw_udp_main(argc,argv);
        return 0;
}

