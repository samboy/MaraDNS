/* Copyright (c) 2007-2014 Sam Trenholme
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

#ifndef __MARARC_H_DEFINED__
#define __MARARC_H_DEFINED__

#include "DwStr.h"
#include "DwDict.h"

/* Some constants pointing to mararc parameters */

/* mararc string parameters */
#define DWM_S_bind_address 0
#define DWM_S_ipv4_bind_addresses 1
#define DWM_S_chroot_dir 2
#define DWM_S_recursive_acl 3
#define DWM_S_random_seed_file 4
#define DWM_S_cache_file 5
#define DWM_S_ip_blacklist 6

/* mararc dictionary parameters */
#define DWM_D_upstream_servers 0
#define DWM_D_root_servers 1

/* mararc numeric parameters */
#define DWM_N_maxprocs 0
#define DWM_N_timeout_seconds 1
#define DWM_N_dns_port 2
#define DWM_N_upstream_port 3
#define DWM_N_handle_overload 4
#define DWM_N_handle_noreply 5
#define DWM_N_recurse_min_bind_port 6
#define DWM_N_recurse_number_ports 7
#define DWM_N_hash_magic_number 8
#define DWM_N_maximum_cache_elements 9
#define DWM_N_maradns_uid 10
#define DWM_N_maradns_gid 11
#define DWM_N_resurrections 12
#define DWM_N_num_retries 13
#define DWM_N_verbose_level 14
#define DWM_N_max_tcp_procs 15
#define DWM_N_timeout_seconds_tcp 16
#define DWM_N_tcp_listen 17
#define DWM_N_max_ar_chain 18
#define DWM_N_ttl_age 19
#define DWM_N_max_inflights 20
#define DWM_N_deliver_all 21
#define DWM_N_filter_rfc1918 22
#define DWM_N_ns_glueless_type 23
#define DWM_N_reject_aaaa 24
#define DWM_N_reject_mx 25
#define DWM_N_truncation_hack 26
#define DWM_N_reject_ptr 27
#define DWM_N_min_ttl_incomplete_cname 28
#define DWM_N_max_ttl 29

/* Number of string parameters in the mararc file */
#define KEY_S_COUNT 7
/* Number of dictionary parameters in the mararc file */
#define KEY_D_COUNT 2
/* Number of numeric parameters in the mararc file */
#define KEY_N_COUNT 30

#ifndef MINGW
/* Location of files we read when we run execfile("foo") */
#define EXECFILE_DIR "/etc/deadwood/execfile/"
#endif /* MINGW */

#ifdef MARARC_C
dw_str *key_s[KEY_S_COUNT + 1]; /* All of the string dwood2rc parameters */
dwd_dict *key_d[KEY_D_COUNT + 1]; /* The dictionary dwood2rc parameters */
int32_t key_n[KEY_N_COUNT + 1]; /* The numeric dwood2rc parameters */

char *key_s_names[KEY_S_COUNT + 1] = {
        "bind_address", /* IP addresses to bind to */
        "ipv4_bind_addresses", /* IP Addresses to bind to (newer name) */
        "chroot_dir", /* Where we run Deadwood from */
        "recursive_acl", /* IPs that we allow recursive queries from */
        "random_seed_file", /* File with seed/key for random number
                             * generator */
        "cache_file", /* File with a copy of Deadwood's cache */
        "ip_blacklist", /* If an answer has any of these IPs, make it a
                         * "not there" answer */
        0 };

char *key_d_names[KEY_D_COUNT + 1] = {
        "upstream_servers", /* Recursive upstream DNS servers */
        "root_servers", /* Non-recursive root DNS servers */
        0 };

char *key_n_names[KEY_N_COUNT + 1] = {
        "maxprocs", /* The maximum number of outstanding queries we can
                     * have */
        "timeout_seconds", /* How long we wait for a reply from the remote
                            * server */
        "dns_port", /* The port we bind to */
        "upstream_port", /* The port we connect to when connecting upstream */
        "handle_overload", /* Reply when overloaded */
        "handle_noreply", /* Reply when no reply from upstream */
        "recurse_min_bind_port", /* The lowest numbered port deadwood will
                                  * bind to */
        "recurse_number_ports", /* The number of ports deadwood is allowed
                                 * to bind to */
        "hash_magic_number", /* A large 31-bit prime number that the hash
                              * compression function uses */
        "maximum_cache_elements", /* Maximum number of elements in cache */
        "maradns_uid", /* Numeric User ID Deadwood runs as */
        "maradns_gid", /* Numeric Group ID Deadwood runs as */
        "resurrections", /* Whether to look up expired records if we can't
                          * connect to upstream */
        "num_retries", /* Number of times we try to connect to an upstream
                        * server before giving up */
        "verbose_level", /* How verbose our logging should be */
        "max_tcp_procs", /* The maximum number of pending TCP queries we
                          * can have */
        "timeout_seconds_tcp", /* Timeout in seconds for active TCP
                                * connections */
        "tcp_listen", /* Whether to enable DNS-over-TCP */
        "max_ar_chain", /* Is RR rotation enabled (1) or disabled (2) */
        "ttl_age", /* Whether to enable (1) or disable (0) TTL aging */
        "max_inflights", /* Maximum number of in-flight requests we allow
                          * a single upstream query to have. */
        "deliver_all", /* Deliver non-cachable replies */
        "filter_rfc1918", /* Don't allow RFC1918 IPs in DNS replies */
        "ns_glueless_type", /* Query type to find NS glue */
        "reject_aaaa", /* Whether to reply to AAAA queries with a
                        * synthetic "not there" reply */
        "reject_mx", /* Whether to reject MX queries with no reply and
                      * logging the query (to help find spam zombies) */
        "truncation_hack", /* Whether to use 1st answer in truncated UDP
                            * replies (if present) */
        "reject_ptr", /* Whether to reject PTR queries and send out a
                         synthetic "not there" reply */
        "min_ttl_incomplete_cname", /* How long to store incomplete CNAME
                                     * records in the cache, in seconds */
        "max_ttl", /* Maximum allowed TTL */
        0 };

#endif /* MARARC_C */

/* Various character classes used by the Mararc parser's finite state
 * machine */

#define dwm_is_alpha(c)      (c >= 'a' && c <= 'z') || \
                             (c >= 'A' && c <= 'Z') || \
                             c == '_'

#define dwm_is_alphanum(c)   (c >= 'a' && c <= 'z') || \
                             (c >= 'A' && c <= 'Z') || \
                             (c >= '0' && c <= '9') || \
                             c == '_'

#define dwm_is_alphastart(c) (c >= 'a' && c <= 'z') || \
                             (c >= 'A' && c <= 'Z')

#define dwm_is_dname(c)      (c >= 'a' && c <= 'z') || \
                             (c >= 'A' && c <= 'Z') || \
                             (c >= '0' && c <= '9') || \
                             c == '-' || c == '.' || c == '_'

#define dwm_is_instring(c)   (c >= ' ' && c <= '~' && c != '#' && c != '"')

#define dwm_is_whitespace(c) (c == ' ' || c == '\t')

#define dwm_is_any(c)        (c >= ' ' && c <= '~') || c == '\t' || c > 127

#define dwm_is_dnamestart(c) (c >= 'a' && c <= 'z') || \
                             (c >= 'A' && c <= 'Z') || \
                             (c >= '0' && c <= '9')

#define dwm_is_number(c)     (c >= '0' && c <= '9')

/* Limits to the number of states, actions, and pattern per state we can
 * have */

/* Maximum number of states */
#define DWM_MAX_STATES 52
/* Maximum number of patterns per state */
#define DWM_MAX_PATTERNS 8

/* The actual state machine that we use to parse a MaraRC file; this is
 * described in the file doc/internals/MARARC.parser */

#define dwm_machine "a Hb Y1c Wxb Rxp T;\n" \
                    "b Xb Rxp T;\n" \
                    "c B1c Wd =e [f +g (y\n" \
                    "d Wd =e [f +g\n" \
                    "e We N4h Qi {6w\n" \
                    "f Wf Qn\n" \
                    "g =5e\n" \
                    "h N4h Wk Hb Rxp T;\n" \
                    "i I3m\n" \
                    "k Wk Hb Rxp T;\n" \
                    "m I3m Qk\n" \
                    "n .2o S2p -2p\n" \
                    "o Qq\n" \
                    "p D2p Qq\n" \
                    "q Wq ]r\n" \
                    "r Wr =s +t\n" \
                    "s Ws Qu\n" \
                    "t =5s\n" \
                    "u I3v\n" \
                    "v I3v Qk\n" \
                    "w }k\n" \
                    "xp T;\n" \
                    "y Qz\n" \
                    "z I7z Qxa\n" \
                    "xa )k\n" \
                    "xb Hb Wxb Y8xb Rxp T;\n"

/* A tokenized single state in the finite state machine */
typedef struct {
        char pattern[DWM_MAX_PATTERNS + 1];
        char action[DWM_MAX_PATTERNS + 1];
        char newstate[DWM_MAX_PATTERNS + 1];
        } dwm_fs;

/* Parse a mararc file; this should only be called once when executing
 * deadwood.  Note that this is the *only* public method in this entire
 * file; all other functions in this file should only be called from
 * other functions in this file.
 * Input: c string that points to mararc file
 * Output: 1 on success; program exits on mararc parse error */
int dwm_parse_mararc(char *name);

/* Fetch a value from a given dictionary variable (num is the number for
 * the dictionary variable we are seeking a given value for, given the
 * dictionary variable and the key inside that variable) */
dw_str *dwm_dict_fetch(int num, dw_str *key);

/* For a given dictionary variable, and a key, return (as a *copied* dw_str
 * object) the next key or 0 if we're at the last key.  If the key given to
 * this function is 0, return the first key. */
dw_str *dwm_dict_nextkey(int num, dw_str *key);

/* Private function: Parse a single file */
int dwm_parse_file(char *name);

#endif /* __MARARC_H_DEFINED__ */
