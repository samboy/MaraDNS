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

#ifndef __DWSYS_H_DEFINED__
#define __DWSYS_H_DEFINED__

#ifndef MINGW
#include <grp.h>
#endif /* MINGW */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "DwSocket.h"

/* Parameters that are currently hardcoded in the source code (This will
 * change once we get something very basic that works) */

#define DW_UID 99      /* UID that we run as */
#define DW_MINTIME 1178488417 /* Minimum allowed timestamp */

/* Make this look like a function just in case we need to make it
 * a function to make things thread-safe */
#define get_time() the_time

/* These are public functions */

/* Initialize the log */
void dw_log_init();

#ifdef MINGW
void dw_tcp_log_init();
#endif /* MINGW */

/* Close the log */
void dw_log_close();

/* Log a char followed by an IP */
void dw_log_ip(char *string, ip_addr_T *ip, int min_log_level);

/* Log a string followed by the contents of a DwStr object */
void dw_log_dwstr(char *s1, dw_str *s2, int min_log_level);

/* Log a string followed by the contents of a DwStr object followed by
 * another string */
void dw_log_dwstr_str(char *s1, dw_str *s2, char *s3, int min_log_level);

/* Log a string; input: String to log; minimum log level that we log this
 * string at */
void dw_log_string(char *string, int min_log_level);

/* Log 3 strings; input: Strings to log; minimum log level that we log these
 * strings at */
void dw_log_3strings(char *s1, char *s2, char *s3, int min_log_level);

/* Log a string, a number, and a string
 * input: String #1, Number, and String #2 to log;
 * minimum log level that we log this at */
void dw_log_number(char *s1, int number, char *s2, int min_log_level);

/* Log a string and a number in hex */
void dw_log_hex(char *s1, uint32_t number, int min_log_level);

/* Log 3 strings; input: Strings to log; minimum log level that we log these
 * strings at; this always logs and is run before Dwood2rc file is parsed */
void dw_alog_3strings(char *s1, char *s2, char *s3);

/* Log a string, a number, and a string
 * input: String #1, Number, and String #2 to log;
 * minimum log level that we log this at
 * This always logs and is run before Dwood2rc file is fully parsed */
void dw_alog_number(char *s1, int number, char *s2);

/* Exit with a fatal error and log it */
void dw_fatal(char *why);

/* Set the 64-bit timestamp starting at 290805600 unix() time (When
 * the Blake's 7 episode Gambit was originally broadcast); this should
 * be called once a second or so */
void set_time();

/* Read mararc parameters and set global variables based on those
 * parameters */
void process_mararc();

/* Initialize the cache */
void init_cache();

#ifndef MINGW
/* Assign handlers for TERM, HUP, and USR1 signals, so we can write
 * the cache to a file */
void setup_signals();
#endif /* MINGW */

/* Process a signal received, writing the cache to a file */
void process_signal(int number);

/* Initialize random number generator.  */
void init_rng();

/* Drop privileges and become unprivileged user */
void sandbox();

/* Get, from the Mararc parameters, the list of bind addresses
 * we will bind to; return this list as a comma-separated dw_str */
dw_str *get_bind_addrs();

/* Make sure a DNS packet is sane, and return the packet's
 * query ID.  If roy_arends_check has a value of 1, we also make sure
 * it's a DNS question (and not a reply).  This is named in honor of
 * Roy Arends, who pointed out the original MaraDNS didn't check this.
 * If this returns -1, the packet was not sane */
int32_t get_dns_qid(unsigned char *a, int len, int roy_arends_check);

/* Given a string with a DNS packet, and the length of that string,
 * make the first two butes of the packet (the query ID) the third
 * argument (qid), and return that random number. -1 on error */
int32_t set_dns_qid(unsigned char *packet, int len, uint16_t qid);

/* This function converts a dw_str object in to a null-terminated
 * C-string with the last item in the comma-separated list in the
 * dw_str, with any leading whitespace in the last item removed */
char *pop_last_item(dw_str *list);

/* This creates a netmask from a single number, storing the number in a
 * string of octets.  0 just makes the string all 0s; 1 makes the string
 * 0x80 0x00 0x00 etc.; 2 makes the string 0xc0 0x00 etc.; etc.
 * The string of octets has a length len (4 for ipv4; 16 for ipv6) */
void make_netmask(int num, uint8_t *str, int len);

/* Get a numeric value from the mararc parameters and make sure it is
 * within a range; if def is not -1, make an out-of-range parameter
 * the def value */
int32_t get_key_n(int32_t get, int32_t min, int32_t max, int32_t def);

#endif /* __DWSYS_H_DEFINED__ */

