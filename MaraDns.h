/* Copyright (c) 2002-2020 Sam Trenholme
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

#ifndef MARADNSH_DEFINED
#define MARADNSH_DEFINED

/* Some constants that are fairly OS specific, concerning the amount of
 * memory threads can use.  These numbers should be higher than the
 * maximum possible thread overhead */
/* The amount of memory used to have threads at all */
#define THREAD_OVERHEAD 536870912
/* The amount of memory a single thread will use */
#define PER_THREAD_MEM 16777216

#include <stdint.h>

/* This is the root server list as of 2007/11/15; the root servers were
 * last changed 2007/11/01 */
/* 2020 update: No longer used; Deadwood has different root server list. 
 * Actually, these days Deadwood has an upstream server list, and only
 * has root servers in documentation examples */
#define ROOT_SERVERS "198.41.0.4"       /* a.root-servers.net (VeriSign) */ \
                     ",192.228.79.201"  /* b.root-servers.net (ISI) */ \
                     ",192.33.4.12"     /* c.root-servers.net (Cogent) */ \
                     ",128.8.10.90"     /* d.root-servers.net (UMaryland) */ \
                     ",192.203.230.10"  /* e.root-servers.net (NASA Ames) */ \
                     ",192.5.5.241"     /* f.root-servers.net (ISC) */ \
                     ",192.112.36.4"    /* g.root-servers.net (DOD NIC) */ \
                     ",128.63.2.53"     /* h.root-servers.net (ArmyRU) */ \
                     ",192.36.148.17"   /* i.root-servers.net (NORDUnet) */ \
                     ",192.58.128.30"   /* j.root-servers.net (VeriSign) */ \
                     ",193.0.14.129"    /* k.root-servers.net (Reseaux) */ \
                     ",199.7.83.42"     /* l.root-servers.net (IANA) */ \
                     ",202.12.27.33"    /* m.root-servers.net (WIDE) */

/* The default UID (User ID) that MaraDNS has; I put this here so packagers
   can change this easily.  This should be the 'nobody' user, or, optionally
   a special 'MaraDNS' user.  This user needs to be able to enter
   the /etc/maradns directory, and read all zone files in /etc/maradns

   If you change this from 707, please also change the mararc man page, 
   which states the default value for this is 707.  To change the 
   man page:

   * Enter the doc/en/source directory

   * Modify the mararc.ej file

   * Enter the doc/en/man directory

   * If you have a recent version of Perl on your system, you should be
     able to update the man page by typing in 'make'.

   * Enter the doc/en/tutorial directory

   * Enter the doc/en/tutorial/text directory

   * If Bash is at /bin, you should be able to update the text documentation
     by typing in make.  Otherwise, change the tools/ej/ej2txt file's first
     line to point to Bash
 */

#define MARADNS_DEFAULT_UID 707

/* The default GID (Group ID) that MaraDNS has; see the default UID notes
   above.  Again: CHANGE THE MARARC MAN PAGE IF YOU CHANGE THIS VALUE */
#define MARADNS_DEFAULT_GID 707

/* The UID that the Duende logging process uses.  CHANGE THE DUENDE MAN
   PAGE IF YOU CHANGE THIS VALUE (same general process as changing the
   mararc man page; the source file for the duende man page is duende.ej) */
#define DUENDE_LOGGER_UID 707

/* The directory that Duende runs in.  This directory has to exist for
   Duende to be able to run.  Again, IF YOU CHANGE THIS, CHANGE THE
   DUENDE MAN PAGE */
#define DUENDE_CHROOT_DIR "/etc/maradns/logger"

/* The default IP address that Askmara uses; this used to be 127.0.0.3
   but is now 127.0.0.1 because many non-Linux systems only use 127.0.0.1
   for the loopback interface.  IF YOU CHANGE THIS, CHANGE THE ASKMARA
   MAN PAGE (askmara.ej) */
#define ASKMARA_DEFAULT_SERVER "127.0.0.1"

/* The default port to bind the DNS server to, and the port that askmara uses
   to bind to.  Note that a lot of MaraDNS' messages are hard-coded
   to say that we are binding on port 53, so only change this for
   debugging purposes.  I use this so that I can debug MaraDNS on
   systems where I do not have root. */
#define DNS_PORT 53

/* The default port to use when contacting remove DNS servers; it may
 * be desirable to have two instances of MaraDNS on the same IP when
 * resolving the dangling CNAME issue on a machine with only one
 * loopback IP (You would * think, with an entire Class A of the IP
 * space reserved for loopback, * more systems would have at least
 * two loopback IPs.  You would be wrong)
 */
#define UPSTREAM_PORT 53

/* Whether we allow MaraDNS to run as a non root user; this is usually
 * disabled, but can be enabled by uncommenting the following line */
/* #define ALLOW_NON_ROOT */

/* The maximum allowed size of a zone name */
#define MAX_ZONE_SIZE 256

#ifndef JS_STRING_INCLUDED
#include "libs/JsStr.h"
#endif

/* The encoding for the strings in the configuration files (3: iso 8859-1) */
#define MARA_LOCALE 3

/* The data types for 32-bit signed and unsigned data */
#define int32 int32_t
#define uint32 uint32_t

/* These data types need to store at least 16 bits, and can store more */
#define int16 int16_t
#define uint16 uint16_t

#ifdef MINGW32
#define MSG_WAITALL 0
#define socklen_t int
#endif /* MINGW32 */

/* The data type used for storing "perm" bits (who gets to view a given
 * DNS record; based on IP) */
#define perm_t uint16

/* The timestamp which MaraDNS now uses; she is now Y2038-complient
   on (what will be by then) legacy systems with a 32-bit time_t
 */
#ifndef MINGW32
#define qual_timestamp int64_t
#else
#define qual_timestamp long long
#endif
/* The magic "Never expire" time */
#define NEVER_EXPIRE 0

/* Structure that holds the information about either a ipv4 or ipv6
 * connection */
typedef struct {
   unsigned char type; /* Type: 4 is ipv4; 6 is ipv6 */
   void *d; /* Data */
   int addrlen;
   } conn;

/* Structure that holds an IPV4 IP and netmask */
typedef struct {
    uint32 ip;
    uint32 mask;
    } ipv4pair;

/* Structure which is a bidirectional linked list which lists which RRs to axe
   next when the cache runs low on free spots */
typedef struct fila { /* Fila: Spanish for "line" */
    struct fila *siguiente; /* Spanish for "next" */
    struct fila *previous;
    unsigned char datatype; /* 0:rr 1:closer */
    void *record; /* This points to the record that this particular element
                     uses */
    js_string *hash_point; /* This points to the query which generates
                              the record in question */
    char nukable_hp; /* Whether the hash point string shold be destroyed
                        when we remove this fila element. 1: Yes, nuke
                        the hash_point string; 0: No, keep the hash
                        point string */
    } fila;

/* DNS server that is closer to the answer for a given request */
typedef struct closer {
    unsigned int num_elements; /* Number of elements in the linked list */
    qual_timestamp ttd; /* Time for this record to die */
    int datatype; /* This is the RR type of the data (RR_A [in which
                     case, the data is a pointer to a uint32] or RR_NS [which
                     makes the data point to a js_string object]) */
    void *data;
    fila *zap; /* So that we can determine in which order to zap RRs */
    struct closer *masked; /* If another record with a ttd after the
                              ttd for this record exists, we want to
                              access that data when this record expires */
    struct closer *next; } closer;

/* Structure which contains the data for a DNS record pointed to from
   the hash */
typedef struct rr {
    qual_timestamp expire; /* When this RR expires (0=authoritative/never) */
    uint32 ttl; /* The TTL for the record in question */
    uint32 authoritative; /* Are we authoritative for this zone */
    struct rr *next; /* Either the first NS for this zone _or_ the next copy
                        of the same record for the same data type */
    struct rr *ip; /* If this is a PTR, MX, or NS record, pointer to the
                      ip the rr domain name points to (if applicable) */
#ifdef IPV6
    struct rr *ip6; /* It's the 2010s and time to link to IPv6 glue */
#endif
    js_string *ptr; /* If this is a PTR request pointing to a CNAME,
                       we want to give them the PTR record along
                       with the CNAME record. */
    uint16 rr_type; /* Type of resource record this entry is */
    js_string *query; /* Pointer to the query one asks to get this answer */
    js_string *data; /* The actual raw binary data for this RR */
    fila *zap; /* Pointer to a structure used for deleting elements from
                  the cache when the cache starts to fill up */
    char seen; /* This is used by udpsuccess() to insure that a given
                  element in the hash is only visited once */
    perm_t perms; /* What IPs can view this element; making this zero
                     means that all IPs can view the element in question */
    struct rr_list *list; /* rr_list of all records this CNAME refers to */
    char rcode; /* This is used to store the rcode for a given DNS answer */
    } rr;

/* Structure for a linked list used in the ANY (and CNAME) rr type */
typedef struct rr_list {
    uint16 rr_type;
    rr *data;
    struct rr_list *next;
    } rr_list;

/* Structure which contains the header as described in Section 4.1.1 of
   RFC1035 */
typedef struct {
    uint16 id; /* 16-bit unsigned ID of Query */
    int qr; /* Boolean query-type (query or answer) */
    int opcode; /* 4-bit opcode flag */
    int aa; /* boolean Authoritative Answer */
    int tc; /* boolean truncation flag */
    int rd; /* boolean "recursion desired" flag */
    int ra; /* boolean "recursion available" flag */
    int z; /* 3-bit reserved "z" flags.  Keep 0 */
    int rcode; /* 4-bit rcode flag */
    uint16 qdcount; /* 16-bit unsigned # of questions */
    uint16 ancount; /* 16-bit unsigned # of answers */
    uint16 nscount; /* 16-bit unsigned # of NS answers */
    uint16 arcount; /* 16-bit unsigned # of additional records */
    } q_header;

/* DNS Question as described in Section 4.1.2 of RFC1035 */
typedef struct {
    js_string *qname; /* Special RFC1035 format of domain name */
    uint16 qtype; /* 16-bit query type */
    uint16 qclass; /* 16-bit query class */
    } q_question;

/* RR format as described in section 4.1.3 of RFC1035 */
typedef struct {
    js_string *name; /* Special RFC1035 format of domain name */
    uint16 type; /* 16-bit record type */
    uint16 class; /* 16-bit record class */
    uint32 ttl; /* 32-bit ttl */
    uint16 rdlength; /* 16-bit length of the RDATA field */
    js_string *rdata; /* variable length resource data */
    } q_rr;

/* This is, as of June 23 2006, a list of all DNS RRs over at
   http://www.iana.org/assignments/dns-parameters */
/* Some query types and their RFC1035 section 3.2.2 values */
/* A record: RFC1035 section 3.4.1 */
#define RR_A 1
/* NS record: RFC1035 section 3.3.11 */
#define RR_NS 2
/* Obsolete; RFC1035 */
#define RR_MD 3
/* Obsolete; RFC1035 */
#define RR_MF 4
/* CNAME: RFC1035 section 3.3.1 */
#define RR_CNAME 5
/* SOA: RFC1035 section 3.3.13 */
#define RR_SOA 6
/* EXPERIMENTAL RFC1035 RRs */
#define RR_MB 7
#define RR_MG 8
#define RR_MR 9
#define RR_NULL 10
/* Non-experimental RFC1035 RR */
#define RR_WKS 11
/* PTR: RFC1035 section 3.3.12 */
#define RR_PTR 12
/* Two more RFC1035 RRs */
#define RR_HINFO 13
#define RR_MINFO 14
/* MX: RFC1035 section 3.3.9 */
#define RR_MX 15
/* TXT: RFC1035 section 3.3.14 */
#define RR_TXT 16
/* RFC1183 RRs */
#define RR_RP 17
#define RR_AFSDB 18
#define RR_X25 19
#define RR_ISDN 20
#define RR_RT 21
/* RFC1706 RRs */
#define RR_NSAP 22
#define RR_NSAP_PTR 23
/* RFC2535, RFC3755, and RFC4034 RRs */
#define RR_SIG 24
#define RR_KEY 25
/* RFC2163 RR */
#define RR_PX 26
/* RFC1712 RR */
#define RR_GPOS 27
/* AAAA: ipv6 addresses (Not in an RFC) */
#define RR_AAAA 28
/* RFC1876 */
#define RR_LOC 29
/* Obsolete RFC2535 and RFC3755 RR */
#define RR_NXT 30
/* "Endpoint" (Not in an RFC) */
#define RR_EID 31
/* "Nimrod" (Not in an RFC) */
#define RR_NIMLOC 32
/* SRV: "service" records (RFC2782) */
#define RR_SRV 33
/* "ATM address" (Not in an RFC) */
#define RR_ATMA 34
/* RFC2168,RFC2915,RFC3403 */
#define RR_NAPTR 35
/* RFC2230 */
#define RR_KX 36
/* RFC2538 */
#define RR_CENT 37
/* DON'T USE THIS A6 RR; harmful RFC2874 */
#define RR_A6 38
/* Again, harmful for same reason A6 is harmful; RFC2672 */
#define RR_DNAME 39
/* Kitchen Sink RR (Not in an RFC; looks to be a joke but BIND supports it) */
#define RR_SINK 40
/* RFC2671 */
#define RR_OPT 41
/* RFC3123 */
#define RR_APL 42
/* RFC3658 */
#define RR_DS 43
/* RFC4255 */
#define RR_SSHFP 44
/* RFC4025 */
#define RR_IPSECKEY 45
/* 3 RFC3755 RRs */
#define RR_RRSIG 46
#define RR_NSEC 47
#define RR_DNSKEY 48
/* 49-98 are unassigned as of 2006/06/23 */
/* SPF: sender policy framework (stops forged email) record */
#define RR_SPF 99
/* Four RRs not in an RFC but are IANA-reserved */
#define RR_UINFO 100
#define RR_UID 101
#define RR_GID 102
#define RR_UNSPEC 103
/* 104-248 are unassigned as of 2006/06/23 */
/* RFC2930 */
#define RR_TKEY 249
/* RFC2845 */
#define RR_TSIG 250
/* RFC251 (treated as AXFR by zoneserver) */
#define RR_IXFR 251
/* AXFR: Special query that requests a zone transfer */
#define RR_AXFR 252
/* RFC1035; not officially obsolete but for all practical purposes
   obsolete */
#define RR_MAILB 253
/* MAILA is officially obsolete */
#define RR_MAILA 254
/* ANY: Special query for all of the records for a given hostname */
#define RR_ANY 255
/* This is not assigned by the IANA, but BIND uses this RR number */
#define RR_ZXFR 256
/* "DNSSEC Trust Authorities"; Not in an RFC */
#define RR_TA 32768
/* RFC4431 */
#define RR_DLV 32769
/* Some "magic" RR types used by askmara */
/* RR_MAGIC_SPACE: Make the character representing the RR a space */
#define RR_MAGIC_SPACE -300
/* RR_MAGIC_EMAIL: Make the character representing the RR a space, and
 * make the first "dot" an at */
#define RR_MAGIC_EMAIL -301

/* The following formats use a single domain name as the data:
   NS CNAME PTR (MB MD MF MG)
*/
#define rr_ns *js_string
#define rr_cname *js_string
#define rr_ptr *js_string

/* The A record is a single unsigned 32-bit integer */
#define rr_a uint32

/* The other supported types we make structures of */

/* SOA: RFC1035 3.3.13 */
typedef struct {
    js_string *mname; /* The name server with authoritative data */
    js_string *rname; /* Domain-name style data: email address */
    uint32 serial; /* 32-bit serial */
    int32 refresh; /* How often slave servers look at the serial to
                    see if it should be refreshed */
    int32 retry; /* How often slave servers should look at the serial when
                  the server is down */
    int32 expire; /* How long before the slave servers "give up" on looking
                   at data from the master server when the master server
                   dies */
    uint32 minimum; /* Default TTL for all RRs in the zone */
    } rr_soa;

/* MX: RFC1035 section 3.3.9 */
typedef struct {
    int16 preference; /* Lower preference MXs are tried before higher
                         preference MXs */
    js_string *exchange; /* Domain-name style data, the actual mail
                            exchanger */
    } rr_mx;

/* The TXT record is a single RFC1035-style character-string */
#define rr_txt *js_string;

/* The various error codes we place in the RCODE section of the header */
#define FORMAT_ERROR 1
#define SERVER_FAIL 2
#define NXDOMAIN_RCODE 3
#define NOT_IMPLEMENTED 4
#define REFUSED 5

/* The longest RRs which we allow to exist in csv1 zone files.
   Warning: If you make this longer, then there is a significant
   risk that the record will be longer than the 512 bytes allowed
   in a DNS packet.  MaraDNS does not current support DNS over TCP.
*/

#define MAX_RECORD_LENGTH 425

#endif /* MARADNSH_DEFINED */
