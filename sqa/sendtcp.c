/* Placed in the public domain 2004 by Sam Trenholme */

/* This is like sendudp, but sends a TCP packet instead of a UDP
   packet.  Used in stress testing of zone server, where we do not need to
   see the answer */

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../MaraDns.h"
/* All of the labels */
#include "../tools/askmara_labels_en.h"
#include "../tuzona/getzone_locale.h"
/* Yes, we use the RNG to make the psudo-random number */
#include "../rng/rng-api-fst.h"

int verbose_mode = 0; /* Whether to have short or verbose output */

/* Generate a psudo-random query-id based on the hostname we give it.
   This helps us test the server against a large number of query IDs */

u_int16_t gen_id(char *hostname) {
    /* May as well bring out the bug guns (e.g. our secure RNG) */
    MARA_BYTE r_inBlock[17],r_outBlock[17],r_binKey[17];
    MARA_BYTE r_keyMaterial[320];
    keyInstance r_keyInst;
    cipherInstance r_cipherInst;
    unsigned char crypto_key[34];
    int desc, len;

    if(hostname == 0)
        return JS_ERROR;

    /* Initialize the keys, including the "binKey" (is this used?) */
    memset(r_binKey,'0',16);
    memset(crypto_key,'z',16);
    /* Make the first 16 characters of the hostname the key (padded by the
       z character) */
    strncpy(crypto_key,hostname,16);
    /* Set the plaintext block to 'zzzzzzzzzzzzzzzz' */
    memset(r_inBlock,'z',16);
    /* If the hostname is longer than 16 characters, make the plaintext
       the longer part of the hostname */
    if(js_strnlen(hostname,1000000) > 16)
    strncpy(r_inBlock,hostname+16,16);

    if(makeKey(&r_keyInst, DIR_ENCRYPT, 128, crypto_key) != 1)
        return JS_ERROR;
    if(cipherInit(&r_cipherInst, MODE_ECB, NULL) != 1)
        return JS_ERROR;
    if(blockEncrypt(&r_cipherInst,&r_keyInst,r_inBlock,128,r_outBlock) != 128)
        return JS_ERROR;

    return ((r_outBlock[0] << 8) & 0xff00) | (r_outBlock[1] & 0x00ff);
    }

int harderror(char *msg) {
    if(verbose_mode == 0)
        printf("# ");
    printf("%s%s%s",L_HARD_ERROR,msg,L_NEWLINE);
    exit(1);
    }

main(int argc, char **argv) {
    char *server_address = NULL;
    struct sockaddr_in dns_udp, server;
    int len_inet; /* Length */
    int s; /* Socket */
    int q; /* Used for binding, etc */
    js_string *outdata; /* Outgoing data */
    js_string *indata, *uindata; /* Incoming data (uncompressed version) */
    q_header header; /* header data */
    q_question question;
    int counter,place,count;
    fd_set rx_set; /* Using select() because if its timeout option */
    int maxd;      /* select() */
    struct timeval tv;  /* select() */
    struct sockaddr_in zone_server; /* AF_INET */
    int n; /* Select() return value */
    unsigned char len[2]; /* Two-byte TCP length header */

    /* Determine what the query string is */
    if(argc < 2 || argc > 4)
        harderror(L_USAGE);

    /* See if we are in verbose mode or not */
    verbose_mode = 0;
    if(argc >= 3 && *argv[1] == '-')
        verbose_mode = 1;

    /* Determine what IP address to connect to */
    if(argc == 3 + verbose_mode)
        server_address = argv[2 + verbose_mode];
    else
        server_address = "127.0.0.3";

    if((indata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_INDATA);
    if((uindata = js_create(2048,1)) == 0)
       harderror(L_JS_CREATE_UINDATA);
    if((outdata = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_OUTDATA);
    if((question.qname = js_create(512,1)) == 0)
       harderror(L_JS_CREATE_QNAME);
    /* Create a UDP client socket */
    if((s = socket(AF_INET,SOCK_DGRAM,0)) == -1)
        harderror(L_SOCKET);

    /* Create a TCP/IP socket */
    s = socket(PF_INET,SOCK_STREAM,0);
    if(s == -1)
        harderror(L_NO_SOCK); /* "Unable to create TCP socket" */

    /* Set up the "zoneserver" structure (the structure used for
       the IP of the machine we connect and send the TCP query to) */
    memset(&zone_server,0,sizeof zone_server);
    zone_server.sin_family = AF_INET;
    zone_server.sin_port = htons(DNS_PORT); /* DNS_PORT: Normally 53 */
    zone_server.sin_addr.s_addr = inet_addr(server_address);
    if(zone_server.sin_addr.s_addr == INADDR_NONE)
        harderror(L_MAL_IP);

    len_inet = sizeof zone_server;

    /* Connect to the zone server */
    if(connect(s,(struct sockaddr *)&zone_server,len_inet) == -1)
        harderror(L_NO_CONNECT); /* "Unable to connect to zone server" */

    /* udp stuff; cruft at this point but this is a debug program,
       not a part of production code */
    /*
    memset(&dns_udp,0,sizeof(dns_udp));
    dns_udp.sin_family = AF_INET; */
    /* When debugging MaraDNS on systems where I do not have root, it is
       useful to be able to contact a MaraDNS server running on a high
       port number.  However, DNS_PORT should be 53 otherwise (defined
       in MaraDNS.h) */
    /* dns_udp.sin_port = htons(DNS_PORT);
    if((dns_udp.sin_addr.s_addr = inet_addr(server_address)) == INADDR_NONE)
        harderror(L_MAL_IP); */

    /* len_inet = sizeof(dns_udp); */

    /* Format a DNS request */
    /* DNS header -> using dig defaults */
    header.id = gen_id(argv[1 + verbose_mode]);
    header.qr = 0;
    header.opcode = 0;
    header.aa = 0;
    header.tc = 0;
    header.rd = 1; /* Recursion desired */
    header.ra = 0;
    header.z = 0;
    header.rcode = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    /* Create a DNS question , and put it in raw UDP format */
    /* DNS question -> looking up an A record... */
    question.qclass = 1; /* ...on the internet */
    if(js_qstr2js(question.qname,argv[1 + verbose_mode]) == JS_ERROR)
        harderror(L_INVALID_Q); /* Invalid query */

    /* Make sure that the csv1-compatible output hashes all non-RR
       output */
    if(verbose_mode == 0)
        printf("# ");

    printf("%s%s%s",L_QUERYING,server_address,L_NEWLINE); /* Querying the server with the IP... */

    /* Make 'Aexample.com.' raw UDP (ok, TCP) data */

    /* Hack: we allow "X" to be an AXFR (zone transfer) */
    if(*question.qname->string == 'X') {
        place = 252; /* 252: AXFR */
        if(hname_2rfc1035(question.qname) == JS_ERROR)
            harderror(L_INVALID_DQ); /* Invalid form of domain query */
        }
    else { /* If we don't ask for an AXFR, get it from the query */
        place = hname_2rfc1035(question.qname);
        }
    if(place == JS_ERROR)
        harderror(L_INVALID_DQ); /* Invalid form of domain query */
    question.qtype = place;

    /* Make a string containing the RAW UDP (ok, TCP) query */
    make_hdr(&header,outdata);
    make_question(&question,outdata);

    /* Send out a TCP DNS request */
    /* Two-byte length header */
    len[0] = (outdata->unit_count & 0xff00) >> 8;
    len[1] = outdata->unit_count & 0xff;
    if(write(s,len,2) == -1)
        harderror(L_SEND_2MARA_BYTE); /* "Could not send 2-byte length header
                                     to zone server" */
    /* Body of request */
    if(write(s,outdata->string,outdata->unit_count) == -1)
        harderror(L_SEND_QUERY); /* "Could not send query to zone server" */
    /* if(sendto(s,outdata->string,outdata->unit_count,0,
       (struct sockaddr *)&dns_udp,len_inet) < 0)
        harderror(L_UDP_NOSEND); *//* Unable to send UDP packet */

    close(s); /* We disconnect; maybe we should read whatever they send
                 then disconnect */

    /* Bye bye */
    exit(0);
    return 0;
    }

