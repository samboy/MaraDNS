/* Placed in the public domain 2002 by Sam Trenholme */

/* This file describes compression RRs.  The format is as follows:

   rr_number: The number this RR has in a DNS packet
   compression_format: A forwat which tells us the format of
   an RR; A ";" is a delimiter; and the following descriptions
   of data are supported:

  1: This describes a number represented by a single octet

  2: This represents numerical data represented by two octets in
     big-endian format

  4: This represents numerical data represented by four octets in
     big-endian or dotted-decimal format

  D: This represents a domain name label

  T: This represents a text record; a single octet indicating the
     length of a string followed by the string in question

  V: This represents variable-length data not to be parsed; this can
     only be the last or only atom in an RR.

  */

/* The format of this data is described in detail in the
   "describing_dns_rrs" document;
   Basically: rr_number|rr_description|to_compress|text_description;
*/

#define RR_COUNT 17

/* These are deliberately out of order so that common RRs are
   first in the list to speed up lookups */

#ifndef __MARADNS_COMPRESS_RRDESCS
#define __MARADNS_COMPRESS_RRDESCS 1
char *rr_descs[RR_COUNT] = {
  ":1|A|4|N|en;IPv4 Addresses [RFC 1035];",
  ":15|MX|2;D|C|en;Mail exchanger records [RFC 1035];",
  ":2|NS|D|C|en;NS (name server) records [RFC 1035];",
  ":6|SOA|D;D;4;4;4;4;4|C|en;SOA records [RFC 1035];",
  ":12|PTR|D|C|en;Reverse DNS lookup records [RFC 1035];",
  ":16|TXT|T;V|N|en;Text data [RFC 1035];",
  ":5|CNAME|D|C|en;CNAME records [RFC 1035];",
  ":3|MD|D|N|en;[RFC 1035];",
  ":4|MF|D|N|en;[RFC 1035];",
  ":7|MB|D|N|en;[RFC 1035];",
  ":8|MG|D|N|en;[RFC 1035];",
  ":9|MR|D|N|en;[RFC 1035];",
  ":14|MINFO|D;D|N|en;[RFC 1035];",
  ":17|RP|D;D|N|en;[RFC 1183];",
  ":18|AFSDB|2;D|N|en;[RFC 1183];",
  ":21|RT|2;D|N|en;[RFC 1183];",
  ":33|SRV|2;2;2;D|N|en;Service [RFC 2052];" };
#endif /* __MARADNS_COMPRESS_RRDESCS */

