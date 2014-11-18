/* Copyright (c) 2002-2006 Sam Trenholme
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

/* Routines for converting varous query data specified in RFC1035 in to
   data to send over the network */

#include "../MaraDns.h"
#include "functions_dns.h"

/* Determine the length of a domain-name label (if it is a compressed
   label, determine the length of the compressed portion)
   Input: the js_string obejct with the domain label in question,
          the offset from the beginning of the js_string object
          with the domain label
   Output: The length of the label, JS_ERROR on error
*/

int dlabel_length(js_string *raw, unsigned int offset) {

    int length;
    unsigned char toread;

    /* Sanity checks */
    if(js_has_sanity(raw) == JS_ERROR)
        return JS_ERROR;
    if(raw->unit_size != 1)
        return JS_ERROR;

    length = 0;
    if(offset > raw->unit_count)
        return JS_ERROR;
    toread = *(raw->string + offset);
    while(length < 256 && toread > 0 && toread != '_') {
        if(toread >= 192) /* compressed label */ {
            if(length + 2 + offset <= raw->unit_count)
               return length + 2;
            else
               return JS_ERROR;
            }
        if(toread > 63)
            return JS_ERROR; /* No EDNS support */
        length += toread + 1;
        /* Go to the next jump */
        if(length + offset > raw->unit_count)
            return JS_ERROR;
        toread = *(raw->string + length + offset);
        }

    if(length + 1 + offset <= raw->unit_count)
        return length + 1;

    return JS_ERROR;

    }

/* Given a q_header structure, initialize the values of the structure
   to sane values */

void init_header(q_header *header) {
    header->id = 0;
    header->qr = 0;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 0;
    header->ra = 0;
    header->z  = 0;
    header->rcode = 0;
    header->qdcount = 0;
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    }

/* Given a q_header structure, and a js object to put the raw UDP data
   in, convert a q_header structure to raw UDP data.
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int make_hdr(q_header *header, js_string *js) {
    unsigned char *raw; /* Raw data to be made js_string */

    /* Some sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
       return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->max_count < 14)
        return JS_ERROR;

    /* Speed things up by making this zero-copy */
    raw = js->string;

    /* Conversion is fairly straightforward */
    raw[0] = (header->id & 0xff00) >> 8;
    raw[1] = (header->id & 0x00ff);
    /* All the flags and 4-bit fields are a little tricky */
    raw[2] = raw[3] = 0;
    if(header->qr == 1)
        raw[2] |= 0x80;
    raw[2] |= (header->opcode & 0x0f) << 3;
    if(header->aa == 1)
        raw[2] |= 0x04;
    if(header->tc == 1)
        raw[2] |= 0x02;
    if(header->rd == 1)
        raw[2] |= 0x01;
    if(header->ra == 1)
        raw[3] |= 0x80;
    raw[3] |= (header->z & 0x07) << 4;
    raw[3] |= (header->rcode & 0x0f);
    /* Now the four unsigned 16-bit fields */
    raw[4] = (header->qdcount & 0xff00) >> 8;
    raw[5] = (header->qdcount & 0x00ff);
    raw[6] = (header->ancount & 0xff00) >> 8;
    raw[7] = (header->ancount & 0x00ff);
    raw[8] = (header->nscount & 0xff00) >> 8;
    raw[9] = (header->nscount & 0x00ff);
    raw[10] = (header->arcount & 0xff00) >> 8;
    raw[11] = (header->arcount & 0x00ff);

    /* Finally, make all that a legit js string */
    if(js->max_count >= 12)
        js->unit_count = 12;

    return JS_SUCCESS;
    }


/* Given a q_header structure, and a js object with the raw UDP data,
   convert raw UDP data to a q_header structure.
   input: pointer to q_header structure, pointer to js_string object
   output: JS_ERROR on error, JS_SUCCESS on success
*/

int read_hdr(js_string *js, q_header *header) {
    unsigned char *raw; /* Raw data to be made js_string */

    /* Some sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
       return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js->max_count < 14)
        return JS_ERROR;

    raw = js->string;

    /* Conversion is fairly straightforward */
    header->id = raw[0] << 8 | raw[1];
    /* All the flags and 4-bit fields are a little tricky */
    if(raw[2] & 0x80)
        header->qr = 1;
    else
        header->qr = 0;
    header->opcode = (raw[2] & 0x78) >> 3;
    if(raw[2] & 0x04)
        header->aa = 1;
    else
        header->aa = 0;
    if(raw[2] & 0x02)
        header->tc = 1;
    else
        header->tc = 0;
    if(raw[2] & 0x01)
        header->rd = 1;
    else
        header->rd = 0;
    if(raw[3] & 0x80)
        header->ra = 1;
    else
        header->ra = 0;
    header->z = (raw[3] & 0x70) >> 4;
    header->rcode = raw[3] & 0x0f;
    /* Now the four unsigned 16-bit fields */
    header->qdcount = raw[4] << 8 | raw[5];
    header->ancount = raw[6] << 8 | raw[7];
    header->nscount = raw[8] << 8 | raw[9];
    header->arcount = raw[10] << 8 | raw[11];

    return JS_SUCCESS;

    }

/* Given a js string object and a q_question structure, place the raw UDP
   format of the query at the end of the js_string object
   input: see above
   output: JS_ERROR on error, JS_SUCCESS on success */

int make_question(q_question *question, js_string *js) {
    int counter;

    unsigned char toread, read;

    int offset = js->unit_count;

    unsigned char *raw;

    counter = toread = 0;

    /* Some sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js_has_sanity(question->qname) == JS_ERROR)
        return JS_ERROR;
    if(question->qname->unit_size != 1)
        return JS_ERROR;
    if(offset >= js->max_count)
        return JS_ERROR;

    raw = question->qname->string;

    /* Copy over the domain-name string in to the js_string object */
    while(counter < 256) {
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < question->qname->max_count &&
               counter + offset < js->max_count)
                /* Then copy the character over */
                *(js->string + offset + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }
        }

    /* Since counter is now sitting on the dot after .com, increment it */
    *(js->string + offset + counter) = 0;
    counter++;

    /* Add the QTYPE and QCLASS to the raw UDP data */
    if(counter + offset + 4 < js->max_count) {
        raw = js->string + counter + offset;
        raw[0] = (question->qtype & 0xff00) >> 8;
        raw[1] = question->qtype & 0x00ff;
        raw[2] = (question->qclass & 0xff00) >> 8;
        raw[3] = question->qclass & 0x00ff;
        }
    else
        return JS_ERROR;

    /* Resize the modified js string */
    if(js->max_count > counter + offset + 4)
        js->unit_count = counter + offset + 4;

    return JS_SUCCESS;

    }

/* Given a js string object and an offset (where we begin reading our
   question), in addition to a q_question structure, read the raw UDP
   format of the query in to the q_question structure
   input: see above
   output: JS_ERROR on error, number of bytes in question on success */

int read_question(js_string *js,q_question *question, int offset) {
    int counter;

    unsigned char toread, read;

    unsigned char *raw;

    counter = toread = 0;

    /* Some sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js_has_sanity(question->qname) == JS_ERROR)
        return JS_ERROR;
    if(question->qname->unit_size != 1)
        return JS_ERROR;
    if(offset >= js->unit_count)
        return JS_ERROR;

    raw = js->string + offset;

    /* Copy over the domain-name string inside the js_string object */
    while(counter < 256) {
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < question->qname->max_count &&
               counter + offset < js->unit_count)
                /* Then copy the character over */
                *(question->qname->string + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }

        }

    /* Since counter is now sitting on the dot after .com, increment it */
    *(question->qname->string + counter) = 0;
    counter++;

    /* Get the QTYPE and QCLASS from the raw UDP data */
    if(counter + offset + 4 <= js->unit_count) {
        raw = js->string + counter + offset;
        question->qtype = (raw[0] << 8 & 0xff00) | (raw[1] & 0xff);
        question->qclass = (raw[2] << 8 & 0xff00) | (raw[3] & 0xff);
        }
    else
        return JS_ERROR;

    /* Resize the qname string in the question structure */
    if(counter < question->qname->max_count)
        question->qname->unit_count = counter;
    else
        return JS_ERROR;

    return counter + 4;

    }

/* Zero-copy implemention of converting the raw UDP data for a domain in
   to a human-readable host name.
   Input:  pointer to js_string object we modify "in place", query type
           (-2 if we wish to make it show a pipe)
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int hname_translate(js_string *hostname, int qtype) {
    int counter = 0, special_root_case = 0;
    unsigned char toread = 0;
    unsigned char *raw = 0;
    int dotseen = 0;

    /* Sanity checks */
    if(js_has_sanity(hostname) == JS_ERROR)
        return JS_ERROR;
    if(hostname->unit_size != 1)
        return JS_ERROR;
    if(hostname->unit_count < 1)
        return JS_ERROR;

    /* Store the length of the first part of the hostname */
    toread = *(hostname->string);

    /* Handle the special case of a zero-length zone name */
    if(hostname->unit_count == 1 && toread == 0)
        special_root_case = 1;

    /* Change the first letter based on the Query type */
    raw = hostname->string;
    switch(qtype) {
        case RR_A:
            *raw = 'A';
            break;
        case RR_NS:
            *raw = 'N';
            break;
        case RR_CNAME:
            *raw = 'C';
            break;
        case RR_SOA:
            *raw = 'S';
            break;
        case RR_PTR:
            *raw = 'P';
            break;
        case RR_MX:
            *raw = '@';
            break;
        case RR_TXT:
            *raw = 'T';
            break;
        case RR_ANY:
            *raw = 'Z';
            break;
        case -2: /* Special command to make it a pipe */
            *raw = '|';
            break;
        case RR_MAGIC_SPACE: /* Special command to make it a space */
        case RR_MAGIC_EMAIL: /* Same as magic space, but make the first
                              * seperator an @ instead of a dot */
            *raw = ' ';
            break;
        default:
            *raw = 'U';
        }

     /* Again, handle the special case of a zero-length host name
        (the "root" of the DNS tree) */
     if(special_root_case == 1) {
        if(hostname->max_count < 2)
            return JS_ERROR;
        hostname->unit_count = 2;
        raw++;
        *raw = '.';
        return JS_SUCCESS;
        }

     /* Convert the hostname delimters in to dots */
     counter = 0;
     dotseen = 0;
     while(counter < 256 && toread > 0) {
         if(toread > 63)
             return JS_ERROR; /* To do: compression support */
         counter += toread + 1;
         /* Get the next "jump" we need to do */
         if(counter > hostname->unit_count)
             return JS_ERROR;
         toread = *(raw + counter);
         /* Buffer overflow protection */
         if(counter <= hostname->unit_count) {
             if(qtype != RR_MAGIC_EMAIL || dotseen > 0) {
                 *(raw + counter) = '.';
             } else {
                 *(raw + counter) = '@';
                 dotseen = 1;
             }
         } else {
             return JS_ERROR;
             }
         }

     return JS_SUCCESS;
     }

/* Zero-copy implemention of converting the raw UDP data for a domain in
   to a human-readable email address
   Input:  pointer to js_string object we modify "in place"
   Output: JS_ERROR on error, JS_SUCCESS on success
*/

int email_translate(js_string *hostname) {
    int counter;
    unsigned char toread;
    int first = 1;
    unsigned char *raw;

    /* Sanity checks */
    if(js_has_sanity(hostname) == JS_ERROR)
        return JS_ERROR;
    if(hostname->unit_size != 1)
        return JS_ERROR;
    if(hostname->unit_count < 1)
        return JS_ERROR;

    /* Store the length of the first part of the hostname */
    toread = *(hostname->string);

    /* Change the first letter based on the Query type */
    raw = hostname->string;
    *raw = '|';

     /* Convert the hostname delimters in to dots */
     counter = 0;
     while(counter < 256 && toread > 0) {
         if(toread > 63)
             return JS_ERROR; /* To do: compression support */
         counter += toread + 1;
         /* Get the next "jump" we need to do */
         if(counter > hostname->unit_count)
             return JS_ERROR;
         toread = *(raw + counter);
         /* Buffer overflow protection */
         if(counter <= hostname->unit_count) {
             if(first) {
                 *(raw + counter) = '@';
                 first = 0;
                 }
             else {
                 *(raw + counter) = '.';
                 }
             }
         else
             return JS_ERROR;
         }

     return JS_SUCCESS;
     }

/* Zero-copy implemention of converting a human-readable host name in to the
   raw RFC1035 UDP data for a domain.
   Input:  pointer to js_string object we modify "in place"
   Output: -1 on error, numeric type of query on success, -2 on
           unsupported query type, -3 on 'U' query type (which
           then has to be specified by the user elsewhere)
*/

int hname_2rfc1035(js_string *hostname) {
    return hname_2rfc1035_starwhitis(hostname,0);
    }

/* Starwhitis: 0: Stars *not* allowed at end of host name
               1: Stars are allowed at host name ends */

int hname_2rfc1035_starwhitis(js_string *hostname, int starwhitis) {
    int counter,seen;
    unsigned char *raw, *towrite;
    int ret = -2;

    /* Sanity checks */
    if(js_has_sanity(hostname) == JS_ERROR)
        return JS_ERROR;
    if(hostname->unit_size != 1)
        return JS_ERROR;
    if(hostname->unit_count < 1)
        return JS_ERROR;

    /* Store the length of the first part of the hostname */
    raw = towrite = hostname->string;

    /* Get the query type from the first letter */
    switch(*raw) {
        case 'A':
            ret = RR_A;
            break;
        case 'N':
            ret = RR_NS;
            break;
        case 'C':
            ret = RR_CNAME;
            break;
        case 'S':
            ret = RR_SOA;
            break;
        case 'P':
            ret = RR_PTR;
            break;
        case '@':
            ret = RR_MX;
            break;
        case 'T':
            ret = RR_TXT;
            break;
        case 'U':
            ret = -3;
            break;
        case 'Z':
            ret = RR_ANY;
            break;
        default:
            return -2;
        }

     /* Handle the trivial case of an input in the form "A." */
     if(*(raw + 1) == '.' && hostname->unit_count == 2) {
         *raw = 0;
         hostname->unit_count = 1;
         return ret;
         }

     /* Also handle the case of the hostname being *just* a star */
     if(*(raw + 1) == '*' && hostname->unit_count == 2 &&
                     starwhitis == 1) {
         *raw = '_';
         hostname->unit_count = 1;
         return ret;
         }

     /* Convert the dots in to hostname delimiters */
     seen = counter = 0;
     while(counter < 256 && counter < hostname->unit_count) {
         counter++;
         if(counter > hostname->unit_count)
             return JS_ERROR;
         if(*(raw + counter) == '.') {
             if(seen < 1 || seen > 63)
                 return JS_ERROR;
             *towrite = seen;
             towrite = raw + counter;
             seen = 0;
             }
         else
             seen++;
         if(counter == hostname->unit_count - 1) /* The final '.' */
             break;
         }

     /* That last '0' for the dot after .com */
     if(counter < 256 && *(raw + counter) == '.') {
         *(raw + counter) = 0;
     /* We need to deal with trailing * characters */
     } else if(counter < 256 && counter > 1 && *(raw + counter) == '*' &&
                     hostname->unit_count > 1 && starwhitis == 1) {
         *(raw + counter - 1) = '_';
         hostname->unit_count--;
     }
     else {
         return JS_ERROR;
     }

     return ret;
     }

/* Zero-copy implemention of converting a human-readable email address in to
   the raw RFC1035 UDP data for a domain.
   Input:  pointer to js_string object we modify "in place" (needs a
           one-octet 'prefix' which can be be any character
   Output: -1 on error, JS_SUCCESS on success
*/

int email_2rfc1035(js_string *hostname) {
     int counter,seen;
     unsigned char *raw, *towrite;

     int firstat = 1;

     /* Sanity checks */
     if(js_has_sanity(hostname) == JS_ERROR)
         return JS_ERROR;
     if(hostname->unit_size != 1)
         return JS_ERROR;
     if(hostname->unit_count < 1)
         return JS_ERROR;

     /* Store the length of the first part of the hostname */
     raw = towrite = hostname->string;

     /* Convert the at/dots in to hostname delimiters */
     seen = counter = 0;
     /* Handle the special case of this being just a dot by itself */
     if(hostname->unit_count == 2 && *(raw + 1) == '.') {
         hostname->unit_count = 1;
         *(hostname->string) = '\0';
         return JS_SUCCESS;
         }

     while(counter < 256 && counter < hostname->unit_count) {
         counter++;
         if(counter > hostname->unit_count)
             return JS_ERROR;
         if((!firstat && *(raw + counter) == '.') ||
             (firstat && *(raw + counter) == '@')) {
             firstat = 0;
             if(seen < 1 || seen > 63)
                 return JS_ERROR;
             *towrite = seen;
             towrite = raw + counter;
             seen = 0;
             }
         else
             seen++;
         if(counter == hostname->unit_count - 1) /* The final '.' */
             break;
         }

     /* Handle the case of this string not having an @ in it by
      * processing the string as one with just dots */
     if(firstat) {
         return hname_2rfc1035_starwhitis(hostname,0);
         }

     /* That last '0' for the dot after .com */
     if(counter < 256 && *(raw + counter) == '.')
         *(raw + counter) = 0;
     else
         return JS_ERROR;

     return JS_SUCCESS;
     }

/* Process the header of a RR record as described in section 4.1.3 of
   RFC1035.  This converts the contents of a RFC1035 header in to an
   q_rr structure.
   input: js_string obejct with the raw UDP data, q_rr struct to put data
          in, offset form beginning of string to look at data for
   output: number of bytes in rr header on success, JS_ERROR on error
*/

int read_rr_h (js_string *js, q_rr *hdr, int offset) {
    int counter;
    unsigned char toread, read;

    unsigned char *raw;

    counter = toread = 0;

    /* Some sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(js_has_sanity(hdr->name) == JS_ERROR)
        return JS_ERROR;
    if(hdr->name->unit_size != 1)
        return JS_ERROR;
    if(offset >= js->max_count)
        return JS_ERROR;

    raw = js->string + offset;

    /* Copy over the domain-name string inside the js_string object */
    while(counter < 256) {
        if(offset + counter > js->unit_count)
            return JS_ERROR;
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < hdr->name->max_count &&
               counter + offset < js->unit_count)
                /* Then copy the character over */
                *(hdr->name->string + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }

        }

    /* Do not forget to copy over that dot after .com */
    *(hdr->name->string + counter) = *(raw + counter);
    /* Since counter is now sitting on the dot after .com, increment it */
    counter++;

    /* Get TYPE, CLASS, TTL, and RDLENGTH from the header */
    if(counter + offset + 10 <= js->unit_count) {
        raw = js->string + counter + offset;
        hdr->type = raw[0] << 8 | raw[1];
        hdr->class = raw[2] << 8 | raw[3];
        hdr->ttl = raw[4] << 24 | raw[5] << 16 | raw[6] << 8 | raw[7];
        hdr->rdlength = raw[8] << 8 | raw[9];
        }
    else
        return JS_ERROR;

    if(counter < hdr->name->max_count)
        hdr->name->unit_count = counter;
    else
        return JS_ERROR;

    return counter + 10;
    }

/* Process the data for various RR types */

/* read_soa: Read a SOA record.
   input: Pointer to js_string, pointer to rr_soa structure, offset
   output: JS_ERROR on error, bytes in SOA record on success
*/
int read_soa(js_string *js, rr_soa *soa, int offset) {
    int counter;
    unsigned char read,toread;

    unsigned char *raw;

    /* Sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(soa->mname) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(soa->rname) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    if(soa->mname->unit_size != 1)
        return JS_ERROR;
    if(soa->rname->unit_size != 1)
        return JS_ERROR;
    if(js->unit_count < offset)
        return JS_ERROR;

    raw = js->string + offset;

    /* Copy over the first domain-name string inside the js_string object */
    counter = 0;
    while(counter < 256) {
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < soa->mname->max_count &&
               counter + offset < js->unit_count)
                /* Then copy the character over */
                *(soa->mname->string + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }

        }

    *(soa->mname->string + counter) = 0;
    counter++; /* Do not forget the dot after .com */
    offset += counter;
    if(soa->mname->max_count < counter)
        return JS_ERROR;
    soa->mname->unit_count = counter;

    raw = js->string + offset;

    /* Copy over the 2nd domain-name string inside the js_string object */
    counter = 0;
    while(counter < 256) {
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < soa->rname->max_count &&
               counter + offset < js->unit_count)
                /* Then copy the character over */
                *(soa->rname->string + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }

        }

    *(soa->rname->string + counter) = 0;
    counter++; /* Do not forget the dot after .com */
    if(soa->rname->max_count < counter)
        return JS_ERROR;
    soa->rname->unit_count = counter;

    if(counter + offset + 20 > js->unit_count)
        return JS_ERROR;

    raw = js->string + counter + offset;
    soa->serial = raw[0] << 24 | raw[1] << 16 | raw[2] << 8 | raw[3];
    soa->refresh = raw[4] << 24 | raw[5] << 16 | raw[6] << 8 | raw[7];
    soa->retry = raw[8] << 24 | raw[9] << 16 | raw[10] << 8 | raw[11];
    soa->expire = raw[12] << 24 | raw[13] << 16 | raw[14] << 8 | raw[15];
    soa->minimum = raw[16] << 24 | raw[17] << 16 | raw[18] << 8 | raw[19];

    /* Return the number of bytes read */
    return counter + 20;

    }

/* read_ns: Read a NS (or any other <domain-name>) record
   input: js_string object with raw UDP data, js_string object to have just
          the NS record, offset from beginning of raw UDP data to get RR
   output: JS_ERROR on ERROR, bytes in <domain-name> on success
*/

int read_ns(js_string *in, js_string *out, int offset) {
    uint16 toread,read;
    int counter;
    unsigned char *raw;

    /* Sanity checks */
    if(js_has_sanity(in) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(out) == JS_ERROR)
        return JS_ERROR;
    if(in->unit_size != 1)
        return JS_ERROR;
    if(out->unit_size != 1)
        return JS_ERROR;
    if(in->unit_count < offset)
        return JS_ERROR;

    raw = in->string + offset;
    /* Copy over the domain-name string inside the js_string object */
    counter = 0;
    while(counter < 256) {
        toread = *(raw + counter);
        if(toread > 63) /* To do: compression support */
            return JS_ERROR;
        read = 0;
        if(toread == 0) /* 0-length query means we are at the dot after .com */
            break;
        while(read <= toread) {
            /* Overflow protection */
            if(counter < out->max_count &&
               counter + offset < in->unit_count)
                /* Then copy the character over */
                *(out->string + counter) = *(raw + counter);
            else
                return JS_ERROR;
            read++;
            counter++;
            }

        }

    *(out->string + counter) = 0;
    counter++; /* Do not forget the dot after .com */
    offset += counter;
    if(out->max_count < counter)
        return JS_ERROR;
    out->unit_count = counter;

    return counter;
    }

/* Process the RR portion of a TXT record.
   Input: pointer to string of uncompressed UDP data, pointer of string to
          put txt record in, offset from beginning of UDP data
   Output: JS_ERROR on error, byes in TXT record on success
*/

int read_txt(js_string *in, js_string *out, int offset) {
    int counter;
    unsigned char toread;

    counter = 0;

    /* Sanity checks */
    if(js_has_sanity(in) == JS_ERROR)
        return JS_ERROR;
    if(js_has_sanity(out) == JS_ERROR)
        return JS_ERROR;
    if(in->unit_size != 1)
        return JS_ERROR;
    if(out->unit_size != 1)
        return JS_ERROR;
    if(in->unit_count < offset)
        return JS_ERROR;

    /* TXT record: Number of bytes to read followed by the bytes */
    toread = *(in->string + offset);

    /* Security overflow protection */
    if(toread >= out->max_count || offset + toread >= in->unit_count)
        return JS_ERROR;

    /* Copy the TXT string over */
    offset++;
    for(counter = 0;counter < toread; counter++)
        *(out->string + counter) = *(in->string + offset + counter);

    out->unit_count = toread;
    return out->unit_count;
    }

/* This function is designed to make a packet which compresses to a size
 * greater than 512 bytes smaller.  The input is an uncompressed DNS packet;
 * the output is the same packet with the last DNS record removed from the
 * packet.  As per RFC2181 9, if we are removing a DNS record from the NS
 * or AN section of a reply, the TC bit is not set.  Otherwise (as a
 * reasonable interpretation of the wishes in RFC2181 9), we remove all DNS
 * information except the header and mark the DNS packet truncated.
 *
 * Input: A js_string object with a full uncompressed raw DNS packet.
 *
 * Output: A point to the above js_string object on success; 0 on error */

js_string *squeeze_to_fit(js_string *packet) {
        q_header hdr;
        int qd,an,ns,ar; /* counts of the various record types */
        int qc,count;
        int offset;

        if(read_hdr(packet,&hdr) == JS_ERROR) {
                return 0;
        }

        qd = hdr.qdcount;
        an = hdr.ancount;
        ns = hdr.nscount;
        ar = hdr.arcount;

        /* If the packet is already marked truncated, we remove all records
         * past the record and otherwise return it as is;
         * In the case of there being no ns nor ar records, we do the same
         * thing */

        if(hdr.tc == 1 || (ns == 0 && ar == 0)) {
                hdr.tc = 1;
                hdr.qdcount = hdr.ancount = hdr.nscount = hdr.arcount = 0;
                make_hdr(&hdr,packet);
                return packet;
        }

        qc = qd;
        count = an + ns + ar;
        offset = 12; /* Beginning of first question */
        /* Jump past all of the questions */
        while(qc > 0) {
                int len;
                len = dlabel_length(packet,offset);
                if(len == JS_ERROR) {
                        hdr.tc = 1;
                        hdr.qdcount = hdr.ancount = hdr.nscount =
                                hdr.arcount = 0;
                        make_hdr(&hdr,packet);
                        return packet;
                }
                len += 4; /* Type and class */
                offset += len;
                if(offset >= packet->unit_count) {
                        hdr.tc = 1;
                        hdr.qdcount = hdr.ancount = hdr.nscount =
                                hdr.arcount = 0;
                        make_hdr(&hdr,packet);
                        return packet;
                }
                qc--;
        }

        /* Jump past all of the answers except for the last one */
        while(count > 1) {
                int len;
                len = dlabel_length(packet,offset);
                if(len == JS_ERROR) {
                        hdr.tc = 1;
                        hdr.qdcount = hdr.ancount = hdr.nscount =
                                hdr.arcount = 0;
                        make_hdr(&hdr,packet);
                        return packet;
                }
                len += 8; /* type, class, TTL, and RDLENGTH */
                offset += len;
                if(offset + 2 >= packet->unit_count) {
                        hdr.tc = 1;
                        hdr.qdcount = hdr.ancount = hdr.nscount =
                                hdr.arcount = 0;
                        make_hdr(&hdr,packet);
                        return packet;
                }
                /* Get len from the rdlength of the data (this is why the
                 * packet *must* be uncompressed) */
                len = (((*(packet->string + offset ) & 0xff) << 8) +
                      *(packet->string + offset + 1));
                offset += len + 2;
                if(offset >= packet->unit_count) {
                        hdr.tc = 1;
                        hdr.qdcount = hdr.ancount = hdr.nscount =
                                hdr.arcount = 0;
                        make_hdr(&hdr,packet);
                        return packet;
                }
                count--;
        }

        /* Now that we've found the last DNS data, remove it from the
         * packet */
        if(ar > 0) {
                ar--;
                hdr.arcount = ar;
        } else if(ns > 0) {
                ns--;
                hdr.nscount = ns;
        } else {
                hdr.tc = 1;
                hdr.qdcount = hdr.ancount = hdr.nscount = hdr.arcount = 0;
                make_hdr(&hdr,packet);
                return packet;
        }

        hdr.tc = 0;
        make_hdr(&hdr,packet);
        packet->unit_count = offset;
        return packet;

}

