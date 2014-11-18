/* Copyright (c) 2002,2003 Sam Trenholme
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

/* Parse a mararc file */

#include "../MaraDns.h"
#include "../libs/MaraHash.h"
#include "ParseCsv1_en.h"
#include <stdlib.h>
#ifndef MINGW32
#include <pwd.h>
#endif
#include <sys/types.h>
#include <stdio.h>

/* Function prototypes */
#include "../dns/functions_dns.h"
#include "functions_parse.h"

/* Parse a single line of a csv1 data file
   input: pointer to line of data, place to put the domain name (with
          class as a 2-byte siffix), place to put the domain data, place
          to put the TTL for this record
   output: 0 on blank or hashed lines, the type of RR on lines where
           we need to add the RR in question, JS_ERROR on fatal error.
           On non-fatal error, we return -2
*/

int parse_csv1_line(js_string *line, js_string *name, js_string *data,
                    uint32 *ttl) {

    /* js_string objects to use in fgrepping for special characters */
    js_string *pipeq = 0, *hashq = 0, *starq = 0, *blankq = 0, *field = 0;

    js_string *tstr; /* Only used when processing the SOA record */

    uint16 type, preference;

    int tempp, pipep, opipep, counter;

    uint32 soanum;

    char pipe = '|';
    char hash = '#';
    char star = '*';

    /* Sanity checks */
    if(mara_goodjs(line) == JS_ERROR)
        return JS_ERROR;
    if(js_get_encode(line) != JS_US_ASCII &&
       js_get_encode(line) != JS_8859_1)
        return JS_ERROR;
    if(mara_goodjs(name) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(data) == JS_ERROR)
        return JS_ERROR;
    if(ttl == 0)
        return JS_ERROR;

    /* Allocate strings if this is the first time we are running this */
    if((pipeq = js_create(7,1)) == 0)
        return JS_ERROR;
    if((hashq = js_create(7,1)) == 0) {
        js_destroy(pipeq);
        return JS_ERROR;
        }
    if((starq = js_create(7,1)) == 0) {
        js_destroy(pipeq); js_destroy(hashq);
        return JS_ERROR;
        }
    if(js_set_encode(starq,MARA_LOCALE) == JS_ERROR) {
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        return JS_ERROR;
        }
    if((blankq = js_create(7,1)) == 0) {
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        return JS_ERROR;
        }
    if(js_set_encode(blankq,MARA_LOCALE) == JS_ERROR) {
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        js_destroy(blankq);
        return JS_ERROR;
        }
    if((field = js_create(256,1)) == 0) {
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        js_destroy(blankq);
        return JS_ERROR;
        }

    /* Place data in those strings */
    if(js_str2js(pipeq,&pipe,1,1) == JS_ERROR)
        goto clean;
    if(js_str2js(hashq,&hash,1,1) == JS_ERROR)
        goto clean;
    if(js_space_chars(blankq) == JS_ERROR)
        goto clean;

    /* use starq as temporary string to append newlines to blankq */
    if(js_newline_chars(starq) == JS_ERROR)
        goto clean;
    if(js_append(starq,blankq) == JS_ERROR)
        goto clean;

    /* While starq has a newline in it, lets make sure the line in
       question ends with a newline character */
    tempp = js_match(starq,line);
    if(tempp == JS_ERROR)
        goto clean;
    if(tempp == -2) {
        js_qstr2js(name,"ERROR");
        js_qstr2js(data,"No newline found in line");
        goto error;
        }

    /* Now, give starq its proper value */
    if(js_str2js(starq,&star,1,1) == JS_ERROR)
        goto clean;

    if(js_qstr2js(name,"") == JS_ERROR)
        goto clean;
    if(js_qstr2js(data,"") == JS_ERROR)
        goto clean;

    /* If the line starts with a '#', then "name" and "data" will
       be empty, and we return 1 */
    tempp = js_match(hashq,line);
    if(tempp == JS_ERROR)
        goto clean;
    if(tempp == 0)
        goto cero; /* no data to modify */

    /* Since there is no leading hash, let us see if this line
       has nothing but space characters in it */
    tempp = js_notmatch(blankq,line);
    if(tempp == JS_ERROR)
        goto clean;
    if(tempp == -2) /* Nothing besides whitespace found */
        goto cero; /* no data to modify */

    /* Since this has some kind of data in it, make sure we have
       a pipe in the line */
    pipep = js_match(pipeq,line);
    if(pipep == JS_ERROR)
        goto clean;
    if(tempp == -2) { /* No pipe found */
        js_qstr2js(name,"ERROR");
        js_qstr2js(data,L_NOPIPE); /* "No pipe found in line" */
        goto error;
        }

    /* OK, copy over the data that extends from the beginning of the
       line to the first pipe */
    if(js_substr(line,name,0,pipep) == JS_ERROR)
        goto clean;
    /* Try to make that string a RFC1035 domain query */
    tempp = hname_2rfc1035(name);
    if(tempp == JS_ERROR) {
        js_qstr2js(name,"ERROR");
        js_qstr2js(data,L_BADQUERY); /* "Error in Query syntax." */
        goto error;
        }
    /* Return error if this is an unsupported RR type */
    if(tempp == -2 || tempp > 65535) {
        js_qstr2js(name,"ERROR");
        js_qstr2js(data,L_UNKNOWNREC); /* "The record type is not supported" */
        goto error;
        }

    type = tempp;

    /* The second field is always the TTL */
    opipep = pipep;
    pipep = js_match_offset(pipeq,line,pipep + 1);
    if(pipep == JS_ERROR)
        goto clean;
    if(pipep <= opipep) {
        js_qstr2js(name,"ERROR");
        js_qstr2js(data,L_MIN3RR); /* "You must have at least three fields in the RR" */
        goto error;
        }
    *ttl = js_atoi(line,opipep + 1);
    if(*ttl == JS_ERROR)
        goto clean;

    /* Depending on the type of RR it is, process the data accordingly */
    switch(tempp) {
        case RR_A:
            if(ddip_2_ip(line,data,pipep + 1) == JS_ERROR) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_DDIP); /* "Malformed dotted decimal IP" */
                goto error;
                }
            break;
        case RR_MX:
            /* Get the preference for this mail exchanger */
            tempp = js_atoi(line,pipep + 1);
            if(tempp < 0 || tempp > 65535) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_MX); /* "Bad MX type" */
                goto error;
                }
            preference = tempp;
            if(js_addbyte(data,(preference >> 8) & 0xff) == JS_ERROR)
                goto clean;
            if(js_addbyte(data,preference & 0xff) == JS_ERROR)
                goto clean;
            tempp = js_match_offset(pipeq,line,pipep + 1);
            if(tempp <= pipep) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_4_MX_FIELDS); /* "There must be four fields in the MX" */
                goto error;
                }
            pipep=tempp;
            /* Add the exchange to the MX data */
            if((tstr = js_create(512,1)) == 0)
                goto clean;
            if(js_substr(line,tstr,pipep,js_length(line) - pipep - 1)
               == JS_ERROR) {
                js_destroy(tstr);
                goto clean;
                }
            if(js_changebyte(tstr,'A',0) == JS_ERROR) {
                js_destroy(tstr);
                goto clean;
                }
            tempp = hname_2rfc1035(tstr);
            if(tempp == JS_ERROR) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_EMAIL); /* "Malformed domain email" */
                js_destroy(tstr);
                goto error;
                }
            if(js_append(tstr,data) == JS_ERROR) {
                js_destroy(tstr);
                goto clean;
                }
            if(js_destroy(tstr) == JS_ERROR)
                goto clean;
            break;
        case RR_NS:
            /* XXX This is a DAV */
            /* Make sure we do not have NS star records */
            if(name->unit_count > 2 && *(name->string + 1) == '*')
                {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_STAR); /* "Star records can not be CNAME nor NS RRs" */
                goto error;
                }
        case RR_CNAME:
        case RR_PTR:
            /* Get the rest of the line */
            if(js_substr(line,data,pipep,js_length(line) - pipep - 1)
               == JS_ERROR)
                goto clean;

            /* Translate the host name the CNAME/PTR/NS points to */
            if(js_changebyte(data,'A',0) == JS_ERROR)
                goto clean;
            tempp = hname_2rfc1035(data);
            if(tempp == JS_ERROR) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_DNAME); /* "Malformed host/domain name" */
                goto error;
                }
            break;

        case RR_TXT:
            /* Get the rest of the line */
            tempp = js_length(line) - pipep - 2;
            if(tempp < 0 || tempp > 255)
                goto clean;
            if(js_substr(line,data,pipep,tempp + 1)
               == JS_ERROR)
                goto clean;
            if(js_changebyte(data,tempp,0) == JS_ERROR)
                goto clean;
            break;
        case -3: /* 'U' type: this allowes MaraDNS to give out data in
                    normally unsupported data types */
            /* Get the type number for this data */
            tempp = js_atoi(line,pipep + 1);
            if(tempp < 0 || tempp > 65535) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_MX); /* "Bad MX type" */
                goto error;
                }
            type = tempp;
            /* Go to the next '|' char */
            tempp = js_match_offset(pipeq,line,pipep + 1);
            if(tempp <= pipep) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_4_MX_FIELDS); /* "There must be four fields in the MX" */
                goto error;
                }
            pipep=tempp;
            /* Get the rest of the line */
            tempp = js_length(line) - pipep - 2;
            if(tempp < 0 || tempp > (MAX_RECORD_LENGTH - 1))
                goto clean;
            if(js_substr(line,data,pipep + 1,tempp) /* Chop off the final \n */
               == JS_ERROR)
                goto clean;
            break;
        case RR_SOA:
            /* Get the domain the SOA is for (a.k.a. the origin) */
            opipep = pipep;
            pipep = js_match_offset(pipeq,line,pipep + 1);
            if(pipep == JS_ERROR)
                goto clean;
            if(pipep <= opipep) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_9_SOA_FIELDS); /* "You must have nine fields in the SOA" */
                goto error;
                }
            if(js_substr(line,data,opipep,pipep - opipep) == JS_ERROR)
                goto clean;
            if(js_changebyte(data,'A',0) == JS_ERROR)
                goto clean;
            tempp = hname_2rfc1035(data);
            if(tempp == JS_ERROR) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_SOA_ORIGIN); /* "Malformed SOA origin" */
                goto error;
                }
            opipep = pipep;
            pipep = js_match_offset(pipeq,line,pipep + 1);
            if(pipep == JS_ERROR)
                goto clean;
            if(pipep <= opipep) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_9_SOA_FIELDS); /* "You must have nine fields in the SOA" */
                goto error;
                }
            /* Add the mname to the SOA data */
            if((tstr = js_create(512,1)) == 0)
                goto clean;
            if(js_substr(line,tstr,opipep,pipep - opipep) == JS_ERROR) {
                js_destroy(tstr);
                goto clean;
                }
            tempp = email_2rfc1035(tstr);
            if(tempp == JS_ERROR) {
                js_qstr2js(name,"ERROR");
                js_qstr2js(data,L_BAD_EMAIL); /* "Malformed domain email" */
                js_destroy(tstr);
                goto error;
                }
            if(js_append(tstr,data) == JS_ERROR) {
                js_destroy(tstr);
                goto clean;
                }
            if(js_destroy(tstr) == JS_ERROR)
                goto clean;
            /* Add the five other fields (Serial, Refresh, Retry, Expire, and
               minimum TTL) to the data (Note: this code assumes that all
               of these numbers are positive) */
            for(counter = 0; counter < 5; counter++) {
                if(pipep == -2) {
                    js_qstr2js(name,"ERROR");
                    js_qstr2js(data,L_9_SOA_FIELDS); /* "You must have nine fields in the SOA" */
                    goto error;
                    }
                soanum = js_atoi(line,pipep + 1);
                if(js_addbyte(data,soanum >> 24) == JS_ERROR)
                    goto clean;
                if(js_addbyte(data,(soanum >> 16) & 0xff) == JS_ERROR)
                    goto clean;
                if(js_addbyte(data,(soanum >> 8) & 0xff) == JS_ERROR)
                    goto clean;
                if(js_addbyte(data,soanum & 0xff) == JS_ERROR)
                    goto clean;
                pipep = js_match_offset(pipeq,line,pipep + 1);
                if(pipep == JS_ERROR)
                    goto clean;
                }
            break;
        default:
            goto clean;
        }

    /* Add the type of query to the end of the name */
    if(js_addbyte(name,(type & 0xff00) >> 16) == JS_ERROR)
        goto clean;
    if(js_addbyte(name,type & 0xff) == JS_ERROR)
        goto clean;

    js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
    js_destroy(blankq); js_destroy(field);
    return type;

    clean:
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        js_destroy(blankq); js_destroy(field);
        return JS_ERROR;
    error:
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        js_destroy(blankq); js_destroy(field);
        return -2;
    cero:
        js_destroy(pipeq); js_destroy(hashq); js_destroy(starq);
        js_destroy(blankq); js_destroy(field);
        return 0;

    }

/* Convert a dotted-decimal IP (in a js_string object) in to a raw IP
   (another js_string object)
   input: pointer to dotted decimal data, pointer to js_string object to
          place raw IP in to, offset from top to start looking
   output: JS_ERROR on error, pointer to first non-ip byte on SUCCESS
           (-2 if no non-ip byte was found)
*/

int ddip_2_ip(js_string *ddip, js_string *ip, int offset) {
    int qr, counter;
    int ret;

    unsigned char ip_byte;

    js_string *dotq = 0;
    js_string *numdotq = 0;

    char dot = '.';

    /* Sanity checks */
    if(mara_goodjs(ddip) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(ip) == JS_ERROR)
        return JS_ERROR;

    /* Allocate string if this is the first time we are running this */
    if(dotq == 0) {
        if((dotq = js_create(7,1)) == 0)
            return JS_ERROR;
        /* Place data in that string */
        if(js_str2js(dotq,&dot,1,1) == JS_ERROR) {
            js_destroy(dotq);
            dotq = 0;
            return JS_ERROR;
            }
        }
    if(numdotq == 0) {
        if((numdotq = js_create(211,1)) == 0) {
            js_destroy(dotq);
            return JS_ERROR;
            }
        if(js_set_encode(numdotq,JS_8859_1) == JS_ERROR) {
            js_destroy(numdotq);
            js_destroy(dotq);
            numdotq = 0;
            return JS_ERROR;
            }
        /* Place numbers in that string */
        if(js_numbers(numdotq) == 0) {
            js_destroy(numdotq);
            js_destroy(dotq);
            numdotq = 0;
            return JS_ERROR;
            }
        /* Add the dot to that regex */
        if(js_append(dotq,numdotq) == JS_ERROR) {
            js_destroy(numdotq);
            js_destroy(dotq);
            numdotq = 0;
            return JS_ERROR;
            }
        }

    /* See the first non number/dot after the offset */
    ret = js_notmatch_offset(numdotq,ddip,offset);
    if(ret == JS_ERROR)
        goto clean;

    /* Initialize the output string */
    js_qstr2js(ip,"");

    /* Begin the ddip (dotted decimal IP) to raw binary ip conversion */
    if(js_length(ddip) < 1)
        goto clean;

    for(counter = 0; counter < 4; counter++) {
        if(offset == -2)
            goto clean;

        qr = js_atoi(ddip,offset);

        if(qr < 0 || qr > 255)
            goto clean;

        ip_byte = qr;

        if(js_addbyte(ip,ip_byte) == JS_ERROR)
            goto clean;

        offset = js_match_offset(dotq,ddip,offset + 1);
        if(offset == JS_ERROR)
            goto clean;

        offset++;
        }

    /* Return error if the IP does not end the string */
    if(ret < offset && offset != -1)
        goto clean;

    /* Destroy the strings we are no longer using */
    js_destroy(dotq);
    js_destroy(numdotq);

    /* Return -2 if there is no non-number/dot after the IP */
    if(ret == -2)
        return -2;
    /* Otherwise, return the offset to the first non-number/dot */
    return ret;

    clean:
       js_destroy(dotq);
       js_destroy(numdotq);
       return JS_ERROR;
    }

/* pre-process a line.  In addition to making domain labels lower-case,
   this converts \ characters in the line in to other values.  \\ is
   backslash, \nnn is an octal value for a character.
   input: pointer of line to process, pointer to place to put
          processed data, pointer to string to substitute % with
          (if 0, no substitution is performed)
   ouput: JS_ERROR on error, JS_SUCCESS on success
*/

int bs_process(js_string *in, js_string *out, js_string *sub) {
    int value, iplace, oplace, subq, inlabel;
    unsigned char byte;
    int firstchar;

    /* Sanity checks */
    if(mara_goodjs(in) == JS_ERROR)
        return JS_ERROR;
    if(mara_goodjs(out) == JS_ERROR)
        return JS_ERROR;
    subq = 1;
    if(sub == 0)
        subq = 0;
    else if(mara_goodjs(sub) == JS_ERROR)
        return JS_ERROR;

    iplace = oplace = inlabel = 0;
    firstchar = 1;
    while(iplace < in->unit_count) {
        byte = *(in->string + iplace);
        /* On new lines, we make lowercase everything from the second byte
           to the first '#' or '|' */
        if(inlabel && byte >= 'A' && byte <= 'Z')
            byte += 32;
        if(firstchar == 1) {
           inlabel = 1;
           firstchar = 0;
           }
        if(byte == '#' || byte == '|')
           inlabel = 0;
        if(subq && byte == '%') { /* replace % with string in sub */
            if(oplace >= out->max_count)
                return JS_ERROR;
            out->unit_count = oplace;
            js_append(sub,out);
            oplace = out->unit_count;
            iplace++;
            continue;
            }
        else if(byte == '\\') {
            iplace++;
            if(iplace >= in->unit_count)
                return JS_ERROR; /* overflow protection */
            byte = *(in->string + iplace);
            if(byte >= '0' && byte <= '3') { /* 0-255 in 3-digit octal */
                value = (byte - '0') * 64;
                /* Second octal digit */
                iplace++;
                if(iplace >= in->unit_count)
                    return JS_ERROR; /* overflow protection */
                byte = *(in->string + iplace);
                if(byte < '0' || byte > '9')
                    return JS_ERROR; /* Octal sequences must have 3 digits */
                value += (byte - '0') * 8;
                /* Third octal digit */
                iplace++;
                if(iplace >= in->unit_count)
                    return JS_ERROR; /* overflow protection */
                byte = *(in->string + iplace);
                if(byte < '0' || byte > '9')
                    return JS_ERROR; /* Octal sequences must have 3 digits */
                value += (byte - '0');
                byte = value;
                }
            else if(byte != '\\' && byte != '%') /* only \###, \%, and \\ */
                return JS_ERROR;
            }
        /* Change the value of the character to the processed byte */
        if(oplace < out->max_count)
            *(out->string + oplace) = byte;
        else
            return JS_ERROR;
        /* Increment the character we write to */
        oplace++;
        /* Increment the character to look at */
        iplace++;
        }

    /* Resize the out string and return success */
    out->unit_count = oplace;
    return JS_SUCCESS;
    }

