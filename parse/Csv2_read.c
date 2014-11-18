/* Copyright (c) 2004-2006,2008,2011 Sam Trenholme
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

#include "../libs/JsStr.h"
#include "../libs/MaraHash.h"
#include "../MaraDns.h"
#include "Csv2_database.h"
#include "Csv2_read.h"
#include "Csv2_functions.h"

/* These are funcitons that read from a file character-by-character,
 * performing macro processing if necessary */

/* Open up a file for reading; the file is a js_string object
 *
 * Input: Filename to open for reading
 * Output: csv2_read object pointing to the file in question, 0 on
 *         error opening up the file
 */

csv2_read *csv2_open(js_string *filename) {
        extern int csv2_tilde_handling;
        csv2_read *out;
        int c;

        if(filename->unit_size != 1) {
                return 0;
        }

        if((out = js_alloc(sizeof(csv2_read),1)) == 0) {
                return 0;
        }

        if((out->filename = js_alloc(filename->unit_count + 3,1)) == 0) {
                js_dealloc(out);
                return 0;
        }

        if(js_js2str(filename,out->filename,filename->unit_count + 1) ==
                        JS_ERROR) {
                js_dealloc(out);
                return 0;
        }

        /* Initialize all of the fields */
        out->stack = 0;
        out->stack_height = 0;
        out->mnum = 0;
        out->mplace = 0;
        out->cplace = 0;
        for(c = 0 ; c < 19 ; c++) {
                out->context[c] = 0;
        }
        out->tilde_seen = 0;
        out->tilde_handling = csv2_tilde_handling;
        if(csv2_tilde_handling == 0) {
            out->chars_allowed = 1; /* Tilde allowed; left curly brace not
                                     * allowed */
        } else {
            out->chars_allowed = 0; /* Neither tilde nor left curly brace
                                     * allowed */
        }
        out->linenum = 1;
        out->justread = -328; /* Make this a magic "beginning of file"
                                 number */
        out->unicode = -1;
        out->ok_to_read = 1;
        out->seen_bug_msg = 0;

        if((out->reading = fopen(out->filename,"rb")) == 0) {
                js_dealloc(out);
                return 0;
        }

        return out;
}

/* Close an open file and dealloc the memory used by the pointer
 *
 * input: csv2_read pointer with the file
 *
 * output: JS_ERROR on error; JS_SUCCESS on success
 */

int csv2_close(csv2_read *file) {
        csv2_file *v, *w;
        int a = 0;
        if(fclose(file->reading) != 0) {
                return JS_ERROR;
        }

        v = file->stack;
        while(v != 0 && a < 1000) {
                w = v->next;
                fclose(v->reading);
                js_dealloc(v->filename);
                js_dealloc(v);
                v = w;
                a++;
        }

        js_dealloc(file->filename);

        if(js_dealloc(file) != JS_SUCCESS) {
                return JS_ERROR;
        }

        return JS_SUCCESS;
}

/* Read a single charcater from an open file; we will eventually place
 * macro processing in this.  The character is returned as an int so
 * we can eventually interpret a utf-8 sequence as a big number (reading
 * multiple bytes in the process).  Negative numbers indicate errors.
 */

int csv2_readchar(csv2_read *file) {
        int out = -2; /* EOF by default */
        char *mstrn = "NO MACROS YET**";

        /* We don't read if we shouldn't */
        if(file->ok_to_read != 1) {
                if(file->seen_bug_msg == 0) {
                    printf("BUG: The code shouln't be trying to read from");
                    printf(" a closed stream!\n");
                    file->seen_bug_msg++;
                }
                return -2; /* Give them an EOF */
        }

        /* If we are inside a macro (right now the only supported macro
         * is a bogus macro that says "*NO MACROS YET**"), we get
         * characters from the macro */
        if(file->mnum == -1) { /* "NO MACROS YET" */
                if(file->mplace < 0 || file->mplace >= 14) {
                        file->mplace = 0;
                        file->mnum = 0;
                }
                else {
                        out = (int)mstrn[file->mplace];
                        if(out == 0) {
                                file->mplace = 0;
                                file->mnum = 0;
                        }
                        else {
                                file->mplace++;
                                file->justread = out;
                                return out;
                        }
                }
        } else if(file->mnum == 2) { /* Bogus '\n' hack */
                file->justread = '\n';
                file->mnum = 0;
                return '\n';
        }

        /* If we are not inside a macro, we just read from the file */
        if(file->mnum == 0) {
read_char:
                out = getc(file->reading);
                /* If there is an unprintable control character, warn the
                 * user; note this may cause a spurious errors to be given
                 * to the user if they use some bizarre encoding in zone
                 * file comments.  Just use Unicode or iso-8859-whatever
                 * for your zone file comments. */
                if(out < 32 && out >= 0 && out != '\t' && out != '\r'
                   && out != '\n') {
                        printf("Warning: Unprintable character in zone file"
                               ": %02x\n",out);
                }
                file->context[file->cplace++] = out;
                if(file->cplace == 19) { file->cplace = 0; }
                if(out == '\n') {
                        file->linenum++;
                }
                if(out == EOF) {
                        if(file->stack != 0) {
                                csv2_pop_file(file);
                                goto read_char;
                        }
                        return -2; /* End of file */
                }

                if(out == '~' && file->tilde_seen < 10) {
                        (file->tilde_seen)++;
                }

                if(out == '{' &&
                   (file->chars_allowed & 2) != 2) { /* Reserved for macro processing */
                        /* Right now, return an error */
                        csv2_error(file, "The '{' character is currently not "
                                 "allowed there in zone files.\nPlease use an "
                                   "unquoted \\x7b "
                                   "if you need this character in a txt or "
                                   "raw record.\nSee the csv2_txt man page "
                                   "for more information.");
                }
                else if(out == '~' &&
                   (file->chars_allowed & 1) != 1) { /* Record separator */
                        csv2_error(file, "The '~' character is currently not "
                                 "allowed there in zone files.\nPlease use an "
                                   "unquoted \\x7e "
                                   "if you need this character in a txt or "
                                   "raw record.\nSee the csv2_txt man page "
                                   "for more information.");
                } else {
                        file->justread = out;
                        return out;
                }
        }
        return out; /* Hmmmm...what should we *really* do here? */
}

/* Get the last character we read again; we make this a function so
 * that this code is written in an OO-style
 * This is not a unicode-aware function; it will return the last octet
 * read, nothing more
 * This will return -328 if we are at the top of the file */
int csv2_justread(csv2_read *file) {
        if(file->ok_to_read != 1) {
                printf("BUG: Don't run csv2_justread on a closed file!\n");
                return -1;
        }
        return file->justread;
}

/* Print out an error; we always close the file on error */
int csv2_error(csv2_read *file, char *why) {
        int c, lastcr;
        printf("Error: ");
        printf("%s\n",why);
        printf("Error is on line ");
        /* If a newline generates an error, this will be confusing
         * because the parser will report the error being on the next
         * line number.  We work around this thusly.  */
        if(file->justread == '\n') {
                file->linenum--;
                file->justread = '\0';
        }
        printf("%d",file->linenum);
        printf(" in file ");
        printf("%s\n",file->filename);

        /* Show them the context of the error */
        printf("context of error: ");

        c = file->cplace;

        /* If we have any CRs before the character, we don't show
         * any of the context before the CR; this will hopefully make
         * the context message useful */
        lastcr = -1;
        do {
                c++;
                c %= 19;
                if(file->context[c] == '\n' && c != file->cplace) {
                        lastcr = c;
                }
        } while(c != file->cplace);
        if(lastcr != -1) {
                c = lastcr + 1;
                c %= 19;
        }

        /* If we're near the beginning of the line */
        if(file->cplace == ((c + 1) % 19) ||
                        file->cplace == ((c + 2) % 19) ||
                        file->cplace == ((c + 3) % 19) ||
                        file->cplace == ((c + 4) % 19)) {
                printf("<near beginning of line> ");
        }

        /* Show them the context */
        do {
                if(file->context[c] >= ' ') {
                        printf("%c",file->context[c]);
                }
                else if(file->context[c] == '\t') {
                        printf("   ");
                } else if(file->context[c] > 0) {
                        printf("~");
                }
                c++;
                c %= 19;
        } while(c != file->cplace);

        printf(" (closing this file)\n");
        /*csv2_close(file);*/
        file->ok_to_read = 0;
        return JS_SUCCESS;
}

/* Take the current file being read, push that file on the stack, and open
 * up a new file.  If opening the new file fails, we just keep reading
 * from the old file */

int csv2_push_file(csv2_read *file, js_string *filename) {
        csv2_file *o;
        char *nf;
        FILE *nfd;

        if(file->stack_height > 7) {
                return 0;
        }

        if(filename == 0) {
                return 0;
        }

        if(filename->unit_size != 1) {
                return 0;
        }

        if((nf = js_alloc(filename->unit_count + 3,1)) == 0) {
                return 0;
        }

        if(js_js2str(filename,nf,filename->unit_count + 1) ==
                        JS_ERROR) {
                js_dealloc(nf);
                return 0;
        }

        if((nfd = fopen(nf,"rb")) == 0) {
                js_dealloc(nf);
                return 0;
        }

        if((o = js_alloc(1,sizeof(csv2_file) + 1)) == 0) {
                js_dealloc(nf);
                fclose(nfd);
                return 0;
        }

        o->filename = file->filename;
        o->reading = file->reading;
        o->next = file->stack;
        file->stack = o;
        file->filename = nf;
        file->reading = nfd;
        file->stack_height++;
        file->mnum = 2; /* '\n' hack */

        return JS_SUCCESS;

}

/* This does the opposite of the push operation above: This closes the file
 * we're currently reading and pops the file from the top of the stack.
 */

int csv2_pop_file(csv2_read *file) {
        csv2_file *v;
        fclose(file->reading);

        js_dealloc(file->filename);
        v = file->stack;

        if(v == 0) {
                csv2_error(file,"Trying to pop from empty stack");
                return 0;
        }

        file->reading = v->reading;
        file->filename = v->filename;
        file->stack = v->next;
        file->stack_height--;
        if(file->stack_height < 0) {
                csv2_error(file,"Trying to pop from empty stack");
                return 0;
        }
        js_dealloc(v);

        return JS_SUCCESS;
}


/* Method to set the "last read" unicode character in the input stream */
int csv2_set_unicode(csv2_read *file, int32 in) {
        if(file->ok_to_read != 1) {
                printf("BUG: Don't run csv2_set_unicode on a closed file!\n");
                return -1;
        }
        file->unicode = in;
        return 0;
}

/* Method to get the "last read" unicode character in the input stream */
int32 csv2_get_unicode(csv2_read *file) {
        if(file->ok_to_read != 1) {
                printf("BUG: Don't run csv2_get_unicode on a closed file!\n");
                return -1;
        }
        return file->unicode;
}

/* Method to allow tilde characters */
void csv2_allow_tilde(csv2_read *file) {
        file->chars_allowed |= 1;
}

/* Method to forbid tilde characters */
void csv2_forbid_tilde(csv2_read *file) {
        file->chars_allowed &= 0x7e;
}

/* Method to allow left curly brace characters */
void csv2_allow_leftbrace(csv2_read *file) {
        file->chars_allowed |= 2;
}

/* Method to forbid left curly brace characters */
void csv2_forbid_leftbrace(csv2_read *file) {
        file->chars_allowed &= 0x7d;
}

/* Method to get whether we have seen a tilde or not */
int csv2_tilde_seen(csv2_read *file) {
        return file->tilde_seen;
}

/* Method to reset whether we have seen a tilde */
void csv2_reset_tilde_seen(csv2_read *file) {
        file->tilde_seen = 0;
}

