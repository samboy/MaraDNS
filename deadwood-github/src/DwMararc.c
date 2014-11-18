/* Copyright (c) 2007-2012 Sam Trenholme
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

#define MARARC_C
#include "DwMararc.h"
#include "DwStr.h"
#include "DwSys.h"
#include "DwStr_functions.h"
#include <stdint.h>
#include <stdio.h>

dwm_fs fsm[DWM_MAX_STATES + 1]; /* Finite state machine */
char *fsm_desc=dwm_machine;

int dwm_linenum = 0;

int dwm_file_depth = 0; /* How many files we're nested in */

/* Set the new fsm state for a given pattern seen in a given fsm state
 * Input: c: Pointer to string with FSM description (pointing to the
 *           character we are currently parsing)
 *        d: The action number for this state that we are processing
 *        state: The state we are processing
 * Output: A revised pointer to the FSM description */
char *dwm_set_newstate(char *c, int d, int32_t state) {
        if(*c < 'a' || *c > 'z') {
                return 0;
        }
        /* If the state starts with x, it's an "expanded" state, with a
         * two-letter name like "xa", "xc", "xp", or "xz" */
        if(*c == 'x') {
                c++;
                if(*c < 'a' || *c > 'z') {
                        return 0;
                }
                fsm[state].newstate[d] = *c - 'a' + 26;
        } else {
                fsm[state].newstate[d] = *c - 'a';
        }
        c++;
        return c;
}

/* Set the action for a given pattern in a given fsm state
 * Input: c: Pointer to string with FSM description (pointing to the
 *           character we are currently parsing)
 *        max: How far we are in the current line (bounds checker)
 *        d: The action number for this state that we are processing
 *        state: The state we are processing
 * Output: A revised pointer to the FSM description */
char *dwm_set_action(char *c, int max, int d, int32_t state) {
        int b = 0;
        if(*c == ';') {
                fsm[state].action[d] = 10; /* Terminate with success */
                fsm[state].newstate[d] = 0;
                c++;
                max++;
                if(max > 52) {
                        return 0;
                }
                return c;
        } else {
                b = *c - '0';
                if(b < 1 || b > 9) {
                        return 0;
                }
                fsm[state].action[d] = b;
        }
        c++;
        max++;
        if(max >= 52) {
                return 0;
        }
        return dwm_set_newstate(c,d,state);
}

/* Convert a one-character FSM class in to a number we put in to
 * the tokenized FSM machine */
char dwm_pattern_process(int b) {
        /* We don't allow literal hashes or quotes in the FSM definition */
        if(b == '#' || b == '"') {
                return 0;
        }
        /* H becomes a hash symbol (so a FSM definition can have comments) */
        if(b == 'H') {
                b = '#';
        }
        /* Q becomes a " symbol (so we don't have ugly escape quoted sequences
         * in the FSM definition) */
        if(b == 'Q') {
                b = '"';
        }
        /* Make letter shortcuts non-printable ASCII control characters */
        if(b >= 'A' && b <= 'Z') {
                b = b - '@'; /* '@' is 'A' - 1 in ASCII */
        }
        return b;
}

/* Set a single state in the finite state machine */
char *dwm_set_fsm(int32_t state, char *c, int max) {
        int b = 0 , d = 0;

        for(; max<52; max++) {

                /* First letter: pattern */
                b = *c;
                if(b < '!' || b > '~') {
                        return 0;
                }
                fsm[state].pattern[d] = dwm_pattern_process(b);

                /* Second latter: action -or- next state */
                c++;
                max++;
                if(*c >= 'a' && *c <= 'z') {
                        fsm[state].action[d] = 0;
                        c = dwm_set_newstate(c,d,state);
                } else {
                        c = dwm_set_action(c,max,d,state);
                }

                /* Sanity check */
                if(c == 0) {
                        return 0;
                }

                /* Advance past whitespace between patterns/actions */
                while(*c == ' ') {
                        c++;
                        max++;
                        if(max >= 52) {
                                return 0;
                        }
                }

                if(*c == '\r' || *c == '\n') { /* Newline ends a state */
                        return c;
                }
                d++;
                if(d >= DWM_MAX_PATTERNS - 1) { /* Bounds checking */
                        return 0;
                }
        }
        return 0;
}

/* Tokenize a single line describing the finite state machine */
char *dwm_tokenize_line(char *c) {
        int b = 0;
        int max = 0;

        /* The first character of a line is the state we are describing */
        if(*c < 'a' || *c > 'z') {
                return 0;
        }
        /* If the first character happens to be an 'x', the state description
         * is two letters long in a form like "xa", "xb", and so on */
        if(*c == 'x') {
                c++;
                max++;
                if(*c < 'a' || *c > 'z') {
                        return 0;
                }
                b = *c - 'a' + 26;
        } else {
                b = *c - 'a';
        }
        if(b < 0 || b > DWM_MAX_STATES - 1) {
                return 0;
        }
        /* OK, now move forward to see the first pattern description */
        c++;
        if(*c != ' ') {
                return 0;
        }
        while(*c == ' ' && max < 52) {
                c++;
                max++;
        }
        if(max >= 52) {
                return 0;
        }
        /* dwm_set_fsm sets how we react to various patterns when in this
         * state */
        c = dwm_set_fsm(b,c,max);
        if(c == 0) {
                return 0;
        }
        if(*c != '\r' && *c != '\n') {
                return 0;
        }
        c++;
        return c;
}

/* Initialize the finite state machine based on the vales set in the
 * dwm_machine constant (which is set in DwMararc.h) */
void dwm_init_fsm() {
        char *c = 0;
        int a = 0;
        int b = 0;

        /* First, we zero it out */
        for(a=0;a<DWM_MAX_STATES;a++) {
                for(b=0;b<DWM_MAX_PATTERNS;b++) {
                        fsm[a].pattern[b] = 0;
                        fsm[a].action[b] = 0;
                        fsm[a].newstate[b] = 0;
                }
        }

        /* Now, we look at the defined fsm and tokenize it */
        c=fsm_desc;
        b=0;
        for(a=0;a<DWM_MAX_STATES;a++) {
                c = dwm_tokenize_line(c);
                /* Error */
                if(c == 0) {
                        return;
                }
                /* Success */
                if(*c == 0) {
                        return;
                }
        }
}

/* Fatal error while parsing Mararc file */
void dwm_fatal(char *why) {
        dw_alog_number("Fatal error in dwood3rc file on line ",dwm_linenum,
                why);
        exit(1);
}

/* Given an input character, and a character class (a number from one
 * to 32), return -1 if we don't match, 1 if we do match */
int dwm_char_class(int32_t in, int cclass) {
        /* In order to save space, we use this C bit of messyness:
         * condition ? true : false
         * This is normally against coding style; we do it so the function
         * fits within the 52-line-per-function limit */
        switch(cclass) {
                case 1: /* A-Za-z_ */
                        return dwm_is_alpha(in) ? 1 : -1;

                case 2: /* A-Za-z0-9_ */
                        return dwm_is_alphanum(in) ? 1 : -1;

                case 4: /* A-Za-z0-9_- */
                        return dwm_is_dname(in) ? 1 : -1;

                case 9: /* printable ASCII except # and " */
                        return dwm_is_instring(in) ? 1 : -1;

                case 14: /* 0-9 */
                        return dwm_is_number(in) ? 1 : -1;

                case 18: /* \r */
                        return (in == '\r') ? 1 : -1;

                case 19: /* A-Za-z0-9 */
                        return dwm_is_dnamestart(in) ? 1 : -1;

                case 20: /* \n */
                        return (in == '\n') ? 1 : -1;

                case 23: /* ' ' or \t */
                        return dwm_is_whitespace(in) ? 1 : -1;

                case 24: /* printable ASCII/hi-bit or \t */
                        return dwm_is_any(in) ? 1 : -1;

                case 25: /* A-Za-z */
                        return dwm_is_alphastart(in) ? 1 : -1;

                default:
                        return -1;
        }
}

/* Given an input character, and a state, return an action (upper 16 bits)
 * and a new state (lower 16 bits).
 * Input: An input character and a current state
 * Output: ((action << 16) | newstate) or -1 on error */
int32_t dwm_process_character(int32_t in, int32_t state) {
        uint16_t action = 0;
        uint16_t newstate = 0;
        int32_t match = -1;
        int a = 0, b = 0;

        /* Sanity checks */
        if(state >= DWM_MAX_STATES) {
                return -1;
        }

        if(fsm[state].pattern[0] == 0) { /* Invalid state */
                return -1;
        }

        for(a=0;a<DWM_MAX_PATTERNS && fsm[state].pattern[a] != 0;a++) {
                b = fsm[state].pattern[a];
                if(b == 0) {
                        return -1;
                /* patterns between 1 and 32 are multi-character classes,
                 * such as "letters" */
                } else if(b < 32) {
                        match = dwm_char_class(in,b);
                /* Higher numbered "patterns" are one-character patterns,
                 * with the value of the character being the ASCII character
                 * we match against */
                } else {
                        if(in == b) {
                                match = 1;
                        } else {
                                match = -1;
                        }
                }
                if(match == 1) {
                        action = fsm[state].action[a];
                        newstate = fsm[state].newstate[a];
                        break;
                }
        }

        if(fsm[state].pattern[a] == 0) { /* Invalid state */
                return -1;
        }

        if(newstate >= DWM_MAX_STATES || action > 4096) {
                return -1;
        }

        return (action << 16) | newstate;
}

/* Initialize the Mararc parameters */

/* Initialize the data used to store MaraRC dictionary parameters */
void dwm_dict_init() {
        int a;
        for(a=0; a < KEY_D_COUNT; a++) {
                key_d[a] = 0;
        }
}

/* Initialize all mararc params */
void dwm_init_mararc() {
        int a = 0;
        for(a = 0; a < KEY_S_COUNT; a++) {
                key_s[a] = 0;
        }
        dwm_dict_init();
        /* Numeric mararc variables have default values.  */
        key_n[DWM_N_maxprocs] = 32;
#ifndef FALLBACK_TIME
        key_n[DWM_N_timeout_seconds] = 1;
#else /* FALLBACK_TIME */
        key_n[DWM_N_timeout_seconds] = 2;
#endif /* FALLBACK_TIME */
        key_n[DWM_N_dns_port] = 53;
        key_n[DWM_N_upstream_port] = 53;
        key_n[DWM_N_handle_overload] = 1;
        key_n[DWM_N_handle_noreply] = 1;
        key_n[DWM_N_recurse_min_bind_port] = 15000;
        key_n[DWM_N_recurse_number_ports] = 4096;
        key_n[DWM_N_hash_magic_number] = 1; /* Not real default value */
        key_n[DWM_N_maximum_cache_elements] = 1024;
        key_n[DWM_N_maradns_uid] = 99;
        key_n[DWM_N_maradns_gid] = 99;
        key_n[DWM_N_resurrections] = 1;
        key_n[DWM_N_num_retries] = 5;
        key_n[DWM_N_verbose_level] = 3;
        key_n[DWM_N_max_tcp_procs] = 8;
        key_n[DWM_N_timeout_seconds_tcp] = 4;
        key_n[DWM_N_tcp_listen] = 0;
        key_n[DWM_N_max_ar_chain] = 1;
        key_n[DWM_N_ttl_age] = 1;
        key_n[DWM_N_max_inflights] = 8;
        key_n[DWM_N_deliver_all] = 1;
        key_n[DWM_N_filter_rfc1918] = 1;
        key_n[DWM_N_ns_glueless_type] = 1;
        key_n[DWM_N_reject_aaaa] = 0;
        key_n[DWM_N_reject_mx] = 1;
        key_n[DWM_N_truncation_hack] = 1;
        key_n[DWM_N_reject_ptr] = 0;
        key_n[DWM_N_min_ttl_incomplete_cname] = 3600;
        key_n[DWM_N_max_ttl] = 86400;
}

/* Look for a Mararc parameter; -1 if not found/error; 0-n if found
 * (0: First index, 1: second index, etc.) */
int32_t dwm_grep_params(dw_str *seek, char *list[], int max) {
        int e = 0;
        dw_str *look = 0;
        int ret = 0;

        if(seek == 0 || list == 0 || max < 1) {
                ret = -1;
                goto catch_dwm_grep_params;
        }

        for(e = 0; e < max; e++) {
                if(list[e] == 0) {
                        ret = -1;
                        goto catch_dwm_grep_params;
                }
                look = dw_create(64);
                dw_qrappend((uint8_t *)list[e],look,0);
                if(dw_issame(seek,look) == 1) {
                        ret = e;
                        goto catch_dwm_grep_params;
                }
                if(look != 0) {
                        dw_destroy(look);
                        look = 0;
                }
        }

        ret = -1;

catch_dwm_grep_params:
        if(look != 0) {
                dw_destroy(look);
                look = 0;
        }
        return ret;
}

/* Start to read another file to parse data from */
void dwm_execfile(dw_str *execfile, dw_str *fname) {
        char *name = 0, *a = 0;
        dw_str *cmp = 0;
        int counter = 0;

        cmp = dw_create(10);
        if(cmp == 0) {
                return;
        }
        if(dw_cstr_append((uint8_t *)"execfile",8,cmp) == -1) {
                dw_destroy(cmp);
                return;
        }
        if(dw_issame(cmp,execfile) != 1) {
                dwm_fatal("Should have execfile here");
                dw_destroy(cmp);
                return;
        }
        dw_destroy(cmp);

#ifndef MINGW
        if(chdir(EXECFILE_DIR) != 0) {
                dwm_fatal("Could not enter execfile directory");
                return;
        }
#endif /* MINGW */

        name = (char *)dw_to_cstr(fname);
        if(name == 0) {
                return;
        }

        a = name;

        /* Clean up path to filename */
        if(*a == '/') {
                *a = '_';
        }
        for(counter = 0; counter < 200; counter++) {
                if(*a == 0) {
                        break;
                }
                if((*a < 'a' || *a > 'z') && *a != '_' && *a != '/') {
                        *a = '_';
                }
                a++;
        }

        dwm_parse_file(name);

        free(name);
}

/* Based on the actions done, determine what to do (this is called from
 * dwm_set_keys()).
 * Output:
 * -1: Error (bad action)
 * 0: Do nothing
 * 1: Set normal string variable
 * 2: Append to normal string variable
 * 3: Set dictionary variable
 * 4: Append to dictionary variable
 * 5: Set numeric variable
 * 6: Init dictionary variable
 * 7: Read other file for more dwood2rc parameters
 */

int dwm_set_todo(dw_str **actions) {
        if(actions[1] == 0) { /* Do nothing */
                return 0;
        }
        if(actions[6] != 0 && actions[1] != 0 && actions[2] == 0) {
                /* Init dictionary variable */
                return 6;
        }
        if(actions[7] != 0) { /* Read and parse other file */
                dwm_execfile(actions[1],actions[7]);
                return 0;
        }
        if(actions[3] == 0) { /* No string to set */
                if(actions[4] == 0) { /* No number to set */
                        return -1;
                } else if(actions[2] != 0) { /* Dictionary variable */
                        return -1;
                } else if(actions[5] != 0) { /* += instead of = */
                        return -1; /* Not supported; should we support this? */
                } else {
                        return 5;
                }
        }
        if(actions[2] != 0) { /* Dictionary variable */
                if(actions[6] != 0) { /* foo["."] = {} line */
                        return 0;
                }
                if(actions[5] != 0) { /* += instead of = */
                        return 4;
                }
                return 3;
        }
        if(actions[5] != 0) { /* += instead of = */
                return 2;
        }
        return 1;
}

/* Add a dictionary key/value pair to the compiled list of MaraRC
 * parameters.
 *
 * Input: Number of MaraRC parameter to modify
 *        Dictionary key index to modify
 *        Value for said key index
 *
 * Output: Void finction
 *
 * Global variables modified: key_d
 */
void dwm_dict_add(int num, dw_str *key, dw_str *value, int todo) {
        dw_str *temp = 0;
        dw_str *check = 0;

        if(num >= KEY_D_COUNT || num < 0) { /* Sanity check */
                dwm_fatal("Unknown dictionary variable");
        }

        if(todo == 6 && (key != 0 || value != 0)) {
                dwm_fatal("Illegal dictionary initialization");
        }

        /* Initialize dictionary if needed*/
        if(key_d[num] == 0 && todo == 6) { /* Initialized with {} */
                key_d[num] = dwd_init();
                return;
#ifndef TINY_BINARY
        } else if(key_d[num] != 0 && todo == 6) { /* Only initialize once */
                dwm_fatal("Dictionary variable already initialized");
#endif /* TINY_BINARY */
        } else if(key_d[num] == 0) {
                dwm_fatal("Uninitialized dictionary variable");
        }

        if(todo != 4) { /* =, create new dictionary element */
#ifndef TINY_BINARY
                check = dwd_fetch(key_d[num],key);
                if(check != 0) {
                        dw_log_dwstr_str("Warning: Dictionary element \"",
                                        key,"\" defined more than once",0);
                        dw_destroy(check);
                        /* I am tempted to make this fatal but will not since
                         * it could make managing large anti-phish/malware
                         * blacklists harder */
                        /*dw_fatal(
                            "Dictionary elements must be defined only once");*/
                }
#endif /* TINY_BINARY */
                key_d[num] = dwd_add(key_d[num],key,value);
                return;
        }

        /* OK, += so we append an already existing element */
        temp = dwd_fetch(key_d[num],key);
        if(temp == 0) {
                dwm_fatal("Appending unset dictionary index");
        }

        dw_append(value,temp);

        dwd_add(key_d[num],key,temp);

        dw_destroy(temp);

}

/* Fetch a value from a given dictionary variable (num is the number for
 * the dictionary variable we are seeking a given value for, given the
 * dictionary variable and the key inside that variable) */
dw_str *dwm_dict_fetch(int num, dw_str *key) {
        if(num >= KEY_D_COUNT) {
                return 0;
        }

        return dwd_fetch(key_d[num],key);

}

/* For a given dictionary variable, and a key, return (as a *copied* dw_str
 * object) the next key or 0 if we're at the last key.  If the key given to
 * this function is 0, return the first key. */
dw_str *dwm_dict_nextkey(int num, dw_str *key) {
        if(num >= KEY_D_COUNT) {
                return 0;
        }
        return dwd_nextkey(key_d[num],key);
}

/* Based on the actions done, set the appropriate Mararc parameters */
void dwm_set_keys(dw_str **actions) {
        int todo = 0, num = 0;
        dw_str **list = 0;

        todo = dwm_set_todo(actions);
        if(todo == 0) {
                return;
        } else if(todo == -1) {
                dwm_fatal("Bad deadwoodrc action");
        }

        if(todo == 1 || todo == 2) { /* Normal variable */
                num = dwm_grep_params(actions[1],key_s_names,KEY_S_COUNT);
                list = key_s;
        } else if(todo == 3 || todo == 4 || todo == 6) { /* Dict. variable */
                num = dwm_grep_params(actions[1],key_d_names,KEY_D_COUNT);
                if(num < 0) { /* Make sure the parameter is a legal one */
                        dwm_fatal("Unknown dwood3rc dictionary parameter");
                }
                dwm_dict_add(num, actions[2], actions[3], todo);
                return;
        } else if(todo == 5) { /* Numeric variable */
                int32_t val;
                num = dwm_grep_params(actions[1],key_n_names,KEY_N_COUNT);
                val = dw_atoi(actions[4],0,10);
                if(val == -1) {
                        dwm_fatal("Invalid numeric value");
                }
                if(num < 0) { /* Make sure the parameter is a legal one */
                        dwm_fatal("Unknown dwood3rc numeric parameter");
                }
                key_n[num] = val;
                return;
        } else { /* Shouldn't get here */
                return;
        }

        if(list == 0) { /* Sanity check */
                dwm_fatal("Unknown dwood3rc action");
        }
        if(num < 0) { /* Make sure the parameter is a legal one */
                dwm_fatal("Unknown dwood3rc string parameter");
        }

        if(list[num] == 0 && (todo & 1) == 0) {
                dwm_fatal("Appending to unset string parameter");
        } else if(list[num] != 0 && (todo & 1) == 0 /* append */) {
                dw_append(actions[3],list[num]);
                return;
        } else if(list[num] != 0) {
                dwm_fatal("Deadwoodrc parameter set twice");
        }

        list[num] = dw_copy(actions[3]);
}

/* If there is an action to perform, perform the action */
void dwm_do_action(int32_t ch, int32_t action, dw_str **actions) {
        if(actions[action] == 0) {
                /* This function is *only* called from dwm_parse_line,
                 * and the destructor for these strings is at the
                 * end of that function */
                actions[action] = dw_create(384);
        }
        dw_addchar(ch, actions[action]);
}

/* Parse a line in a MaraRC (Dwood#RC) file */
int dwm_parse_line(FILE *look) {
        dw_str *actions[11];
        int a = 0;
        int32_t action = 0, state = 0, mix = 0, ch = 0, last = 0;
        int ret = 0;

        for(a = 0; a < 11; a++) {
                actions[a] = 0;
        }

        ch = fgetc(look);
        if(feof(look)) {
                ret = 1; /* End of file reached */
                goto catch_dwm_parse_line;
        }

        while(action != 10) {
                mix = dwm_process_character(ch,state);
                if(mix < 0) {
                        ret = -1;
                        goto catch_dwm_parse_line;
                }
                action = (mix >> 16) & 0x7fff;
                state = mix & 0x7fff;
                if(action == 10) { /* Terminate */
                        ret = 0; /* Line parsed */
                        break; /* Now we need to set the keys */
                } else if(action == 8) {
                        ret = -4; /* Fatal: No leading whitespace */
                        goto catch_dwm_parse_line;
                } else if(action > 0 && action < 10) {
                        dwm_do_action(ch,action,actions);
                }
                last = ch;
                ch = fgetc(look);
                if(feof(look) && last != '\r' && last != '\n') {
                        ret = -3; /* Premature EOF; incomplete last line */
                        goto catch_dwm_parse_line;
                }
        }

        dwm_set_keys(actions); /* Sets mararc parameters based on actions */

catch_dwm_parse_line: /* Actions strings destructor */
        for(a = 0; a < 11; a++) {
                if(actions[a] != 0) {
                        dw_destroy(actions[a]);
                        actions[a] = 0;
                }
        }
        return ret;
}

/* Parse a single filename; used by dwm_parse_mararc and dwm_execfile to
 * parse the contents of a single file */
int dwm_parse_file(char *name) {
        FILE *look;
        int a = 0;

        if(dwm_file_depth > 8 || name == 0) {
                return -1;
        }

        dwm_file_depth++;

        look = fopen(name,"rb");
        if(look == NULL) {
                return -1; /* File open error */
        }

        do {
                a = dwm_parse_line(look);
                if(a == -3) {
                        dwm_fatal("incomplete last line");
                } else if(a == -4) {
                        dwm_fatal("leading whitespace not allowed");
                }
                if(a != 0 && a != 1) {
                        dwm_fatal("deadwoodrc parse error");
                }
                if(dwm_file_depth == 1) {
                        dwm_linenum++;
                }
        } while (a == 0);

        fclose(look);

        dwm_file_depth--;

        return 1;
}

/* Parse a mararc file; this should only be called once when executing
 * deadwood.  Note that this is the *only* public method in this entire
 * file; all other functions in this file should only be called from
 * other functions in this file.
 * Input: c string that points to mararc file
 * Output: 1 on success; program exits on mararc parse error */
int dwm_parse_mararc(char *name) {
        dwm_linenum = 1;

        dwm_init_fsm();
        dwm_init_mararc();

        return dwm_parse_file(name);
}

#ifdef HAVE_MAIN

/* Debugging function to make sure fsm is correctly set up */

void show_fsm() {
        int a = 0, b = 0, q = 0;
        for(a = 0; a < DWM_MAX_STATES; a++) {
                if(fsm[a].pattern[0] != 0) {
                        printf("State %d\n",a);
                }
                for(b = 0; b < DWM_MAX_PATTERNS; b++) {
                        q = fsm[a].pattern[b];
                        if(q > 0 && q < 32 && fsm[a].action[b] != 10) {
                                printf("Pattern @%d action %d newstate %d\n",
                                        fsm[a].pattern[b],
                                        fsm[a].action[b],
                                        fsm[a].newstate[b]);
                        } else if(q >= '!' && fsm[a].action[b] != 10) {
                                printf("Pattern %c action %d newstate %d\n",
                                        fsm[a].pattern[b],
                                        fsm[a].action[b],
                                        fsm[a].newstate[b]);

                        } else if(q > 0 && q < 32) {
                                printf("Pattern @%d action %d (terminate)\n",
                                        fsm[a].pattern[b],
                                        fsm[a].action[b]);
                        } else if(q >= '!') {
                                printf("Pattern %c action %d (terminate)\n",
                                        fsm[a].pattern[b],
                                        fsm[a].action[b]);
                        } else {
                                break;
                        }
                }
                if(fsm[a].pattern[0] != 0) {
                        printf("\n");
                }
        }
}

int main() {
        int a = 0;

        dwm_parse_mararc("deadwoodrc");

        show_fsm();

        for(a=0;a<KEY_S_COUNT;a++) {
                printf("%s is ",key_s_names[a]);
                if(key_s[a] == 0) {
                        printf("not set.\n");
                } else {
                        dw_stdout(key_s[a]);
                }
        }

        for(a=0;a<KEY_D_COUNT;a++) {
                printf("%s is ",key_d_names[a]);
                if(key_s[a] == 0) {
                        printf(" not set.\n");
                } else {
                        dw_stdout(key_d[a]);
                }
        }

        return 0;
}

#endif /* HAVE_MAIN */

