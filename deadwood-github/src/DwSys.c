/* Copyright (c) 2007-2022 Sam Trenholme
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef MINGW
#include <grp.h>
#include <signal.h>
#else
#include <winsock.h>
#include <wincrypt.h>
#endif /* MINGW */

#include "DwSocket.h"
#include "version.h"
#include "DwBlockHash.h"

/* Timestamp */
int64_t the_time = 0;

/* RNG seed/state */
dwr_rg *rng_seed;

/* Whether to read the cache file */
int do_read_cache = 1;
struct stat mararc_st;

/* Mararc parameters that are set in DwMararc.c */
extern dw_str *key_s[];
extern dw_str *key_d[];
extern int32_t key_n[];

/* The cache that is used for storing DNS queries */
dw_hash *cache = 0;

/* A block hash file used for blocking hosts in a manner which is fast
 * while using a minimum amount of memory */
blockHash *blocked_hosts_hash = 0;

/* The user and group ID Deadwood runs as */
extern int32_t maradns_uid;
extern int32_t maradns_gid;

#ifdef MINGW
FILE *LOG = 0;
void dw_win_time() {
        SYSTEMTIME t;
        char d[256];
        char h[256];
        GetLocalTime(&t);
        GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &t,
                NULL, d, 250);
        GetTimeFormat(LOCALE_SYSTEM_DEFAULT, TIME_FORCE24HOURFORMAT, &t,
                NULL, h, 250);
        fprintf(LOG,"%s %s: ",d,h);
}
#endif /* MINGW */

/* Logging functions */
/* Initialize the log */
void dw_log_init() {
#ifdef MINGW
        LOG = fopen("dwlog.txt","ab");
        dw_win_time();
        fprintf(LOG,"%s\n","==Deadwood started==");
#endif /* MINGW */
        return;
}

/* Close the log */
void dw_log_close() {
#ifdef MINGW
        dw_win_time();
        fprintf(LOG,"%s\n","==Deadwood stopped==");
        fclose(LOG);
#endif /* MINGW */
        return;
}

/* Log a string followed by the contents of a DwStr object ; private */
void dw_log_dwstr_p(char *s1, dw_str *s2, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];
        uint8_t q = 0;

        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s",s1);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s",s1);
#endif /* MINGW */

        if(s2 == 0) {
#ifndef MINGW
                printf("(null dw_str)");
#else /* MINGW */
                fprintf(LOG,"(null dw_str)");
#endif /* MINGW */
                return;
        }

        for(ll = 0 ; ll < s2->len ; ll++) {
                q = *(s2->str + ll);
                if(q >= '.' && q <= '~' /* Last ASCII char */ && q != '\\'
                   && q != '{' && q != '}') {
#ifndef MINGW
                        printf("%c",q);
#else /* MINGW */
                        fprintf(LOG,"%c",q);
#endif /* MINGW */
                } else if(q == '-') {
#ifndef MINGW
                        printf("%c",q);
#else /* MINGW */
                        fprintf(LOG,"%c",q);
#endif /* MINGW */
                } else if(q == ' ') {
#ifndef MINGW
                        printf("{%c}",q);
#else /* MINGW */
                        fprintf(LOG,"{%c}",q);
#endif /* MINGW */
                } else {
#ifndef MINGW
                        printf("\\%03o",q);
#else /* MINGW */
                        fprintf(LOG,"\\%03o",q);
#endif /* MINGW */
                }
        }
}

/* Log an IP; private */
void dw_log_ip_p(ip_addr_T *ip) {
        int counter = 0;

        if(ip == 0) {
#ifndef MINGW
                printf("%s","(null IP)\n");
#else /* MINGW */
                fprintf(LOG,"%s","(null IP)\n");
#endif /* MINGW */
                return;
        }

        if(ip->len == 4) {
                for(counter = 0; counter < 3; counter++) {
#ifndef MINGW
                        printf("%d.",ip->ip[counter]);
#else /* MINGW */
                        fprintf(LOG,"%d.",ip->ip[counter]);
#endif /* MINGW */
                }
#ifndef MINGW
                printf("%d ",ip->ip[3]);
#else /* MINGW */
                fprintf(LOG,"%d ",ip->ip[3]);
#endif /* MINGW */
#ifndef NOIP6
        } else if(ip->len == 16) {
                for(counter = 0; counter < 15; counter++) {
#ifndef MINGW
                        printf("%02x:",ip->ip[counter]);
#else /* MINGW */
                        fprintf(LOG,"%02x:",ip->ip[counter]);
#endif /* MINGW */
                }
#ifndef MINGW
                printf("%02x ",ip->ip[15]);
#else /* MINGW */
                fprintf(LOG,"%02x ",ip->ip[15]);
#endif /* MINGW */
#endif /* NOIP6 */
        } else {
#ifndef MINGW
                printf("%s%d","IP of length ",ip->len);
#else /* MINGW */
                fprintf(LOG,"%s%d","IP of length ",ip->len);
#endif /* MINGW */
        }
}

/* Log a char followed by an IP */
void dw_log_ip(char *string, ip_addr_T *ip, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];
        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s ",string);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s ",string);
#endif /* MINGW */

        dw_log_ip_p(ip);

#ifndef MINGW
        printf("%s","\n");
#else /* MINGW */
        fprintf(LOG,"%s","\n");
#endif /* MINGW */

}

/* Log a string followed by the contents of a DwStr object */
void dw_log_dwstr(char *s1, dw_str *s2, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];
        if(ll <= 0 || ll < min_log_level) {
                return;
        }

        dw_log_dwstr_p(s1,s2,min_log_level);

        /* OK, add a newline */

#ifndef MINGW
        printf("%s","\n");
#else /* MINGW */
        fprintf(LOG,"%s","\n");
#endif /* MINGW */
}

/* Log a string followed by the contents of a DwStr object as a series of
 * decimal integers separated by dots (so IPs in strings look normal) */
void dw_log_dwstrip(char *s1, dw_str *s2, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];
        int a;
        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s",s1);
#else /* MINGW */
        fprintf(LOG,"%s",s1);
#endif /* MINGW */

        if(s2 != 0 && s2->str != 0) {
                for(a=0;a<s2->len;a++) {
#ifndef MINGW
                        printf("%d.",*(s2->str + a));
#else /* MINGW */
                        fprintf(LOG,"%d.",*(s2->str + a));
#endif /* MINGW */
                }
        }

        /* OK, add a newline */

#ifndef MINGW
        printf("%s","\n");
#else /* MINGW */
        fprintf(LOG,"%s","\n");
#endif /* MINGW */
}

/* Log a string followed by the contents of a DwStr object followed by
 * another string */
void dw_log_dwstr_str(char *s1, dw_str *s2, char *s3, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];
        if(ll <= 0 || ll < min_log_level) {
                return;
        }

        dw_log_dwstr_p(s1,s2,min_log_level);

        /* OK, add a newline */

#ifndef MINGW
        printf("%s\n",s3);
#else /* MINGW */
        fprintf(LOG,"%s\n",s3);
#endif /* MINGW */
}


/* Log a string; input: String to log; minimum log level that we log this
 * string at */
void dw_log_string(char *string, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];

        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s\n",string);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s\n",string);
#endif /* MINGW */

}

/* Log 3 strings; input: Strings to log; minimum log level that we log these
 * strings at */
void dw_log_3strings(char *s1, char *s2, char *s3, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];

        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s%s%s\n",s1,s2,s3);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s%s%s\n",s1,s2,s3);
#endif /* MINGW */
}

/* Log a string, a number, and a string
 * input: String #1, Number, and String #2 to log;
 * minimum log level that we log this at */
void dw_log_number(char *s1, int number, char *s2, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];

        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s%d%s\n",s1,number,s2);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s%d%s\n",s1,number,s2);
#endif /* MINGW */

}

void dw_log_hex(char *s1, uint32_t number, int min_log_level) {
        int32_t ll = key_n[DWM_N_verbose_level];

        if(ll <= 0 || ll < min_log_level) {
                return;
        }

#ifndef MINGW
        printf("%s%x\n",s1,number);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s%x\n",s1,number);
#endif /* MINGW */
}

/* Log 3 strings; input: Strings to log; minimum log level that we log these
 * strings at; this always logs and is run before Dwood2rc file is parsed */
void dw_alog_3strings(char *s1, char *s2, char *s3) {

#ifndef MINGW
        printf("%s%s%s\n",s1,s2,s3);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s%s%s\n",s1,s2,s3);
#endif /* MINGW */

}

/* Log a string, a number, and a string
 * input: String #1, Number, and String #2 to log;
 * minimum log level that we log this at
 * This always logs and is run before Dwood2rc file is fully parsed */
void dw_alog_number(char *s1, int number, char *s2) {

#ifndef MINGW
        printf("%s%d %s\n",s1,number,s2);
#else /* MINGW */
        dw_win_time();
        fprintf(LOG,"%s%d %s\n",s1,number,s2);
#endif /* MINGW */

}

/* Exit with a fatal error */
/* Exit with a fatal error */
void dw_fatal(char *why) {
        if(why != 0) {
#ifndef MINGW
                printf("Fatal: %s\n",why);
#else /* MINGW */
                dw_win_time();
                fprintf(LOG,"Fatal: %s\n",why);
#endif /* MINGW */
        } else {
#ifndef MINGW
                printf("Fatal: Unknown fatal error\n");
#else /* MINGW */
                dw_win_time();
                fprintf(LOG,"Fatal: Unknown fatal error\n");
#endif /* MINGW */
        }
        dw_log_close();
        exit(1);
}

/* Set the 64-bit timestamp starting at 290805600 unix() time (When
 * the Blake's 7 episode Gambit was originally broadcast); this should
 * be called several times a second.  Each second has 256 "ticks". */
void set_time() {
#ifdef FALLBACK_TIME
        time_t sys_time;
        sys_time = time(0);
        if(sizeof(sys_time) > 4) {
                if(sys_time != -1) {
                        the_time = sys_time - 290805600;
                }
        } else {
                if(sys_time < DW_MINTIME) {
                        the_time = sys_time + 4004161696U;
                } else {
                        the_time = sys_time - 290805600;
                }
        }
        the_time <<= 8; /* Each second has 256 "ticks" */
#else /* FALLBACK_TIME */
#ifndef MINGW
        struct timespec posix_time;
        time_t coarse;
        long fine;
        long result;
        result = clock_gettime(CLOCK_REALTIME, &posix_time);
        if(result == 0) { /* Successful getting time */
                coarse = posix_time.tv_sec;
                fine = posix_time.tv_nsec;
                if(sizeof(coarse) > 4) {
                        if(coarse != -1) {
                                the_time = coarse - 290805600;
                        }
                } else {
                        if(coarse < DW_MINTIME) {
                                the_time = coarse + 4004161696U;
                        } else {
                                the_time = coarse - 290805600;
                        }
                }
                the_time <<= 8;
                fine /= 3906250; /* 256 "ticks" per second */
                if(fine > 0 && fine <= 256) {
                        the_time += fine;
                }
                //printf("time: %llx control %lx\n",the_time,time(0)-290805600);//DEBUG
        }
#else /* MINGW */
        FILETIME win_time = { 0, 0 };
	uint64_t calc_time = 0; // Unsigned to not have Y15424 issue
        GetSystemTimeAsFileTime(&win_time);
        calc_time = win_time.dwHighDateTime & 0xffffffff;
        calc_time <<= 32;
        calc_time |= (win_time.dwLowDateTime & 0xffffffff);
        calc_time *= 2;
        calc_time /= 78125;
        calc_time -= 3055431475200LL;
        the_time = calc_time;
#endif /* MINGW */
#endif /* FALLBACK_TIME */
}

/* Set up some signal handlers, so MaraDNS can write the cache to a file
 * when exiting */
#ifndef MINGW
int got_signal = 0;

/* Handler for various signals.
 *
 * TERM: Write cache to disk, end program, exit with 0
 * HUP:  Write cache to disk, end program, exit with 8
 * USR1: Write cache to disk; continue running program
 */

/* TERM signal handler */
void handle_signal(int code) {
        switch(code) {
                case SIGTERM:
                case SIGINT:
                        got_signal = 1;
                        break;
                case SIGHUP:
                        got_signal = 2;
                        break;
                case SIGUSR1:
                        got_signal = 3;
        }
        signal(code, handle_signal);
}

/* Assign handlers for TERM, HUP, and USR1 signals */
void setup_signals() {
        signal(SIGTERM,handle_signal);
        signal(SIGHUP,handle_signal);
        signal(SIGUSR1,handle_signal);
        signal(SIGINT,handle_signal);
}
#endif /* MINGW */

/* Process a signal received */
void process_signal(int number) {
        dw_str *filename = 0;
        char *fname_convert = 0;

#ifndef MINGW
        /* Clear the signal flag */
        got_signal = 0;
#endif /* MINGW */

        /* Write the cache contents to disk */
        filename = key_s[DWM_S_cache_file];
        if(cache != 0 && filename != 0) {
                dw_filename_sanitize(filename);
                fname_convert = (char *)dw_to_cstr(filename);
                dwh_write_hash(cache,fname_convert);
                free(fname_convert);
        }

#ifndef MINGW
        /* Exit if they requested it (*NIX only) */
        if(number == 1) { /* TERM */
                exit(0);
        } else if(number == 2) { /* HUP */
                exit(8); /* Use by Duende to indicate we exited with HUP */
        }
#endif /* MINGW */
}

/* Initialize the cache */
void init_cache() {
        dw_str *filename = 0;
        char *fname_convert = 0;
        struct stat cache_st;

        dwh_process_mararc_params(); /* Get the cache size */
        if(cache != 0) { /* Don't init cache twice */
                return;
        }

        /* See if we can read the cache from a file */
        filename = key_s[DWM_S_cache_file];
        if(filename != 0 && do_read_cache == 1) {
                dw_filename_sanitize(filename);
                fname_convert = (char *)dw_to_cstr(filename);
#ifndef MINGW
                if(sizeof(time_t) > 4 &&
                   stat(fname_convert,&cache_st) == 0 &&
                   cache_st.st_mtime < mararc_st.st_mtime) {
                        dw_log_string(
                              "Cache older than rc file; not reading cache",0);
                } else {
#endif /* MINGW */
                        cache = dwh_read_hash(fname_convert);
#ifndef MINGW
                }
#endif /* MINGW */
                free(fname_convert);
        }

        if(cache == 0) { /* Just in case read from file failed */
                cache = dwh_hash_init(0); /* Size comes from dwood2rc */
        }
}

/* If present, load a hash file of blocked hosts.  This file is in a
 * special binary format allowing a lot of host names (to be blocked)
 * to be stored using little memory while being fast to check if a 
 * given host name is listed */
void load_blocked_hosts_hash_file() {
	dw_str *filename = 0;
	char *fname_convert = 0;
	filename = key_s[DWM_S_blocked_hosts_hash_file];	
	if(filename == 0) { // Not set
		return; 
	}
	dw_filename_sani_two(filename);
	fname_convert = (char *)dw_to_cstr(filename);
        if(fname_convert == NULL) {
                dw_fatal("Problem converting blocked_hosts_hash_file");
        }
        blocked_hosts_hash = DBH_makeBlockHash(fname_convert);
        if(blocked_hosts_hash == NULL) {
                dw_fatal("Problem reading blocked_hosts_hash_file");
        }
        /* Do not load file with 0 key unless allow_block_hash_zero_key=1 */
        if(blocked_hosts_hash->sipKey1 == 0 && 
           blocked_hosts_hash->sipKey2 == 0 &&
           key_n[DWM_N_allow_block_hash_zero_key] != 1) {
		dw_fatal("Zero key block hash not allowed by default");
        }
	free(fname_convert);
}

/* Read mararc parameters and set global variables based on those
 * parameters; disable cache reading if cache file is more recent */
void process_mararc(char *name) {
        if(dwm_parse_mararc(name) != 1) {
                dw_log_3strings("Fatal error parsing file ",name,"",1);
                exit(1);
        }
        /* The following sanity check triggers a warning; disabled */
        /*if(key_s == 0 || key_d == 0) {
                dw_fatal("error getting mararc parameters");
        }*/
        /* If the dwood3rc is newer than the cache file, do not read the
         * cache */
#ifndef MINGW
        if(sizeof(time_t) > 4 && stat(name,&mararc_st) != 0) {
                dw_log_string("Can not stat rc file; not reading cache",0);
                do_read_cache = 0;
        }
#endif /* MINGW */
}

/* Given a C-string string containing random noise, the length of that
 * string, initialize the RNG */
void noise_to_rng(uint8_t *noise, int len) {
        dw_str *z = 0;

        z = dw_create(len + 1);
        if(z == 0) {
                dw_fatal("error creating rng dw_str");
        }

        if(dw_cstr_append(noise, len, z) == -1) {
                dw_fatal("error putting noise in dw_str object");
        }

        rng_seed = dwr_init_rg(z);

        if(rng_seed == 0) {
                dw_fatal("error initializing rng_seed");
        }

        /* Make sure we are generating random numbers which differ */
        dw_log_hex("Random number test: ",dwr_rng(rng_seed),128);

        if(z != 0) {
                dw_destroy(z);
                z = 0;
        }
}

/* Given a pointer to some noise, and a desired length, open up the
 * random_seed_file and get between 16 bytes and the desired length from
 * said file, putting the entropy in the noise pointer */
void get_entropy_from_seedfile(uint8_t *noise,int len) {
#ifdef MINGW
        /* To make life easier for Windows users, we no longer
         * require them to make a secret.txt file before running
         * Deadwood */
        HCRYPTPROV CryptContext;
        int b;
        b = CryptAcquireContext(&CryptContext, NULL, NULL, PROV_RSA_FULL,
                CRYPT_VERIFYCONTEXT);
        if(b != 1) {
                dw_fatal("Can not call CryptAcquireContext");
        }
        b = CryptGenRandom(CryptContext, 32, noise);
        if(b != 1) {
                dw_fatal("Can not call CryptGenRandom");
        }
        CryptReleaseContext(CryptContext,0);
#else /* MINGW */
        char *filename = 0;
        int zap = 0;
        int seed = -1;

        if(key_s[DWM_S_random_seed_file] == 0) {
                filename = "/dev/urandom"; /* Default filename */
        } else {
                filename = (char *)dw_to_cstr(key_s[DWM_S_random_seed_file]);
                zap = 1;
        }

        seed = open(filename, O_RDONLY);
        if(seed == -1) {
                dw_log_3strings("Fatal error opening random seed file ",
                       filename,"",1);
                exit(1);
        }

        if(read(seed,(void *)noise,len) < 16) {
                dw_log_3strings("Unable to get 128 bits of entropy; file ",
                       filename,
                       " must be\n at least 16 bytes (128 bits) long",1);
                exit(1);
        }

        if(zap == 1) {
                free(filename);
                filename = 0;
        }
        close(seed);
#endif /* MINGW */
}

/* Initialize random number generator.  Note that some bytes of the "noise"
 * string will have random junk in them.  This is intentional. */
void init_rng() {
        int a = 0;
        uint8_t *noise = 0;
        int64_t tstamp = 0;
        pid_t pnum = 1;

        noise = (uint8_t *)dw_malloc(512);
        if(noise == 0) {
                dw_fatal("error allocating memory for noise");
        }
#ifdef VALGRIND_NOERRORS
        /* Valgrind reports our intentional use of values of uncleared
         * allocated memory as one source of entropy as an error, so we
         * allow it to be disabled for Valgrind testing */
        memset(noise,0,512);
#endif /* VALGRIND_NOERRORS */

        get_entropy_from_seedfile(noise,256);

        /* Get entropy from the current timestamp */
        set_time();
        tstamp = get_time();
        for(a = 0 ; a < 8 ; a++) {
                *(noise + a + 256) = tstamp & 0xff;
                tstamp >>= 8;
        }

        /* Get entropy from the process' ID number */
        pnum = getpid();
        for(a = 0 ; a < sizeof(pnum) ; a++ ) {
                *(noise + a + 272) = pnum & 0xff;
                pnum >>= 8;
        }

        /* Initialize the RNG based on the contents of noise */
        noise_to_rng(noise,510);

        if(noise != 0) {
                free(noise);
                noise = 0;
        }

}

/* Drop privileges and become unprivileged user */
void sandbox() {
#ifndef MINGW
#ifndef __CYGWIN__
        unsigned char *c = 0;
        gid_t g = DW_UID;
        if(key_s[DWM_S_chroot_dir] == 0) {
                dw_fatal("chroot_dir not set");
        }
        c = dw_to_cstr(key_s[DWM_S_chroot_dir]);
        if(c == 0) {
                dw_fatal("Converting chroot_dir to string failed");
        }
        if(chdir((char *)c) != 0) {
                printf("There is no directory %s\n",(char *)c);
                dw_fatal("chdir() failed");
        }
#ifndef QNX
        if(chroot((char *)c) == -1) {
                dw_fatal("chroot() failed");
        }
#endif /* QNX */
        if(setgroups(1,&g) == -1) {
                dw_fatal("setgroups() failed");
        }
        if(setgid(maradns_gid) != 0) {
                dw_fatal("setgid() failed");
        }
        if(setuid(maradns_uid) != 0) {
                dw_fatal("setuid() failed");
        }
        if(setuid(0) == 0) {
                dw_fatal("Your kernel\'s setuid() is broken");
        }

        if(c != 0) {
                free(c);
                c = 0;
        }
        return;
#endif /* __CYGWIN__ */
#endif /* MINGW */
}

/* Get, from the Mararc parameters, the list of bind addresses
 * we will bind to; return this list as a comma-separated dw_str */
dw_str *get_bind_addrs() {
        dw_str *bind = 0;

        if(key_s[DWM_S_bind_address] != 0) {
                bind = dw_copy(key_s[DWM_S_bind_address]);
        } else if(key_s[DWM_S_ipv4_bind_addresses] != 0) {
                bind = dw_copy(key_s[DWM_S_ipv4_bind_addresses]);
        } else {
                        dw_fatal("Please set bind_address");
        }

        if(bind == 0) {
                goto catch_get_bind_addrs;
        }

        if(key_s[DWM_S_bind_address] != 0 &&
           key_s[DWM_S_ipv4_bind_addresses] != 0) {
                if(dw_addchar(',',bind) == -1) {
                        goto catch_get_bind_addrs;
                }
                if(dw_append(key_s[DWM_S_ipv4_bind_addresses],bind) == -1) {
                        goto catch_get_bind_addrs;
                }
        }

        return bind;

catch_get_bind_addrs:
        if(bind != 0) {
                dw_destroy(bind);
                bind = 0;
        }
        return 0;
}

/* Make sure a DNS packet is sane, and return the packet's
 * query ID.  If roy_arends_check has a value of 1, we also make sure
 * it's a DNS question (and not a reply).  This is named in honor of
 * Roy Arends, who pointed out the original MaraDNS didn't check this.
 * If this returns -1, the packet was not sane.
 *
 * If roy_arends_check has a value of 2, we make sure the packet is
 * a sane packet for a recursive request.  In more detail:
 *
 * QR must be 0
 * Opcode must be 0
 * RD must be 1
 * Z must be 0
 * RCODE must be 0
 * QDCOUNT must be 1
 * ANCOUNT, NSCOUNT, and ARCOUNT must be 0
 */

int32_t get_dns_qid(unsigned char *a, int len, int roy_arends_check) {
        /* Make sure we're kosher */
        if(len < 12) { /* Size of DNS header */
                return -1;
        }
        if(roy_arends_check == 1 && ((a[2] & 0x80) != 0)) {
                /* If it's an answer, not a query */
                return -1;
        }
        if(roy_arends_check == 2 && (
           /* a[2]: QR, Opcode (4 bits), AA, TC, and RD */
           ((a[2] & 0xf9)) != 0x01 ||
           /* a[3]: RA, Z (1 bit), AD & CD (2 bits, RFC2535), RCODE (4 bits) */
           ((a[3] & 0x4f)) != 0x00 ||
           /* a[4] and a[5]: QDCOUNT */
           a[4] != 0 || a[5] != 1 ||
           /* a[6], a[7]: ANCOUNT */
           a[6] != 0 || a[7] != 0 ||
           /* a[8], a[9]: NSCOUNT */
           a[8] != 0 || a[9] != 0 ||
           /* a[10], a[11]: ARCOUNT */
           a[10] != 0))
        {
                return -1;
        }
        if(roy_arends_check == 2 && a[11] == 1) {
                return -2; /* Send NOTIMPL; OPT/EDNS not supported */
        }
        if(roy_arends_check == 2 && a[11] != 0) {
                return -1; /* Drop packet */
        }
        /* A DNS header is not considered kosher if it doesn't
         * have an question, nor any other RRs ; we look
         * at QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT */
        if(a[5] == 0 && a[4] == 0 && a[6] == 0 && a[7] == 0 &&
           a[8] == 0 && a[9] == 0 && a[10] == 0 && a[11] == 0) {
                dw_log_string("Warning: Blank DNS packet",10);
                return -1;
        }

        return (a[0] << 8) | a[1];
}

/* Given a string with a DNS packet, and the length of that string,
 * make the first two bytes of the packet (the query ID) the third
 * argument (qid), and return that number. -1 on error */
int32_t set_dns_qid(unsigned char *packet, int len, uint16_t qid) {
        /* Make sure we're kosher */
        if(len < 12) { /* Size of DNS header */
                return -1;
        }
        *packet = qid >> 8;
        *(packet + 1) = qid & 0xff;
        return qid;
}

/* This function converts a dw_str object in to a null-terminated
 * C-string with the last item in the comma-separated list in the
 * dw_str, with any leading whitespace in the last item removed */
char *pop_last_item(dw_str *list) {
        dw_str *a = 0, *b = 0;
        char *ret = 0;

        a = dw_qspop(list);
        if(a == 0) {
                goto catch_pop_last_item;
        }
        b = dw_zap_lws(a);
        if(b == 0) {
                goto catch_pop_last_item;
        }
        ret = (char *)dw_to_cstr(b);

catch_pop_last_item:
        if(a != 0) {
                dw_destroy(a);
                a = 0;
        }
        if(b != 0) {
                dw_destroy(b);
                b = 0;
        }
        return ret;
}

/* This creates a netmask from a single number, storing the number in a
 * string of octets.  0 just makes the string all 0s; 1 makes the string
 * 0x80 0x00 0x00 etc.; 2 makes the string 0xc0 0x00 etc.; etc.
 * The string of octets has a length len (4 for ipv6; 16 for ipv6) */
void make_netmask(int num, uint8_t *str, int len) {
        int div = 0, rem = 0;
        uint8_t last = 0;

        if(len < 1 || len > 64) {
                return;
        }

        /* Since we're dividing by a power of 2, we don't need to do
         * an expensive division */
        div = num >> 3;
        rem = (num & 0x07);

        if(div < 0 || div > len) { /* Sanity check */
                return;
        }

        /* The last byte in the string is determined by the modulo */
        last = 0xff;
        last <<= (8 - rem);

        /* This kind of coding is dangerous.  I have triple-checked
         * the following code and don't see any possible overflows */
        while(div > 0) { /* 0xff up until the last non-0 byte */
                *str = 0xff;
                str++;
                div--;
                len--;
        }
        if(len > 0) { /* Check needed for /32 and /128 masks */
                *str = last; /* The last non-0 byte */
                len--;
                while(len > 0) { /* The rest of the mask is 0x00 */
                        str++;
                        *str = 0x00;
                        len--;
                }
        }
}

/* Get a numeric value from the mararc parameters and make sure it is
 * within a range; if def is not -1, make an out-of-range parameter
 * the def value */
int32_t get_key_n(int32_t get, int32_t min, int32_t max, int32_t def) {
        int32_t val;

        val = key_n[get];

        if(val < min) {
                if(def == -1) {
                        val = min;
                } else {
                        val = def;
                }
        } else if(val > max) {
                if(def == -1) {
                        val = max;
                } else {
                        val = def;
                }
        }
        return val;
}

