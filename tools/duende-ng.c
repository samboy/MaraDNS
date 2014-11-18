/* Copyright (c) 2003-2008, 2011 Sam Trenholme and others
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

/* This is the version of Duende which Nicholas Bamber has worked very
 * hard to bring up to snuff to work with Debian.  Not only did he fix
 * a bug with reaping Duende's children (which I have backported to the
 * "classic" Duende), he also has added some features.  To summarize:

  short form  long form        description
  -c          --chroot=DIR     Directory log helper should change and chroot to
  -g          --gid=GID        Groupid log helper should change down to
  -i          --ident=STR      How log helper should be identified in syslog
  -p          --pid=FILE       File used to store pid of duende process
  -r          --restart_on=INT Exit status on which to restart child process
  -u          --uid=UID        Userid log helper should change down to

 * I thank Nicholas Bamber for his hard volunteer work making Duende a
 * better program.  Note that this version of Duende uses the argp library
 * to process these options which may not compile with some libcs and on some
 * embedded systems; hence the "ng" designation
 *
 * More information may or may not be here:
 *
 *      http://www.periapt.co.uk/arcana/struggling-with-duende
 *
 */

/* I would like to thank D. Richard Felker III for his invaluable help
   with debugging how the pipes are set up here */

/* This program is a helper application which does the following:

   It starts the maradns process

   It syslog()s maradns' output via a chroot'd unprivledged child process

   If maradns exits with a code of 8, this means that she was given a
   HUP signal.  Restart the MaraDNS process

   If this process gets a HUP signal, restart the MaraDNS process

 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <argp.h>
#include <string.h>
#include "../MaraDns.h"

int got_hup_signal = 0;
int got_term_signal = 0;

/* needed for command line overrides */
struct argument
{
    int duende_uid; /* = DUENDE_LOGGER_UID; */
    int duende_gid; /* = DUENDE_LOGGER_UID; */
    int restart_on_exit;
    const char *duende_chroot;
    const char *duende_pid_file;
    const char *duende_ident;
    int argc;
    char **argv;
};

static const struct argp_option options[] = {
    {"pid",    'p', "FILE", 0, "File used to store pid of duende process"},
    {"uid",    'u', "UID",  0, "Userid log helper should change down to"},
    {"gid",    'g', "GID",  0, "Groupid log helper should change down to"},
    {"chroot", 'c', "DIR",  0, "Directory log helper should change and chroot to"},
    {"ident",  'i', "STR",  0, "How log helper should be identified in syslog"},
    {"restart_on",    'r', "INT",  0, "Exit status on which to restart child process"},
    {0}
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct argument *arguments = state->input;

    switch(key) {
        case 'c': /* chroot */
            arguments->duende_chroot = arg;
            break;
        case 'i': /* ident */
            arguments->duende_ident = arg;
            break;
        case 'u': /* uid */
            arguments->duende_uid = atoi(arg);
            break;
        case 'r': /* restart on */
            arguments->restart_on_exit = atoi(arg);
            break;
        case 'g': /* gid */
            arguments->duende_gid = atoi(arg);
            break;
        case 'p': /* pid */
            arguments->duende_pid_file = arg;
            break;
        case ARGP_KEY_NO_ARGS:
            argp_usage(state);
        case ARGP_KEY_ARGS:
            arguments->argc = state->argc - state->next;
            arguments->argv = state->argv + state->next;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static char doc[] = "duende -- a program to manage a daemon process, logging its standard output and error to syslog";
static char args_doc[] = "command [arguments...]";

static struct argp argp = {options, parse_opt, args_doc, doc};

/* If we get a HUP signal set the flag so we can restart the MaraDNS child
   process */
void handle_hup() {
    got_hup_signal = 1;
    return;
    }

void handle_term() {
    got_term_signal = 1;
    return;
    }

/* Helper process which syslogs stuff from either MaraDNS' stdout or stderr. */

void log_helper(const struct argument *arguments, int stdout_fd) {
    char out_buf[1024];

    /* We can't use our signal handlers because fgets is blocking */
    signal(SIGTERM,SIG_DFL);
    signal(SIGHUP,SIG_DFL);

    /* Open up the sys log */
    syslog(LOG_ALERT,"%s process starting up", arguments->duende_ident);

    /* Drop all privileges */
    if (chdir(arguments->duende_chroot) != 0) {
        syslog(LOG_ALERT,"Can not enter chroot directory %s", arguments->duende_chroot);
        syslog(LOG_ALERT,"%s","We can not log daemon output");
        printf("Fatal error logging; read syslog\n");
        printf("%s directory required to exist\n",arguments->duende_chroot);
        exit(1);
    }
#if ! (defined __CYGWIN__ || defined QNX)
    if (chroot(arguments->duende_chroot) != 0) {
        syslog(LOG_ALERT,"Can not chroot to directory %s",arguments->duende_chroot);
        printf("Fatal error logging; read syslog\n");
        exit(1);
    }
#endif
    if(setgid(arguments->duende_gid) != 0) {
        syslog(LOG_ALERT,"%s%d","Can not change GID to ", arguments->duende_gid);
        printf("Fatal error logging; read syslog\n");
        exit(1);
    }
    if(setuid(arguments->duende_uid) != 0) {
        syslog(LOG_ALERT,"%s%d","Can not change UID to ", arguments->duende_uid);
        syslog(LOG_ALERT,"%s","We can not log daemon output");
        printf("Fatal error logging; read syslog\n");
        exit(1);
    }


    /* Log both stdout and stderr */
    dup2(stdout_fd,0);
    for(;;) {
        if(fgets(out_buf,1020,stdin) == out_buf)
#ifdef __FreeBSD__
            /* FreeBSD doesn't log daemon.info messages by default; while
             * this can be changed by editing /etc/syslog.conf, it *is*
             * an issue that can cause confusion */
            syslog(LOG_ALERT,"%s",out_buf);
#else /* __FreeBSD__ */
            syslog(LOG_ALERT,"%s",out_buf);
#endif /* __FreeBSD__ */
        }

    syslog(LOG_ALERT,"log_helper process terminating");
    exit(0);

    }


/* If a child exits, see if the child exited with a code of 8 or received
   a HUP signal.  In either of these cases, restart the child daemon and the
   (if needed) logger process).  Otherwise, exit */

void handle_child_exited(int exit_status, pid_t alive, pid_t exited, int restart_code) {
        if(WIFEXITED(exit_status)) { /* Exit with exit code */
            if(WEXITSTATUS(exit_status) != restart_code) { /* Anything but HUP */
                kill(alive,SIGTERM);
                syslog(LOG_ALERT,"Child exited with status %d",exit_status);
                exit(WEXITSTATUS(exit_status));
                }
            }
        if(WIFSIGNALED(exit_status)) { /* Got signal */
            if(WTERMSIG(exit_status) != SIGHUP) {
                syslog(LOG_ALERT,"Child got signal %d",exit_status);
                kill(alive,SIGTERM);
                exit(1);
                }
            }
       /* If you somehow stop the child daemon, we go bye bye */
       if(WIFSTOPPED(exit_status)) {
            syslog(LOG_ALERT,"Child stopped");
            kill(exited,SIGTERM);
            kill(alive,SIGTERM);
            exit(2);
            }
       /* Clean up the system logging */
       syslog(LOG_ALERT,"Cleaning up system logging");
       kill(alive,SIGTERM);
    }

/* The main process forks off the child.  Right now, I will just have
   it fork off the MaraDNS process, hardwired as /usr/sbin/maradns,
   directing her standard output to
   /dev/null.  The revision of this file will correctly handle Mara's
   output
 */

int main(int argc, char **argv) {
    int exit_status;
    int check_pid;
    pid_t pid, log_pid;
    int stream1[2]; /* Used for piping */
    struct argument arguments;

    /* Initialize data structures */
    arguments.duende_chroot = DUENDE_CHROOT_DIR;
    arguments.duende_pid_file = 0;
    arguments.duende_gid = DUENDE_LOGGER_UID;
    arguments.duende_uid = DUENDE_LOGGER_UID;
    arguments.duende_ident = "log-helper";
    arguments.restart_on_exit = 8;
    arguments.argc = 0;
    arguments.argv = 0;

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);

    if (arguments.argv == 0 || arguments.argv[0] == 0) {
        printf("FATAL: Unable to identify command\n");
        exit(1);
    }

    /* Let children know that duende is running */
    if(setenv("DUENDE_IS_RUNNING","1",0) != 0) {
        printf("FATAL: Unable to set environment variable\n");
        exit(1);
    }

    /* The parent immediately exits */
    if(fork() != 0)
        exit(0);

    /* The child becomes a full-fledged daemon */
    setpgid(0,0); /* No longer visible in 'ps' without the 'auxw' argument */

    /* Write our PID to a file if the user so desires us to */
    if(arguments.duende_pid_file) {
        FILE *fp_pid = fopen(arguments.duende_pid_file,"w");
        if (!fp_pid) {
            syslog(LOG_ALERT,"Fatal writing, to PID file, error\n");
            exit(1);
        }
        unsigned int local_pid = getpid();
        fprintf(fp_pid,"%u",local_pid);
        fclose(fp_pid);
    }
    /* Sysadmins expect HUP to reload, so we set that up */
    signal(SIGHUP,handle_hup);
    signal(SIGTERM,handle_term);
    signal(SIGINT,handle_term);

    pid = 0; log_pid = 0;

    openlog(arguments.duende_ident,LOG_PID,LOG_DAEMON);

    for(;;) {
        if (pipe(stream1) != 0) {
            syslog(LOG_ALERT,"Fatal pipe error");
            exit(3);
        }
        pid = fork();
        if (pid == -1) {
            syslog(LOG_ALERT,"Fatal pid error");
            exit(1);
        }
        if (pid == 0) { /* Child; this one execs maradns */
            close(stream1[0]);
            /* Dup the standard output */
            if (dup2(stream1[1],1) != 1) {
                syslog(LOG_ALERT,"Fatal dup2 error 1");
                exit(4);
            }
            /* And the standard error */
            if (dup2(stream1[1],2) != 2) {
                syslog(LOG_ALERT,"Fatal dup2 error 2");
                exit(5);
            }
            execvp(arguments.argv[0],arguments.argv);
            /* OK, not found */
            printf("duende: %s: Command can't run, terminating\n",arguments.argv[0]);
            syslog(LOG_ALERT,"Command can't run, terminating\n");
            exit(1);
        }

        /* Parent */
        close(stream1[1]);
        log_pid = fork();
        if (log_pid == 0) { /* Child to syslog all of MaraDNS' output */
            log_helper(&arguments, stream1[0]);
            syslog(LOG_ALERT,"log_helper finished, terminating\n");
            exit(1);
        }
        for(;;) {
            /* If we got a HUP signal, send it to the child */
            if (got_hup_signal == 1) {
                kill(pid,SIGHUP);
                got_hup_signal = 0;
            }
            /* If we got a TERM or INT signal, send it to the children
               then exit ourselves */
            else if (got_term_signal == 1) {
                /* XXX: make sure term really stops the children */
                kill(pid,SIGTERM);
                kill(log_pid,SIGTERM);
                syslog(LOG_ALERT,"got term signal, terminating\n");
                exit(0);
            }
            sleep(1);
            int wait_pid = waitpid(-1, &exit_status, WNOHANG);
            if (wait_pid == pid) { /* If child ended */
                handle_child_exited(exit_status,log_pid,pid,arguments.restart_on_exit);
                close(stream1[0]);
                break; /* Out of the inner loop; re-start Mara */
            }
            /* If logger terminated */
            else if (wait_pid == log_pid) {
                handle_child_exited(exit_status,pid,log_pid,arguments.restart_on_exit);
                close(stream1[0]);
                break; /* Out of the inner loop; re-start Mara */
            }
            else if (wait_pid > 0) {
                syslog(LOG_ALERT, "unexpected child reaped: %i", wait_pid);
            }
        }
    }
}

