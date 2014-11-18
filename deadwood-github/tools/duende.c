/* Copyright (c) 2003-2008 Sam Trenholme
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

/* The UID that the Duende logging process uses.  CHANGE THE DUENDE MAN
   PAGE IF YOU CHANGE THIS VALUE (same general process as changing the
   mararc man page; the source file for the duende man page is duende.ej) */
#define DUENDE_LOGGER_UID 66

/* The directory that Duende runs in.  This directory has to exist for
   Duende to be able to run.  Again, IF YOU CHANGE THIS, CHANGE THE
   DUENDE MAN PAGE */
#define DUENDE_CHROOT_DIR "/etc/maradns/logger"

int got_hup_signal = 0;
int got_term_signal = 0;

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

void log_helper(char *name,int stdout_fd) {
    char out_buf[1024];

    /* We can't use our signal handlers because fgets is blocking */
    signal(SIGTERM,SIG_DFL);
    signal(SIGHUP,SIG_DFL);

    /* Open up the sys log */
    openlog(name,0,LOG_DAEMON);

    /* Drop all privileges */
    if(chdir(DUENDE_CHROOT_DIR) != 0) {
       syslog(LOG_ALERT,"Can not enter chroot directory %s",DUENDE_CHROOT_DIR);
        syslog(LOG_ALERT,"%s","We can not log daemon output");
        printf("Fatal error logging; read syslog\n");
        printf("%s directory required to exist\n",DUENDE_CHROOT_DIR);
        exit(1);
        }
    if(setuid(DUENDE_LOGGER_UID) != 0) {
        syslog(LOG_ALERT,"%s%d","Can not change UID to ",DUENDE_LOGGER_UID);
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
            syslog(LOG_INFO,"%s",out_buf);
#endif /* __FreeBSD__ */
        }

    syslog(LOG_ALERT,"log_helper process terminating");
    exit(0);

    }


/* If a child exits, see if the child exited with a code of 8 or received
   a HUP signal.  In either of these cases, restart the child daemon and the
   (if needed) logger process).  Otherwise, exit */

void handle_child_exited(int exit_status, pid_t alive, pid_t exited) {
        if(WIFEXITED(exit_status)) { /* Exit with exit code */
            if(WEXITSTATUS(exit_status) != 8) { /* Anything but HUP */
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
    pid_t pid, log_pid;
    int stream1[2]; /* Used for piping */
    int exec_argv_offset = 1; /* Also used to determine PID writing */
    if(argv[0] == NULL || argv[1] == NULL) {
        printf("Usage: duende (--pid=/path/to/file) [program] [arguments]\n");
        exit(1);
        }
    if(!strncasecmp(argv[1],"--pid=",6)) {
        if(argv[2] == NULL) {
            printf(
                "Usage: duende (--pid=/path/to/file) [program] [arguments]\n");
            exit(1);
            }
        exec_argv_offset = 2;
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
    if(exec_argv_offset == 2) {
        FILE *fp_pid = fopen(argv[1] + 6,"w");
        if(!fp_pid) {
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

    for(;;) {
        if(pipe(stream1) != 0) {
            syslog(LOG_ALERT,"Fatal pipe error");
            exit(3);
            }
        pid = fork();
        if(pid == -1) {
            syslog(LOG_ALERT,"Fatal pid error");
            exit(1);
            }
        if(pid == 0) { /* Child; this one execs maradns */
            close(stream1[0]);
            /* Dup the standard output */
            if(dup2(stream1[1],1) != 1) {
                syslog(LOG_ALERT,"Fatal dup2 error 1");
                exit(4);
                }
            /* And the standard error */
            if(dup2(stream1[1],2) != 2) {
                syslog(LOG_ALERT,"Fatal dup2 error 2");
                exit(5);
                }
            argv[0] = argv[exec_argv_offset];
            execvp(argv[exec_argv_offset],argv + exec_argv_offset);
            /* OK, not found */
            printf("duende: %s: Command can't run, terminating\n",argv[exec_argv_offset]);
            syslog(LOG_ALERT,"Command can't run, terminating\n");
            exit(1);
            }

        /* Parent */
        close(stream1[1]);
        log_pid = fork();
        if(log_pid == 0) { /* Child to syslog all of MaraDNS' output */
            argv[0] = "duende-log-helper";
            log_helper(argv[exec_argv_offset],stream1[0]);
            syslog(LOG_ALERT,"log_helper finished, terminating\n");
            exit(1);
            }
        for(;;) {
            /* If we got a HUP signal, send it to the child */
            if(got_hup_signal == 1) {
                kill(pid,SIGHUP);
                got_hup_signal = 0;
                }
            /* If we got a TERM or INT signal, send it to the children
               then exit ourselves */
            else if(got_term_signal == 1) {
                /* XXX: make sure term really stops the children */
                kill(pid,SIGTERM);
                kill(log_pid,SIGTERM);
                syslog(LOG_ALERT,"got term signal, terminating\n");
                exit(0);
                }
            sleep(1);
            if(waitpid(pid,&exit_status,WNOHANG) == pid) { /* If child ended */
                handle_child_exited(exit_status,log_pid,pid);
                close(stream1[0]);
                break; /* Out of the inner loop; re-start Mara */
                }
            /* If logger terminated */
            if(waitpid(log_pid,&exit_status,WNOHANG) == log_pid) {
                handle_child_exited(exit_status,pid,log_pid);
                close(stream1[0]);
                break; /* Out of the inner loop; re-start Mara */
                }
            }
        }
    }

