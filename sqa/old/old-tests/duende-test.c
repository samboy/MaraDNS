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

/* This is an application which tests to see if our select() stuff
   breaks down because MaraDNS is multithreaded */

#include <pthread.h>
#include <stdio.h>

void subthread(int ignored) {
    fprintf(stdout,"Stdout in sub thread\n");
    fprintf(stderr,"Stderr in sub-thread\n");
    for(;;) {
        fflush(stdout);
        fprintf(stdout,"More stdout in sub thread\n");
        fprintf(stderr,"More stderr in sub-thread\n");
        }
    sleep(1);
    return;
    }

int main() {
    pthread_t thread;
    pthread_attr_t attr;

    fprintf(stdout,"Stdout in main thread\n");
    fprintf(stderr,"Stderr in main thread\n");

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

    if(pthread_create(&thread,&attr,(void *)subthread,NULL) != 0) {
        fprintf(stderr,"Failed to create subthread\n");
        }

    pthread_attr_destroy(&attr);

    for(;;) {
        fflush(stdout);
        fprintf(stdout,"More stdout in main thread\n");
        fprintf(stderr,"More stderr in main thread\n");
        }

    }

