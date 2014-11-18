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

/* Headers for the underlying OS calls */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <limits.h>
#include <unistd.h>
#ifdef THREADS
#include <pthread.h>
#endif /* THREADS */

/* Headers for the string routines */
#include "JsStr.h"

/* Structures that keep track of allocated memory */
#ifdef DEBUG
#define HASH_SIZE 100000
typedef struct lt_hash_spot {
    void *allocated_memory;
    struct lt_hash_spot *next;
    char *de_donde; /* From where */
    int allocated_size;
    } lt_hash_spot;
int lt_hash_initialized = 0;
lt_hash_spot lt_hash[HASH_SIZE];
int total_allocated_memory = 0;
#define THREADS
#endif /* DEBUG */
#ifdef THREADS
pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;
#endif /* THREADS */

/* js_alloc: Allocate memory from the underlying OS.
   input: The unit count and unit size of memory to allocate
   output: An anonymous pointer to the allocated memory */

void *js_alloc(int unit_count, int unit_size) {
    void *data;
#ifdef DEBUG
    unsigned int hash_index,counter;
    lt_hash_spot *new,*point;
#endif /* DEBUG */
    /* Sanity check: Never allow this; makes C act buggy */
    if(unit_size == 0 || unit_count == 0)
        return 0;
    data = (void *)malloc(unit_count * unit_size);
#ifdef DEBUG
    /* If debug is set, we have a 64k element hash table which uses the low
       16 bits of the memory allocated as the hash index.  Each element in
       the hash table is a linked list, which has the address and number of
       bytes allocated for each piece of allocated memory */

    hash_index = (int)data;
    hash_index %= HASH_SIZE;
#ifdef THREADS
    pthread_mutex_lock(&alloc_lock);
#endif /* THREADS */
    /* Initialize the lt hash the first time we run this routine */
    if(lt_hash_initialized == 0) {
        for(counter = 0; counter < HASH_SIZE; counter++)
            lt_hash[counter].allocated_size = 0;
        lt_hash_initialized = 1;
        }
    /* If the hash pointer is empty, use that */
    if(lt_hash[hash_index].allocated_size == 0) {
        lt_hash[hash_index].allocated_size = unit_count * unit_size;
        lt_hash[hash_index].allocated_memory = data;
        lt_hash[hash_index].de_donde = 0;
        lt_hash[hash_index].next = 0;
        }
    /* Otherwise, go down the linked list, place the new node at the
       end of the branch in question */
    else {
        new = malloc(sizeof(lt_hash_spot));
        if(new == NULL) {
            printf("Aieeee, can not allocate memeory for lt_hash_spot!\n");
            exit(1);
            }
        new->allocated_size = unit_count * unit_size;
        new->next = 0;
        new->allocated_memory = data;
        new->de_donde = 0;
        point = lt_hash[hash_index].next;
        if(point == 0) {
            lt_hash[hash_index].next = new;
            }
        else {
            while(point->next != 0)
                point = point->next;
            point->next = new;
            }
        }
    total_allocated_memory += unit_count * unit_size;
#ifdef THREADS
    pthread_mutex_unlock(&alloc_lock);
#endif /* THREADS */
#endif /* DEBUG */
    if(data == NULL) {
        /* Securty: In a situtation where we can not allocate memory,
           the subsequent behavior of the program is undefined.  Hence,
           the best thing to do is exit then and there */
        printf("Aieeeeee, can not allocate memory!");
        exit(64);
        return (void *)0;
        }
    return data;
    }

/* js_alloc_DEBUG: Allocate memory from the underlying OS.
   input: The unit count and unit size of memory to allocate,
          from where they allocated this memory
   output: An anonymous pointer to the allocated memory */

void *js_alloc_DEBUG(int unit_count, int unit_size, char *whence) {
    void *data;
#ifdef DEBUG
    unsigned int hash_index,counter;
    lt_hash_spot *new,*point;
    char *why;
#endif /* DEBUG */
    data = (void *)malloc(unit_count * unit_size);
#ifdef DEBUG
    /* If debug is set, we have a 64k element hash table which uses the low
       16 bits of the memory allocated as the hash index.  Each element in
       the hash table is a linked list, which has the address and number of
       bytes allocated for each piece of allocated memory */

    hash_index = (int)data;
    hash_index %= HASH_SIZE;
    /* Set up the string used to tell people why this memory was
       allocated */
    if((why = malloc(strlen(whence) + 2)) == 0) {
        printf("Aieeee, mem alloc problem\n");
        exit(64);
        }
    strncpy(why,whence,strlen(whence) + 1);
#ifdef THREADS
    pthread_mutex_lock(&alloc_lock);
#endif /* THREADS */
    /* Initialize the lt hash the first time we run this routine */
    if(lt_hash_initialized == 0) {
        for(counter = 0; counter < HASH_SIZE; counter++)
            lt_hash[counter].allocated_size =0;
        lt_hash_initialized = 1;
        }
    /* If the hash pointer is empty, use that */
    if(lt_hash[hash_index].allocated_size == 0) {
        lt_hash[hash_index].allocated_size = unit_count * unit_size;
        lt_hash[hash_index].allocated_memory = data;
        lt_hash[hash_index].de_donde = why;
        lt_hash[hash_index].next = 0;
        }
    /* Otherwise, go down the linked list, place the new node at the
       end of the branch in question */
    else {
        new = malloc(sizeof(lt_hash_spot));
        if(new == NULL) {
            printf("Aieeee, can not allocate memeory for lt_hash_spot!\n");
            exit(1);
            }
        new->allocated_size = unit_count * unit_size;
        new->next = 0;
        new->allocated_memory = data;
        new->de_donde = why;
        point = lt_hash[hash_index].next;
        if(point == 0) {
            lt_hash[hash_index].next = new;
            }
        else {
            while(point->next != 0)
                point = point->next;
            point->next = new;
            }
        }
    total_allocated_memory += unit_count * unit_size;
#ifdef THREADS
    pthread_mutex_unlock(&alloc_lock);
#endif /* THREADS */
#endif /* DEBUG */
    if(data == NULL) {
        /* Securty: In a situtation where we can not allocate memory,
           the subsequent behavior of the program is undefined.  Hence,
           the best thing to do is exit then and there */
        printf("Aieeeeee, can not allocate memory!");
        exit(64);
        return (void *)0;
        }
    return data;
    }

/* js_dealloc: Deallocate memory from the underlying OS
   input: A pointer to the memory we wish to free
   output: -1 on failure, 1 on success */

int js_dealloc(void *pointer) {
#ifdef DEBUG
    lt_hash_spot *lpoint,*llast;
    unsigned int hash_index;
#endif /* DEBUG */
    if(pointer == 0) /* We don't bother with already dealloced memory */
            return 1;
#ifdef DEBUG
    /* We need to find out the number of bytes that we have allocated
       for this given address; subtract that from the total amount of
       memory used, then removed the node which keeps track of the allocated
       memory in question.  */
#ifdef THREADS
    pthread_mutex_lock(&alloc_lock);
#endif /* THREADS */
    hash_index = (int)pointer;
    hash_index %= HASH_SIZE;
    if(lt_hash[hash_index].allocated_memory == pointer) {
        lpoint = lt_hash[hash_index].next;
        total_allocated_memory -= lt_hash[hash_index].allocated_size;
        if(lpoint == 0) {
            lt_hash[hash_index].allocated_size = 0;
            lt_hash[hash_index].allocated_memory = 0;
            if(lt_hash[hash_index].de_donde != 0)
                free(lt_hash[hash_index].de_donde);
            lt_hash[hash_index].de_donde = 0;
            }
        else {
            lt_hash[hash_index].allocated_size = lpoint->allocated_size;
            lt_hash[hash_index].allocated_memory = lpoint->allocated_memory;
            lt_hash[hash_index].next = lpoint->next;
            if(lt_hash[hash_index].de_donde != 0)
                free(lt_hash[hash_index].de_donde);
            lt_hash[hash_index].de_donde = lpoint->de_donde;
            free(lpoint);
            }
        }
    else {
        lpoint = lt_hash[hash_index].next;
        llast = 0;
        while(lpoint->allocated_memory != pointer) {
            llast = lpoint;
            lpoint = lpoint->next;
            if(lpoint == 0) {
                printf("Fatal: lpoint is 0; should not be\n");
                printf("Debugging info: hash_index %x\n",hash_index);
                lpoint = lt_hash[hash_index].next;
                while(lpoint != 0) {
                    printf("lpoint: %p\n",lpoint);
                    lpoint = lpoint->next;
                    }
                exit(1);
                }
            }
        total_allocated_memory -= lpoint->allocated_size;
        if(llast == 0) {
            lt_hash[hash_index].next = lpoint->next;
            }
        else {
            llast->next = lpoint->next;
            }
        if(lpoint->de_donde != 0)
            free(lpoint->de_donde);
        free(lpoint);
        }
#ifdef THREADS
    pthread_mutex_unlock(&alloc_lock);
#endif /* THREADS */
#endif /* DEBUG */
    free(pointer);
    return 1;
    }

#ifdef DEBUG
/* Function which prints to the standard output all unallocated strings which
   we have a record of */
int js_show_leaks() {
    lt_hash_spot *point;
    int counter,total = 0;
    for(counter = 0; counter < HASH_SIZE; counter++) {
        point = &lt_hash[counter];
        while(point != 0 && point->allocated_memory != 0) {
            if(point->de_donde != 0) {
                printf("%s: %d bytes at %p\n",point->de_donde,
                       point->allocated_size,point->allocated_memory);
                total += point->allocated_size;
                }
            point = point->next;
            }
        }
    printf("Allocated memory accounted for:       %d\n",total);
    printf("Allocated memory *not* accounted for: %d\n",
           total_allocated_memory - total);
    printf("Total memory allocated:               %d\n",
           total_allocated_memory);
    return 0;
    }
#else  /* DEBUG */
#define js_show_leaks()
#endif /* DEBUG */

/* Routine which tells us how much memory we have allocated.
   Input: None
   Output: The number of bytes allocated by js_alloc routines; 0 if
           it can not be determine (we do not have DEBUG set to keep
           track of it)
*/

int js_tell_memory_allocated() {
#ifdef DEBUG
    return total_allocated_memory;
#else
    return 0;
#endif
    }

/* js_show_stdout: Display the contents of a given js_string
                          object on standard output
   input: Pointer to js_string object
   output: -1 on failure, 1 on success */
int js_show_stdout(js_string *js) {
    int counter = 0;

    if(js_has_sanity(js) < 0)
        return -1;

    while(counter < js->unit_size * js->unit_count) {
        putc(*(js->string + counter),stdout);
        counter++;
        }

    return 1;
    }

/* show_esc_stdout: Display a csv1-compatible backslash escaped
                    version of a given js_string object on standard output
   input: Pointer to js_string object
   output: -1 on failure, 1 on success */
int show_esc_stdout(js_string *js) {
    int counter = 0;
    unsigned char this;

    if(js_has_sanity(js) < 0)
        return -1;

    if(js->unit_size != 1) /* There is a bug which changes this while keeping
                              the sanity */
        return -1;
    while(counter < js->unit_size * js->unit_count) {
        this = *(js->string + counter);
        if(this < 32 || this > 126) {
            printf("\\%03o",this);
            }
        else if(this == '\\' || this == '%') {
            printf("\\%c",this);
            }
        else {
            putc(*(js->string + counter),stdout);
            }
        counter++;
        }

    return 1;
    }

/* safe_esc_stdout: Display a safe csv2-compatible backslash escaped
                    version of a dlabel; this will make an
                    hex escape sequence anything
                    that is not [A-Za-z0-9\-\_]
   input: Pointer to js_string object
   output: -1 on failure, 1 on success */
int safe_esc_stdout(js_string *js) {
    int counter = 0;
    unsigned char this;

    if(js_has_sanity(js) < 0)
        return -1;

    if(js->unit_size != 1) /* There is a bug which changes this while keeping
                              the sanity */
        return -1;
    while(counter < js->unit_size * js->unit_count) {
        this = *(js->string + counter);
        /* A lot of the fetchzone code makes the first character a
         * space, which needs to be faithfully copied */
        if(this == ' ' && counter == 0) {
                printf(" ");
        }
        else if((this >= 'A' && this <= 'Z') || (this >= 'a' && this <= 'z')
           || this == '-' || this == '_' || this > 127 /* UTF-8 */
           || this == '.' || this == '@' || (this >= '0' && this <= '9')) {
            printf("%c",this);
            }
        /* We show a star only if it is the first character and the second
         * character is a '.' character */
        else if(this == '*' && counter == 0 && js->unit_count > 2 &&
                *(js->string + 1) == '.') {
            printf("%c",this);
            }
        else {
            printf("\\x%02x",this);
            }
        counter++;
        }

    return 1;
    }

/* js_getline_stdin: Get a line from the standard input
   input: To to js_string object to put stdin contents in
   output: JS_ERROR on error, JS_SUCCESS on success.
   note: js->encoding needs to be set to something besides JS_BINARY */
int js_getline_stdin(js_string *js) {
    char *temp; /* Temporary place to put chars until they become
                   a part of js */
    js_string *newlines, *append;
    int counter = 0;
    temp = js_alloc(js->unit_size,1);
    newlines = js_create(256,js->unit_size);
    if(newlines == 0)
        return JS_ERROR;
    newlines->encoding = js->encoding;
    append = js_create(256,js->unit_size);
    if(append == 0) {
        js_destroy(newlines);
        js_dealloc(temp);
        return JS_ERROR;
        }
    js_newline_chars(newlines);
    if(js_has_sanity(js) == JS_ERROR)
        goto error;
    if(temp == 0) {
        js_destroy(newlines);
        js_destroy(append);
        js_dealloc(temp);
        return JS_ERROR;
        }
    /* Blank out the js string */
    js->unit_count = 0;
    while(!feof(stdin) && js_match(newlines,js) == -2) {
        temp[counter] = getc(stdin);
        counter++;
        if(counter >= js->unit_size) {
            counter = 0;
            js_str2js(append,temp,1,js->unit_size);
            if(js_append(append,js) == JS_ERROR)
                goto error;
            }
        }

    /* Success! */
    js_destroy(append);
    js_destroy(newlines);
    js_dealloc(temp);
    return JS_SUCCESS;

    error:
        js_destroy(append);
        js_destroy(newlines);
        js_dealloc(temp);
        return JS_ERROR;
    }

/* js_open: Open a file
   input:  js_string pointing to file we wish to open, flags
   output: void */
void js_open(js_string *filename, js_file *desc, int flags) {
    char temp[256];

    /* Return if the length of the string is greater than
       the space we allocated for the filename */
    if(filename->unit_count * filename->unit_size > 255) {
        desc->filetype = -1;
        return;
        }

    /* Copy over the filename to the temp string to make it a
       null terminated string */

    js_js2str(filename,temp,255);

    desc->filetype = JS_OPEN2;
    desc->file_desc = open(temp,flags,00600);
    desc->number = -1; /* You can set up buffering later if you want */
    desc->eof = 0; /* Are we at the end of file? */
    desc->buffer = 0;

    if(desc->file_desc == -1) {
        desc->filetype = -1;
        return;
        }

    return;

    }

/* js_open_append: Open a file for appending
   input:  js_string pointing to file we wish to open
   output: JS_SUCCESS on success, JS_ERROR on error */
int js_open_append(js_string *filename, js_file *desc) {
    js_open(filename,desc,O_WRONLY | O_APPEND | O_CREAT);
    if(desc->filetype == -1)
        return JS_ERROR;
    else
        return JS_SUCCESS;
    }

/* js_open_write: Open a file for writing
   input:  js_string pointing to file we wish to open
   output: JS_SUCCESS on success, JS_ERROR on error */
int js_open_write(js_string *filename, js_file *desc) {
    js_open(filename,desc,O_WRONLY | O_CREAT);
    if(desc->filetype == -1)
        return JS_ERROR;
    else
        return JS_SUCCESS;
    }

/* js_open_read: Open a file for reading
   input:  js_string pointing to file we wish to open
   output: JS_SUCCESS on success, JS_ERROR on error */
int js_open_read(js_string *filename,js_file *desc) {
    js_open(filename,desc,O_RDONLY);
    if(desc->filetype == -1)
        return JS_ERROR;
    else
        return JS_SUCCESS;
    }

/* js_rewind: Rewind to the beginning of a given file
   input: File descriptor
   output: JS_ERROR (-1) on error, JS_SUCCESS on success */
int js_rewind(js_file *desc) {

    if(desc == 0)
        return JS_ERROR;
    if(desc->filetype != JS_OPEN2)
        return JS_ERROR;

    /* Get rid of the buffer */
    if(desc->buffer != 0)
        js_destroy(desc->buffer);
    desc->number = -1;

    if(lseek(desc->file_desc,0,SEEK_SET) == -1)
        return JS_ERROR;

    return JS_SUCCESS;

    }

/* js_read: Read n bytes from a file, and place those bytes in a js_string
            object.
   input: File descriptor, js_string object, bytes to read
   output: JS_ERROR (-1) on error, bytes read on success */
int js_read(js_file *desc, js_string *js, int count) {

    ssize_t value;
    int ret;

    /* Sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(desc->filetype != JS_OPEN2)
        return JS_ERROR;
    if(count % js->unit_size != 0)
        return JS_ERROR;
#ifndef MINGW32
    if(count < 0 || count > 1048576)
        return JS_ERROR;
#if (SSIZE_MAX < 1048576)
    if(count > SSIZE_MAX)
        return JS_ERROR;
#endif /* SSIZE_MAX small */
#else
    if(count < 0 || count > 1024)
        return JS_ERROR;
#endif

    if(count > js->unit_size * js->max_count)
        return JS_ERROR;

    value = read(desc->file_desc,js->string,count);

    if(value == -1)
        return JS_ERROR;

    ret = value;

    if(ret % js->unit_size != 0) {
         js->unit_count = 0;
         return JS_ERROR;
         }

    js->unit_count = ret / js->unit_size;

    return ret;

    }

/* js_write: Write from a js_string object in to a file
   input: File descriptor, js_string object
   output: JS_ERROR (-1) on error, JS_SUCCESS on success */
int js_write(js_file *desc, js_string *js) {

    ssize_t value;
    int to_write,written;

    /* Sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(desc->filetype != JS_OPEN2)
        return JS_ERROR;

    to_write = js->unit_size * js->unit_count;
#ifndef MINGW32
    if(to_write < 0 || to_write > 1048576)
        return JS_ERROR;
#if (SSIZE_MAX < 1048576)
    if(to_write > SSIZE_MAX)
        return JS_ERROR;
#endif /* SSIZE_MAX small */
#else
    if(to_write < 0 || to_write > 1024)
        return JS_ERROR;
#endif

    value = write(desc->file_desc,js->string,to_write);

    written = value;

    if(written != to_write)
        return JS_ERROR;

    return JS_SUCCESS;

    }

/* js_close: Close an opened file
   input: js file descriptor
   output: JS_ERROR (-1) on error, JS_SUCCESS (1) on success */
int js_close(js_file *desc) {
    int ret;

    /* Close the file, making sure we closed it */
    ret = close(desc->file_desc);

    /* Get rid of the buffer */
    if(desc->buffer != 0)
        js_destroy(desc->buffer);
    desc->number = -1;

    if(ret == -1)
        return JS_ERROR;

    /* Change the filetype of the closed file to an invalid filetype */
    desc->filetype = JS_ERROR;

    return JS_SUCCESS;

    }


/* Some UNIX systems do not have a flock(), since it did not become part
   of the POSIX specification.  Since MaraDNS does not currently use
   these routines, we can safely not compile them. */

#ifndef NO_FLOCK

/* js_lock: Lock a file using flock()
   input: Pointer to file desc
   output: JS_ERROR on error, JS_SUCCESS on success */
int js_lock(js_file *desc) {

    /* Lock the file: This may freeze here waiting for lock */
    flock(desc->file_desc,LOCK_EX);

    return JS_SUCCESS;

    }

/* js_unlock: Unlock a file using flock()
   input: Pointer to file desc
   output: JS_ERROR on error, JS_SUCCESS on success */
int js_unlock(js_file *desc) {

    /* Lock the file: This may freeze here waiting for lock */
    flock(desc->file_desc,LOCK_UN);

    return JS_SUCCESS;

    }

#endif /* SOLARIS, see commentary above */

/* js_buf_eof: Tell us if we hit the end of a given file
   input: Pointer to file descriptor
   output: 0 if not end of file, otherwise 1 */
int js_buf_eof(js_file *desc) {
    if(desc->eof && desc->number >= desc->buffer->unit_count)
        return 1;
    return 0;
    }

/* js_buf_read: Read a new chunk of the file and put it in the buffer
   input: Pointer to a file descriptor
   output: JS_ERROR (-1) on error, JS_SUCCESS(1) on success */
int js_buf_read(js_file *desc) {
    int bytes_read;

    /* Sanity check */
    if(js_has_sanity(desc->buffer) == -1)
        return -1;
    bytes_read = js_read(desc,desc->buffer,
                         JS_BUFSIZE * desc->buffer->unit_size);
    if(bytes_read != JS_BUFSIZE * desc->buffer->unit_size)
        desc->eof = 1;
    desc->number = 0;

    return JS_SUCCESS;
    }

/* js_buf_getline: Grab a line from an opened file (uses buffering)
   input: Pointer to file descriptor of open file, pointer to js_string to
          put line in
   output: JS_ERROR (-1) on error, JS_SUCCESS(1) on success,
           -2 if the line is too long for the string
 */

int js_buf_getline(js_file *desc, js_string *js) {
    js_string *newlines, *temp;
    int next_newln;
    int overflowed = 0;

    /* Sanity check */
    if(js_has_sanity(js) == -1)
        return -1;

    /* This is tricky to do because we have to do our own buffering */
    /* If the buffer is not there yet, create one */
    if(desc->number == -1) {
        if(desc->buffer == 0)
            desc->buffer = js_create(JS_BUFSIZE + 10,js->unit_size);
        js_buf_read(desc);
        }

    /* Sanity check */
    if(js->unit_size != desc->buffer->unit_size)
        return -1;

    /* Make an js_string object that is all of the allowed newline
       characters */
    newlines = js_create(js->max_count,js->unit_size);
    js_copy(js,newlines);
    js_newline_chars(newlines);

    /* Find the next newline character in the string */
    next_newln = js_match_offset(newlines,desc->buffer,desc->number);
    /* If we are at the end of the buffer in question w/o finding a
       newline... */
    if(next_newln == -2 && desc->eof == 0) {
        /* ...then we put the rest of the buffer in js, but only if
           it will fit in js.  Otherwise, we blank out js and return
           success. */
        if(JS_BUFSIZE + 1 - desc->number < js->max_count && overflowed == 0)
            js_substr(desc->buffer,js,desc->number,
                      JS_BUFSIZE - desc->number);
        else {
            js_str2js(js,"",0,js->unit_size); /* blank line if overflow */
            overflowed = 1;
            }
        /* And load up a new buffer */
        js_buf_read(desc);
        /* If the new buffer does not have a newline in it, and is a full-sized
           buffer, then we handle this special case */
        while(js_match(newlines,desc->buffer) == -2 && desc->eof == 0) {
            if(js->unit_count + JS_BUFSIZE < js->max_count && overflowed == 0)
                js_append(desc->buffer,js);
            else {
                js_str2js(js,"",0,js->unit_size);
                overflowed = 1;
                }
            js_buf_read(desc);
            }
        next_newln = js_match(newlines,desc->buffer);
        temp = js_create(js->max_count,js->unit_size);
        js_substr(desc->buffer,temp,0,next_newln + 1);
        js_append(temp,js);
        js_destroy(temp);
        if(next_newln != -2)
            desc->number = next_newln + 1;
        if(desc->number >= JS_BUFSIZE)
            js_buf_read(desc);
        js_destroy(newlines);
        if(overflowed == 1)
            return -2;
        return JS_SUCCESS;
        }
    else if(next_newln == -2) {
        /* We have EOF.  Read the string and return it */
        /* With overflow checking, of course */
        if(desc->buffer->unit_count - desc->number < js->max_count
           && overflowed == 0)
            js_substr(desc->buffer,js,desc->number,
                      desc->buffer->unit_count - desc->number);
        else {
            js_str2js(js,"",0,js->unit_size);
            overflowed = 1;
            }

        /* Make sure js_buf_eof sees it as an EOF */
        desc->number = desc->buffer->unit_count + 1;

        js_destroy(newlines);
        if(overflowed == 1)
            return -2;
        return JS_SUCCESS;
        }

    /* At this point, we can assume that we found a newline in the buffer */
    if(next_newln + 1 - desc->number < js->max_count) {
        js_substr(desc->buffer,js,desc->number,next_newln + 1 - desc->number);
        desc->number = next_newln + 1;
        if(desc->number >= JS_BUFSIZE)
            js_buf_read(desc);
        }
    else
        js_str2js(js,"",0,js->unit_size);

    js_destroy(newlines);

    if(overflowed == 1)
        return -2;

    return JS_SUCCESS;

    }

/* js_qstr2js: "Quick" version of js_str2js routine.
   input: pointer to js object, NULL-terminated string
   output: JS_ERROR on failure, JS_SUCCESS on success
   note: it's here because of strlen call */
int js_qstr2js(js_string *js, char *string) {
    if(js == 0) {
        return JS_ERROR;
        }
    return js_str2js(js,string,strlen(string),js->unit_size);
    }

/* js_adduint32: Add a 32-bit number to the end of a js_string obejct
                 in big-endian format, where the js->unit_size is one.
   input: pointer to js_string object, number to add
   output: JS_ERROR on error, JS_SUCCESS on success
   (This is in OS because of the dependency on uint32_t
*/

int js_adduint32(js_string *js, uint32_t number) {

    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return JS_ERROR;
    if(js->unit_size != 1)
        return JS_ERROR;
    /* No buffer overflows */
    if(js->unit_count + 4 >= js->max_count)
        return JS_ERROR;

    /* Add the uint16 to the end of the string */
    *(js->string + js->unit_count) = (number >> 24) & 0xff;
    *(js->string + js->unit_count + 1) = (number >> 16) & 0xff;
    *(js->string + js->unit_count + 2) = (number >> 8) & 0xff;
    *(js->string + js->unit_count + 3) = number & 0xff;
    js->unit_count += 4;

    return JS_SUCCESS;
    }

/* js_readuint32: Read a single uint32 (in big-endian format)
                  from a js_string object
   input: pointer to js_string object, offset from beginning
          of string (0 is beginning of string, 1 second byte, etc.)
   output: JS_ERROR on error, value of uint32 on success
           (Hack: 0xffffffff is the same as -1 in comparisons)
   (This is in OS because of the dependency on uint32_t)
*/

uint32_t js_readuint32(js_string *js, unsigned int offset) {

    uint32_t ret;
    /* sanity checks */
    if(js_has_sanity(js) == JS_ERROR)
        return 0xffffffff;
    if(js->unit_size != 1)
        return 0xffffffff;
    if(offset > (js->unit_count - 4) || offset < 0)
        return 0xffffffff;

    ret = ((*(js->string + offset) << 24) & 0xff000000) |
          ((*(js->string + offset + 1) << 16) & 0xff0000) |
          ((*(js->string + offset + 2) << 8) & 0xff00) |
           (*(js->string + offset + 3) & 0xff);

    /* Make sure we do not inadvertently return JS_ERROR */
    if(ret == 0xffffffff)
        ret = 0xfffffffe;

    return ret;

    }

/* js_strnlen: Determine the length of a null-terminated string, up
 * to the length determined by the limit.  This is here because strnlen
 * is, alas, not a portable string library call.  This call is originally
 * by Matthew T. Russotto */
int js_strnlen(char *s, uint32_t limit) {
        uint32_t len;
        if(limit > 2147483600 || limit < 0) { /* Just under 2 ** 31 */
                return JS_ERROR;
        }
        if(s == NULL) {
                return JS_ERROR;
        }
        len = 0;
        while(len < limit && (*s++)) {
                len++;
        }
        return len;
}

