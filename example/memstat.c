/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * Example program using libcouchbase_server_stat.
 *
 * @author Trond Norbye
 * @todo add documentation
 */

/* @todo figure out what I need to include for win32 in the headers! */
#include "config.h"

#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <libcouchbase/couchbase.h>
#ifdef WIN32
#define PRIu64 "llu"

static int isatty(int a) {
    (void)a;
    return 1;
}

static char *getpass(const char *prompt)
{
    size_t len;
    static char buffer[1024];
    fprintf(stdout, "%s", prompt);
    fflush(stdout);

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return NULL;
    }

    len = strlen(buffer) - 1;
    while (buffer[len] == '\r' || buffer[len] == '\n') {
        buffer[len] = '\0';
        --len;
    }

    return buffer;
}
#endif

static void usage(char cmd, const void *arg, void *cookie);
static void set_char_ptr(char cmd, const void *arg, void *cookie) {
    const char **myptr = cookie;
    *myptr = arg;
    (void)cmd;
}

const char *host = "localhost:8091";
const char *username = NULL;
const char *passwd = NULL;
const char *bucket = NULL;
const char *filename = "-";

static void set_auth_data(char cmd, const void *arg, void *cookie) {
    (void)cmd;
    (void)cookie;
    username = arg;
    if (isatty(fileno(stdin))) {
        char prompt[80];
        snprintf(prompt, sizeof(prompt), "Please enter password for %s: ", username);
        passwd = getpass(prompt);
        if (passwd == NULL) {
            exit(EXIT_FAILURE);
        }
    } else {
        size_t len;
        char buffer[80];
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            exit(EXIT_FAILURE);
        }
        len = strlen(buffer) - 1;
        while (len > 0 && isspace(buffer[len])) {
            buffer[len] = '\0';
            --len;
        }
        if (len == 0) {
            exit(EXIT_FAILURE);
        }
        passwd = strdup(buffer);
    }
}

typedef void (*OPTION_HANDLER)(char cmd, const void *arg, void *cookie);
static struct {
    const char *name;
    const char *description;
    int argument;
    char letter;
    OPTION_HANDLER handler;
    void *cookie;
} my_options[256];

static void setup_options(void)
{
    my_options['?'].name = "help";
    my_options['?'].description = "\t-?\tPrint program usage information";
    my_options['?'].argument = 0;
    my_options['?'].letter = '?';
    my_options['?'].handler = usage;
    my_options['u'].name = "username";
    my_options['u'].description = "\t-u nm\tSpecify username";
    my_options['u'].argument = 1;
    my_options['u'].letter = 'u';
    my_options['u'].handler = set_auth_data;
    my_options['h'].name = "host";
    my_options['h'].description = "\t-h host\tHost to read configuration from";
    my_options['h'].argument = 1;
    my_options['h'].letter = 'h';
    my_options['h'].handler = set_char_ptr;
    my_options['h'].cookie = (void*)&host;
    my_options['b'].name = "bucket";
    my_options['b'].description = "\t-b bucket\tThe bucket to connect to";
    my_options['b'].argument = 1;
    my_options['b'].letter = 'b';
    my_options['b'].handler = set_char_ptr;
    my_options['b'].cookie = (void*)&bucket;
    my_options['o'].name = "file";
    my_options['o'].description = "\t-o filename\tSend the output to this file";
    my_options['o'].argument = 1;
    my_options['o'].letter = 'o';
    my_options['o'].handler = set_char_ptr;
    my_options['o'].cookie = (void*)&filename;
}

/**
 * Handle all of the command line options the user passed on the command line.
 * Please note that this function will set optind to point to the first option
 *
 * @param argc Argument count
 * @param argv Argument vector
 */
static void handle_options(int argc, char **argv) {
    struct option opts[256];
    int ii = 0;
    char shortopts[128];
    int jj = 0;
    int kk = 0;
    int c;

    memset(opts, 0, sizeof(opts));
    memset(shortopts, 0, sizeof(shortopts));
    setup_options();

    for (ii = 0; ii < 256; ++ii) {
        if (my_options[ii].name != NULL) {
            opts[jj].name = (char*)my_options[ii].name;
            opts[jj].has_arg = my_options[ii].argument ? required_argument : no_argument;
            opts[jj].val = my_options[ii].letter;

            shortopts[kk++] = (char)opts[jj++].val;
            if (my_options[ii].argument) {
                shortopts[kk++] = ':';
            }
        }
    }

    while ((c = getopt_long(argc, argv, shortopts, opts, NULL)) != EOF) {
        if (my_options[c].handler != NULL) {
            my_options[c].handler((char)c, optarg, my_options[c].cookie);
        } else {
            usage((char)c, NULL, NULL);
        }
    }
}

FILE *output;

static void stat_callback(libcouchbase_t instance,
                          const void* cookie,
                          const char* server_endpoint,
                          libcouchbase_error_t error,
                          const void* key,
                          size_t nkey,
                          const void* value,
                          size_t nvalue)
{
    (void)instance;
    (void)cookie;
    (void)server_endpoint;
    if (error == LIBCOUCHBASE_SUCCESS) {
        if (nkey > 0) {
            fprintf(output, "%s\t", server_endpoint);
            fwrite(key, nkey, 1, output);
            fprintf(output, "\t");
            fwrite(value, nvalue, 1, output);
            fprintf(output, "\n");
        }
    } else {
        fprintf(stderr, "Error: %s\n",
                libcouchbase_strerror(instance, error));
        exit(EXIT_FAILURE);
    }
}

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t error,
                           const char *errinfo)
{
    if (errinfo) {
        fprintf(stderr, "Error: %s (%s)\n",
                libcouchbase_strerror(instance, error), errinfo);
    } else {
        fprintf(stderr, "Error: %s\n",
                libcouchbase_strerror(instance, error));
    }
    exit(EXIT_FAILURE);
}


int main(int argc, char **argv)
{
    struct libcouchbase_io_opt_st *io;
    libcouchbase_t instance;
    int ii;
    libcouchbase_error_t ret;

    handle_options(argc, argv);

    if (strcmp(filename, "-") == 0) {
        output = stdout;
    } else {
        output = fopen(filename, "w");
        if (output == NULL) {
            fprintf(stderr, "Failed to open %s: %s\n", filename,
                    strerror(errno));
            return 1;
        }
    }

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        return 1;
    }
    instance = libcouchbase_create(host, username,
                                   passwd, bucket, io);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        return 1;
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);

    ret = libcouchbase_connect(instance);
    if (ret != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server: %s\n",
                libcouchbase_strerror(instance, ret));
        return 1;
    }
    /* Wait for the connect to compelete */
    libcouchbase_wait(instance);

    (void)libcouchbase_set_stat_callback(instance, stat_callback);

    if (optind == argc) {
        ret = libcouchbase_server_stats(instance, NULL, NULL, 0);
        if (ret != LIBCOUCHBASE_SUCCESS) {
            fprintf(stderr, "Failed to send requests\n");
            return 1;
        }
    } else {
        for (ii = optind; ii < argc; ++ii) {
            ret = libcouchbase_server_stats(instance, NULL, argv[ii], strlen(argv[ii]));
            if (ret != LIBCOUCHBASE_SUCCESS) {
                fprintf(stderr, "Failed to send requests\n");
                return 1;
            }
        }
    }

    libcouchbase_wait(instance);

    return 0;
}

static void usage(char cmd, const void *arg, void *cookie)
{
    int ii;
    (void)cmd;
    (void)arg;
    (void)cookie;

    fprintf(stderr, "Usage: ./memstat [options] keys\n");
    for (ii = 0; ii < 256; ++ii) {
        if (my_options[ii].name != NULL) {
            fprintf(stderr, "%s\n", my_options[ii].description);
        }
    }
    exit(EXIT_FAILURE);
}
