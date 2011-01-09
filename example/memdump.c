/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
 * Example program using libmembase_tap_cluster.
 *
 * @author Trond Norbye
 * @todo add documentation
 */
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <event.h>

#include <libmembase/membase.h>

static void usage(char cmd, const void *arg, void *cookie);
static void set_char_ptr(char cmd, const void *arg, void *cookie) {
    (void)cmd;
    const char **myptr = cookie;
    *myptr = arg;
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
        char buffer[80];
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            exit(EXIT_FAILURE);
        }
        size_t len = strlen(buffer) - 1;
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
    bool argument;
    char letter;
    OPTION_HANDLER handler;
    void *cookie;
} my_options[256] = {
    ['?'] = {
        .name = "help",
        .description = "\t-?\tPrint program usage information",
        .argument = false,
        .letter = '?',
        .handler = usage
    },
    ['u'] = {
        .name = "username",
        .description = "\t-u nm\tSpecify username",
        .argument = true,
        .letter = 'u',
        .handler = set_auth_data
    },
    ['h'] = {
        .name = "host",
        .description = "\t-h host\tHost to read configuration from",
        .argument = true,
        .letter = 'h',
        .handler = set_char_ptr,
        .cookie = &host
    },
    ['b'] = {
        .name = "bucket",
        .description = "\t-b bucket\tThe bucket to connect to",
        .argument = true,
        .letter = 'b',
        .handler = set_char_ptr,
        .cookie = &bucket
    },
    ['o'] = {
        .name = "file",
        .description = "\t-o filename\tSend the output to this file",
        .argument = true,
        .letter = 'o',
        .handler = set_char_ptr,
        .cookie = &filename
    },
};

/**
 * Handle all of the command line options the user passed on the command line.
 * Please note that this function will set optind to point to the first option
 *
 * @param argc Argument count
 * @param argv Argument vector
 */
static void handle_options(int argc, char **argv) {
    struct option opts[256] =  { [0] = { .name = NULL } };
    int ii = 0;
    char shortopts[128] = { 0 };
    int jj = 0;
    int kk = 0;
    for (ii = 0; ii < 256; ++ii) {
        if (my_options[ii].name != NULL) {
            opts[jj].name = (char*)my_options[ii].name;
            opts[jj].has_arg = my_options[ii].argument ? required_argument : no_argument;
            opts[jj].val = my_options[ii].letter;

            shortopts[kk++] = (char)opts[jj].val;
            if (my_options[ii].argument) {
                shortopts[kk++] = ':';
            }
        }
    }

    int c;
    while ((c = getopt_long(argc, argv, shortopts, opts, NULL)) != EOF) {
        if (my_options[c].handler != NULL) {
            my_options[c].handler((char)c, optarg, my_options[c].cookie);
        } else {
            usage((char)c, NULL, NULL);
        }
    }
}

FILE *output;

static void tap_mutation(libmembase_t instance,
                         const void *key,
                         size_t nkey,
                         const void *data,
                         size_t nbytes,
                         uint32_t flags,
                         uint32_t exp,
                         const void *es,
                         size_t nes)
{
    fwrite(key, nkey, 1, output);
    fprintf(output, " 0x%04X\r\n", (unsigned int)nbytes);
    (void)instance;
    (void)data;
    (void)flags;
    (void)exp;
    (void)es;
    (void)nes;
}

int main(int argc, char **argv)
{
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

    struct event_base *evbase = event_init();

    libmembase_t instance = libmembase_create(host, username,
                                              passwd, bucket, evbase);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libmembase instance\n");
        return 1;
    }

    if (libmembase_connect(instance) != LIBMEMBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libmembase instance to server\n");
        return 1;
    }

    libmembase_callback_t callbacks = {
        .tap_mutation = tap_mutation,
    };
    libmembase_set_callbacks(instance, &callbacks);
    libmembase_tap_cluster(instance, NULL, true);

    return 0;
}

static void usage(char cmd, const void *arg, void *cookie)
{
    (void)cmd;
    (void)arg;
    (void)cookie;

    fprintf(stderr, "Usage: ./memdump [options]\n");
    for (int ii = 0; ii < 256; ++ii) {
        if (my_options[ii].name != NULL) {
            fprintf(stderr, "%s\n", my_options[ii++].description);
        }
    }
    exit(EXIT_FAILURE);
}
