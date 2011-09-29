/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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
 * Example program using libcouchbase_view_execute.
 *
 * This example shows how to plug the JSON parser to libcouchbase view
 * function. In this example we used libyajl to parse and reformat the
 * results, the code could be modified easily to build native objects for
 * your application domain.
 *
 * NOTE: you need to install libyajl library with headers to build this
 * example.
 *
 * @author Sergey Avseyev
 */
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <libcouchbase/couchbase.h>

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>

static void usage(char cmd, const void *arg, void *cookie);
static void set_flag(char cmd, const void *arg, void *cookie) {
    (void)cmd; (void)arg;
    *((int *)cookie) = 1;
}

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
const char *post_data= NULL;
int chunked = 0;
int minify = 0;
int force_utf8 = 0;

struct cookie_st {
    struct libcouchbase_io_opt_st *io;
    yajl_handle parser;
    yajl_gen gen;
};

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
        .description = "\t-?\t\tPrint program usage information",
        .argument = false,
        .letter = '?',
        .handler = usage
    },
    ['u'] = {
        .name = "username",
        .description = "\t-u name\t\tSpecify username",
        .argument = true,
        .letter = 'u',
        .handler = set_auth_data
    },
    ['h'] = {
        .name = "host",
        .description = "\t-h host\t\tHost to read configuration from",
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
    ['c'] = {
        .name = "chunked",
        .description = "\t-c\t\tUse chunked callback to stream the data",
        .argument = false,
        .letter = 'c',
        .handler = set_flag,
        .cookie = &chunked
    },
    ['d'] = {
        .name = "data",
        .description = "\t-d\t\tPOST data, e.g. {\"keys\": [\"key1\", \"key2\", ...]}",
        .argument = true,
        .letter = 'd',
        .handler = set_char_ptr,
        .cookie = &post_data
    },
    ['m'] = {
        .name = "minify",
        .description = "\t-m\t\tMinify JSON rather than beautify",
        .argument = false,
        .letter = 'm',
        .handler = set_flag,
        .cookie = &minify
    },
    ['f'] = {
        .name = "force-utf8",
        .description = "\t-f\t\tForce utf-8, i.e. allow invalid characters inside strings during parsing",
        .argument = false,
        .letter = 'u',
        .handler = set_flag,
        .cookie = &force_utf8
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

static int reformat_null(void *ctx)
{
    yajl_gen_null(ctx);
    return 1;
}

static int reformat_boolean(void *ctx, int boolean)
{
    yajl_gen_bool(ctx, boolean);
    return 1;
}

static int reformat_number(void *ctx, const char *str, unsigned int len)
{
    yajl_gen_number(ctx, str, len);
    return 1;
}

static int reformat_string(void *ctx, const unsigned char *str,
                           unsigned int len)
{
    yajl_gen_string(ctx, str, len);
    return 1;
}

static int reformat_map_key(void *ctx, const unsigned char *str,
                            unsigned int len)
{
    yajl_gen_string(ctx, str, len);
    return 1;
}

static int reformat_start_map(void *ctx)
{
    yajl_gen_map_open(ctx);
    return 1;
}


static int reformat_end_map(void *ctx)
{
    yajl_gen_map_close(ctx);
    return 1;
}

static int reformat_start_array(void *ctx)
{
    yajl_gen_array_open(ctx);
    return 1;
}

static int reformat_end_array(void *ctx)
{
    yajl_gen_array_close(ctx);
    return 1;
}

static yajl_callbacks parser_callbacks = {
    reformat_null,
    reformat_boolean,
    NULL,
    NULL,
    reformat_number,
    reformat_string,
    reformat_start_map,
    reformat_map_key,
    reformat_end_map,
    reformat_start_array,
    reformat_end_array
};

static void view_data_callback(libcouchbase_t instance,
                               const void *cookie,
                               libcouchbase_error_t error,
                               const char *uri,
                               const void *bytes, size_t nbytes)
{
    struct cookie_st *c = (struct cookie_st *)cookie;
    yajl_status st;
    (void)instance; (void)uri; (void)error;

    if (bytes) {
        st = yajl_parse(c->parser, bytes, (unsigned int)nbytes);
        if (st != yajl_status_ok && st != yajl_status_insufficient_data) {
            unsigned char *str = yajl_get_error(c->parser, 1, bytes, (unsigned int)nbytes);
            fprintf(stderr, "%s", (const char *) str);
            yajl_free_error(c->parser, str);
            c->io->stop_event_loop(c->io);
        }
    } else { /* end of response */
        st = yajl_parse_complete(c->parser);
        if (st != yajl_status_ok && st != yajl_status_insufficient_data) {
            unsigned char *str = yajl_get_error(c->parser, 1, bytes, (unsigned int)nbytes);
            fprintf(stderr, "%s", (const char *) str);
            yajl_free_error(c->parser, str);
        } else {
            const unsigned char *buf;
            unsigned int len;
            yajl_gen_get_buf(c->gen, &buf, &len);
            fwrite(buf, 1, len, output);
            yajl_gen_clear(c->gen);
        }
        c->io->stop_event_loop(c->io);
    }
}

static void view_complete_callback(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_error_t error,
                                   const char *uri,
                                   const void *bytes, size_t nbytes)
{
    struct cookie_st *c = (struct cookie_st *)cookie;
    yajl_status st;
    (void)instance;

    fprintf(stderr, "View %s ... ", uri);
    if (error == LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "OK\n");
        st = yajl_parse(c->parser, bytes, (unsigned int)nbytes);
        if (st != yajl_status_ok && st != yajl_status_insufficient_data) {
            unsigned char *str = yajl_get_error(c->parser, 1, bytes, (unsigned int)nbytes);
            fprintf(stderr, "%s", (const char *) str);
            yajl_free_error(c->parser, str);
        } else {
            const unsigned char *buf;
            unsigned int len;
            yajl_gen_get_buf(c->gen, &buf, &len);
            fwrite(buf, 1, len, output);
            yajl_gen_clear(c->gen);
        }
    } else {
        fprintf(stderr, "FAIL\n");
        fwrite(bytes, nbytes, 1, output);
    }
    c->io->stop_event_loop(c->io);
}

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t error,
                           const char *errinfo)
{
    (void)instance;
    fprintf(stderr, "Error %d", error);
    if (errinfo) {
        fprintf(stderr, ": %s", errinfo);
    }
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    char *uri;
    const char *bytes;
    size_t nbytes = 0;
    struct cookie_st cookie;
    yajl_parser_config parser_cfg = {1, 1}; /* { allowComments, checkUTF8 } */
    yajl_gen_config gen_cfg = {1, "  "};    /* { beautify, indentString } */
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

    uri = argv[optind];
    if (!uri) {
        usage(0, NULL, NULL);
    }
    if (force_utf8) {
        parser_cfg.checkUTF8 = 0;
    }
    if (minify) {
        gen_cfg.beautify = 0;
    }
    cookie.gen = yajl_gen_alloc(&gen_cfg, NULL);
    cookie.parser = yajl_alloc(&parser_callbacks, &parser_cfg, NULL, (void *)cookie.gen);
    cookie.io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (cookie.io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        return 1;
    }
    libcouchbase_t instance = libcouchbase_create(host, username,
                                                  passwd, bucket, cookie.io);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        return 1;
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server\n");
        return 1;
    }

    // Wait for the connect to compelete
    libcouchbase_wait(instance);

    if (chunked) {
        (void)libcouchbase_set_view_data_callback(instance, view_data_callback);
    } else {
        (void)libcouchbase_set_view_complete_callback(instance, view_complete_callback);
    }


    bytes = post_data;
    if (bytes) {
        nbytes = strlen(bytes);
    }

    if (libcouchbase_view_execute(instance, (void *)&cookie, uri, bytes, nbytes) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to execute view\n");
        return 1;
    }

    /* Start the event loop and let it run until request will be completed
     * with success or failure (see view callbacks)  */
    cookie.io->run_event_loop(cookie.io);

    yajl_free(cookie.parser);
    yajl_gen_free(cookie.gen);
    return 0;
}

static void usage(char cmd, const void *arg, void *cookie)
{
    (void)cmd;
    (void)arg;
    (void)cookie;

    fprintf(stderr, "Usage: ./couchview [options] viewid\n");
    for (int ii = 0; ii < 256; ++ii) {
        if (my_options[ii].name != NULL) {
            fprintf(stderr, "%s\n", my_options[ii].description);
        }
    }
    exit(EXIT_FAILURE);
}
