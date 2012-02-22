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

#include "internal.h"
#include <dlfcn.h>

#ifdef LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
#include <libcouchbase/libevent_io_opts.h>
#endif

static void set_error(libcouchbase_error_t *error, libcouchbase_error_t code) {
    if (error != NULL) {
        *error = code;
    }
}


typedef libcouchbase_io_opt_t* (*create_func)(struct event_base *base);

#ifndef LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
static create_func get_create_func(const char *image,
                                   libcouchbase_error_t *error) {
    union my_hack {
        create_func create;
        void* voidptr;
    } my_create ;
    void *dlhandle = dlopen(image, RTLD_NOW | RTLD_LOCAL);
    if (dlhandle == NULL) {
        set_error(error, LIBCOUCHBASE_ERROR);
        return NULL;
    }

    my_create.create = NULL;
    my_create.voidptr = dlsym(dlhandle, "libcouchbase_create_libevent_io_opts");
    if (my_create.voidptr == NULL) {
        dlclose(dlhandle);
    }

    return my_create.create;
}
#endif

LIBCOUCHBASE_API
libcouchbase_io_opt_t* libcouchbase_create_io_ops(libcouchbase_io_ops_type_t type,
                                                  void *cookie,
                                                  libcouchbase_error_t *error)
{
    libcouchbase_io_opt_t *ret = NULL;
    if (type == LIBCOUCHBASE_IO_OPS_DEFAULT || type == LIBCOUCHBASE_IO_OPS_LIBEVENT) {
        create_func c;
#ifdef LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
        c = libcouchbase_create_libevent_io_opts;
#else
        c = get_create_func(NULL, error);
        if (c == NULL) {
#ifdef __APPLE__
            c = get_create_func("libcouchbase_libevent.1.dylib", error);
#else
            c = get_create_func("libcouchbase_libevent.so.1", error);
#endif /* __APPLE__ */
        }
#endif /* LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED */

        if (c != NULL) {
            ret = c(cookie);
            if (ret == NULL) {
                set_error(error, LIBCOUCHBASE_ENOMEM);
            }
        }

    } else {
        set_error(error, LIBCOUCHBASE_NOT_SUPPORTED);
    }

    return ret;
}
