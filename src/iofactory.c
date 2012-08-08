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

static void set_error(libcouchbase_error_t *error, libcouchbase_error_t code)
{
    if (error != NULL) {
        *error = code;
    }
}


typedef libcouchbase_io_opt_t *(*create_func)(struct event_base *base);

struct plugin_st {
    void *dlhandle;
    union {
        create_func create;
        void *voidptr;
    } func;
};

static void get_create_func(const char *image,
                            struct plugin_st *plugin,
                            libcouchbase_error_t *error)
{
    void *dlhandle = dlopen(image, RTLD_NOW | RTLD_LOCAL);
    if (dlhandle == NULL) {
        set_error(error, LIBCOUCHBASE_ERROR);
        return;
    }

    plugin->func.create = NULL;
    plugin->func.voidptr = dlsym(dlhandle, "libcouchbase_create_libevent_io_opts");
    if (plugin->func.voidptr == NULL) {
        dlclose(dlhandle);
        dlhandle = NULL;
    } else {
        plugin->dlhandle = dlhandle;
    }
}

#ifdef __APPLE__
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".1.dylib"
#else
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".so.1"
#endif

LIBCOUCHBASE_API
libcouchbase_io_opt_t *libcouchbase_create_io_ops(libcouchbase_io_ops_type_t type,
                                                  void *cookie,
                                                  libcouchbase_error_t *error)
{
    libcouchbase_io_opt_t *ret = NULL;
    if (type == LIBCOUCHBASE_IO_OPS_DEFAULT || type == LIBCOUCHBASE_IO_OPS_LIBEVENT) {
        struct plugin_st plugin;
        memset(&plugin, 0, sizeof(plugin));
        /* search definition in main program */
        get_create_func(NULL, &plugin, error);

#ifndef LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
        if (plugin.func.create == NULL) {
            get_create_func(PLUGIN_SO("libevent"), &plugin, error);
        }
#endif

        if (plugin.func.create != NULL) {
            ret = plugin.func.create(cookie);
            if (ret == NULL) {
                set_error(error, LIBCOUCHBASE_CLIENT_ENOMEM);
            } else {
                ret->dlhandle = plugin.dlhandle;
            }
        }

    } else {
        set_error(error, LIBCOUCHBASE_NOT_SUPPORTED);
    }

    return ret;
}
#undef PLUGIN_SO
