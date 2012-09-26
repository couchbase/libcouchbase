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

typedef lcb_io_opt_t (*create_func)(struct event_base *base);
typedef lcb_error_t (*create_v1_func)(lcb_io_opt_t *io, const void *cookie);

struct plugin_st {
    void *dlhandle;
    union {
        create_func create;
        create_v1_func create_v1;
        void *voidptr;
    } func;
};

static lcb_error_t get_create_func(const char *image,
                                   const char *symbol,
                                   struct plugin_st *plugin)
{
    void *dlhandle = dlopen(image, RTLD_NOW | RTLD_LOCAL);
    if (dlhandle == NULL) {
        return LCB_ERROR;
    }

    memset(plugin, 0, sizeof(*plugin));
    plugin->func.create = NULL;
    plugin->func.voidptr = dlsym(dlhandle, symbol);
    if (plugin->func.voidptr == NULL) {
        dlclose(dlhandle);
        dlhandle = NULL;
        return LCB_ERROR;
    } else {
        plugin->dlhandle = dlhandle;
    }
    return LCB_SUCCESS;
}

#ifdef __APPLE__
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".1.dylib"
#else
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".so.1"
#endif

#define PLUGIN_SYMBOL(NAME) "lcb_create_"NAME"_io_opts"

static lcb_error_t create_v0(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options);

static lcb_error_t create_v1(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options);

#define USE_PLUGIN(OPTS, PLUGIN_NAME, PLUGIN_CONST)             \
        switch (OPTS->version) {                                \
        case 0:                                                 \
            OPTS->v.v0.type = PLUGIN_CONST;                     \
            break;                                              \
        case 1:                                                 \
            OPTS->v.v1.sofile = PLUGIN_SO(PLUGIN_NAME);         \
            OPTS->v.v1.symbol = PLUGIN_SYMBOL(PLUGIN_NAME);     \
            break;                                              \
        }

static void override_from_env(struct lcb_create_io_ops_st *options)
{
    char *plugin = getenv("LIBCOUCHBASE_EVENT_PLUGIN_NAME");
    if (plugin != NULL && *plugin != '\0') {
        if (strncmp("libevent", plugin, 8) == 0) {
            USE_PLUGIN(options, "libevent", LCB_IO_OPS_LIBEVENT);
        } else if (strncmp("libev", plugin, 5) == 0) {
            USE_PLUGIN(options, "libev", LCB_IO_OPS_LIBEV);
        } else if (options->version == 1) {
            char *symbol = getenv("LIBCOUCHBASE_EVENT_PLUGIN_SYMBOL");
            if (symbol == NULL || *symbol == '\0') {
                options->v.v1.sofile = plugin;
                options->v.v1.symbol = symbol;
            }
        }
    }
}

#undef USE_PLUGIN

LIBCOUCHBASE_API
lcb_error_t lcb_create_io_ops(lcb_io_opt_t *io,
                              const struct lcb_create_io_ops_st *io_opts)
{
    struct lcb_create_io_ops_st options;

    memset(&options, 0, sizeof(struct lcb_create_io_ops_st));
    if (io_opts == NULL) {
        options.version = 0;
        options.v.v0.type = LCB_IO_OPS_DEFAULT;
    } else {
        memcpy(&options, io_opts, sizeof(struct lcb_create_io_ops_st));
    }
    override_from_env(&options);
    switch (options.version) {
    case 0:
        return create_v0(io, &options);
    case 1:
        return create_v1(io, &options);
    default:
        return LCB_NOT_SUPPORTED;
    }
}

static lcb_error_t create_v0(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options)
{
    lcb_error_t ret = LCB_SUCCESS;
    lcb_io_ops_type_t type;
    void *cookie = NULL;
    const char *sofile;
    const char *symbol;

    type = options->v.v0.type;
    cookie = options->v.v0.cookie;
    if (type == LCB_IO_OPS_DEFAULT) {
#if defined(HAVE_LIBEVENT) || defined(HAVE_LIBEVENT2)
        type = LCB_IO_OPS_LIBEVENT;
#elif defined(HAVE_LIBEV)
        type = LCB_IO_OPS_LIBEV;
#endif
    }

    switch (type) {
    case LCB_IO_OPS_LIBEVENT:
        sofile = PLUGIN_SO("libevent");
        symbol = PLUGIN_SYMBOL("libevent");
        break;
    case LCB_IO_OPS_LIBEV:
        sofile = PLUGIN_SO("libev");
        symbol = PLUGIN_SYMBOL("libev");
        break;
    default:
        return LCB_NOT_SUPPORTED;
    }

    {
        struct plugin_st plugin;
        struct lcb_io_opt_st *iop = NULL;

        /* search definition in main program */
        ret = get_create_func(NULL, symbol, &plugin);

        if (ret != LCB_SUCCESS) {
            if (plugin.func.create == NULL) {
                ret = get_create_func(sofile, symbol, &plugin);
            }
            if (ret != LCB_SUCCESS) {
                return ret;
            }
        }

        iop = plugin.func.create(cookie);
        if (iop == NULL) {
            return LCB_CLIENT_ENOMEM;
        } else {
            iop->dlhandle = plugin.dlhandle;
        }
        *io = iop;
    }

    return LCB_SUCCESS;
}
#undef PLUGIN_SO

static lcb_error_t create_v1(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options)
{
    struct plugin_st plugin;
    lcb_error_t ret = get_create_func(options->v.v1.sofile,
                                      options->v.v1.symbol,
                                      &plugin);

    if (ret != LCB_SUCCESS) {
        return ret;
    }

    ret = plugin.func.create_v1(io, options->v.v1.cookie);
    if (ret != LCB_SUCCESS) {
        if (options->v.v1.sofile != NULL) {
            dlclose(plugin.dlhandle);
        }
        return LCB_CLIENT_ENOMEM;
    } else {
        if ((*io)->version > 0) {
            (*io)->dlhandle = plugin.dlhandle;
        }
    }

    return LCB_SUCCESS;
}
