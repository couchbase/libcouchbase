/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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

/* @todo add static prototypes */

struct user_cookie {
    void *cookie;
    struct libcouchbase_callback_st callbacks;
    libcouchbase_error_t retcode;
};

static void restore_user_env(libcouchbase_t instance);
static void restore_wrapping_env(libcouchbase_t instance,
                                 struct user_cookie *user,
                                 libcouchbase_error_t error);

static void tap_mutation_callback(libcouchbase_t instance,
                                  const void *cookie,
                                  const void *key,
                                  libcouchbase_size_t nkey,
                                  const void *data,
                                  libcouchbase_size_t nbytes,
                                  libcouchbase_uint32_t flags,
                                  libcouchbase_time_t exp,
                                  libcouchbase_cas_t cas,
                                  libcouchbase_vbucket_t vbucket,
                                  const void *es,
                                  libcouchbase_size_t nes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.tap_mutation(instance, cookie, key, nkey, data,
                              nbytes, flags, exp, cas, vbucket,
                              es, nes);
    restore_wrapping_env(instance, c, LIBCOUCHBASE_SUCCESS);
    libcouchbase_maybe_breakout(instance);
}

static void tap_deletion_callback(libcouchbase_t instance,
                                  const void *cookie,
                                  const void *key,
                                  libcouchbase_size_t nkey,
                                  libcouchbase_cas_t cas,
                                  libcouchbase_vbucket_t vbucket,
                                  const void *es,
                                  libcouchbase_size_t nes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.tap_deletion(instance, cookie, key, nkey,
                              cas, vbucket, es, nes);
    restore_wrapping_env(instance, c, LIBCOUCHBASE_SUCCESS);
    libcouchbase_maybe_breakout(instance);
}

static void tap_flush_callback(libcouchbase_t instance,
                               const void *cookie,
                               const void *es,
                               libcouchbase_size_t nes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.tap_flush(instance, cookie, es, nes);
    restore_wrapping_env(instance, c, LIBCOUCHBASE_SUCCESS);
    libcouchbase_maybe_breakout(instance);
}

static void tap_opaque_callback(libcouchbase_t instance,
                                const void *cookie,
                                const void *es,
                                libcouchbase_size_t nes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.tap_opaque(instance, cookie, es, nes);
    restore_wrapping_env(instance, c, LIBCOUCHBASE_SUCCESS);
    libcouchbase_maybe_breakout(instance);
}

static void tap_vbucket_set_callback(libcouchbase_t instance,
                                     const void *cookie,
                                     libcouchbase_vbucket_t vbid,
                                     libcouchbase_vbucket_state_t state,
                                     const void *es,
                                     libcouchbase_size_t nes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.tap_vbucket_set(instance, cookie, vbid, state, es, nes);
    restore_wrapping_env(instance, c, LIBCOUCHBASE_SUCCESS);
    libcouchbase_maybe_breakout(instance);
}

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t error,
                           const char *errinfo)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.error(instance, error, errinfo);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void stat_callback(libcouchbase_t instance,
                          const void *command_cookie,
                          const char *server_endpoint,
                          libcouchbase_error_t error,
                          const void *key,
                          libcouchbase_size_t nkey,
                          const void *value,
                          libcouchbase_size_t nvalue)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.stat(instance, command_cookie, server_endpoint,
                      error, key, nkey, value, nvalue);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void get_callback(libcouchbase_t instance,
                         const void *cookie,
                         libcouchbase_error_t error,
                         const void *key, libcouchbase_size_t nkey,
                         const void *bytes, libcouchbase_size_t nbytes,
                         libcouchbase_uint32_t flags, libcouchbase_cas_t cas)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.get(instance, cookie, error, key, nkey, bytes, nbytes,
                     flags, cas);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void storage_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_storage_t operation,
                             libcouchbase_error_t error,
                             const void *key, libcouchbase_size_t nkey,
                             libcouchbase_cas_t cas)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.storage(instance, cookie, operation, error, key,
                         nkey, cas);
    restore_wrapping_env(instance, c, error);

    libcouchbase_maybe_breakout(instance);
}

static void arithmetic_callback(libcouchbase_t instance,
                                const void *cookie,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey,
                                libcouchbase_uint64_t value,
                                libcouchbase_cas_t cas)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.arithmetic(instance, cookie, error, key, nkey,
                            value, cas);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void remove_callback(libcouchbase_t instance,
                            const void *cookie,
                            libcouchbase_error_t error,
                            const void *key, libcouchbase_size_t nkey)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.remove(instance, cookie, error, key, nkey);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void touch_callback(libcouchbase_t instance,
                           const void *cookie,
                           libcouchbase_error_t error,
                           const void *key, libcouchbase_size_t nkey)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.touch(instance, cookie, error, key, nkey);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void view_complete_callback(libcouchbase_http_request_t request,
                                   libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_error_t error,
                                   libcouchbase_http_status_t status,
                                   const char *path,
                                   libcouchbase_size_t npath,
                                   const void *bytes,
                                   libcouchbase_size_t nbytes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.view_complete(request, instance, cookie, error,
                               status, path, npath, bytes, nbytes);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void view_data_callback(libcouchbase_http_request_t request,
                               libcouchbase_t instance,
                               const void *cookie,
                               libcouchbase_error_t error,
                               libcouchbase_http_status_t status,
                               const char *path,
                               libcouchbase_size_t npath,
                               const void *bytes,
                               libcouchbase_size_t nbytes)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.view_data(request, instance, cookie, error,
                           status, path, npath, bytes, nbytes);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void flush_callback(libcouchbase_t instance,
                           const void *cookie,
                           const char *server_endpoint,
                           libcouchbase_error_t error)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.flush(instance, cookie, server_endpoint, error);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void observe_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_error_t error,
                             libcouchbase_observe_t status,
                             const void *key,
                             libcouchbase_size_t nkey,
                             libcouchbase_cas_t cas,
                             int is_master,
                             libcouchbase_time_t ttp,
                             libcouchbase_time_t ttr)
{
    struct user_cookie *c = (void *)instance->cookie;

    restore_user_env(instance);
    c->callbacks.observe(instance, cookie, error, status,
                         key, nkey, cas, is_master, ttp, ttr);
    restore_wrapping_env(instance, c, error);
    libcouchbase_maybe_breakout(instance);
}

static void restore_user_env(libcouchbase_t instance)
{
    struct user_cookie *cookie = (void *)instance->cookie;
    /* Restore the users environment */
    instance->cookie = cookie->cookie;
    instance->callbacks = cookie->callbacks;
}

static void restore_wrapping_env(libcouchbase_t instance,
                                 struct user_cookie *user,
                                 libcouchbase_error_t error)
{
    user->callbacks = instance->callbacks;
    /* Install new callbacks */
    instance->callbacks.get = get_callback;
    instance->callbacks.storage = storage_callback;
    instance->callbacks.arithmetic = arithmetic_callback;
    instance->callbacks.remove = remove_callback;
    instance->callbacks.stat = stat_callback;
    instance->callbacks.touch = touch_callback;
    instance->callbacks.flush = flush_callback;
    instance->callbacks.tap_mutation = tap_mutation_callback;
    instance->callbacks.tap_deletion = tap_deletion_callback;
    instance->callbacks.tap_flush = tap_flush_callback;
    instance->callbacks.tap_opaque = tap_opaque_callback;
    instance->callbacks.tap_vbucket_set = tap_vbucket_set_callback;
    instance->callbacks.error = error_callback;
    instance->callbacks.view_complete = view_complete_callback;
    instance->callbacks.view_data = view_data_callback;
    instance->callbacks.observe = observe_callback;

    user->cookie = (void *)instance->cookie;
    user->retcode = error;
    instance->cookie = user;
}


libcouchbase_error_t libcouchbase_synchandler_return(libcouchbase_t instance,
                                                     libcouchbase_error_t retcode)
{
    struct user_cookie cookie;

    if (instance->syncmode == LIBCOUCHBASE_ASYNCHRONOUS ||
        retcode != LIBCOUCHBASE_SUCCESS) {
        return retcode;
    }

    restore_wrapping_env(instance, &cookie, LIBCOUCHBASE_SUCCESS);
    libcouchbase_wait(instance);
    restore_user_env(instance);
    return cookie.retcode;
}
