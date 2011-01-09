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
 * @todo Add documentation about the library (how it works etc)
 *
 * @author Trond Norbye
 */
#ifndef LIBMEMBASE_MEMBASE_H
#define LIBMEMBASE_MEMBASE_H 1

#include <stdint.h>
#include <stddef.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <memcached/vbucket.h>
#include <libmembase/types.h>
#include <libmembase/callbacks.h>

struct event_base;

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Create an instance of libmembase
     * @param host The host (with optional port) to connect to retrieve the
     *             vbucket list from
     * @param user the username to use
     * @param passwd The password
     * @param bucket The bucket to connect to
     * @param base the libevent base we're for this instance
     * @return A handle to libmembase, or NULL if an error occured.
     */
    libmembase_t libmembase_create(const char *host,
                                   const char *user,
                                   const char *passwd,
                                   const char *bucket,
                                   struct event_base *base);


    /**
     * Destroy (and release all allocated resources) an instance of libmembase.
     * Using instance after calling destroy will most likely cause your
     * application to crash.
     *
     * @param instance the instance to destroy.
     */
    void libmembase_destroy(libmembase_t instance);

    /**
     * Connect to the server and get the vbucket and serverlist.
     */
    libmembase_error_t libmembase_connect(libmembase_t instance);

    /**
     * Associate a cookie with an instance of libmembase
     * @param instance the instance to associate the cookie to
     * @param cookie the cookie to associate with this instance.
     */
    void libmembase_set_cookie(libmembase_t instance, const void *cookie);


    /**
     * Retrieve the cookie associated with this instance
     * @param instance the instance of libmembase
     * @return The cookie associated with this instance or NULL
     */
    const void *libmembase_get_cookie(libmembase_t instance);

    /**
     * Set the packet filter for this instance
     * @param instance the instance of libmembase
     * @param filter the new packet filter to associate with this instance
     */
    void libmembase_set_packet_filter(libmembase_t instance,
                                      libmembase_packet_filter_t filter);

    /**
     * Set the command handlers
     * @param instance the instance of libmembase
     * @param callback the new set of callbacks
     */
    void libmembase_set_callbacks(libmembase_t instance,
                                  libmembase_callback_t *callbacks);

    /**
     * Use the TAP protocol to tap the cluster
     * @param instance the instance to tap
     * @param filter the tap filter to use
     * @param callbacks the calback to use
     * @param block set to true if you want libmembase to run the event
     *              dispatcher loop
     */
    void libmembase_tap_cluster(libmembase_t instance,
                                libmembase_tap_filter_t filter,
                                bool block);

    /**
     * Execute all of the batched requests
     * @param instance the instance containing the requests
     */
    void libmembase_execute(libmembase_t instance);

    /**
     * Get a number of values from the cache. You need to run the
     * event loop yourself (or call libmembase_execute) to retrieve
     * the data.
     *
     * @param instance the instance used to batch the requests from
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @return The status of the operation
     */
    libmembase_error_t libmembase_mget(libmembase_t instance,
                                       size_t num_keys,
                                       const void * const *keys,
                                       const size_t *nkey);

    /**
     * Get a number of values from the cache. You need to run the
     * event loop yourself (or call libmembase_execute) to retrieve
     * the data.
     *
     * @param instance the instance used to batch the requests from
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @return The status of the operation
     */
    libmembase_error_t libmembase_mget_by_key(libmembase_t instance,
                                              const void *hashkey,
                                              size_t nhashkey,
                                              size_t num_keys,
                                              const void * const *keys,
                                              const size_t *nkey);

    /**
     * Spool a store operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param operation constraints for the storage operation (add/replace etc)
     * @param key the key to set
     * @param nkey the number of bytes in the key
     * @param bytes the value to set
     * @param nbytes the size of the value
     * @param flags the user-defined flag section for the item
     * @param exp When the object should expire
     * @param cas the cas identifier for the existing object if you want to
     *            ensure that you're only replacing/append/prepending a
     *            specific object. Specify 0 if you don't want to limit to
     *            any cas value.
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_store(libmembase_t instance,
                                        libmembase_storage_t operation,
                                        const void *key, size_t nkey,
                                        const void *bytes, size_t nbytes,
                                        uint32_t flags, time_t exp,
                                        uint64_t cas);

    /**
     * Spool a store operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param operation constraints for the storage operation (add/replace etc)
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to set
     * @param nkey the number of bytes in the key
     * @param bytes the value to set
     * @param nbytes the size of the value
     * @param flags the user-defined flag section for the item
     * @param exp When the object should expire
     * @param cas the cas identifier for the existing object if you want to
     *            ensure that you're only replacing/append/prepending a
     *            specific object. Specify 0 if you don't want to limit to
     *            any cas value.
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_store_by_key(libmembase_t instance,
                                               libmembase_storage_t operation,
                                               const void *hashkey,
                                               size_t nhashkey,
                                               const void *key, size_t nkey,
                                               const void *bytes, size_t nbytes,
                                               uint32_t flags, time_t exp,
                                               uint64_t cas);

    /**
     * Spool an arithmetic operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param key the key to set
     * @param nkey the number of bytes in the key
     * @param delta The amount to add / subtract
     * @param exp When the object should expire
     * @param create set to true if you want the object to be created if it
     *               doesn't exist.
     * @param initial The initial value of the object if we create it
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_arithmetic(libmembase_t instance,
                                             const void *key, size_t nkey,
                                             int64_t delta, time_t exp,
                                             bool create, uint64_t initial);

    /**
     * Spool an arithmetic operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to set
     * @param nkey the number of bytes in the key
     * @param delta The amount to add / subtract
     * @param exp When the object should expire
     * @param create set to true if you want the object to be created if it
     *               doesn't exist.
     * @param initial The initial value of the object if we create it
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_arithmetic_by_key(libmembase_t instance,
                                                    const void *hashkey,
                                                    size_t nhashkey,
                                                    const void *key,
                                                    size_t nkey,
                                                    int64_t delta, time_t exp,
                                                    bool create,
                                                    uint64_t initial);

    /**
     * Spool a remove operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object (or 0 if you don't care)
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_remove(libmembase_t instance,
                                         const void *key, size_t nkey,
                                         uint64_t cas);

    /**
     * Spool a remove operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libmembase_execute).
     *
     * @param instance the handle to libmembase
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object (or 0 if you don't care)
     * @return Status of the operation.
     */
    libmembase_error_t libmembase_remove_by_key(libmembase_t instance,
                                                const void *hashkey,
                                                size_t nhashkey,
                                                const void *key, size_t nkey,
                                                uint64_t cas);

#ifdef __cplusplus
}
#endif

#endif
