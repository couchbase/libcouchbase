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
 * @todo Add documentation about the library (how it works etc)
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_COUCHBASE_H
#define LIBCOUCHBASE_COUCHBASE_H 1

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include <libcouchbase/configuration.h>
#include <libcouchbase/visibility.h>
#include <libcouchbase/types.h>
#include <libcouchbase/behavior.h>
#include <libcouchbase/callbacks.h>
#include <libcouchbase/tap_filter.h>
#include <libcouchbase/timings.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Get the version of the library.
     *
     * @param version where to store the numeric representation of the
     *         version (or NULL if you don't care)
     *
     * @return the textual description of the version ('\0'
     *          terminated). Do <b>not</b> try to release this string.
     *
     */
    LIBCOUCHBASE_API
    const char *libcouchbase_get_version(uint32_t *version);

    /**
     * Create a new instance of one of the library-supplied io ops types.
     * @param type The predefined type you want to create
     * @param cookie Extra cookie-information supplied to the creation
     *               of the io ops type
     * @param error Where to store information about why creation failed
     * @return pointer to a newly created io ops structure
     */
    LIBCOUCHBASE_API
    libcouchbase_io_opt_t* libcouchbase_create_io_ops(libcouchbase_io_ops_type_t type,
                                                      void *cookie,
                                                      libcouchbase_error_t *error);


    /**
     * Create an instance of libcouchbase
     * @param host The host (with optional port) to connect to retrieve the
     *             vbucket list from
     * @param user the username to use
     * @param passwd The password
     * @param bucket The bucket to connect to
     * @param io the io handle to use
     * @return A handle to libcouchbase, or NULL if an error occured.
     */
    LIBCOUCHBASE_API
    libcouchbase_t libcouchbase_create(const char *host,
                                       const char *user,
                                       const char *passwd,
                                       const char *bucket,
                                       struct libcouchbase_io_opt_st *io);


    /**
     * Destroy (and release all allocated resources) an instance of libcouchbase.
     * Using instance after calling destroy will most likely cause your
     * application to crash.
     *
     * @param instance the instance to destroy.
     */
    LIBCOUCHBASE_API
    void libcouchbase_destroy(libcouchbase_t instance);

    /**
     * Connect to the server and get the vbucket and serverlist.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_connect(libcouchbase_t instance);

    /**
     * Returns the last error that was seen within libcoubhase.
     *
     * @param instance the connection whose last error should be returned.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_get_last_error(libcouchbase_t instance);

    /**
     * Try to send/receive data buffered on the servers
     *
     * @param instance the handle to libcouchbase
     */
    LIBCOUCHBASE_API
    void libcouchbase_flush_buffers(libcouchbase_t instance, const void* cookie);

    /**
     * Associate a cookie with an instance of libcouchbase
     * @param instance the instance to associate the cookie to
     * @param cookie the cookie to associate with this instance.
     */
    LIBCOUCHBASE_API
    void libcouchbase_set_cookie(libcouchbase_t instance, const void *cookie);


    /**
     * Retrieve the cookie associated with this instance
     * @param instance the instance of libcouchbase
     * @return The cookie associated with this instance or NULL
     */
    LIBCOUCHBASE_API
    const void *libcouchbase_get_cookie(libcouchbase_t instance);

    /**
     * Use the TAP protocol to tap the cluster
     * @param instance the instance to tap
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param filter the tap filter to use
     * @param block set to true if you want libcouchbase to run the event
     *              dispatcher loop
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_tap_cluster(libcouchbase_t instance,
                                                  const void *command_cookie,
                                                  libcouchbase_tap_filter_t filter,
                                                  int block);

    /**
     * Wait for the execution of all batched requests
     * @param instance the instance containing the requests
     */
    LIBCOUCHBASE_API
    void libcouchbase_wait(libcouchbase_t instance);

    /**
     * Get a number of values from the cache. You need to run the
     * event loop yourself (or call libcouchbase_execute) to retrieve
     * the data. You might want to alter the expiry time for the object
     * you're fetching, and to do so you should specify the new expiry
     * time in the exp parameter. To use an ordinary mget use NULL
     * for the exp parameter.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @param exp the new expiration time for the object
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_mget(libcouchbase_t instance,
                                           const void *command_cookie,
                                           size_t num_keys,
                                           const void * const *keys,
                                           const size_t *nkey,
                                           const time_t *exp);

    /**
     * Get a number of values from the cache. You need to run the
     * event loop yourself (or call libcouchbase_execute) to retrieve
     * the data. You might want to alter the expiry time for the object
     * you're fetching, and to do so you should specify the new expiry
     * time in the exp parameter. To use an ordinary mget use NULL
     * for the exp parameter.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_mget_by_key(libcouchbase_t instance,
                                                  const void *command_cookie,
                                                  const void *hashkey,
                                                  size_t nhashkey,
                                                  size_t num_keys,
                                                  const void * const *keys,
                                                  const size_t *nkey,
                                                  const time_t *exp);


    /**
     * Touch (set expiration time) on a number of values in the cache
     * You need to run the event loop yourself (or call
     * libcouchbase_execute) to retrieve the results of the operations.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_mtouch(libcouchbase_t instance,
                                  const void *command_cookie,
                                             size_t num_keys,
                                             const void * const *keys,
                                             const size_t *nkey,
                                             const time_t *exp);

    /**
     * Touch (set expiration time) on a number of values in the cache
     * You need to run the event loop yourself (or call
     * libcouchbase_execute) to retrieve the results of the operations.
     *
     * Set <code>nhashkey</code> to 0 if you want to hash each individual
     * key.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @param exp the new expiration time for the items
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_mtouch_by_key(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    size_t nhashkey,
                                                    size_t num_keys,
                                                    const void * const *keys,
                                                    const size_t *nkey,
                                                    const time_t *exp);


    /**
     * Request server statistics. Without a key specified the server will
     * respond with a "default" set of statistics information. Each piece of
     * statistical information is returned in its own packet (key contains
     * the name of the statistical item and the body contains the value in
     * ASCII format). The sequence of return packets is terminated with a
     * packet that contains no key and no value.
     *
     * The command will signal about transfer completion by passing NULL as
     * the server endpoint and 0 for key length. Note that key length will
     * be zero when some server responds with error. In latter case server
     * endpoint argument will indicate the server address.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie a cookie passed to all of the notifications
     *                       from this command
     * @param arg the argument of the STATS command.
     * @param narg the number of bytes in the argument.
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_server_stats(libcouchbase_t instance,
                                                   const void* command_cookie,
                                                   const void* arg,
                                                   size_t narg);

    /**
     * Spool a store operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
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
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_store(libcouchbase_t instance,
                                            const void *command_cookie,
                                            libcouchbase_storage_t operation,
                                            const void *key, size_t nkey,
                                            const void *bytes, size_t nbytes,
                                            uint32_t flags, time_t exp,
                                            uint64_t cas);

    /**
     * Spool a store operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * This _store_by_key function differs from the _store function in that
     * you can specify a different value for hashkey to specify a different
     * character string for the client to use when hashing to the proper
     * location in the cluster.
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
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
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_store_by_key(libcouchbase_t instance,
                                                   const void *command_cookie,
                                                   libcouchbase_storage_t operation,
                                                   const void *hashkey,
                                                   size_t nhashkey,
                                                   const void *key,
                                                   size_t nkey,
                                                   const void *bytes,
                                                   size_t nbytes,
                                                   uint32_t flags,
                                                   time_t exp,
                                                   uint64_t cas);

    /**
     * Spool an arithmetic operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param key the key to set
     * @param nkey the number of bytes in the key
     * @param delta The amount to add / subtract
     * @param exp When the object should expire
     * @param create set to true if you want the object to be created if it
     *               doesn't exist.
     * @param initial The initial value of the object if we create it
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_arithmetic(libcouchbase_t instance,
                                                 const void *command_cookie,
                                                 const void *key, size_t nkey,
                                                 int64_t delta, time_t exp,
                                                 int create, uint64_t initial);

    /**
     * Spool an arithmetic operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
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
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_arithmetic_by_key(libcouchbase_t instance,
                                                        const void *command_cookie,
                                                        const void *hashkey,
                                                        size_t nhashkey,
                                                        const void *key,
                                                        size_t nkey,
                                                        int64_t delta,
                                                        time_t exp,
                                                        int create,
                                                        uint64_t initial);

    /**
     * Spool a remove operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object (or 0 if you don't care)
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_remove(libcouchbase_t instance,
                                             const void *command_cookie,
                                             const void *key, size_t nkey,
                                             uint64_t cas);

    /**
     * Spool a remove operation to the cluster. The operation <b>may</b> be
     * sent immediately, but you won't be sure (or get the result) until you
     * run the event loop (or call libcouchbase_execute).
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object (or 0 if you don't care)
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_remove_by_key(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    size_t nhashkey,
                                                    const void *key,
                                                    size_t nkey,
                                                    uint64_t cas);


    /**
     * Get a textual descrtiption for the given error code
     * @param instance the instance the error code belongs to (you might
     *                 want different localizations for the different instances)
     * @param error the error code
     * @return A textual description of the error message. The caller should
     *         <b>not</b> release the memory returned from this function.
     */
    LIBCOUCHBASE_API
    const char *libcouchbase_strerror(libcouchbase_t instance,
                                      libcouchbase_error_t error);


    /**
     * Flush the entire couchbase cluster!
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_flush(libcouchbase_t instance,
                                            const void* cookie);

#ifdef __cplusplus
}
#endif

#endif
