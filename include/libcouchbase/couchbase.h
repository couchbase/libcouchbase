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

#include <stddef.h>
#include <time.h>

#include <libcouchbase/configuration.h>
#include <libcouchbase/visibility.h>
#include <libcouchbase/types.h>
#include <libcouchbase/compat.h>
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
    const char *libcouchbase_get_version(libcouchbase_uint32_t *version);

    /**
     * Create a new instance of one of the library-supplied io ops types.
     * @param type The predefined type you want to create
     * @param cookie Extra cookie-information supplied to the creation
     *               of the io ops type
     * @param error Where to store information about why creation failed
     * @return pointer to a newly created io ops structure
     */
    LIBCOUCHBASE_API
    libcouchbase_io_opt_t *libcouchbase_create_io_ops(libcouchbase_io_ops_type_t type,
                                                      void *cookie,
                                                      libcouchbase_error_t *error);


    /**
     * Create an instance of libcouchbase.
     *
     * @param hosts A list of hosts:port separated by ';' to the
     *              administration port of the couchbase cluster. (ex:
     *              "host1;host2:9000;host3" would try to connect to
     *              host1 on port 8091, if that fails it'll connect to
     *              host2 on port 9000 etc).
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
     * Set the number of usec the library should allow an operation to
     * be vaild.
     *
     * Please note that the timeouts are <b>not</b> that accurate,
     * because they may be delayed by the application code before it
     * drives the event loop.
     *
     * Please note that timeouts is not stored on a per operation
     * base, but on the instance. That means you <b>can't</b> pipeline
     * two requests after eachother with different timeout values.
     *
     * @param instance the instance to set the timeout for
     * @param usec the new timeout value.
     */
    LIBCOUCHBASE_API
    void libcouchbase_set_timeout(libcouchbase_t instance, libcouchbase_uint32_t usec);

    /**
     * Get the current timeout value used by this instance (in usec)
     */
    LIBCOUCHBASE_API
    libcouchbase_uint32_t libcouchbase_get_timeout(libcouchbase_t instance);

    /**
     * Get the current host
     */
    LIBCOUCHBASE_API
    const char *libcouchbase_get_host(libcouchbase_t instance);

    /**
     * Get the current port
     */
    LIBCOUCHBASE_API
    const char *libcouchbase_get_port(libcouchbase_t instance);

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
    void libcouchbase_flush_buffers(libcouchbase_t instance, const void *cookie);

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
                                           libcouchbase_size_t num_keys,
                                           const void *const *keys,
                                           const libcouchbase_size_t *nkey,
                                           const libcouchbase_time_t *exp);

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
                                                  libcouchbase_size_t nhashkey,
                                                  libcouchbase_size_t num_keys,
                                                  const void *const *keys,
                                                  const libcouchbase_size_t *nkey,
                                                  const libcouchbase_time_t *exp);

    /**
     * Get an item with a lock that has a timeout. It can then be unlocked
     * with either a CAS operation or with an explicit unlock command.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param key the key to get
     * @param nkey the length of the key
     * @param exp the expiration time for the lock. If exp is NULL, the
     *            Couchbase will use default value (usually 15 seconds, but
     *            could be configured). Default value will be used if
     *            specified value is larger than allowed maximum (usually
     *            29, but could be configured on server).
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_getl(libcouchbase_t instance,
                                           const void *command_cookie,
                                           const void *key,
                                           libcouchbase_size_t nkey,
                                           libcouchbase_time_t *exp);

    /**
     * Get an item with a lock that has a timeout. Use hashkey argument to
     * locate the vbucket. It can then be unlocked with either a CAS
     * operation or with an explicit unlock command. All mutation commands
     * will return LIBCOUCHBASE_ETMPFAIL for locked keys.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to get
     * @param nkey the length of the key
     * @param exp the expiration time for the lock. If exp is NULL, the
     *            Couchbase will use default value (usually 15 seconds, but
     *            could be configured). Default value will be used if
     *            specified value is larger than allowed maximum (usually
     *            29, but could be configured on server).
     * @return The status of the operation. Returns LIBCOUCHBASE_ETMPFAIL if
     *         the lock was unsuccessful or LIBCOUCHBASE_KEY_ENOENT for
     *         missing key.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_getl_by_key(libcouchbase_t instance,
                                                  const void *command_cookie,
                                                  const void *hashkey,
                                                  libcouchbase_size_t nhashkey,
                                                  const void *key,
                                                  libcouchbase_size_t nkey,
                                                  libcouchbase_time_t *exp);

    /**
     * Unlock the key locked with GETL.
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object
     * @return Status of the operation. LIBCOUCHBASE_ETMPFAIL if the key
     *         cannot be unlocked (wrong CAS or non-locked).
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_unlock(libcouchbase_t instance,
                                             const void *command_cookie,
                                             const void *key,
                                             libcouchbase_size_t nkey,
                                             libcouchbase_cas_t cas);

    /**
     * Unlock the key locked with GETL. Use hashkey to locate the vbucket.
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param hashkey the key to use for hashing
     * @param nhashkey the number of bytes in hashkey
     * @param key the key to delete
     * @param nkey the number of bytes in the key
     * @param cas the cas value for the object
     * @return Status of the operation. LIBCOUCHBASE_ETMPFAIL if the key
     *         cannot be unlocked (wrong CAS or non-locked).
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_unlock_by_key(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    libcouchbase_size_t nhashkey,
                                                    const void *key,
                                                    libcouchbase_size_t nkey,
                                                    libcouchbase_cas_t cas);

    /**
     * Touch (set expiration time) on a number of values in the cache
     * You need to run the event loop yourself (or call
     * libcouchbase_execute) to retrieve the results of the operations. All
     * mutation commands will return LIBCOUCHBASE_ETMPFAIL for locked keys.
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num_keys the number of keys to get
     * @param keys the array containing the keys to get
     * @param nkey the array containing the lengths of the keys
     * @param exp the array containing the expiry times for each key. Values
     *            larger than 30*24*60*60 seconds (30 days) are interpreted
     *            as absolute times (from the epoch).
     * @return The status of the operation. Returns LIBCOUCHBASE_ETMPFAIL if
     *         the lock was unsuccessful or LIBCOUCHBASE_KEY_ENOENT for
     *         missing key.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_mtouch(libcouchbase_t instance,
                                             const void *command_cookie,
                                             libcouchbase_size_t num_keys,
                                             const void *const *keys,
                                             const libcouchbase_size_t *nkey,
                                             const libcouchbase_time_t *exp);

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
                                                    libcouchbase_size_t nhashkey,
                                                    libcouchbase_size_t num_keys,
                                                    const void *const *keys,
                                                    const libcouchbase_size_t *nkey,
                                                    const libcouchbase_time_t *exp);


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
                                                   const void *command_cookie,
                                                   const void *arg,
                                                   libcouchbase_size_t narg);

    /**
     * Request server versions. The callback will be invoked with the
     * instance, server address, version string, and version string length.
     *
     * When all server versions have been received, the callback is invoked
     * with the server endpoint argument set to NULL
     *
     * @param instance the handle to libcouchbase
     * @param command_cookie a cookie passed to each invocation of the callback
     *                          from this command
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_server_versions(libcouchbase_t instance,
                                                      const void *command_cookie);
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
     * @param flags the user-defined flag section for the item (doesn't have
     *              any meaning to Couchbase server)
     * @param exp When the object should expire. The expiration time is
     *            either an offset into the future.. OR an absolute
     *            timestamp, depending on how large (numerically) the
     *            expiration is. if the expiration exceeds 30 months
     *            (i.e. 24 * 3600 * 30) then it's an absolute timestamp.
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
                                            const void *key, libcouchbase_size_t nkey,
                                            const void *bytes, libcouchbase_size_t nbytes,
                                            libcouchbase_uint32_t flags, libcouchbase_time_t exp,
                                            libcouchbase_cas_t cas);

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
                                                   libcouchbase_size_t nhashkey,
                                                   const void *key,
                                                   libcouchbase_size_t nkey,
                                                   const void *bytes,
                                                   libcouchbase_size_t nbytes,
                                                   libcouchbase_uint32_t flags,
                                                   libcouchbase_time_t exp,
                                                   libcouchbase_cas_t cas);

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
                                                 const void *key,
                                                 libcouchbase_size_t nkey,
                                                 libcouchbase_int64_t delta,
                                                 libcouchbase_time_t exp,
                                                 int create,
                                                 libcouchbase_uint64_t initial);

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
                                                        libcouchbase_size_t nhashkey,
                                                        const void *key,
                                                        libcouchbase_size_t nkey,
                                                        libcouchbase_int64_t delta,
                                                        libcouchbase_time_t exp,
                                                        int create,
                                                        libcouchbase_uint64_t initial);

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
                                             const void *key,
                                             libcouchbase_size_t nkey,
                                             libcouchbase_cas_t cas);

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
                                                    libcouchbase_size_t nhashkey,
                                                    const void *key,
                                                    libcouchbase_size_t nkey,
                                                    libcouchbase_cas_t cas);


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
                                            const void *cookie);

    /**
     * Execute Couchbase View matching given path and yield JSON result object.
     * The client should setup view_complete callback in order to fetch the
     * result. Also he can setup view_data callback to fetch response body
     * in chunks as soon as possible, it will be called each time the library
     * receive a data chunk from socket. The empty <tt>bytes</tt> argument
     * (NULL pointer and zero size) is the sign of end of response. Chunked
     * callback allows to save memory on large datasets.
     *
     * It doesn't automatically breakout like other operations when you use
     * libcouchbase_execute().
     *
     * @param instance The handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param path A view path string with optional query params (e.g. skip,
     *             limit etc.)
     * @param npath Size of path
     * @param body The POST body for Couchbase View request.
     * @param nbody Size of body
     * @param method HTTP message type to be sent to server
     * @param chunked If true the client will use libcouchbase_couch_data_callback
     *                to notify about response and libcouchbase_couch_complete
     *                otherwise.
     * @param error Where to store information about why creation failed
     *
     * @example Fetch first 10 docs from the bucket
     *    const char path[] = "_all_docs?limit=10";
     *    libcouchbase_make_couch_request(instance, NULL, path, npath
     *                                    NULL, 0, LIBCOUCHBASE_HTTP_METHOD_GET, 1);
     *
     * @example Filter first 10 docs using POST request
     *    const char path[] = "_all_docs?limit=10";
     *    const char body[] = "{\"keys\": [\"test_1000\", \"test_10002\"]}"
     *    libcouchbase_make_couch_request(instance, NULL, path, npath
     *                                    body, sizeof(body),
     *                                    LIBCOUCHBASE_HTTP_METHOD_GET, 1);
     */
    LIBCOUCHBASE_API
    libcouchbase_http_request_t libcouchbase_make_couch_request(libcouchbase_t instance,
                                                                const void *command_cookie,
                                                                const char *path,
                                                                libcouchbase_size_t npath,
                                                                const void *body,
                                                                libcouchbase_size_t nbody,
                                                                libcouchbase_http_method_t method,
                                                                int chunked,
                                                                libcouchbase_error_t *error);

    /**
     * Cancel HTTP request (view or management API). This function could be
     * called from the callback to stop the request.
     */
    LIBCOUCHBASE_API
    void libcouchbase_cancel_http_request(libcouchbase_http_request_t request);

#ifdef __cplusplus
}
#endif

#endif
