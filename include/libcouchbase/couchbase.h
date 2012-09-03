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
#include <libcouchbase/arguments.h>
#include <libcouchbase/compat.h>
#include <libcouchbase/behavior.h>
#include <libcouchbase/callbacks.h>
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
    const char *lcb_get_version(lcb_uint32_t *version);

    /**
     * Create a new instance of one of the library-supplied io ops types.
     * @param type The predefined type you want to create
     * @param cookie Extra cookie-information supplied to the creation
     *               of the io ops type
     * @param error Where to store information about why creation failed
     * @return pointer to a newly created io ops structure
     */
    LIBCOUCHBASE_API
    lcb_io_opt_t *lcb_create_io_ops(lcb_io_ops_type_t type,
                                    void *cookie,
                                    lcb_error_t *error);


    /**
     * Create an instance of lcb.
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
     * @return A handle to lcb, or NULL if an error occured.
     */
    LIBCOUCHBASE_API
    lcb_t lcb_create(const char *host,
                     const char *user,
                     const char *passwd,
                     const char *bucket,
                     struct lcb_io_opt_st *io);


    /**
     * Destroy (and release all allocated resources) an instance of lcb.
     * Using instance after calling destroy will most likely cause your
     * application to crash.
     *
     * @param instance the instance to destroy.
     */
    LIBCOUCHBASE_API
    void lcb_destroy(lcb_t instance);

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
    void lcb_set_timeout(lcb_t instance, lcb_uint32_t usec);

    /**
     * Get the current timeout value used by this instance (in usec)
     */
    LIBCOUCHBASE_API
    lcb_uint32_t lcb_get_timeout(lcb_t instance);

    /**
     * Get the current host
     */
    LIBCOUCHBASE_API
    const char *lcb_get_host(lcb_t instance);

    /**
     * Get the current port
     */
    LIBCOUCHBASE_API
    const char *lcb_get_port(lcb_t instance);

    /**
     * Connect to the server and get the vbucket and serverlist.
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_connect(lcb_t instance);

    /**
     * Returns the last error that was seen within libcoubhase.
     *
     * @param instance the connection whose last error should be returned.
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_get_last_error(lcb_t instance);

    /**
     * Try to send/receive data buffered on the servers
     *
     * @param instance the handle to lcb
     */
    LIBCOUCHBASE_API
    void lcb_flush_buffers(lcb_t instance, const void *cookie);

    /**
     * Associate a cookie with an instance of lcb
     * @param instance the instance to associate the cookie to
     * @param cookie the cookie to associate with this instance.
     */
    LIBCOUCHBASE_API
    void lcb_set_cookie(lcb_t instance, const void *cookie);


    /**
     * Retrieve the cookie associated with this instance
     * @param instance the instance of lcb
     * @return The cookie associated with this instance or NULL
     */
    LIBCOUCHBASE_API
    const void *lcb_get_cookie(lcb_t instance);

    /**
     * Wait for the execution of all batched requests
     * @param instance the instance containing the requests
     */
    LIBCOUCHBASE_API
    void lcb_wait(lcb_t instance);

    /**
     * Returns non-zero if the event loop is running now
     *
     * @param instance the instance to run the event loop for.
     * @return non-zero if nobody is waiting for IO interaction
     */
    LIBCOUCHBASE_API
    int lcb_is_waiting(lcb_t instance);

    /**
     * Stop event loop. Might be useful to breakout the event loop
     *
     * @param instance the instance to run the event loop for.
     */
    LIBCOUCHBASE_API
    void lcb_breakout(lcb_t instance);

    /**
     * Get a number of values from the cache.
     *
     * If you specify a non-zero value for expiration, the server will
     * update the expiration value on the item (refer to the
     * documentation on lcb_store to see the meaning of the
     * expiration). All other members should be set to zero.
     *
     * Example:
     *   lcb_get_cmd_t *get = calloc(1, sizeof(*get));
     *   get->version = 0;
     *   get->v.v0.key = "my-key";
     *   get->v.v0.nkey = strlen(get->v.v0.key);
     *   // Set an expiration of 60 (optional)
     *   get->v.v0.exptime = 60;
     *   lcb_get_cmd_t* commands[] = { get };
     *   lcb_get(instance, NULL, 1, commands);
     *
     * It is possible to get an item with a lock that has a timeout. It can
     * then be unlocked with either a CAS operation or with an explicit
     * unlock command.
     *
     * You may specify the expiration value for the lock in the
     * expiration (setting it to 0 cause the server to use the default
     * value).
     *
     * Example: Get and lock the key
     *   lcb_get_cmd_t *get = calloc(1, sizeof(*get));
     *   get->version = 0;
     *   get->v.v0.key = "my-key";
     *   get->v.v0.nkey = strlen(get->v.v0.key);
     *   // Set a lock expiration of 60 (optional)
     *   get->v.v0.lock = 1;
     *   get->v.v0.exptime = 60;
     *   lcb_get_cmd_t* commands[] = { get };
     *   lcb_get(instance, NULL, 1, commands);
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to get
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_get(lcb_t instance,
                        const void *command_cookie,
                        lcb_size_t num,
                        const lcb_get_cmd_t *const *commands);

    /**
     * Get a number of replca values from the cache.
     *
     * Example:
     *   lcb_get_replica_cmd_t *get = calloc(1, sizeof(*get));
     *   get->version = 0;
     *   get->v.v0.key = "my-key";
     *   get->v.v0.nkey = strlen(get->v.v0.key);
     *   lcb_get_replica-cmd_t* commands[] = { get };
     *   lcb_get_replica(instance, NULL, 1, commands);
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to get
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_get_replica(lcb_t instance,
                                const void *command_cookie,
                                lcb_size_t num,
                                const lcb_get_replica_cmd_t *const *commands);
    /**
     * Unlock the key locked with lcb_get_locked
     *
     * You should initialize the key, nkey and cas member in the
     * lcb_item_st structure for the keys to get. All other
     * members should be set to zero.
     *
     * Example:
     *   lcb_unlock_cmd_t *unlock = calloc(1, sizeof(*unlock));
     *   unlock->version = 0;
     *   unlock->v.v0.key = "my-key";
     *   unlock->v.v0.nkey = strlen(unlock->v.v0.key);
     *   unlock->v.v0.cas = 0x666;
     *   lcb_unlock_cmd_t* commands[] = { unlock };
     *   lcb_unlock(instance, NULL, 1, commands);
     *
     * @param instance the handle to lcb
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to unlock
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_unlock(lcb_t instance,
                           const void *command_cookie,
                           lcb_size_t num,
                           const lcb_unlock_cmd_t *const *commands);

    /**
     * Touch (set expiration time) on a number of values in the cache.
     *
     * Values larger than 30*24*60*60 seconds (30 days) are
     * interpreted as absolute times (from the epoch). All other
     * members should be set to zero.
     *
     * Example:
     *   lcb_touch_cmd_t *touch = calloc(1, sizeof(*touch));
     *   touch->version = 0;
     *   touch->v.v0.key = "my-key";
     *   touch->v.v0.nkey = strlen(item->v.v0.key);
     *   touch->v.v0.exptime = 0x666;
     *   lcb_touch_cmd_t* commands[] = { touch };
     *   lcb_touch(instance, NULL, 1, commands);
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num the total number of elements in the commnands array
     * @param commands the array containing the items to touch
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_touch(lcb_t instance,
                          const void *command_cookie,
                          lcb_size_t num,
                          const lcb_touch_cmd_t *const *commands);

    /**
     * Store an item in the cluster.
     *
     * You may initialize all of the members in the the
     * lcb_item_st structure with the values you want.
     * Values larger than 30*24*60*60 seconds (30 days) are
     * interpreted as absolute times (from the epoch). Unused members
     * should be set to zero.
     *
     * Example:
     *   lcb_store_cmd_st *store = calloc(1, sizeof(*store));
     *   store->version = 0;
     *   store->v.v0.key = "my-key";
     *   store->v.v0.nkey = strlen(store->v.v0.key);
     *   store->v.v0.bytes = "{ value:666 }"
     *   store->v.v0.nbytes = strlen(store->v.v0.bytes);
     *   store->v.v0.flags = 0xdeadcafe;
     *   store->v.v0.cas = 0x1234;
     *   store->v.v0.exptime = 0x666;
     *   store->v.v0.datatype = LCB_JSON;
     *   store->v.v0.operation = LCB_REPLACE;
     *   lcb_store_cmd_st* commands[] = { store };
     *   lcb_store(instance, NULL, 1, commands);
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param operation constraints for the storage operation (add/replace etc)
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to store
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_store(lcb_t instance,
                          const void *command_cookie,
                          lcb_size_t num,
                          const lcb_store_cmd_t *const *commands);

    /**
     * Perform arithmetic operation on a keys value.
     *
     * You should initialize the key, nkey and expiration member in
     * the lcb_item_st structure for the keys to update.
     * Values larger than 30*24*60*60 seconds (30 days) are
     * interpreted as absolute times (from the epoch). All other
     * members should be set to zero.
     *
     * Example:
     *   lcb_arithmetic_cmd_t *arithmetic = calloc(1, sizeof(*arithmetic));
     *   arithmetic->version = 0;
     *   arithmetic->v.v0.key = "counter";
     *   arithmetic->v.v0.nkey = strlen(arithmetic->v.v0.key);
     *   arithmetic->v.v0.initial = 0x666;
     *   arithmetic->v.v0.create = 1;
     *   arithmetic->v.v0.delta = 1;
     *   lcb_arithmetic_cmd_t* commands[] = { arithmetic };
     *   lcb_arithmetic(instance, NULL, 1, commands);
     *
     * @param instance the handle to lcb
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param create set to true if you want the object to be created if it
     *               doesn't exist.
     * @param delta The amount to add / subtract
     * @param initial The initial value of the object if we create it
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to operate on
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_arithmetic(lcb_t instance,
                               const void *command_cookie,
                               lcb_size_t num,
                               const lcb_arithmetic_cmd_t *const *commands);

    /**
     * Observe key
     *
     * Example:
     *   lcb_observe_cmd_t *observe = calloc(1, sizeof(*observe));
     *   observe->version = 0;
     *   observe->v.v0.key = "my-key";
     *   observe->v.v0.nkey = strlen(observe->v.v0.key);
     *   lcb_observe_cmd_t* commands[] = { observe };
     *   lcb_observe(instance, NULL, 1, commands);
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to observe
     * @return The status of the operation
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_observe(lcb_t instance,
                            const void *command_cookie,
                            lcb_size_t num,
                            const lcb_observe_cmd_t *const *commands);

    /**
     * Remove a key from the cluster
     *
     * Example:
     *   lcb_remove_cmd_t *remove = calloc(1, sizeof(*remove));
     *   remove->version = 0;
     *   remove->v.v0.key = "my-key";
     *   remove->v.v0.nkey = strlen(remove->v.v0.key);
     *   remove->v.v0.cas = 0x666;
     *   lcb_remove_cmd_t* commands[] = { remove };
     *   lcb_remove(instance, NULL, 1, commands);
     *
     * @param num the total number of elements in the commands array
     * @param commands the array containing the items to remove
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_remove(lcb_t instance,
                           const void *command_cookie,
                           lcb_size_t num,
                           const lcb_remove_cmd_t *const *commands);

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
    lcb_error_t lcb_server_stats(lcb_t instance,
                                 const void *command_cookie,
                                 const void *arg,
                                 lcb_size_t narg);

    /**
     * Request server versions. The callback will be invoked with the
     * instance, server address, version string, and version string length.
     *
     * When all server versions have been received, the callback is invoked
     * with the server endpoint argument set to NULL
     *
     * @param instance the handle to lcb
     * @param command_cookie a cookie passed to each invocation of the callback
     *                          from this command
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_server_versions(lcb_t instance, const void *command_cookie);


    /**
     * Get a textual descrtiption for the given error code
     * @param instance the instance the error code belongs to (you might
     *                 want different localizations for the different instances)
     * @param error the error code
     * @return A textual description of the error message. The caller should
     *         <b>not</b> release the memory returned from this function.
     */
    LIBCOUCHBASE_API
    const char *lcb_strerror(lcb_t instance, lcb_error_t error);


    /**
     * Set the loglevel on the servers
     *
     * @param instance the instance used to batch the requests from
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param server The server to set the verbosity level on (NULL == all servers)
     * @param level the new verbosity level to set on the desired memcached servers
     *              in the cluster
     * @return The status of the operation.
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_set_verbosity(lcb_t instance,
                                  const void *command_cookie,
                                  const char *server,
                                  lcb_verbosity_level_t level);

    /**
     * Flush the entire couchbase cluster!
     *
     * @param instance the handle to lcb
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @return Status of the operation.
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_flush(lcb_t instance, const void *cookie);

    /**
     * Execute HTTP request matching given path and yield JSON result object.
     * Depending on type it could be:
     *
     * - LCB_HTTP_TYPE_VIEW
     *
     *   The client should setup view_complete callback in order to fetch
     *   the result. Also he can setup view_data callback to fetch response
     *   body in chunks as soon as possible, it will be called each time the
     *   library receive a data chunk from socket. The empty <tt>bytes</tt>
     *   argument (NULL pointer and zero size) is the sign of end of
     *   response. Chunked callback allows to save memory on large datasets.
     *
     * - LCB_HTTP_TYPE_MANAGEMENT
     *
     *   Management requests allow you to configure the cluster, add/remove
     *   buckets, rebalance etc. The result will be passed to management
     *   callbacks (data/complete).
     *
     * Example: Fetch first 10 docs from '_design/test/_view/all' view
     *   lcb_error_t err;
     *   lcb_http_cmd_t *cmd = calloc(1, sizeof(lcb_http_cmd_t));
     *   cmd->version = 0;
     *   cmd->v.v0.path = "_design/test/_view/all?limit=10";
     *   cmd->v.v0.npath = strlen(item->v.v0.path);
     *   cmd->v.v0.body = NULL;
     *   cmd->v.v0.nbody = 0;
     *   cmd->v.v0.method = LCB_HTTP_METHOD_GET;
     *   cmd->v.v0.chunked = 1;
     *   cmd->v.v0.content_type = "application/json";
     *   lcb_make_http_request(instance, NULL, LCB_HTTP_TYPE_VIEW,
     *                         &cmd, &err);
     *
     * Example: The same as above but with POST filter
     *   lcb_error_t err;
     *   lcb_http_cmd_t *cmd = calloc(1, sizeof(lcb_http_cmd_t));
     *   cmd->version = 0;
     *   cmd->v.v0.path = "_design/test/_view/all?limit=10";
     *   cmd->v.v0.npath = strlen(item->v.v0.path);
     *   cmd->v.v0.body = "{\"keys\": [\"test_1000\", \"test_10002\"]}"
     *   cmd->v.v0.nbody = strlen(item->v.v0.body);
     *   cmd->v.v0.method = LCB_HTTP_METHOD_POST;
     *   cmd->v.v0.chunked = 1;
     *   cmd->v.v0.content_type = "application/json";
     *   lcb_make_http_request(instance, NULL, LCB_HTTP_TYPE_VIEW,
     *                         &cmd, &err);
     *
     * Example: Delete bucket via REST management API
     *   lcb_error_t err;
     *   lcb_http_cmd_t cmd;
     *   cmd->version = 0;
     *   cmd.v.v0.path = query.c_str();
     *   cmd.v.v0.npath = query.length();
     *   cmd.v.v0.body = NULL;
     *   cmd.v.v0.nbody = 0;
     *   cmd.v.v0.method = LCB_HTTP_METHOD_DELETE;
     *   cmd.v.v0.chunked = false;
     *   cmd.v.v0.content_type = "application/x-www-form-urlencoded";
     *   lcb_make_http_request(instance, NULL, LCB_HTTP_TYPE_MANAGEMENT,
     *                         &cmd, &err);
     *
     * @param instance The handle to lcb
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param type The type of the request needed.
     * @param cmd The struct describing the command options
     * @param error Where to store information about why creation failed
     */
    LIBCOUCHBASE_API
    lcb_http_request_t lcb_make_http_request(lcb_t instance,
                                             const void *command_cookie,
                                             lcb_http_type_t type,
                                             const lcb_http_cmd_t *cmd,
                                             lcb_error_t *error);

    /**
     * Cancel HTTP request (view or management API). This function could be
     * called from the callback to stop the request.
     *
     * @param instance The handle to lcb
     * @param request The request handle
     */
    LIBCOUCHBASE_API
    void lcb_cancel_http_request(lcb_t instance,
                                 lcb_http_request_t request);

    /**
     * Create timer event. The user will be notified through timer callback.
     *
     * @param instance The handle to lcb
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param usec The timespan in microseconds
     * @param periodic Should the library re-schedule the timer
     * @param callback The callback to notify the caller
     * @param error Where to store information about why creation failed
     */
    LIBCOUCHBASE_API
    lcb_timer_t lcb_timer_create(lcb_t instance,
                                 const void *command_cookie,
                                 lcb_uint32_t usec,
                                 int periodic,
                                 lcb_timer_callback callback,
                                 lcb_error_t *error);

    /**
     * Destroy the timer. All non-periodic timers will be sweeped
     * automatically. All timers will be sweeped when the connection
     * instance will be destroyed. It is safe to call this function several
     * times for given timer.
     *
     * @param instance The handle to lcb
     * @param timer the timer handle
     */
    LIBCOUCHBASE_API
    lcb_error_t lcb_timer_destroy(lcb_t instance, lcb_timer_t timer);

    /**
     * Get the number of the replicas in the cluster
     *
     * @param instance The handle to lcb
     *
     * @return -1 if the cluster wasn't configured yet, and number of
     *         replicas otherwise.
     */
    LIBCOUCHBASE_API
    lcb_int32_t lcb_get_num_replicas(lcb_t instance);

    /**
     * Return a NULL-terminated list of 0-terminated strings consisting of
     * node hostnames:admin_ports for the entire cluster.
     * The storage duration of this list is only valid until the
     * next call to a libcouchbase function and/or when returning control to
     * libcouchbase' event loop.
     */
    LIBCOUCHBASE_API
    const char * const * lcb_get_server_list(lcb_t instance);

#ifdef __cplusplus
}
#endif

#endif
