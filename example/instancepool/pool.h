/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#ifndef POOL_H
#define POOL_H

#include <libcouchbase/couchbase.h>
#include <pthread.h>
#include <queue>
#include <vector>

namespace lcb {

class Pool {
public:
    /**
     * Create a new pool to use across threads
     * @param options The options used to initialize the instance
     * @param items How many items should be in the pool
     */
    Pool(const lcb_create_st& options, size_t items = 10);
    virtual ~Pool();

    /**Get an instance from the pool. You should call #push() when you are
     * done with the instance
     * @return an lcb_t instance */
    lcb_t pop();

    /**Release an instance back into the pool
     * @param instance The instance to release */
    void push(lcb_t instance);

    // Connect all the instances in the pool. This should be called once the
    // pool has been constructed
    lcb_error_t connect();

protected:
    /**Function called after the instance is created. You may
     * customize the instance here with e.g. lcb_set_cookie()
     * @param instance the newly created instance */
    virtual void initialize(lcb_t instance) = 0;

private:
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    std::queue<lcb_t> instances;

    // List of all instances
    std::vector<lcb_t> all_instances;
    size_t initial_size;
};
} // namespace


/**
 * The clients of a connection pool should not need to know the
 * internals of the pool. All they want to do is to grab an instance
 * for a while
 */
typedef struct lcb_pool_st* lcb_pool_t;

/**
 * Create a pool of connections that the client may grab to perform some
 * operations and then release it back to the pool.
 *
 * @param size the number of instances in the pool
 * @param options the options to create the pool with (hostname, bucket etc).
 *                please note that you <b>cannot</b> specify an IO object here
 *                because we don't know if it is threadsafe or not...
 * @param pool the created pool is returned here
 * @param initiate a function called for all of the created instances to
 *                 allow you to specify the callbacks and set options etc.
 * @return LCB_SUCCESS on success, or an appropriate error code on failure
 */
lcb_error_t pool_create(unsigned int size,
                        const struct lcb_create_st *options,
                        lcb_pool_t *pool,
                        void (*initiate)(lcb_t));

/**
 * Get an instance from the connection pool. If none is available
 * the caller is <b>blocked</b> until one is available.
 *
 * @param pool the pool to allocate the instance from
 * @return a libcoucbase instance
 */
lcb_t pool_pop(lcb_pool_t pool);

/**
 * Put the libcouchbase instance back into the pool.
 *
 * @param pool where to store the instance
 * @param instance the instance to release
 */
void pool_push(lcb_pool_t pool, lcb_t instance);

#endif
