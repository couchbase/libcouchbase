/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017-Present Couchbase, Inc.
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

#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

#include <libcouchbase/couchbase.h>

static void get_callback(const lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *resp)
{
    lcb_STATUS rc = lcb_respget_status(resp);
    const char *key;
    size_t nkey;
    lcb_respget_key(resp, &key, &nkey);
    fprintf(stderr, "GET \"%.*s\", %s\n", (int)nkey, key, lcb_strerror_short(rc));

    (void)instance;
    (void)cbtype;
}

typedef struct {
    lcb_INSTANCE *instance;
    pthread_mutex_t mutex;
} my_CTX;

/*
 * This function uses the same instance between threads. A lock is required for every operation
 */
static void *thread_func(void *arg)
{
    my_CTX *ctx = arg;

    const char *key = "key";
    lcb_CMDGET *cmd = NULL;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_key(cmd, key, strlen(key));

    // every operation, that requires modification of the instance should be protected by the mutex
    pthread_mutex_lock(&ctx->mutex);

    lcb_STATUS rc = lcb_get(ctx->instance, NULL, cmd);
    lcb_cmdget_destroy(cmd);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Could not schedule GET \"%.*s\", %s\n", (int)strlen(key), key, lcb_strerror_short(rc));
    } else {
        lcb_wait(ctx->instance, LCB_WAIT_DEFAULT);
    }

    pthread_mutex_unlock(&ctx->mutex);
    return NULL;
}

/**
 *
 * This example demonstrates strategy, where single lcb_INSTANCE is shared between multiple threads.
 *
 * Key observations here:
 *
 * 1. less resources will be consumed by the library (memory, descriptors, etc)
 * 2. if the application does not have any other work to do, threads will compete for the connections, and
 *    the bandwidth will be lower than expected.
 *
 * As with any multi-threaded application, it requires extra testing and analysis to meet all performance and
 * correctness requirements.
 *
 * See threads-private.c for the alternative approach.
 *
 */
int main(int argc, const char *argv[])
{
#define number_of_threads 10
    const char *connection_string = (argc > 1) ? argv[1] : "couchbase://127.0.0.1/default";
    const char *username = (argc > 2) ? argv[2] : "Administrator";
    const char *password = (argc > 3) ? argv[3] : "password";

    pthread_t thrs[number_of_threads];

    my_CTX ctx;

    // initialize mutex that will protect the shared instance
    pthread_mutex_init(&ctx.mutex, NULL);

    // create and connect shared instance of the connection
    lcb_CREATEOPTS *options = NULL;
    lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(options, connection_string, strlen(connection_string));
    lcb_createopts_credentials(options, username, strlen(username), password, strlen(password));
    lcb_create(&ctx.instance, options);
    lcb_connect(ctx.instance);
    lcb_wait(ctx.instance, LCB_WAIT_DEFAULT);
    lcb_install_callback(ctx.instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);

    for (int ii = 0; ii < number_of_threads; ii++) {
        // path shared context to each of the threads
        pthread_create(&thrs[ii], NULL, thread_func, &ctx);
    }

    for (int ii = 0; ii < number_of_threads; ii++) {
        void *ign;
        pthread_join(thrs[ii], &ign);
    }

    lcb_destroy(ctx.instance);

    return 0;
}
