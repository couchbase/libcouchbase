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
#ifdef __linux__
#include <sys/syscall.h>
#endif

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
    lcb_LOGGER *base;
    lcb_LOG_SEVERITY min_level;
    char path[1024];
    FILE *file;
} my_LOGGER;

static const char *level_str(lcb_LOG_SEVERITY severity)
{
    switch (severity) {
        case LCB_LOG_TRACE:
            return "TRACE";
        case LCB_LOG_DEBUG:
            return "DEBUG";
        case LCB_LOG_INFO:
            return "INFO ";
        case LCB_LOG_WARN:
            return "WARN ";
        case LCB_LOG_ERROR:
            return "ERROR";
        case LCB_LOG_FATAL:
            return "FATAL";
        default:
            return "";
    }
}
static void log_callback(const lcb_LOGGER *logger, uint64_t iid, const char *subsys, lcb_LOG_SEVERITY severity,
                         const char *srcfile, int srcline, const char *fmt, va_list ap)
{
    my_LOGGER *wrapper = NULL;
    lcb_logger_cookie(logger, (void **)&wrapper);
    if (wrapper == NULL) {
        return;
    }
    if (severity < wrapper->min_level) {
        return;
    }

    uint64_t tid = 0;
#if defined(__APPLE__)
    pthread_threadid_np(NULL, &tid);
#elif defined(__linux__)
    tid = syscall(SYS_gettid);
#endif
    char buf[1024] = {0};
    int written = snprintf(buf, sizeof(buf), "%s [thread=0x%08llx, instance=0x%08llx] ", level_str(severity), tid, iid);
    vsnprintf(buf + written, sizeof(buf) - written, fmt, ap);

    fprintf(wrapper->file, "%s\n", buf);
    (void)srcfile;
    (void)srcline;
    (void)subsys;
}

/*
 * This function uses an instance per thread. Since no other thread is using the instance, locking is not required
 */
static void *thread_func_unlocked(void *arg)
{
    lcb_INSTANCE *instance = (lcb_INSTANCE *)arg;

    lcb_connect(instance);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);

    const char *key = "key";
    lcb_CMDGET *cmd = NULL;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_key(cmd, key, strlen(key));

    lcb_STATUS rc = lcb_get(instance, NULL, cmd);
    lcb_cmdget_destroy(cmd);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Could not schedule GET \"%.*s\", %s\n", (int)strlen(key), key, lcb_strerror_short(rc));
    } else {
        lcb_wait(instance, LCB_WAIT_DEFAULT);
    }
    return NULL;
}

/**
 *
 * This example demonstrates strategy, where every thread has associated lcb_INSTANCE, which is never shared
 *
 * Key observations here:
 *
 * 1. more resources will be consumed by the library (memory, descriptors, etc)
 * 2. the application will be able to use network more efficiently
 * 3. the application must supply thread-safe version of the logger, or create new logger object for each of the
 *    lcb_INSTANCE.
 *
 * As with any multi-threaded application, it requires extra testing and analysis to meet all performance and
 * correctness requirements.
 *
 * See threads-shared.c for the alternative approach.
 *
 */
int main(int argc, const char *argv[])
{
#define number_of_threads 10
    const char *connection_string = (argc > 1) ? argv[1] : "couchbase://127.0.0.1/default";
    const char *username = (argc > 2) ? argv[2] : "Administrator";
    const char *password = (argc > 3) ? argv[3] : "password";

    pthread_t thrs[number_of_threads];

    // multiple threads with independent instances
    lcb_INSTANCE *instances[number_of_threads];
    my_LOGGER loggers[number_of_threads];

    for (int ii = 0; ii < number_of_threads; ii++) {
        lcb_CREATEOPTS *options = NULL;
        lcb_createopts_create(&options, LCB_TYPE_BUCKET);
        lcb_createopts_connstr(options, connection_string, strlen(connection_string));
        lcb_createopts_credentials(options, username, strlen(username), password, strlen(password));

        // let each thread write logs to separate file
        loggers[ii].min_level = LCB_LOG_TRACE;
        snprintf(loggers[ii].path, sizeof(loggers[ii].path), "/tmp/lcb-%03d.log", ii);
        loggers[ii].file = fopen(loggers[ii].path, "a+");
        lcb_logger_create(&loggers[ii].base, &loggers[ii]);
        lcb_logger_callback(loggers[ii].base, log_callback);
        lcb_createopts_logger(options, loggers[ii].base);

        lcb_create(&instances[ii], options);
    }

    for (int ii = 0; ii < number_of_threads; ii++) {
        pthread_create(&thrs[ii], NULL, thread_func_unlocked, instances[ii]);
    }

    for (int ii = 0; ii < number_of_threads; ii++) {
        void *ign;
        pthread_join(thrs[ii], &ign);
        lcb_destroy(instances[ii]);
        fclose(loggers[ii].file);
    }

    return 0;
}
