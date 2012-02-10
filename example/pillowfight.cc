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
#include "config.h"
#include <sys/types.h>
#include <stdint.h>
#include <libcouchbase/couchbase.h>

#include <iostream>
#include <map>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>

#include "tools/commandlineparser.h"


using namespace std;

class Configuration {
public:
 Configuration() : host(),
        maxKey(1000),
        iterations(1000),
        fixedSize(true),
        setprc(33),
        prefix(""),
        maxSize(1024),
        numThreads(1)
    {
        // @todo initialize the random sequence in seqno
        data = static_cast<void*>(new char[maxSize]);
    }

    ~Configuration() {
        delete []static_cast<char*>(data);
    }

    const char *getHost() const {
        if (host.length() > 0) {
            return host.c_str();
        }
        return NULL;
    }

    void setHost(const char *val) {
        host.assign(val);
    }

    const char *getUser() {
        if (user.length() > 0) {
            return user.c_str();
        }
        return NULL;
    }

    const char *getPasswd() {
        if (passwd.length() > 0) {
            return passwd.c_str();
        }
        return NULL;
    }

    void setPassword(const char *p) {
        passwd.assign(p);
    }

    void setUser(const char *u) {
        user.assign(u);
    }

    const char *getBucket() {
        if (bucket.length() > 0) {
            return bucket.c_str();
        }
        return NULL;
    }

    void setBucket(const char *b) {
        bucket.assign(b);
    }

    void setIterations(uint32_t val) {
        iterations = val;
    }

    void setMaxKeys(uint32_t val) {
        maxKey = val;
    }

    void setKeyPrefix(const char *val) {
        prefix.assign(val);
    }

    void setNumThreads(uint32_t val) {
        numThreads = val;
    }

    void *data;

    std::string host;
    std::string user;
    std::string passwd;
    std::string bucket;

    uint32_t maxKey;
    uint32_t iterations;
    bool fixedSize;
    uint32_t setprc;
    std::string prefix;
    uint32_t maxSize;
    uint32_t numThreads;

} config;

extern "C" {
    static void storageCallback(libcouchbase_t, const void *,
                                libcouchbase_storage_t , libcouchbase_error_t,
                                const void *, libcouchbase_size_t, libcouchbase_cas_t);

    static void getCallback(libcouchbase_t, const void *,
                            libcouchbase_error_t, const void *, libcouchbase_size_t,
                            const void *, libcouchbase_size_t, libcouchbase_uint32_t,
                            libcouchbase_cas_t);

    static void timingsCallback(libcouchbase_t, const void *,
                                libcouchbase_timeunit_t, libcouchbase_uint32_t,
                                libcouchbase_uint32_t, libcouchbase_uint32_t,
                                libcouchbase_uint32_t);
}

class ThreadContext {
public:
    ThreadContext() :
        currSeqno(0), instance(NULL) {
        // @todo fill the random seqnos

    }
    ~ThreadContext() {
        if (instance != NULL) {
            libcouchbase_destroy(instance);
        }
    }
    bool create(void) {
        struct libcouchbase_io_opt_st *io;
        io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL,
                                        NULL);
        if (!io) {
            std::cerr << "Failed to create an IO instance" << std::endl;
            return false;
        }

        instance = libcouchbase_create(config.getHost(), config.getUser(),
                                       config.getPasswd(), config.getBucket(), io);

        if (instance != NULL) {
            (void)libcouchbase_set_storage_callback(instance, storageCallback);
            (void)libcouchbase_set_get_callback(instance, getCallback);

            return true;
        } else {
            return false;
        }
    }

    bool connect(void) {
        if ((error = libcouchbase_connect(instance)) != LIBCOUCHBASE_SUCCESS) {
            std::cerr << "Failed to connect: "
                      << libcouchbase_strerror(instance, error) << std::endl;
            return false;
        }

        libcouchbase_wait(instance);
        error = libcouchbase_get_last_error(instance);
        if (error != LIBCOUCHBASE_SUCCESS) {
            std::cerr << "Failed to connect: "
                      << libcouchbase_strerror(instance, error) << std::endl;
            return false;
        }

        return true;
    }

    bool run(bool loop) {
        do {
            bool timings = true;
            if (libcouchbase_enable_timings(instance) != LIBCOUCHBASE_SUCCESS) {
                std::cerr << "Failed to enable timings!: "
                          << libcouchbase_strerror(instance, error) << std::endl;
                timings = false;
            }

            bool pending = false;
            for (uint32_t ii = 0; ii < config.iterations; ++ii) {
                std::string key;
                generateKey(key);

                libcouchbase_uint32_t flags = 0;
                libcouchbase_uint32_t exp = 0;

                if (config.setprc > 0 && (nextSeqno() % 100) < config.setprc) {
                    libcouchbase_store(instance, this, LIBCOUCHBASE_SET,
                                       key.c_str(), (libcouchbase_size_t)key.length(),
                                       config.data,
                                       config.maxSize, flags,
                                       exp, 0);
                } else {
                    const char* keys[1];
                    libcouchbase_size_t nkey[1];
                    keys[0] = key.c_str();
                    nkey[0] = (libcouchbase_size_t)key.length();
                    if (libcouchbase_mget(instance, this, 1,
                                          reinterpret_cast<const void * const *>(keys), nkey, NULL)
                        != LIBCOUCHBASE_SUCCESS) {
                        // @error
                    }
                }

                if (ii % 10 == 0) {
                    libcouchbase_wait(instance);
                } else {
                    libcouchbase_wait(instance);
                    //pending = true;
                }
            }

            if (pending) {
                libcouchbase_wait(instance);
            }

            if (timings) {
                dumpTimings("Run");
                libcouchbase_disable_timings(instance);
            }
        } while (loop);

        return true;
    }

    bool populate(uint32_t start, uint32_t stop) {
        bool timings = true;
        if (libcouchbase_enable_timings(instance) != LIBCOUCHBASE_SUCCESS) {
            std::cerr << "Failed to enable timings!: "
                      << libcouchbase_strerror(instance, error) << std::endl;
            timings = false;
        }

        for (uint32_t ii = start; ii < stop; ++ii) {
            std::string key;
            generateKey(key, ii);

            error = libcouchbase_store(instance,
                                       reinterpret_cast<void*> (this), LIBCOUCHBASE_SET,
                                       key.c_str(),
                                       (libcouchbase_size_t)key.length(),
                                       config.data, config.maxSize, 0, 0, 0);
            if (error != LIBCOUCHBASE_SUCCESS) {
                std::cerr << "Failed to store item: "
                          << libcouchbase_strerror(instance, error) << std::endl;
            }
            libcouchbase_wait(instance);
            if (error != LIBCOUCHBASE_SUCCESS) {
                std::cerr << "Failed to store item: "
                          << libcouchbase_strerror(instance, error) << std::endl;
            }
        }

        if (timings) {
            dumpTimings("Populate");
            libcouchbase_disable_timings(instance);
        }

        return true;
    }

protected:
    // the callback methods needs to be able to set the error handler..
    friend void storageCallback(libcouchbase_t, const void *,
                                libcouchbase_storage_t , libcouchbase_error_t,
                                const void *, libcouchbase_size_t, libcouchbase_cas_t);
    friend void getCallback(libcouchbase_t, const void *,
                            libcouchbase_error_t, const void *, libcouchbase_size_t,
                            const void *, libcouchbase_size_t, libcouchbase_uint32_t,
                            libcouchbase_cas_t);

    void setError(libcouchbase_error_t e) {
        error = e;
    }

    void dumpTimings(std::string header) {
        std::stringstream ss;
        ss << header << std::endl;
        ss << "              +---------+---------+---------+---------+" << std::endl;
        libcouchbase_get_timings(instance, reinterpret_cast<void*> (&ss),
                                 timingsCallback);
        ss << "              +----------------------------------------" << endl;
        std::cout << ss.str();
    }

private:
    uint32_t nextSeqno() {
        uint32_t ret = seqno[currSeqno];
        currSeqno += ret;
        if (currSeqno > 8191) {
            currSeqno &= 0xff;
        }
        return ret;
    }

    void generateKey(std::string &key,
                     uint32_t ii = static_cast<uint32_t>(-1)) {
        if (ii == static_cast<uint32_t>(-1)) {
            // get random key
            ii = nextSeqno() % config.maxKey;
        }

        std::stringstream ss;
        ss << config.prefix << ":" << ii;
        key.assign(ss.str());
    }

    uint32_t seqno[8192];
    uint32_t currSeqno;

    libcouchbase_t instance;
    libcouchbase_error_t error;
};

static void storageCallback(libcouchbase_t, const void *cookie,
                            libcouchbase_storage_t, libcouchbase_error_t error,
                            const void *, libcouchbase_size_t, libcouchbase_cas_t) {
    ThreadContext *tc;
    tc = const_cast<ThreadContext*>(reinterpret_cast<const ThreadContext*>(cookie));
    tc->setError(error);
}

static void getCallback(libcouchbase_t, const void *cookie,
                        libcouchbase_error_t error, const void *,
                        libcouchbase_size_t, const void *,
                        libcouchbase_size_t, libcouchbase_uint32_t,
                        libcouchbase_cas_t) {
    ThreadContext *tc;
    tc = const_cast<ThreadContext*>(reinterpret_cast<const ThreadContext*>(cookie));
    tc->setError(error);

}

static void timingsCallback(libcouchbase_t instance, const void *cookie,
                            libcouchbase_timeunit_t timeunit,
                            libcouchbase_uint32_t min,
                            libcouchbase_uint32_t max,
                            libcouchbase_uint32_t total,
                            libcouchbase_uint32_t maxtotal) {
    std::stringstream *ss =
        const_cast<std::stringstream*> (reinterpret_cast<const std::stringstream*> (cookie));
    char buffer[1024];
    int offset = sprintf(buffer, "[%3u - %3u]", min, max);

    switch (timeunit) {
    case LIBCOUCHBASE_TIMEUNIT_NSEC:
        offset += sprintf(buffer + offset, "ns");
        break;
    case LIBCOUCHBASE_TIMEUNIT_USEC:
        offset += sprintf(buffer + offset, "us");
        break;
    case LIBCOUCHBASE_TIMEUNIT_MSEC:
        offset += sprintf(buffer + offset, "ms");
        break;
    case LIBCOUCHBASE_TIMEUNIT_SEC:
        offset += sprintf(buffer + offset, "s");
        break;
    default:
        ;
    }

    int num = static_cast<int>(static_cast<float>(40.0) * static_cast<float>(total) / static_cast<float>(maxtotal));

    offset += sprintf(buffer + offset, " |");
    for (int ii = 0; ii < num; ++ii) {
        offset += sprintf(buffer + offset, "#");
    }

    offset += sprintf(buffer + offset, " - %u\n", total);
    *ss << buffer;
    (void)cookie;
    (void)maxtotal;
    (void)instance;
}

static void handle_options(int argc, char **argv) {
    Getopt getopt;
    getopt.addOption(new CommandLineOption('?', "help", false,
                                           "Print this help text"));
    getopt.addOption(new CommandLineOption('h', "host", true,
                                           "Hostname to connect to"));
    getopt.addOption(new CommandLineOption('b', "bucket", true,
                                           "Bucket to use"));
    getopt.addOption(new CommandLineOption('u', "user", true,
                                           "Username for the rest port"));
    getopt.addOption(new CommandLineOption('P', "password", true,
                                           "password for the rest port"));
    getopt.addOption(new CommandLineOption('i', "iterations", true, "Number of iterations to run"));
    getopt.addOption(new CommandLineOption('I', "num-items", true, "Number of items to operate on"));
    getopt.addOption(new CommandLineOption('p', "key-prefix", true, "Use the following prefix for keys"));
    getopt.addOption(new CommandLineOption('t', "num-threads", true, "The number of threads to use"));
    /* getopt.addOption(new CommandLineOption()); */
    /* getopt.addOption(new CommandLineOption()); */

    if (!getopt.parse(argc, argv)) {
        getopt.usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    std::vector<CommandLineOption*>::iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->found) {
            switch ((*iter)->shortopt) {
            case 'h' :
                config.setHost((*iter)->argument);
                break;

            case 'b' :
                config.setBucket((*iter)->argument);
                break;

            case 'u' :
                config.setUser((*iter)->argument);
                break;

            case 'P' :
                config.setPassword((*iter)->argument);
                break;

            case 'i' :
                config.setIterations(atoi((*iter)->argument));
                break;

            case 'I':
                config.setMaxKeys(atoi((*iter)->argument));
                break;

            case 'p' :
                config.setKeyPrefix((*iter)->argument);
                break;

            case 't':
                config.setNumThreads(atoi((*iter)->argument));
                break;

            case '?':
                getopt.usage(argv[0]);
                exit(EXIT_FAILURE);
            default:
                abort();
            }

        }
    }
}

/**
 * Program entry point
 * @param argc argument count
 * @param argv argument vector
 * @return 0 success, 1 failure
 */
int main(int argc, char **argv) {
    handle_options(argc, argv);

    ThreadContext ctx;
    if (!ctx.create() || !ctx.connect()) {
        return 1;
    }

    ctx.populate(0, config.maxKey);
    ctx.run(true);

    return 0;
}
