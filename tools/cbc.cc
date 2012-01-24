/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#include <iostream>
#include <sstream>
#include <ctype.h>
#include <getopt.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <cerrno>
#include <libcouchbase/couchbase.h>

#include "configuration.h"
#include "commandlineparser.h"

using namespace std;

enum cbc_command_t {
    cbc_illegal,
    cbc_cat,
    cbc_cp,
    cbc_create,
    cbc_flush,
    cbc_receive,
    cbc_rm,
    cbc_stats,
    cbc_send,
    cbc_version
};

extern "C" {
    // libcouchbase use a C linkage!

    static void error_callback(libcouchbase_t instance,
                               libcouchbase_error_t error,
                               const char *errinfo)
    {
        cerr << "ERROR: " << libcouchbase_strerror(instance, error) << endl;
        if (errinfo) {
            cerr << "\t\"" << errinfo << "\"" << endl;
        }
        exit(EXIT_FAILURE);
    }


    static void storage_callback(libcouchbase_t instance,
                                 const void *,
                                 libcouchbase_storage_t,
                                 libcouchbase_error_t error,
                                 const void *key, size_t nkey,
                                 libcouchbase_cas_t cas)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "Stored \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\" CAS 0x" << hex << cas << endl;
        } else {
            cerr << "Failed to store \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\":" << endl
                      << libcouchbase_strerror(instance, error) << endl;

            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *e = static_cast<bool*>(cookie);
            *e = true;
        }
    }

    static void remove_callback(libcouchbase_t instance,
                                const void *,
                                libcouchbase_error_t error,
                                const void *key, size_t nkey)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "Removed \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\"" << endl;
        } else {
            cerr << "Failed to remove \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\":" << endl
                      << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool*>(cookie);
            *err = true;
        }
    }

    static void get_callback(libcouchbase_t instance,
                             const void *,
                             libcouchbase_error_t error,
                             const void *key, size_t nkey,
                             const void *bytes, size_t nbytes,
                             uint32_t flags, libcouchbase_cas_t cas)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "\"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\" Size " << nbytes << " Flags 0x" << std::hex
                 << flags << " CAS 0x" << cas << endl;
            cerr.flush();
            cout.write(static_cast<const char*>(bytes), nbytes);
            cout.flush();
        } else {
            cerr << "Failed to get \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\": " << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool*>(cookie);
            *err = true;
        }
    }

    static void stat_callback(libcouchbase_t instance,
                              const void*,
                              const char* server_endpoint,
                              libcouchbase_error_t error,
                              const void* key,
                              size_t nkey,
                              const void* value,
                              size_t nvalue)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            if (nkey > 0) {
                cout << server_endpoint << "\t";
                cout.write(static_cast<const char*>(key), nkey);
                cout << "\t";
                cout.write(static_cast<const char*>(value), nvalue);
                cout << endl;
            }
        } else {
            cerr << "Failure requesting stats:" << endl
                 << libcouchbase_strerror(instance, error) << endl;

            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool*>(cookie);
            *err = true;
        }
    }

    static void flush_callback(libcouchbase_t instance,
                               const void*,
                               const char* server_endpoint,
                               libcouchbase_error_t error)
    {
        if (error != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to flush node \"" << server_endpoint
                 << "\": " << libcouchbase_strerror(instance, error)
                 << endl;
            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool*>(cookie);
            *err = true;
        }
    }

    static void timings_callback(libcouchbase_t, const void *,
                                 libcouchbase_timeunit_t timeunit,
                                 uint32_t min, uint32_t max,
                                 uint32_t total, uint32_t maxtotal) {
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

        int num = static_cast<int>(static_cast<float>(40.0) *
                                   static_cast<float>(total) /
                                   static_cast<float>(maxtotal));

        offset += sprintf(buffer + offset, " |");
        for (int ii = 0; ii < num; ++ii) {
            offset += sprintf(buffer + offset, "#");
        }

        offset += sprintf(buffer + offset, " - %u\n", total);
        cerr << buffer;
    }
}

static bool cp(libcouchbase_t instance, list<string> &keys)
{
    for (list<string>::iterator ii = keys.begin(); ii != keys.end(); ++ii) {
        std::string key = *ii;
        struct stat st;
        if (stat(key.c_str(), &st) == 0) {
            char *bytes = new char[(size_t)st.st_size];
            if (bytes != NULL) {
                ifstream file(key.c_str(), ios::binary);
                if (file.good() && file.read(bytes, st.st_size) && file.good()) {
                    libcouchbase_store(instance,
                                       NULL,
                                       LIBCOUCHBASE_SET,
                                       key.c_str(), key.length(),
                                       bytes, (size_t)st.st_size,
                                       0, 0, 0);
                    delete []bytes;
                } else {
                    cerr << "Failed to read file \"" << key << "\": "
                         << strerror(errno) << endl;
                    return false;
                }
            } else {
                cerr << "Failed to allocate memory for \"" << key << "\": "
                     << strerror(errno) << endl;
                return false;
            }
        } else {
            cerr << "Failed to open \"" << key << "\": " <<  strerror(errno) << endl;
            return false;
        }
    }

    return true;
}

static bool rm(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to delete" << endl;
        return false;
    }

    for (list<string>::iterator ii = keys.begin(); ii != keys.end(); ++ii) {
        std::string key = *ii;
        libcouchbase_error_t err;
        err = libcouchbase_remove(instance, NULL, key.c_str(), key.length(), 0);
        if (err != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to remove \"" << key << "\":" << endl
                 << libcouchbase_strerror(instance, err) << endl;
            return false;
        }
    }
    return true;
}

static bool cat(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to get" << endl;
        return false;
    }

    const char* *k = new const char*[keys.size()];
    size_t *s = new size_t[keys.size()];

    int idx = 0;
    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter, ++idx) {
        k[idx] = iter->c_str();
        s[idx] = iter->length();
    }

    libcouchbase_error_t err = libcouchbase_mget(instance, NULL, idx,
                                                 (const void * const *)k,
                                                 s, NULL);

    delete []k;
    delete []s;

    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to send requests:" << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
   }

    return true;
}

static bool stats(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        libcouchbase_error_t err;
        err = libcouchbase_server_stats(instance, NULL, NULL, 0);
        if (err != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to request stats: " << endl
                 << libcouchbase_strerror(instance, err) << endl;
            return false;
        }
    } else {
        for (list<string>::iterator ii = keys.begin(); ii != keys.end(); ++ii) {
            std::string key = *ii;
            libcouchbase_error_t err;
            err = libcouchbase_server_stats(instance, NULL, key.c_str(), key.length());
            if (err != LIBCOUCHBASE_SUCCESS) {
                cerr << "Failed to request stats: " << endl
                     << libcouchbase_strerror(instance, err) << endl;
                return false;
            }
        }
    }

    return true;
}

static bool flush(libcouchbase_t instance, list<string> &keys)
{
    if (!keys.empty()) {
        cerr << "Ignoring arguments." << endl;
    }

    libcouchbase_error_t err;
    err = libcouchbase_flush(instance, NULL);
    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to flush: " << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
    }

    return true;
}

static bool spool(string &data) {
    stringstream ss;
    char buffer[1024];
    size_t nr;
    while ((nr = fread(buffer, 1, sizeof(buffer), stdin)) != (size_t)-1) {
        if (nr == 0) {
            break;
        }
        ss.write(buffer, nr);
    }
    data.assign(ss.str());
    return nr == 0 || feof(stdin) != 0;
}

static bool create(libcouchbase_t instance, list<string> &keys,
                   uint32_t exptime, uint32_t flags, bool add)
{
    if (keys.size() != 1) {
        cerr << "Usage: You need to specify a single key" << endl;
        return false;
    }

    string &key = keys.front();

    string data;
    if (!spool(data)) {
        cerr << "Failed to read input data: " << strerror(errno)
             << endl;
        return false;
    }

    libcouchbase_storage_t operation;
    if (add) {
        operation = LIBCOUCHBASE_ADD;
    } else {
        operation = LIBCOUCHBASE_SET;
    }

    libcouchbase_error_t err;
    err = libcouchbase_store(instance, NULL, operation,
                             key.c_str(), key.length(),
                             data.data(), data.length(),
                             flags, exptime, 0);

    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to store object: " << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
    }

    return true;
}

extern bool receive(libcouchbase_t instance, list<string> &keys);
extern bool send(libcouchbase_t instance, list<string> &keys);

static void handleCommandLineOptions(enum cbc_command_t cmd, int argc, char **argv)
{
    Configuration config;
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
    getopt.addOption(new CommandLineOption('T', "enable-timings", false,
                                           "Enable command timings"));

    uint32_t flags = 0;
    uint32_t exptime = 0;
    bool add = false;
    if (cmd == cbc_create) {
        getopt.addOption(new CommandLineOption('f', "flag", true,
                                               "Flag for the new object"));
        getopt.addOption(new CommandLineOption('e', "exptime", true,
                                               "Expiry time for the new object"));
        getopt.addOption(new CommandLineOption('a', "add", false,
                                               "Fail if the object exists"));
    }

    if (!getopt.parse(argc, argv)) {
        getopt.usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    vector<CommandLineOption*>::iterator iter;
    for (iter = getopt.options.begin(); iter != getopt.options.end(); ++iter) {
        if ((*iter)->found) {
            bool unknownOpt = true;
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

            case 'T' :
                config.setTimingsEnabled(true);
                break;

            case '?':
            default:
                if (cmd == cbc_create) {
                    unknownOpt = false;
                    switch ((*iter)->shortopt) {
                    case 'f':
                        flags = (uint32_t)atoi((*iter)->argument);
                        break;
                    case 'e':
                        flags = (uint32_t)atoi((*iter)->argument);
                        break;
                    case 'a':
                        add = true;
                        break;
                    default:
                        unknownOpt = true;
                    }
                }

                if (unknownOpt) {
                    getopt.usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    libcouchbase_t instance = libcouchbase_create(config.getHost(),
                                                  config.getUser(),
                                                  config.getPassword(),
                                                  config.getBucket(),
                                                  NULL);
    if (instance == 0) {
        cerr << "Failed to create couchbase instance" << endl;
        exit(EXIT_FAILURE);
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    (void)libcouchbase_set_flush_callback(instance, flush_callback);
    (void)libcouchbase_set_get_callback(instance, get_callback);
    (void)libcouchbase_set_remove_callback(instance, remove_callback);
    (void)libcouchbase_set_stat_callback(instance, stat_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    libcouchbase_error_t ret = libcouchbase_connect(instance);
    if (ret != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to connect libcouchbase instance to server:" << endl
                  << "\t\"" << libcouchbase_strerror(instance, ret) << "\"" << endl;
        exit(EXIT_FAILURE);
    }
    libcouchbase_wait(instance);

    bool error = false;
    libcouchbase_set_cookie(instance, static_cast<void*>(&error));

    if (config.isTimingsEnabled()) {
        libcouchbase_enable_timings(instance);
    }

    bool success;
    switch (cmd) {
    case cbc_cat:
        success = cat(instance, getopt.arguments);
        break;
    case cbc_cp:
        success = cp(instance, getopt.arguments);
        break;
    case cbc_rm:
        success = rm(instance, getopt.arguments);
        break;
    case cbc_receive:
        success = receive(instance, getopt.arguments);
        break;
    case cbc_stats:
        success = stats(instance, getopt.arguments);
        break;
    case cbc_send:
        success = send(instance, getopt.arguments);
        break;
    case cbc_flush:
        success = flush(instance, getopt.arguments);
        break;
    case cbc_create:
        success = create(instance, getopt.arguments, exptime, flags, add);
        break;
    default:
        cerr << "Not implemented" << endl;
        success = false;
    }

    if (!success) {
        error = true;
    } else {
        libcouchbase_wait(instance);
        if (config.isTimingsEnabled()) {
            libcouchbase_get_timings(instance, NULL,
                                     timings_callback);
            libcouchbase_disable_timings(instance);
        }
    }

    libcouchbase_destroy(instance);
    exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void lowercase(string &str)
{
    ssize_t len = str.length();
    stringstream ss;
    for (ssize_t ii = 0; ii < len; ++ii) {
        ss << static_cast<char>(tolower(str[ii]));
    }
    str.assign(ss.str());
}

static cbc_command_t getBuiltin(string name)
{
    lowercase(name);
    if (name.find("cbc-cat") != string::npos) {
        return cbc_cat;
    } else if (name.find("cbc-cp") != string::npos) {
        return cbc_cp;
    } else if (name.find("cbc-create") != string::npos) {
        return cbc_create;
    } else if (name.find("cbc-receive") != string::npos) {
        return cbc_receive;
    } else if (name.find("cbc-rm") != string::npos) {
        return cbc_rm;
    } else if (name.find("cbc-send") != string::npos) {
        return cbc_send;
    } else if (name.find("cbc-stats") != string::npos) {
        return cbc_stats;
    } else if (name.find("cbc-flush") != string::npos) {
        return cbc_flush;
    } else if (name.find("cbc-version") != string::npos) {
        return cbc_version;
    }

    return cbc_illegal;
}

/**
 * Program entry point
 * @param argc argument count
 * @param argv argument vector
 * @return 0 success, 1 failure
 */
int main(int argc, char **argv)
{
    cbc_command_t cmd = getBuiltin(argv[0]);
    if (cmd == cbc_illegal) {
        if (argc > 1) {
            if (strcmp(argv[1], "cat") == 0) {
                cmd = cbc_cat;
            } else if (strcmp(argv[1], "cat") == 0) {
                cmd = cbc_cat;
            } else if (strcmp(argv[1], "cp") == 0) {
                cmd = cbc_cp;
            } else if (strcmp(argv[1], "create") == 0) {
                cmd = cbc_create;
            } else if (strcmp(argv[1], "receive") == 0) {
                cmd = cbc_receive;
            } else if (strcmp(argv[1], "rm") == 0) {
                cmd = cbc_rm;
            } else if (strcmp(argv[1], "send") == 0) {
                cmd = cbc_send;
            } else if (strcmp(argv[1], "stats") == 0) {
                cmd = cbc_stats;
            } else if (strcmp(argv[1], "flush") == 0) {
                cmd = cbc_flush;
            } else if (strcmp(argv[1], "version") == 0) {
                cmd = cbc_version;
            }
        } else {
            std::cerr << "Usage: cbc command [options]" << std::endl
                      << "\tcommand may be: cat, cp, create, rm, stats, flush, version" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (cmd == cbc_illegal) {
            std::cerr << "Error: Unknown command \""<< argv[1] << "\"" << std::endl;
            exit(EXIT_FAILURE);
        }
        --argc;
        ++argv;
    }

    if (cmd == cbc_version) {
        cout << "cbc built from: " << PACKAGE_STRING << endl
             << "    using libcouchbase: " << libcouchbase_get_version(NULL)
             << endl;
    } else {
        handleCommandLineOptions(cmd, argc, argv);
    }

    return EXIT_SUCCESS;
}
