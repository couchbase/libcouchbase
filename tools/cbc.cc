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
#include <map>
#include <iostream>
#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdlib>
#include <libcouchbase/couchbase.h>
#include "internal.h"
#include "configuration.h"
#include "commandlineparser.h"

#ifdef HAVE_LIBYAJL2
#include <yajl/yajl_version.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_tree.h>
#endif

using namespace std;

enum cbc_command_t {
    cbc_illegal,
    cbc_cat,
    cbc_cp,
    cbc_create,
    cbc_flush,
    cbc_lock,
    cbc_receive,
    cbc_rm,
    cbc_send,
    cbc_stats,
    cbc_unlock,
    cbc_verify,
    cbc_version,
    cbc_hash,
    cbc_help,
    cbc_view,
    cbc_admin,
    cbc_bucket_create,
    cbc_bucket_delete,
    cbc_observe
};

struct cp_params {
    list<string> *keys;
    map<string, vector<libcouchbase_cas_t> > results;
    libcouchbase_size_t sent;
    bool need_persisted;
    int need_replicated;
    int total_persisted;
    int total_replicated;
    int max_tries;
    int tries;
    libcouchbase_uint32_t timeout;
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

    void observe_timer_callback(libcouchbase_timer_t timer,
                                libcouchbase_t instance,
                                const void *cookie)
    {
        // perform observe query
        struct cp_params *params = (struct cp_params *)cookie;
        int idx = 0;
        libcouchbase_error_t err;
        const char* *k = new const char*[params->keys->size()];
        libcouchbase_size_t *s = new libcouchbase_size_t[params->keys->size()];

        for (list<string>::iterator iter = params->keys->begin();
                iter != params->keys->end(); ++iter, ++idx) {
            k[idx] = iter->c_str();
            s[idx] = iter->length();
        }
        err = libcouchbase_observe(instance, static_cast<const void *>(params), idx, (const void * const *)k, s);
        if (err != LIBCOUCHBASE_SUCCESS) {
            // report the issue and exit
            error_callback(instance, err, "Failed to schedule observe query");
        }
        delete []k;
        delete []s;
        (void)timer;
    }

    void schedule_observe(libcouchbase_t instance, struct cp_params *params)
    {
        libcouchbase_error_t err;
        if (params->tries > params->max_tries) {
            error_callback(instance, LIBCOUCHBASE_ETIMEDOUT, "Exceeded number of tries");
        }
        libcouchbase_timer_create(instance, params, params->timeout, 0,
                                  observe_timer_callback, &err);
        if (err != LIBCOUCHBASE_SUCCESS) {
            // report the issue and exit
            error_callback(instance, err, "Failed to setup timer for observe");
        }
        params->timeout *= 2;
        params->tries++;
        params->total_persisted = params->total_replicated = 0;
    }

    static void storage_callback(libcouchbase_t instance,
                                 const void *cookie,
                                 libcouchbase_storage_t,
                                 libcouchbase_error_t error,
                                 const void *key, libcouchbase_size_t nkey,
                                 libcouchbase_cas_t cas)
    {
        struct cp_params *params = static_cast<struct cp_params *>(const_cast<void *>(cookie));
        if (params->need_persisted || params->need_replicated > 0) {
            params->sent++;
            // if it is the latest key in the series
            if (params->sent == params->keys->size()) {
                schedule_observe(instance, params);
            }
        } else {
            if (error == LIBCOUCHBASE_SUCCESS) {
                cerr << "Stored \"";
                cerr.write(static_cast<const char *>(key), nkey);
                cerr << "\" CAS:" << hex << cas << endl;
            } else {
                cerr << "Failed to store \"";
                cerr.write(static_cast<const char *>(key), nkey);
                cerr << "\":" << endl
                     << libcouchbase_strerror(instance, error) << endl;

                void *instance_cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
                bool *e = static_cast<bool *>(instance_cookie);
                *e = true;
            }
        }
    }

    static void remove_callback(libcouchbase_t instance,
                                const void *,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "Removed \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\"" << endl;
        } else {
            cerr << "Failed to remove \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\":" << endl
                 << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void unlock_callback(libcouchbase_t instance,
                                const void *,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "Unlocked \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\"" << endl;
        } else {
            cerr << "Failed to unlock \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\":" << endl
                 << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void get_callback(libcouchbase_t instance,
                             const void *,
                             libcouchbase_error_t error,
                             const void *key, libcouchbase_size_t nkey,
                             const void *bytes, libcouchbase_size_t nbytes,
                             libcouchbase_uint32_t flags, libcouchbase_cas_t cas)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "\"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\" Size:" << nbytes << " Flags:" << std::hex
                 << flags << " CAS:" << cas << endl;
            cerr.flush();
            cout.write(static_cast<const char *>(bytes), nbytes);
            cout.flush();
        } else {
            cerr << "Failed to get \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\": " << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void verify_callback(libcouchbase_t instance,
                                const void *,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey,
                                const void *bytes, libcouchbase_size_t nbytes,
                                libcouchbase_uint32_t, libcouchbase_cas_t)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            char fnm[FILENAME_MAX];
            memcpy(fnm, key, nkey);
            fnm[nkey] = '\0';
            struct stat st;
            if (stat(fnm, &st) == -1) {
                cerr << "Failed to look up: \"" << fnm << "\"" << endl;
            } else if ((libcouchbase_size_t)st.st_size != nbytes) {
                cerr << "Incorrect size for: \"" << fnm << "\"" << endl;
            } else {
                char *dta = new char[(libcouchbase_size_t)st.st_size];
                if (dta == NULL) {
                    cerr << "Failed to allocate memory to compare: \""
                         << fnm << "\"" << endl;
                } else {
                    ifstream file(fnm, ios::binary);
                    if (file.good() && file.read(dta, st.st_size) && file.good()) {
                        if (memcmp(dta, bytes, nbytes) != 0) {
                            cerr << "Content differ: \"" << fnm << "\"" << endl;
                        }
                    } else {
                        cerr << "Failed to read \""  << fnm << "\"" << endl;
                    }
                    delete []dta;
                }
            }
        } else {
            cerr << "Failed to get \"";
            cerr.write(static_cast<const char *>(key), nkey);
            cerr << "\": " << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void stat_callback(libcouchbase_t instance,
                              const void *,
                              const char *server_endpoint,
                              libcouchbase_error_t error,
                              const void *key,
                              libcouchbase_size_t nkey,
                              const void *value,
                              libcouchbase_size_t nvalue)
    {
        if (error == LIBCOUCHBASE_SUCCESS) {
            if (nkey > 0) {
                cout << server_endpoint << "\t";
                cout.write(static_cast<const char *>(key), nkey);
                cout << "\t";
                cout.write(static_cast<const char *>(value), nvalue);
                cout << endl;
            }
        } else {
            cerr << "Failure requesting stats:" << endl
                 << libcouchbase_strerror(instance, error) << endl;

            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void flush_callback(libcouchbase_t instance,
                               const void *,
                               const char *server_endpoint,
                               libcouchbase_error_t error)
    {
        if (error != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to flush node \"" << server_endpoint
                 << "\": " << libcouchbase_strerror(instance, error)
                 << endl;
            void *cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool *>(cookie);
            *err = true;
        }
    }

    static void timings_callback(libcouchbase_t, const void *,
                                 libcouchbase_timeunit_t timeunit,
                                 libcouchbase_uint32_t min, libcouchbase_uint32_t max,
                                 libcouchbase_uint32_t total, libcouchbase_uint32_t maxtotal)
    {
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

    static void data_callback(libcouchbase_http_request_t, libcouchbase_t,
                              const void *, libcouchbase_error_t,
                              libcouchbase_http_status_t,
                              const char *, libcouchbase_size_t,
                              const void *bytes, libcouchbase_size_t nbytes)
    {
        cout.write(static_cast<const char *>(bytes), nbytes);
        cout.flush();
    }

    static void complete_callback(libcouchbase_http_request_t,
                                  libcouchbase_t instance,
                                  const void *,
                                  libcouchbase_error_t error,
                                  libcouchbase_http_status_t status,
                                  const char *path, libcouchbase_size_t npath,
                                  const void *bytes, libcouchbase_size_t nbytes)
    {
        cerr << "\"";
        cerr.write(static_cast<const char *>(path), npath);
        cerr << "\": ";
        if (error == LIBCOUCHBASE_SUCCESS) {
            cerr << "OK Size:" << nbytes << endl;
            cout.write(static_cast<const char *>(bytes), nbytes);
        } else {
            cerr << "FAIL(" << error << ") "
                 << libcouchbase_strerror(instance, error)
                 << " Status:" << status
                 << " Size:" << nbytes << endl;
            cout.write(static_cast<const char *>(bytes), nbytes);
        }
        cout.flush();
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
        void *instance_cookie = const_cast<void *>(libcouchbase_get_cookie(instance));
        bool *err = static_cast<bool *>(instance_cookie);

        if (cookie) {
            struct cp_params *params = (struct cp_params *)cookie;
            if (key) {
                string key_str = string(static_cast<const char *>(key), nkey);
                vector<libcouchbase_cas_t> &res = params->results[key_str];
                if (res.size() == 0) {
                    res.resize(1);
                }
                if (status == LIBCOUCHBASE_OBSERVE_PERSISTED) {
                    if (is_master) {
                        params->total_persisted++;
                        res[0] = cas;
                    } else {
                        params->total_replicated++;
                        res.push_back(cas);
                    }
                } else {
                    cas = 0;
                }
            } else {
                // check persistence conditions
                int nkeys = params->keys->size();
                bool ok = true;

                if (params->need_persisted) {
                    ok &= params->total_persisted == nkeys;
                }
                if (params->need_replicated > 0) {
                    ok &= params->total_replicated == (nkeys * params->need_replicated);
                }
                if (ok) {
                    map<string, libcouchbase_cas_t> done;
                    for (list<string>::iterator ii = params->keys->begin();
                            ii != params->keys->end(); ++ii) {
                        string kk = *ii;
                        vector<libcouchbase_cas_t> &res = params->results[kk];
                        libcouchbase_cas_t cc = res[0];
                        if (cc == 0) {
                            // the key wasn't persisted on master, but
                            // replicas might have old version persisted
                            schedule_observe(instance, params);
                            return;
                        } else {
                            if (params->need_replicated > 0) {
                                int matching_cas = 0;
                                for (vector<libcouchbase_cas_t>::iterator jj = res.begin() + 1;
                                        jj != res.end(); ++jj) {
                                    if (*jj == cc) {
                                        matching_cas++;
                                    }
                                }
                                if (matching_cas != params->need_replicated) {
                                    // some replicas has old value => retry
                                    schedule_observe(instance, params);
                                    return;
                                }
                            }
                            done[kk] = cc;
                        }
                    }
                    // all or nothing
                    if (done.size() == params->keys->size()) {
                        for (map<string, libcouchbase_cas_t>::iterator ii = done.begin();
                                ii != done.end(); ++ii) {
                            cerr << "Stored \"" << ii->first << "\" CAS:" << hex << ii->second << endl;
                        }
                    } else {
                        schedule_observe(instance, params);
                    }
                } else {
                    schedule_observe(instance, params);
                }
            }
        } else {
            if (key == NULL) {
                return; /* end of packet */
            }
            if (error == LIBCOUCHBASE_SUCCESS) {
                switch (status) {
                case LIBCOUCHBASE_OBSERVE_FOUND:
                    cerr << "FOUND";
                    break;
                case LIBCOUCHBASE_OBSERVE_PERSISTED:
                    cerr << "PERSISTED";
                    break;
                case LIBCOUCHBASE_OBSERVE_NOT_FOUND:
                    cerr << "NOT_FOUND";
                    break;
                default:
                    cerr << "UNKNOWN";
                    break;
                }
                cerr << " \"";
                cerr.write(static_cast<const char *>(key), nkey);
                if (status == LIBCOUCHBASE_OBSERVE_FOUND ||
                        status == LIBCOUCHBASE_OBSERVE_PERSISTED) {
                    cerr << "\" CAS:" << std::hex << cas;
                }
                cerr << " IsMaster:" << std::boolalpha << (bool)is_master
                     << std::dec << " TimeToPersist:" << ttp
                     << " TimeToReplicate:" << ttr << endl;
            } else {
                cerr << "Failed to observe: " << libcouchbase_strerror(instance, error) << endl;
                *err = true;
            }
        }
    }
}

static bool cp_impl(libcouchbase_t instance, list<string> &keys, bool json, bool persisted, int replicated, int max_tries)
{
    libcouchbase_size_t currsz = 0;
    struct cp_params *cookie = new struct cp_params();

    cookie->results = map<string, vector<libcouchbase_cas_t> >();
    cookie->keys = &keys;
    cookie->need_persisted = persisted;
    cookie->need_replicated = replicated;
    cookie->max_tries = max_tries;
    cookie->timeout = 100000; // initial timeout: 100ms
    cookie->total_persisted = cookie->total_replicated = cookie->tries = 0;

    for (list<string>::iterator ii = keys.begin(); ii != keys.end(); ++ii) {
        string key = *ii;
        struct stat st;
        if (stat(key.c_str(), &st) == 0) {
            char *bytes = new char[(libcouchbase_size_t)st.st_size + 1];
            if (bytes != NULL) {
                ifstream file(key.c_str(), ios::binary);
                if (file.good() && file.read(bytes, st.st_size) && file.good()) {
                    bytes[st.st_size] = '\0';
#ifdef HAVE_LIBYAJL2
                    if (json) {
                        yajl_val obj, id;
                        const char *path[] = {"_id", NULL};
                        if ((obj = yajl_tree_parse(bytes, NULL, 0)) == NULL) {
                            cerr << "Failed to parse file \"" << key << "\" as JSON." << endl;
                            delete []bytes;
                            return false;
                        }
                        id = yajl_tree_get(obj, path, yajl_t_string);
                        if (id == NULL) {
                            cerr << "Failed to validate file \"" << key
                                 << "\" as document (no '_id' attribute)." << endl;
                            delete []bytes;
                            return false;
                        }
                        key.assign(id->u.string);
                        yajl_tree_free(obj);
                    }
#else
                    (void)json;
#endif
                    libcouchbase_store(instance,
                                       static_cast<void *>(cookie),
                                       LIBCOUCHBASE_SET,
                                       key.c_str(), key.length(),
                                       bytes, (libcouchbase_size_t)st.st_size,
                                       0, 0, 0);
                    delete []bytes;
                    currsz += (libcouchbase_size_t)st.st_size;

                    // To avoid too much buffering flush at a regular
                    // interval
                    if (currsz > (2 * 1024 * 1024)) {
                        libcouchbase_wait(instance);
                        currsz = 0;
                    }
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

static bool rm_impl(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to delete" << endl;
        return false;
    }

    for (list<string>::iterator ii = keys.begin(); ii != keys.end(); ++ii) {
        string key = *ii;
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

static bool cat_impl(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to get" << endl;
        return false;
    }

    const char* *k = new const char*[keys.size()];
    libcouchbase_size_t *s = new libcouchbase_size_t[keys.size()];

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

static bool observe_impl(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to observe" << endl;
        return false;
    }

    const char* *k = new const char*[keys.size()];
    libcouchbase_size_t *s = new libcouchbase_size_t[keys.size()];

    int idx = 0;
    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter, ++idx) {
        k[idx] = iter->c_str();
        s[idx] = iter->length();
    }

    libcouchbase_error_t err = libcouchbase_observe(instance, NULL, idx,
                                                    (const void * const *)k, s);

    delete []k;
    delete []s;

    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to send requests:" << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
    }

    return true;
}

static bool hash_impl(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to hash" << endl;
        return false;
    }

    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter) {
        int vbucket_id, idx;
        (void)vbucket_map(instance->vbucket_config, iter->c_str(), iter->length(), &vbucket_id, &idx);
        libcouchbase_server_t *server = instance->servers + idx;
        cout << "\"" << *iter << "\"\t" << "vBucket:" << vbucket_id
             << " Server:\"" << server->authority << "\"";
        if (server->couch_api_base) {
            cout << " CouchAPI:\"" << server->couch_api_base << "\"";
        }
        libcouchbase_size_t nrepl = (libcouchbase_size_t)vbucket_config_get_num_replicas(instance->vbucket_config);
        if (nrepl > 0) {
            cout << " Replicas:";
            for (libcouchbase_size_t ii = 0; ii < nrepl; ++ii) {
                cout << "\"" << instance->servers[ii].authority << "\"";
                if (ii != nrepl - 1) {
                    cout << ",";
                }
            }
        }
        cout << endl;
    }

    return true;
}

static bool view_impl(libcouchbase_t instance, string &query, string &data,
                      bool chunked, libcouchbase_http_method_t method)
{
    libcouchbase_error_t rc;

    libcouchbase_make_couch_request(instance, NULL, query.c_str(), query.length(),
                                    data.c_str(), data.length(), method, chunked, &rc);
    if (rc != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to send requests:" << endl
             << libcouchbase_strerror(instance, rc) << endl;
        return false;
    }
    return true;
}

static bool admin_impl(libcouchbase_t instance, string &query, string &data,
                       bool chunked, libcouchbase_http_method_t method)
{
    libcouchbase_error_t rc;

    libcouchbase_make_management_request(instance, NULL, query.c_str(), query.length(),
                                         data.c_str(), data.length(), method, chunked, &rc);
    if (rc != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to send requests: " << endl
             << libcouchbase_strerror(instance, rc) << endl;
        return false;
    }
    return true;
}

static bool bucket_delete_impl(libcouchbase_t instance, list<string> &names)
{
    libcouchbase_error_t rc;

    for (list<string>::iterator iter = names.begin(); iter != names.end(); ++iter) {
        string query = "/pools/default/buckets/" + *iter;
        libcouchbase_make_management_request(instance, NULL, query.c_str(), query.length(),
                                             NULL, 0, LIBCOUCHBASE_HTTP_METHOD_DELETE,
                                             false, &rc);
        if (rc != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to send requests: " << endl
                 << libcouchbase_strerror(instance, rc) << endl;
            return false;
        }
    }
    return true;
}

static bool bucket_create_impl(libcouchbase_t instance, list<string> &names,
                               string &bucket_type, string &auth_type, int ram_quota,
                               string &sasl_password, int replica_num, int proxy_port)
{
    libcouchbase_error_t rc;
    const char query[] = "/pools/default/buckets";

    if (names.empty()) {
        cerr << "ERROR: you need to specify at least on bucket name" << endl;
        return false;
    }
    for (list<string>::iterator iter = names.begin(); iter != names.end(); ++iter) {
        stringstream data;
        data << "name=" << *iter
             << "&bucketType=" << bucket_type
             << "&ramQuotaMB=" << ram_quota
             << "&replicaNumber=" << replica_num
             << "&authType=" << auth_type
             << "&saslPassword=" << sasl_password;
        if (proxy_port > 0) {
            data << "&proxyPort=" << proxy_port;
        }
        libcouchbase_make_management_request(instance, NULL, query, sizeof(query) - 1,
                                             data.str().c_str(), data.str().length(),
                                             LIBCOUCHBASE_HTTP_METHOD_POST, false, &rc);
        if (rc != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to send requests: " << endl
                 << libcouchbase_strerror(instance, rc) << endl;
            return false;
        }
    }
    return true;
}

static bool lock_impl(libcouchbase_t instance, list<string> &keys, libcouchbase_time_t exptime)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to lock" << endl;
        return false;
    }

    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter) {
        libcouchbase_error_t err = libcouchbase_getl(instance, NULL,
                                                     (const void *)iter->c_str(),
                                                     (libcouchbase_size_t)iter->length(),
                                                     &exptime);

        if (err != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to send requests:" << endl
                 << libcouchbase_strerror(instance, err) << endl;
            return false;
        }

    }
    return true;
}

static bool unlock_impl(libcouchbase_t instance, list<string> &keys)
{
    if (keys.empty()) {
        cerr << "ERROR: you need to specify the key to unlock" << endl;
        return false;
    }

    if (keys.size() % 2 != 0) {
        cerr << "ERROR: you need to specify key-cas pairs, "
             << "therefore argument list should be odd" << endl;
        return false;
    }

    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter) {
        libcouchbase_cas_t cas;
        string key = *iter;
        stringstream ss(*(++iter));
        ss >> hex >> cas;
        libcouchbase_error_t err = libcouchbase_unlock(instance, NULL,
                                                       (const void *)key.c_str(),
                                                       (libcouchbase_size_t)key.length(), cas);

        if (err != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to send requests:" << endl
                 << libcouchbase_strerror(instance, err) << endl;
            return false;
        }

    }
    return true;
}

static bool stats_impl(libcouchbase_t instance, list<string> &keys)
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
            string key = *ii;
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

static bool flush_impl(libcouchbase_t instance, list<string> &keys)
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

static bool spool(string &data)
{
    stringstream ss;
    char buffer[1024];
    libcouchbase_size_t nr;
    while ((nr = fread(buffer, 1, sizeof(buffer), stdin)) != (libcouchbase_size_t) - 1) {
        if (nr == 0) {
            break;
        }
        ss.write(buffer, nr);
    }
    data.assign(ss.str());
    return nr == 0 || feof(stdin) != 0;
}

static bool create_impl(libcouchbase_t instance, list<string> &keys,
                        libcouchbase_uint32_t exptime, libcouchbase_uint32_t flags, bool add)
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

static bool verify_impl(libcouchbase_t instance, list<string> &keys)
{
    (void)libcouchbase_set_get_callback(instance, verify_callback);
    return cat_impl(instance, keys);
}

static void loadKeys(list<string> &keys)
{
    char buffer[1024];
    while (fgets(buffer, (int)sizeof(buffer), stdin) != NULL) {
        libcouchbase_size_t idx = strlen(buffer);
        while (idx > 0 && isspace(buffer[idx - 1])) {
            --idx;
        }
        buffer[idx] = '\0';
        keys.push_back(buffer);
    }
}

static bool isValidBucketName(const char *n)
{
    bool rv = strlen(n) > 0;
    for (; *n; n++) {
        rv &= isalpha(*n) || isdigit(*n) || *n == '.' || *n == '%' || *n == '_' || *n == '-';
    }
    return rv;
}

static bool verifyBucketNames(list<string> &names)
{
    for (list<string>::iterator ii = names.begin(); ii != names.end(); ++ii) {
        if (!isValidBucketName(ii->c_str())) {
            return false;
        }
    }
    return true;
}

extern bool receive_impl(libcouchbase_t instance, list<string> &keys);
extern bool send_impl(libcouchbase_t instance, list<string> &keys);

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
    getopt.addOption(new CommandLineOption('t', "timeout", true,
                                           "Specify timeout value"));

    libcouchbase_uint32_t flags = 0;
    libcouchbase_uint32_t exptime = 0;
    bool add = false;
    if (cmd == cbc_create) {
        getopt.addOption(new CommandLineOption('f', "flag", true,
                                               "Flag for the new object"));
        getopt.addOption(new CommandLineOption('e', "exptime", true,
                                               "Expiry time for the new object"));
        getopt.addOption(new CommandLineOption('a', "add", false,
                                               "Fail if the object exists"));
    }

    if (cmd == cbc_lock) {
        getopt.addOption(new CommandLineOption('e', "exptime", true,
                                               "Expiry time for the lock"));
    }

    bool json = false;
    bool persisted = false;
    int replicated = 0;
    int max_tries = 5;
    if (cmd == cbc_cp) {
        getopt.addOption(new CommandLineOption('p', "persisted", false,
                                               "Ensure that key has been persisted to master node"));
        getopt.addOption(new CommandLineOption('r', "replicated", true,
                                               "Ensure that key has been replicated and persisted to given number of replicas"));
        getopt.addOption(new CommandLineOption('m', "max-tries", true,
                                               "The number of attempts for observing keys (default: 5)"));
#ifdef HAVE_LIBYAJL2
        getopt.addOption(new CommandLineOption('j', "json", false,
                                               "Treat value as JSON document (take key from '_id' attribute)"));
#endif
    }

    bool chunked = false;
    string data;
    libcouchbase_http_method_t method = LIBCOUCHBASE_HTTP_METHOD_GET;
    if (cmd == cbc_view || cmd == cbc_admin) {
        getopt.addOption(new CommandLineOption('c', "chunked", false,
                                               "Use chunked callback to stream the data"));
        getopt.addOption(new CommandLineOption('d', "data", true,
                                               "HTTP body data for POST or PUT requests, e.g. {\"keys\": [\"key1\", \"key2\", ...]}"));
        getopt.addOption(new CommandLineOption('X', "request", true,
                                               "HTTP request method, possible values GET, POST, PUT, DELETE (default GET)"));
    }
    string bucket_type = "membase";
    string auth_type = "sasl";
    int ram_quota = 100;
    string sasl_password;
    int replica_num = 1;
    int proxy_port = 0;
    if (cmd == cbc_bucket_create) {
        getopt.addOption(new CommandLineOption('B', "bucket-type", true,
                                               "Bucket type, possible values are: membase (with alias couchbase), memcached) (default: membase)"));
        getopt.addOption(new CommandLineOption('q', "ram-quota", true,
                                               "RAM quota in megabytes (default: 100)"));
        getopt.addOption(new CommandLineOption('a', "auth-type", true,
                                               "Type of bucket authentication, possible values are: none, sasl (default: sasl)."
                                               " Note you should specify free port for 'none'"));
        getopt.addOption(new CommandLineOption('s', "sasl-passord", true,
                                               "Password for SASL (default: '')"));
        getopt.addOption(new CommandLineOption('r', "replica-number", true,
                                               "Number of the nodes each key should be replicated, allowed values 0-3 (default 1)"));
        getopt.addOption(new CommandLineOption('p', "proxy-port", true,
                                               "Proxy port (default 11211)"));
    }
    if (!getopt.parse(argc, argv)) {
        getopt.usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    vector<CommandLineOption *>::iterator iter;
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

            case 't' :
                config.setTimeout((*iter)->argument);
                break;

            case 'T' :
                config.setTimingsEnabled(true);
                break;

            case '?':
                getopt.usage(argv[0]);
                exit(EXIT_SUCCESS);
                // NOTREACHED

            default:
                if (cmd == cbc_create) {
                    unknownOpt = false;
                    switch ((*iter)->shortopt) {
                    case 'f':
                        flags = (libcouchbase_uint32_t)atoi((*iter)->argument);
                        break;
                    case 'e':
                        flags = (libcouchbase_uint32_t)atoi((*iter)->argument);
                        break;
                    case 'a':
                        add = true;
                        break;
                    default:
                        unknownOpt = true;
                    }
                } else if (cmd == cbc_cp) {
                    unknownOpt = false;
                    switch ((*iter)->shortopt) {
                    case 'p':
                        persisted = true;
                        break;
                    case 'r':
                        replicated = atoi((*iter)->argument);
                        break;
                    case 'm':
                        max_tries = atoi((*iter)->argument);
                        break;
#ifdef HAVE_LIBYAJL2
                    case 'j':
                        json = true;
                        break;
#endif
                    default:
                        unknownOpt = true;
                    }
                } else if (cmd == cbc_lock) {
                    unknownOpt = false;
                    switch ((*iter)->shortopt) {
                    case 'e':
                        flags = (libcouchbase_uint32_t)atoi((*iter)->argument);
                        break;
                    default:
                        unknownOpt = true;
                    }
                } else if (cmd == cbc_view || cmd == cbc_admin) {
                    unknownOpt = false;
                    string arg = (*iter)->argument;
                    switch ((*iter)->shortopt) {
                    case 'c':
                        chunked = true;
                        break;
                    case 'd':
                        data = (*iter)->argument;
                        break;
                    case 'X':
                        if (arg == "GET") {
                            method = LIBCOUCHBASE_HTTP_METHOD_GET;
                        } else if (arg == "POST") {
                            method = LIBCOUCHBASE_HTTP_METHOD_POST;
                        } else if (arg == "PUT") {
                            method = LIBCOUCHBASE_HTTP_METHOD_PUT;
                        } else if (arg == "DELETE") {
                            method = LIBCOUCHBASE_HTTP_METHOD_DELETE;
                        } else {
                            unknownOpt = true;
                            cerr << "Usupported HTTP method: " << arg << endl;
                        }
                        break;
                    default:
                        unknownOpt = true;
                    }
                } else if (cmd == cbc_bucket_create) {
                    string arg = (*iter)->argument;
                    switch ((*iter)->shortopt) {
                    case 'B':
                        if (arg == "couchbase") {
                            bucket_type = "membase";
                        } else {
                            bucket_type = arg;
                        }
                        break;
                    case 'q':
                        ram_quota = atoi((*iter)->argument);
                        break;
                    case 'a':
                        auth_type = arg;
                        break;
                    case 's':
                        sasl_password = arg;
                        break;
                    case 'r':
                        replica_num = atoi((*iter)->argument);
                        break;
                    case 'p':
                        proxy_port = atoi((*iter)->argument);
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
    if (instance == NULL) {
        cerr << "Failed to create couchbase instance" << endl;
        exit(EXIT_FAILURE);
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    (void)libcouchbase_set_flush_callback(instance, flush_callback);
    (void)libcouchbase_set_get_callback(instance, get_callback);
    (void)libcouchbase_set_remove_callback(instance, remove_callback);
    (void)libcouchbase_set_stat_callback(instance, stat_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);
    (void)libcouchbase_set_unlock_callback(instance, unlock_callback);
    (void)libcouchbase_set_observe_callback(instance, observe_callback);
    (void)libcouchbase_set_couch_data_callback(instance, data_callback);
    (void)libcouchbase_set_couch_complete_callback(instance, complete_callback);
    (void)libcouchbase_set_management_data_callback(instance, data_callback);
    (void)libcouchbase_set_management_complete_callback(instance, complete_callback);

    if (config.getTimeout() != 0) {
        libcouchbase_set_timeout(instance, config.getTimeout());
    }

    libcouchbase_error_t ret = libcouchbase_connect(instance);
    if (ret != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to connect libcouchbase instance to server:" << endl
             << "\t\"" << libcouchbase_strerror(instance, ret) << "\"" << endl;
        exit(EXIT_FAILURE);
    }
    libcouchbase_wait(instance);

    bool error = false;
    libcouchbase_set_cookie(instance, static_cast<void *>(&error));

    if (config.isTimingsEnabled()) {
        libcouchbase_enable_timings(instance);
    }

    list<string> keys;

    bool success = false;
    switch (cmd) {
    case cbc_cat:
        success = cat_impl(instance, getopt.arguments);
        break;
    case cbc_lock:
        success = lock_impl(instance, getopt.arguments, exptime);
        break;
    case cbc_unlock:
        success = unlock_impl(instance, getopt.arguments);
        break;
    case cbc_cp:
        if (replicated < 0) {
            cerr << "Number of replicas must be positive integer" << endl;
            success = false;
            break;
        }
        if (getopt.arguments.size() == 1 && getopt.arguments.front() == "-") {
            loadKeys(keys);
            success = cp_impl(instance, keys, json, persisted, replicated, max_tries);
        } else {
            success = cp_impl(instance, getopt.arguments, json, persisted, replicated, max_tries);
        }
        break;
    case cbc_rm:
        success = rm_impl(instance, getopt.arguments);
        break;
    case cbc_receive:
        success = receive_impl(instance, getopt.arguments);
        break;
    case cbc_stats:
        success = stats_impl(instance, getopt.arguments);
        break;
    case cbc_send:
        success = send_impl(instance, getopt.arguments);
        break;
    case cbc_flush:
        success = flush_impl(instance, getopt.arguments);
        break;
    case cbc_create:
        success = create_impl(instance, getopt.arguments, exptime, flags, add);
        break;
    case cbc_verify:
        if (getopt.arguments.size() == 1 && getopt.arguments.front() == "-") {
            loadKeys(keys);
            success = verify_impl(instance, keys);
        } else {
            success = verify_impl(instance, getopt.arguments);
        }
        break;
    case cbc_hash:
        success = hash_impl(instance, getopt.arguments);
        break;
    case cbc_view:
    case cbc_admin:
        switch (getopt.arguments.size()) {
        case 1:
            if (cmd == cbc_view) {
                success = view_impl(instance, getopt.arguments.front(), data, chunked, method);
            } else {
                success = admin_impl(instance, getopt.arguments.front(), data, chunked, method);
            }
            break;
        case 0:
            cerr << "Missing endpoint" << endl;
            break;
        default:
            cerr << "There must be only one endpoint specified" << endl;
        }
        break;
    case cbc_bucket_create:
        if (verifyBucketNames(getopt.arguments)) {
            success = bucket_create_impl(instance, getopt.arguments,
                                         bucket_type, auth_type, ram_quota,
                                         sasl_password, replica_num, proxy_port);
        } else {
            cerr << "Bucket name can only contain characters in range A-Z, "
                 "a-z, 0-9 as well as underscore, period, dash & percent" << endl;
        }
        break;
    case cbc_bucket_delete:
        if (verifyBucketNames(getopt.arguments)) {
            success = bucket_delete_impl(instance, getopt.arguments);
        } else {
            cerr << "Bucket name can only contain characters in range A-Z, "
                 "a-z, 0-9 as well as underscore, period, dash & percent" << endl;
        }
        break;
    case cbc_observe:
        success = observe_impl(instance, getopt.arguments);
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
    libcouchbase_ssize_t len = str.length();
    stringstream ss;
    for (libcouchbase_ssize_t ii = 0; ii < len; ++ii) {
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
    } else if (name.find("cbc-lock") != string::npos) {
        return cbc_lock;
    } else if (name.find("cbc-unlock") != string::npos) {
        return cbc_unlock;
    } else if (name.find("cbc-version") != string::npos) {
        return cbc_version;
    } else if (name.find("cbc-verify") != string::npos) {
        return cbc_verify;
    } else if (name.find("cbc-hash") != string::npos) {
        return cbc_hash;
    } else if (name.find("cbc-help") != string::npos) {
        return cbc_help;
    } else if (name.find("cbc-view") != string::npos) {
        return cbc_view;
    } else if (name.find("cbc-admin") != string::npos) {
        return cbc_admin;
    } else if (name.find("cbc-bucket-create") != string::npos) {
        return cbc_bucket_create;
    } else if (name.find("cbc-bucket-delete") != string::npos) {
        return cbc_bucket_delete;
    } else if (name.find("cbc-observe") != string::npos) {
        return cbc_observe;
    }

    return cbc_illegal;
}

static void printHelp()
{
    cerr << "Usage: cbc command [options]" << endl
         << "command may be:" << endl
         << "   help            show this help or for given command" << endl
         << "   cat             output keys to stdout" << endl
         << "   cp              store files to the cluster" << endl
         << "   create          store files with options" << endl
         << "   observe         observe key state" << endl
         << "   flush           remove all keys from the cluster" << endl
         << "   hash            hash key(s) and print out useful info" << endl
         << "   lock            lock keys" << endl
         << "   unlock          unlock keys" << endl
         << "   rm              remove keys" << endl
         << "   stats           show stats" << endl
         << "   verify          verify content in cache with files" << endl
         << "   version         show version" << endl
         << "   view            execute couchbase view (aka map/reduce) request" << endl
         << "   admin           execute request to management REST API" << endl
         << "   bucket-create   create data bucket on the cluster" << endl
         << "   bucket-delete   delete data bucket" << endl
         << "Use 'cbc command --help' to show the options" << endl;
}

/**
 * Program entry point
 * @param argc argument count
 * @param argv argument vector
 * @return 0 success, 1 failure
 */
int main(int argc, char **argv)
{
    string cmdstr(argv[0]);
    cbc_command_t cmd = getBuiltin(cmdstr);

    if (cmd == cbc_illegal) {
        if (argc > 1) {
            cmdstr.assign("cbc-");
            cmdstr.append(argv[1]);
            cmd = getBuiltin(cmdstr);
        }
        if (cmd == cbc_illegal) {
            if (cmdstr != argv[0]) {
                cerr << "Error: Unknown command \"" << cmdstr << "\"" << endl;
            }
            printHelp();
            exit(EXIT_FAILURE);
        }
        --argc;
        ++argv;
    }

    if (cmd == cbc_help) {
        if (argc > 1) {
            cmdstr.assign("cbc-");
            cmdstr.append(argv[1]);
            cmd = getBuiltin(cmdstr);
            if (cmd == cbc_illegal) {
                cerr << "Error: Unknown command \"" << cmdstr << "\"" << endl;
                printHelp();
                exit(EXIT_FAILURE);
            } else {
                const char *help_argv[] = {argv[1], "-?", NULL};
                handleCommandLineOptions(cmd, 2, (char **)help_argv);
            }
        } else {
            printHelp();
        }
    } else if (cmd == cbc_version) {
        cout << "cbc built from: " << PACKAGE_STRING << endl
             << "    using libcouchbase: " << libcouchbase_get_version(NULL)
             << endl;
#ifdef HAVE_LIBYAJL2
        int version = yajl_version();
        cout << "    using libyajl: "
             << version / 10000 << "."
             << (version / 100) % 100 << "."
             << version % 100 << endl;
#endif
    } else {
        handleCommandLineOptions(cmd, argc, argv);
    }

    return EXIT_SUCCESS;
}
