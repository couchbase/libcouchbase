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

/**
 * This file contains the implementation of the method(s) needed to
 * convert an error constant to a textual representation.
 *
 * @author Trond Norbye
 * @todo Localize the function..
 */

#include "internal.h"

LIBCOUCHBASE_API
const char *libcouchbase_strerror(libcouchbase_t instance,
                                  libcouchbase_error_t error) {
    (void)instance;
    switch (error) {
    case LIBCOUCHBASE_SUCCESS:
        return "Success";
    case LIBCOUCHBASE_KEY_ENOENT:
        return "No such key";
    case LIBCOUCHBASE_E2BIG:
        return "Object too big";
    case LIBCOUCHBASE_ENOMEM:
        return "Out of memory";
    case LIBCOUCHBASE_KEY_EEXISTS:
        return "Key exists (with a different CAS value)";
    case LIBCOUCHBASE_EINVAL:
        return "Invalid arguments";
    case LIBCOUCHBASE_NOT_STORED:
        return "Not stored";
    case LIBCOUCHBASE_DELTA_BADVAL:
        return "Not a number";
    case LIBCOUCHBASE_NOT_MY_VBUCKET:
        return "The vbucket is not located on this server";
    case LIBCOUCHBASE_AUTH_ERROR:
        return "Authentication error";
    case LIBCOUCHBASE_AUTH_CONTINUE:
        return "Continue authentication";
    case LIBCOUCHBASE_ERANGE:
        return "Invalid range";
    case LIBCOUCHBASE_UNKNOWN_COMMAND:
        return "Unknown command";
    case LIBCOUCHBASE_NOT_SUPPORTED:
        return "Not supported";
    case LIBCOUCHBASE_EINTERNAL:
        return "Internal error";
    case LIBCOUCHBASE_EBUSY:
        return "Too busy. Try again later";
    case LIBCOUCHBASE_ETMPFAIL:
        return "Temporary failure. Try again later";
    case LIBCOUCHBASE_LIBEVENT_ERROR:
        return "Problem using libevent";
    case LIBCOUCHBASE_NETWORK_ERROR:
        return "Network error";
    case LIBCOUCHBASE_UNKNOWN_HOST:
        return "Unknown host";
    case LIBCOUCHBASE_ERROR:
        return "Generic error";
    case LIBCOUCHBASE_PROTOCOL_ERROR:
        return "Protocol error";
    case LIBCOUCHBASE_ETIMEDOUT:
        return "Operation timed out";
    case LIBCOUCHBASE_CONNECT_ERROR:
        return "Connection failure";
    case LIBCOUCHBASE_BUCKET_ENOENT:
        return "No such bucket";
    default:
        return "Unknown error.. are you sure libcouchbase gave you that?";
    }
}
