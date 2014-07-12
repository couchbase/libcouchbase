/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2012 Couchbase, Inc.
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
#include "internal.h"

LIBCOUCHBASE_API
lcb_error_t lcb_get_last_error(lcb_t instance){return instance->last_error;}

LIBCOUCHBASE_API
const char *lcb_strerror(lcb_t instance, lcb_error_t error)
{
    #define X(c, v, t, s) if (error == c) { return s; }
    LCB_XERR(X)
    #undef X

    (void)instance;
    return "Unknown error";
}


static int errtype_map[] = {
    #define X(c, v, t, s) t,
    LCB_XERR(X)
    #undef X
    -1
};

LIBCOUCHBASE_API
int lcb_get_errtype(lcb_error_t err)
{
    if (err >= LCB_MAX_ERROR_VAL || (int)err < 0) {
        return -1;
    }
    return errtype_map[err];
}
