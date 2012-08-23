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

#include "internal.h"
#include "winsock_io_opts.h"

static void set_error(lcb_error_t *error, lcb_error_t code)
{
    if (error != NULL) {
        *error = code;
    }
}


LIBCOUCHBASE_API
lcb_io_opt_t *lcb_create_io_ops(lcb_io_ops_type_t type,
                                void *cookie,
                                lcb_error_t *error)
{
    lcb_io_opt_t *ret = NULL;
    (void)cookie;
    if (type == LCB_IO_OPS_DEFAULT || type == LCB_IO_OPS_WINSOCK) {
        ret = lcb_create_winsock_io_opts();
        if (ret == NULL) {
            set_error(error, LCB_CLIENT_ENOMEM);
        }
    } else {
        set_error(error, LCB_NOT_SUPPORTED);
    }

    return ret;
}
