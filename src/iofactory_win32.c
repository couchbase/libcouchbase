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

LIBCOUCHBASE_API
lcb_error_t lcb_create_io_ops(lcb_io_opt_t *io,
                              const struct lcb_create_io_ops_st *options)
{
    lcb_error_t ret = LCB_SUCCESS;
    lcb_io_ops_type_t type = LCB_IO_OPS_DEFAULT;

    if (options != NULL) {
        if (options->version != 0) {
            return LCB_EINVAL;
        }
        type = options->v.v0.type;
    }

    if (type == LCB_IO_OPS_DEFAULT || type == LCB_IO_OPS_WINSOCK) {
        *io = lcb_create_winsock_io_opts();
        if (*io == NULL) {
            return LCB_CLIENT_ENOMEM;
        }
    } else {
        return LCB_NOT_SUPPORTED;
    }

    return LCB_SUCCESS;
}
