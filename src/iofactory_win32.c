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
#include <libcouchbase/winsock.h>

static void set_error(libcouchbase_error_t *error, libcouchbase_error_t code) {
    if (error != NULL) {
        *error = code;
    }
}


LIBCOUCHBASE_API
libcouchbase_io_opt_t* libcouchbase_create_io_ops(libcouchbase_io_ops_type_t type,
                                                  void *cookie,
                                                  libcouchbase_error_t *error)
{
    libcouchbase_io_opt_t *ret = NULL;
    (void)cookie;
    if (type == LIBCOUCHBASE_IO_OPS_DEFAULT || type == LIBCOUCHBASE_IO_OPS_WINSOCK) {
        ret = libcouchbase_create_winsock_io_opts();
        if (ret == NULL) {
            set_error(error, LIBCOUCHBASE_ENOMEM);
        }
    } else {
        set_error(error, LIBCOUCHBASE_NOT_SUPPORTED);
    }

    return ret;
}
