/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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
void libcouchbase_behavior_set_syncmode(libcouchbase_t instance, libcouchbase_syncmode_t syncmode)
{
    instance->syncmode = syncmode;
}

LIBCOUCHBASE_API
libcouchbase_syncmode_t libcouchbase_behavior_get_syncmode(libcouchbase_t instance)
{
    return instance->syncmode;
}

LIBCOUCHBASE_API
void libcouchbase_behavior_set_ipv6(libcouchbase_t instance,
                                    libcouchbase_ipv6_t mode)
{
    instance->ipv6 = mode;
}

LIBCOUCHBASE_API
libcouchbase_ipv6_t libcouchbase_behavior_get_ipv6(libcouchbase_t instance)
{
    return instance->ipv6;
}
