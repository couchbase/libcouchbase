/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016-2021 Couchbase, Inc.
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

#include "query_cache.hh"
#include "n1ql-internal.h"

lcb_QUERY_CACHE *lcb_n1qlcache_create(void)
{
    return new lcb_QUERY_CACHE{};
}

void lcb_n1qlcache_destroy(lcb_QUERY_CACHE *cache)
{
    delete cache;
}

void lcb_n1qlcache_clear(lcb_QUERY_CACHE *cache)
{
    cache->clear();
}
