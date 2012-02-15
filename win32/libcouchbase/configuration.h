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
 * Settings detected at "configure" time that the source needs to be
 * aware of (on the client installation).
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_CONFIGURATION_H
#define LIBCOUCHBASE_CONFIGURATION_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define LIBCOUCHBASE_VERSION_STRING "1.0.1"
#define LIBCOUCHBASE_VERSION 0x010001
#define LIBCOUCHBASE_VERSION_CHANGESET unknown

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define PACKAGE_STRING "libcouchbase 1.0.1"
    typedef __int64 libcouchbase_int64_t;
    typedef unsigned long libcouchbase_size_t;
    typedef long libcouchbase_ssize_t;
    typedef unsigned __int8 libcouchbase_uint8_t;
    typedef unsigned __int16 libcouchbase_vbucket_t;
    typedef unsigned __int16 libcouchbase_uint16_t;
    typedef unsigned __int32 libcouchbase_uint32_t;
    typedef unsigned __int64 libcouchbase_cas_t;
    typedef unsigned __int64 libcouchbase_uint64_t;
    typedef time_t libcouchbase_time_t;
#else
    typedef int64_t libcouchbase_int64_t;
    typedef size_t libcouchbase_size_t;
    typedef ssize_t libcouchbase_ssize_t;
    typedef uint16_t libcouchbase_vbucket_t;
    typedef uint8_t libcouchbase_uint8_t;
    typedef uint16_t libcouchbase_uint16_t;
    typedef uint32_t libcouchbase_uint32_t;
    typedef uint64_t libcouchbase_cas_t;
    typedef uint64_t libcouchbase_uint64_t;
    typedef time_t libcouchbase_time_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
