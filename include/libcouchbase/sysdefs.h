/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2020 Couchbase, Inc.
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
 * Basic platform includes.
 */
#ifndef LCB_SYSDEFS_H
#define LCB_SYSDEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include <stddef.h>
#include <winsock2.h>
#include <basetsd.h>

/* TODO: consider using pstdint.h from http://www.azillionmonkeys.com/qed/pstdint.h */
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

typedef __int64 lcb_int64_t;
typedef __int32 lcb_int32_t;
typedef SIZE_T lcb_size_t;
typedef SSIZE_T lcb_ssize_t;
typedef unsigned __int8 lcb_uint8_t;
typedef unsigned __int16 lcb_vbucket_t;
typedef unsigned __int16 lcb_uint16_t;
typedef unsigned __int32 lcb_uint32_t;
typedef unsigned __int64 lcb_uint64_t;

/** FIXME: This should be a native type, but it's already defined here.. */
typedef unsigned __int32 lcb_time_t;
#else
#include <sys/types.h>
#include <stdint.h>
#include <time.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stddef.h>
#endif

typedef int64_t lcb_int64_t;
typedef int32_t lcb_int32_t;
typedef size_t lcb_size_t;
typedef ssize_t lcb_ssize_t;
typedef uint16_t lcb_vbucket_t;
typedef uint8_t lcb_uint8_t;
typedef uint16_t lcb_uint16_t;
typedef uint32_t lcb_uint32_t;
typedef uint64_t lcb_uint64_t;
typedef time_t lcb_time_t;
#endif

typedef lcb_int64_t lcb_S64;   /**< @brief Signed 64 bit type */
typedef lcb_uint64_t lcb_U64;  /**< @brief Unsigned 64 bit type */
typedef lcb_uint32_t lcb_U32;  /**< @brief Unsigned 32 bit type */
typedef lcb_int32_t lcb_S32;   /**< @brief Signed 32 bit type */
typedef lcb_uint16_t lcb_U16;  /**< @brief Unsigned 16 bit type */
typedef lcb_uint8_t lcb_U8;    /**< @brief unsigned 8 bit type */
typedef lcb_size_t lcb_SIZE;   /**< @brief Unsigned size type */
typedef lcb_ssize_t lcb_SSIZE; /**<@brief Signed size type */
typedef lcb_time_t lcb_SECS;   /**< @brief Unsigned 'seconds time' type */

#ifdef __GNUC__
#define LCB_DEPRECATED(X) X __attribute__((deprecated))
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)
#define LCB_DEPRECATED2(X, reason) X __attribute__((deprecated(reason)))
#else
#define LCB_DEPRECATED2(X, reason) LCB_DEPRECATED(X)
#endif
#elif defined(_MSC_VER)
#define LCB_DEPRECATED(X) __declspec(deprecated) X
#define LCB_DEPRECATED2(X, reason) __declspec(deprecated(reason)) X
#else
#define LCB_DEPRECATED(X) X
#define LCB_DEPRECATED2(X, reason) X
#endif

/**
 * CCBC-1678: Couchbase Server views are deprecated since 7.0+ and slated for
 * removal. Wrap a view-related declaration with this macro to emit a compile
 * time warning at each user call site, without changing the ABI or removing
 * the symbol. The diagnostic message is identical for every view API entry
 * so the deprecation can be located and lifted as a single change later.
 *
 * A translation unit that legitimately implements or exercises the views API
 * (the views implementation files, view-specific tests, examples, and the
 * `cbc` tool) can suppress the diagnostic for itself by defining the macro
 * to `X` *before* including any libcouchbase header, e.g.:
 *
 *     #define LCB_DEPRECATE_VIEWS(X) X
 *     #include <libcouchbase/couchbase.h>
 *
 * The `#ifndef` guard below honours that pre-definition. Note that the scope
 * is the whole translation unit: the deprecation attribute is attached to the
 * declaration, so once the public header has been preprocessed, redefining
 * the macro further down the file has no effect. For sub-file granularity
 * use `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` blocks.
 */
#ifndef LCB_DEPRECATE_VIEWS
#define LCB_DEPRECATE_VIEWS(X)                                                                                         \
    LCB_DEPRECATED2(X,                                                                                                 \
                    "Views are deprecated in Couchbase Server 7.0+. Instead of views, use the Query Service (SQL++).")
#endif

/**
 * Mark a public API entry point as @uncommitted: experimental, not part of
 * the stable libcouchbase contract, and subject to change or removal in a
 * future release without prior announcement. Wrap a declaration with this
 * macro to emit a compile-time warning at every user call site, without
 * changing the ABI or removing the symbol. The diagnostic message is shared
 * across every uncommitted entry point so all such APIs can be located and
 * promoted (or retired) as a single change later.
 *
 * A translation unit that legitimately implements, tests, or demonstrates
 * an uncommitted API (the implementation source files, the dedicated unit
 * tests, the in-tree examples) can suppress the diagnostic for itself by
 * defining the macro to `X` *before* including any libcouchbase header,
 * e.g.:
 *
 *     #define LCB_UNCOMMITTED_API(X) X
 *     #include <libcouchbase/couchbase.h>
 *
 * Scope rule is the same as for LCB_DEPRECATE_VIEWS: the attribute is
 * attached during preprocessing, so redefining the macro further down the
 * file has no effect on already-preprocessed declarations. For sub-file
 * granularity use a `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"`
 * block.
 */
#ifndef LCB_UNCOMMITTED_API
#define LCB_UNCOMMITTED_API(X)                                                                                         \
    LCB_DEPRECATED2(X, "This API is uncommitted: experimental, not covered by the libcouchbase compatibility "         \
                       "guarantee, and may change or be removed in a future release without notice.")
#endif

#ifdef __cplusplus
}
#endif

#endif /* LCB_SYSDEFS_H */
