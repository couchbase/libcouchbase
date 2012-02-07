/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
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
 * This file contains the static part of the configure script. Please add
 * all platform specific conditional code to this file.
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_CONFIG_STATIC_H
#define LIBCOUCHBASE_CONFIG_STATIC_H 1

#if !defined HAVE_STDINT_H && defined WIN32
# include "win_stdint.h"
#else
# include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef _WIN32
#include "win32/win_errno_sock.h"
typedef int ssize_t;
#define snprintf _snprintf
#undef strdup
#define strdup _strdup
#else
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif /* _WIN32 */

#ifndef HAVE_HTONLL
#ifdef WORDS_BIGENDIAN
#define ntohll(a) a
#define htonll(a) a
#else
#define ntohll(a) libcouchbase_byteswap64(a)
#define htonll(a) libcouchbase_byteswap64(a)

#ifdef __cplusplus
extern "C" {
#endif
    extern uint64_t libcouchbase_byteswap64(uint64_t val);
#ifdef __cplusplus
}
#endif
#endif /* WORDS_BIGENDIAN */
#endif /* HAVE_HTONLL */


#ifdef linux
#undef ntohs
#undef ntohl
#undef htons
#undef htonl
#endif

#ifndef HAVE_GETHRTIME
typedef uint64_t hrtime_t;
extern hrtime_t gethrtime(void);
#endif

#endif /* LIBCOUCHBASE_CONFIG_STATIC_H */
