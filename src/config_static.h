/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
#ifndef LIBMEMBASE_CONFIG_STATIC_H
#define LIBMEMBASE_CONFIG_STATIC_H 1

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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

#ifndef WIN32
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

#ifndef HAVE_HTONLL
#ifdef WORDS_BIGENDIAN
#define ntohll(a) a
#define htonll(a) a
#else
#define ntohll(a) libmembase_byteswap64(a)
#define htonll(a) libmembase_byteswap64(a)

#ifdef __cplusplus
extern "C" {
#endif
extern uint64_t libmembase_byteswap64(uint64_t val);
#ifdef __cplusplus
}
#endif
#endif
#endif

#if defined (__SUNPRO_C) && (__SUNPRO_C >= 0x550)
#define LIBMEMBASE_API __global
#elif defined __GNUC__
#define LIBMEMBASE_API __attribute__ ((visibility("default")))
#else
#define LIBMEMBASE_API
#endif

#endif
