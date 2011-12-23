#
#     Copyright 2010, 2011 Couchbase, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
AC_PREREQ(2.60)
m4_include([m4/version.m4])
AC_INIT(libcouchbase, VERSION_NUMBER, support@couchbase.com)
AC_CONFIG_SRCDIR([src/internal.h])
AC_CONFIG_AUX_DIR(config)
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE(subdir-objects)
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AM_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# the malloc tests seems to be broken for cross compilation.. ignore them
ac_cv_func_malloc_0_nonnull=yes
ac_cv_func_realloc_0_nonnull=yes

COUCHBASE_GENERIC_COMPILER(c99)
AM_CPPFLAGS="$AM_CPPFLAGS -I\${top_srcdir}/src"
VERSION_NUMBER_HEX=GIT_VERSION_NUMBER_HEX
CHANGESET=GIT_CHANGESET
AC_SUBST(VERSION_NUMBER_HEX)
AC_SUBST(CHANGESET)

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(dlopen, dl)

AC_PATH_PROG(JAVA, java, no)
AC_PATH_PROG(WGET, wget, no)
AC_PATH_PROG(CURL, curl, no)

dnl Enable to specify external source for memcached headers. For example:
dnl https://raw.github.com/memcached/memcached/engine-pu/include/memcached/
AC_ARG_WITH([memcached-headers-url],
    [AC_HELP_STRING([--with-memcached-headers-url], [Download protocol_binary.h from given location.])],
    [
        AS_IF([test "x${WGET}" != "xno"],
              [DOWNLOAD="${WGET} -q -O"],
              [ AS_IF([test "x${CURL}" != "xno"],
                      [DOWNLOAD="${CURL} -s -o"],
                      [AC_MSG_ERROR([You need wget or curl in path to download the headers.])])])
        mkdir -p include/memcached && \
        ${DOWNLOAD} include/memcached/protocol_binary.h ${withval}/protocol_binary.h  && \
        ${DOWNLOAD} include/memcached/vbucket.h ${withval}/vbucket.h
        CFLAGS="${CFLAGS} -Iinclude"
    ]
)

AC_CHECK_HEADERS_ONCE([mach/mach_time.h memcached/protocol_binary.h
                       sys/socket.h sys/time.h netinet/in.h inttypes.h
                       netdb.h unistd.h ws2tcpip.h winsock2.h
                       libvbucket/vbucket.h event.h])

AS_IF([test "x$ac_cv_header_memcached_protocol_binary_h" != "xyes"],
      [AC_MSG_ERROR(Failed to locate memcached/protocol_binary.h)])

dnl Check that we're able to find a usable libvbucket
AC_CACHE_CHECK([for libvbucket], [ac_cv_have_libvbucket],
  [ saved_libs="$LIBS"
    LIBS=-lvbucket
    AC_TRY_LINK([
      #include <libvbucket/vbucket.h>
            ],[
      VBUCKET_CONFIG_HANDLE config = vbucket_config_parse_file(NULL);
            ],[
      ac_cv_have_libvbucket="yes"
            ], [
      ac_cv_have_libvbucket="no"
      ])
    LIBS="$saved_libs"
  ])

AS_IF([test "x${ac_cv_have_libvbucket}" != "xyes" -o "x$ac_cv_header_libvbucket_vbucket_h" != "xyes"],
      [AC_MSG_ERROR(Failed to locate libvbucket)])

dnl Check that we've got a usable libevent
AC_CACHE_CHECK([for libevent], [ac_cv_have_libevent],
  [ saved_libs="$LIBS"
    LIBS=-levent
    AC_TRY_LINK([
      #include <event.h>
            ],[
      event_init();
            ],[
      ac_cv_have_libevent="yes"
            ], [
      ac_cv_have_libevent="no"
      ])
    LIBS="$saved_libs"
  ])

AS_IF([test "x${ac_cv_have_libevent}" != "xyes" -o "x$ac_cv_header_event_h" != "xyes"],
      [AC_MSG_ERROR(Failed to locate libevent)])

AC_CACHE_CHECK([for libevent2], [ac_cv_have_libevent2],
  [ saved_libs="$LIBS"
    LIBS=-levent
    AC_TRY_LINK([
      #include <event2/event.h>
            ],[
      event_new(NULL, 0, 0, NULL, NULL);
            ],[
      ac_cv_have_libevent2="yes"
            ], [
      ac_cv_have_libevent2="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBEVENT2, [test "x${ac_cv_have_libevent2}" = "xyes"])
AS_IF([test "x${ac_cv_have_libevent2}" = "xyes"],
      [AC_DEFINE([HAVE_LIBEVENT2], [1], [We have libevent2])])

dnl Check if we've got libyajl
AC_CACHE_CHECK([for libyajl], [ac_cv_have_libyajl],
  [ saved_libs="$LIBS"
    LIBS=-lyajl
    AC_TRY_LINK([
      #include <yajl/yajl_parse.h>
            ],[
      yajl_handle parser = yajl_alloc(0, 0, 0, 0);
            ],[
      ac_cv_have_libyajl="yes"
            ], [
      ac_cv_have_libyajl="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBYAJL, [test "$ac_cv_have_libyajl" = "yes"])

LIBSASL=-lsasl
dnl Check for sasl
AC_CACHE_CHECK([for libsasl], [ac_cv_have_libsasl],
  [ saved_libs="$LIBS"
    LIBS=-lsasl
    AC_TRY_LINK([
      #include <stdlib.h>
      #include <sasl/sasl.h>
            ],[
      sasl_server_init(NULL, NULL);
            ],[
      ac_cv_have_libsasl="yes"
            ], [
      ac_cv_have_libsasl="no"
      ])
    LIBS="$saved_libs"
  ])

AS_IF([test "$ac_cv_have_libsasl" = no], [
  AC_CACHE_CHECK([for libsasl2], [ac_cv_have_libsasl2],
    [ saved_libs="$LIBS"
      LIBS=-lsasl2
      AC_TRY_LINK([
        #include <stdlib.h>
        #include <sasl/sasl.h>
              ],[
        sasl_server_init(NULL, NULL);
              ],[
        ac_cv_have_libsasl2="yes"
              ], [
        ac_cv_have_libsasl2="no"
        ])
      LIBS="$saved_libs"
    ])
  AS_IF([test "x${ac_cv_have_libsasl2}" = "xno"],
      [AC_MSG_ERROR(Failed to locate a usable sasl library)])
  LIBSASL=-lsasl2
])

AC_SUBST(LIBSASL)

AC_CACHE_CHECK([for htonll], [ac_cv_have_htonll],
    [AC_TRY_LINK([
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
                 ], [
return htonll(0);
                 ],
                 [ ac_cv_have_htonll=yes ],
                 [ ac_cv_have_htonll=no ])
])
AS_IF([test "x$ac_cv_have_htonll" = "xyes"],[
       AC_DEFINE([HAVE_HTONLL], [1], [Have ntohll])])

AC_ARG_ENABLE([couchbasemock],
    [AS_HELP_STRING([--disable-couchbasemock],
            [Build tests that use couchbasemock. @<:@default=on@:>@])],
    [ac_cv_enable_couchbasemock="$enableval"],
    [ac_cv_enable_couchbasemock="yes"])

AS_IF([test "x${ac_cv_enable_couchbasemock}" = "xyes"],
      [AS_IF([test "x$WGET" = "xno"],
             [AC_MSG_ERROR([You need wget in path to download the mock server.
Try add --disable-couchbasemock
])])
       AS_IF([test "x$JAVA" = "xno"],
             [AC_MSG_ERROR([You need java in path to run the mock server.
Try add --disable-couchbasemock
])])])

AM_CONDITIONAL(HAVE_COUCHBASEMOCK, [test "x${ac_cv_enable_couchbasemock}" = "xyes"])

AC_CHECK_FUNCS_ONCE(gethrtime clock_gettime gettimeofday)
AM_CONDITIONAL(HAVE_GETHRTIME, [test "x${ac_cv_func_gethrtime}" = "xyes"])

AH_TOP([
#ifndef CONFIG_H
#define CONFIG_H
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

/*
 * This file is generated by running configure. Any changes you make to this
 * file will be overwritten the next time you run configure. If you want to
 * make permanent changes to the file you should edit configure.ac instead.
 * All platform-specific includes should be placed inside config_static.h
 * to keep the config.h as small as possible. That allows us for easily
 * use another build systems with a poor support for automake (like Windows)
 *
 * @author Trond Norbye
 */
])

AH_BOTTOM([
#include "config_static.h"
#endif
])

dnl ----------------------------------------------------------------------------
#PANDORA_VC_VERSION
AC_CONFIG_FILES([Makefile include/libcouchbase/configuration.h])
AC_OUTPUT
