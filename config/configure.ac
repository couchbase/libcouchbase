#
#     Copyright 2010-2013 Couchbase, Inc.
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
AC_MSG_WARN([
*** WARNING
*** Building libcouchbase with Autotools and the ./configure script is no longer
*** supported. It is recommended you build the library with CMake. This script is
*** provided as a convenience for those platforms/systems on which building with CMake
*** contains bugs.])

AC_CONFIG_SRCDIR([src/internal.h])
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_HOST

# Preserve what the user specified as CFLAGS/CXXFLAGS/CPPFLAGS/LDFLAGS
SAVE_CFLAGS="$CFLAGS"
SAVE_CXXFLAGS="$CXXFLAGS"
SAVE_CPPFLAGS="$CPPFLAGS"
SAVE_LDFLAGS="$LDFLAGS"

# The stupid automake system thinks it is a good idea to inject
# -g -O2 to C(XX)FLAGS if it isn't set..
# Why I don't like this? Well -g is in conflict with -g3 that I'm
# adding for Sun Studio
AS_IF([test "x$CFLAGS" = "x" ],
      [CFLAGS="-I."])
AS_IF([test "x$CXXFLAGS" = "x" ],
      [CXXFLAGS="-I."])
AS_IF([test "x$CPPFLAGS" = "x" ],
      [CPPFLAGS="-I."])

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE(subdir-objects foreign tar-pax)
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
LT_INIT([disable-static shared dlopen pic-only])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_C_BIGENDIAN

# Restore CFLAGS/CXXFLAGS now that I've prevented automake
# to inject the extra options ;)
AS_IF([test "x$CFLAGS" = "x-I." ],
      [CFLAGS=""])
AS_IF([test "x$CXXFLAGS" = "x-I." ],
      [CXXFLAGS=""])
AS_IF([test "x$CPPFLAGS" = "x-I." ],
      [CPPFLAGS=""])

# It is common to install all stuff to /usr/local prefix on FreeBSD
case "$host_os" in
    freebsd*)
    ac_default_prefix=/usr/local
    AS_IF([test "x${ac_cv_env_CPPFLAGS_set}" = "x"],
          [CPPFLAGS="${CPPFLAGS} -I/usr/local/include"])
    AS_IF([test "x${ac_cv_env_LDFLAGS_set}" = "x"],
          [LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/local/lib/event2"])
    ;;
esac

# the malloc tests seems to be broken for cross compilation.. ignore them
ac_cv_func_malloc_0_nonnull=yes
ac_cv_func_realloc_0_nonnull=yes

COUCHBASE_GENERIC_COMPILER(c99)

AM_CPPFLAGS="$AM_CPPFLAGS -I\${top_srcdir}/src -I\${top_srcdir}/contrib -I\${top_srcdir}/contrib/cbsasl/include"
AM_NOWARN_CPPFLAGS="$AM_NOWARN_CPPFLAGS -I\${top_srcdir}/src -I\${top_srcdir}/contrib -I\${top_srcdir}/contrib/cbsasl/include"
LCB_VERSION_CHANGESET=GIT_CHANGESET
REVDESCRIBE=GIT_DESCRIBE
AC_SUBST(LCB_VERSION_CHANGESET)
AC_SUBST(REVDESCRIBE)

#
# To ensure that we don't break applications in mysterious ways we need
# to version our library. For a detailed description, check out:
# http://www.gnu.org/software/libtool/manual/libtool.html#Libtool-versioning
#
API_CURRENT=2
API_REVISION=28
API_AGE=0
AC_SUBST(API_CURRENT)
AC_SUBST(API_REVISION)
AC_SUBST(API_AGE)

# The actual version numbers for the developers ;)
LCB_VERSION="2.5.2"
LCB_VERSION_HEX=`echo ${LCB_VERSION} | awk -F. '{printf "0x%0.2d%0.2d%0.2d", $1, $2, $3}'`
AC_SUBST(LCB_VERSION)
AC_SUBST(LCB_VERSION_HEX)

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(dlopen, dl)
AC_SEARCH_LIBS(floor, m)
AC_SEARCH_LIBS(pow, m)
AC_SEARCH_LIBS(fabs, m)

AC_CHECK_HEADERS_ONCE([mach/mach_time.h sys/socket.h sys/time.h
                       netinet/in.h inttypes.h netdb.h unistd.h  stdint.h
                       sys/uio.h sys/types.h fcntl.h dlfcn.h sys/sdt.h limits.h stdarg.h])

AC_ARG_ENABLE([ssl], [AS_HELP_STRING([--enable-ssl], [Do not build SSL support. @<:@default=on@:>@])],
    [ac_cv_enable_ssl="$enableval"], [ac_cv_enable_ssl="yes"])
AM_CONDITIONAL(ENABLE_SSL, [ test "x${ac_cv_enable_ssl}" = "xyes"])
AS_IF([test "x${ac_cv_enable_ssl}" = "xyes"], AC_DEFINE(ENABLE_SSL, [1], [SSL Support will be enabled]))

m4_include([m4/ax_check_openssl.m4])
AX_CHECK_OPENSSL([ac_cv_have_openssl="yes"], [ac_cv_have_openssl="no"])
AM_CONDITIONAL(HAVE_OPENSSL, [test "x${ac_cv_have_openssl}" = "xyes"])
AS_IF([test "x${ac_cv_have_openssl}" != "xyes" && test "x${ac_cv_enable_ssl}" = "xyes"],
      [AC_MSG_ERROR(OpenSSL development files must be installed for SSL support. Use --enable-ssl=no to force)])


AC_ARG_ENABLE([snappy], [AS_HELP_STRING([--enable-snappy], [Enable snappy compression. @<:@default=off@:>@])],
    [ac_cv_enable_snappy="$enableval"], [ac_cv_enable_snappy="no"])

AC_ARG_ENABLE([static-snappy], [AS_HELP_STRING([--enable-static-snappy], [Use bundled libsnappy. @<:@default=off@:>@])],
    [ac_cv_enable_static_snappy="$enableval"], [ac_cv_enable_static_snappy="no"])

m4_include([m4/ax_check_snappy.m4])
AX_CHECK_SNAPPY([ac_cv_have_snappy="yes"], [ac_cv_have_snappy="no"])
AM_CONDITIONAL(HAVE_SNAPPY, [test "x${ac_cv_have_snappy}" = "xyes"])
AM_CONDITIONAL(BUILD_STATIC_SNAPPY, [test "x${ac_cv_enable_static_snappy}" = "xyes"])
AM_CONDITIONAL(ENABLE_SNAPPY, [test "x${ac_cv_enable_snappy}" = "xyes"])

AS_IF([test "x${ac_cv_have_snappy}" != "xyes" && test "x${ac_cv_enable_snappy}" = "xyes" && test "x${ac_cv_enable_static_snappy}" != "xyes"],
      [AC_MSG_ERROR(Snappy support requires either an installed libsnappy or the --enable-static-snappy option)])

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

AC_ARG_ENABLE([tools],
    [AS_HELP_STRING([--disable-tools],
            [Build tools. @<:@default=on@:>@])],
    [ac_cv_enable_tools="$enableval"],
    [ac_cv_enable_tools="yes"])

AC_ARG_ENABLE([cxx],
    [AS_HELP_STRING([--disable-cxx],
            [Build stuff written in C++. @<:@default=on@:>@])],
    [ac_cv_enable_cxx="$enableval"],
    [ac_cv_enable_cxx="yes"])

AM_CONDITIONAL(HAVE_CXX, [test "x${ac_cv_prog_cxx_works}" = "xyes" -a "x${ac_cv_enable_cxx}" = "xyes"])
AS_IF([test "x${ac_cv_enable_tools}" = "xyes"],
      [AS_IF([test "x${ac_cv_prog_cxx_works}" != "xyes" -o "x${ac_cv_enable_cxx}" != "xyes"],
             [AC_MSG_ERROR([You need C++ compiler to build tools. Try add --disable-tools])])])
AM_CONDITIONAL(BUILD_TOOLS, [test "x${ac_cv_enable_tools}" = "xyes"])

AC_CHECK_FUNCS_ONCE([gethrtime clock_gettime gettimeofday QueryPerformanceCounter alarm setitimer])
# For Linux
AC_SEARCH_LIBS(clock_gettime, rt)
AM_CONDITIONAL(HAVE_GETHRTIME, [test "x${ac_cv_func_gethrtime}" = "xyes"])

# On HP-UX we need to link libxnet(3lib)
AC_CHECK_DECL([__hpux])
AS_IF([test "x$ac_cv_have_decl___hpux" = "xyes"],
      [AC_CHECK_LIB(xnet, t_error, ,
                    AC_MSG_ERROR([*** -lxnet needed on HP-UX ***]))])

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

dnl restore CFLAGS, CPPFLAGS, CXXFLAGS and LDFLAGS
CFLAGS="$SAVE_CFLAGS"
CXXFLAGS="$SAVE_CXXFLAGS"
CPPFLAGS="$SAVE_CPPFLAGS"
LDFLAGS="$SAVE_LDFLAGS"

dnl ----------------------------------------------------------------------------
AC_CONFIG_FILES([Makefile include/libcouchbase/configuration.h])
AC_OUTPUT
