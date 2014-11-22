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
CHANGESET=GIT_CHANGESET
REVDESCRIBE=GIT_DESCRIBE
AC_SUBST(CHANGESET)
AC_SUBST(REVDESCRIBE)

#
# To ensure that we don't break applications in mysterious ways we need
# to version our library. For a detailed description, check out:
# http://www.gnu.org/software/libtool/manual/libtool.html#Libtool-versioning
#
API_CURRENT=2
API_REVISION=20
API_AGE=0
AC_SUBST(API_CURRENT)
AC_SUBST(API_REVISION)
AC_SUBST(API_AGE)

# The actual version numbers for the developers ;)
LCB_VERSION="2.4.4"
LCB_VERSION_HEX=`echo ${LCB_VERSION} | awk -F. '{printf "0x%0.2d%0.2d%0.2d", $1, $2, $3}'`
AC_SUBST(LCB_VERSION)
AC_SUBST(LCB_VERSION_HEX)

AC_ARG_ENABLE([fat_binary],
    [AS_HELP_STRING([--enable-fat-binary],
                    [Build a fat binary for mac os x @<:@default=off@:>@])],
    [ac_cv_fat_binary="$enableval"])

AS_IF([test "x$ac_cv_fat_binary" = "xyes"], [
        AM_CPPFLAGS="$AM_CPPFLAGS -force_cpusubtype_ALL -arch i386 -arch x86_64"
        AM_NOWARN_CPPFLAGS="$AM_NOWARN_CPPFLAGS -force_cpusubtype_ALL -arch i386 -arch x86_64"
        AM_LDFLAGS="$AM_LDFLAGS -force_cpusubtype_ALL -arch i386 -arch x86_64"
        CPPFLAGS="$CPPFLAGS -force_cpusubtype_ALL -arch i386 -arch x86_64"
        LDFLAGS="$LDFLAGS -force_cpusubtype_ALL -arch i386 -arch x86_64"
        ac_cv_dependency_tracking="no"
      ])

AC_ARG_ENABLE([m32],
    [AS_HELP_STRING([--enable-m32],
                    [Pass -m32 to the compiler and linker @<:@default=off@:>@])],
    [ac_cv_m32="$enableval"])
AC_ARG_ENABLE([m64],
    [AS_HELP_STRING([--enable-m64],
                    [Pass -m64 to the compiler and linker @<:@default=off@:>@])],
    [ac_cv_m64="$enableval"])

AS_IF([test "x$ac_cv_m32" = "xyes"],
      [ AM_CPPFLAGS="$AM_CPPFLAGS -m32"
        AM_NOWARN_CPPFLAGS="$AM_NOWARN_CPPFLAGS -m32"
        AM_LDFLAGS="$AM_LDFLAGS -m32"
        CPPFLAGS="$CPPFLAGS -m32"
        LDFLAGS="$LDFLAGS -m32"
        AS_IF([test "x$ac_cv_m64" = "xyes"],
              [ AC_MSG_ERROR([You cannot specify -m32 and -m64. Pick one of them]) ]) ],
      [ AS_IF([test "x$ac_cv_m64" = "xyes"],
              [ AM_CPPFLAGS="$AM_CPPFLAGS -m64"
                AM_NOWARN_CPPFLAGS="$AM_NOWARN_CPPFLAGS -m64"
                AM_LDFLAGS="$AM_LDFLAGS -m64"
                CPPFLAGS="$CPPFLAGS -m64"
                LDFLAGS="$LDFLAGS -m64"
              ]) ])

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(dlopen, dl)
AC_SEARCH_LIBS(floor, m)
AC_SEARCH_LIBS(pow, m)
AC_SEARCH_LIBS(fabs, m)

AC_CHECK_HEADERS_ONCE([mach/mach_time.h sys/socket.h sys/time.h
                       netinet/in.h inttypes.h netdb.h unistd.h
                       ws2tcpip.h winsock2.h event.h stdint.h
                       sys/uio.h sys/types.h fcntl.h dlfcn.h
                       ev.h libev/ev.h sys/sdt.h limits.h stdarg.h])

AS_IF([test "x$ac_cv_header_stdint_h" != "xyes"],
      [AC_MSG_ERROR(Failed to locate stdint.h)])

AS_IF([test "x$ac_cv_header_libev_ev_h" = "xyes"],
      [AC_DEFINE([HAVE_LIBEV_EV_H], [1], [Have non-standard place for libev header])])

dnl Allow to build library without event library dependency, which is useful
dnl if the application already have one.
AC_ARG_ENABLE([plugins],
              [AS_HELP_STRING([--disable-plugins], [Build without plugins. Note that in this case most of the tests will be skipped.])],
              [ac_cv_enable_plugins="no"],
              [ac_cv_enable_plugins="yes"])
AM_CONDITIONAL(BUILD_PLUGINS, [test "x$ac_cv_enable_plugins" = "xyes"])
AS_IF([test "x$ac_cv_enable_plugins" = "xyes"],
      [AC_DEFINE([BUILD_PLUGINS], [1], [Build plugins])])

dnl Check that we can use winsock2 plugin
AC_CACHE_CHECK([for winsock2], [ac_cv_have_winsock2],
  [ saved_libs="$LIBS"
    LIBS=-lws2_32
    AC_TRY_LINK([
      #include <winsock2.h>
      #include <ws2tcpip.h>
            ],[
      DWORD error = WSAGetLastError();
            ],[
      ac_cv_have_winsock2="yes"
            ], [
      ac_cv_have_winsock2="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_WINSOCK2, [test "$ac_cv_have_winsock2" = "yes"])

dnl Check that we've got a usable libev3
AC_CACHE_CHECK([for libev3], [ac_cv_have_libev3],
  [ saved_libs="$LIBS"
    LIBS=-lev
    AC_TRY_LINK([
      #include <sys/types.h>
      #ifdef HAVE_LIBEV_EV_H
      #include <libev/ev.h>
      #else
      #include <ev.h>
      #endif
            ],[
      struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO|EVFLAG_NOENV);
      ev_loop(loop, 0);
            ],[
      ac_cv_have_libev3="yes"
            ], [
      ac_cv_have_libev3="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBEV3, [test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libev3}" = "xyes" ])
AS_IF([test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libev3}" = "xyes"],
      [AC_DEFINE([HAVE_LIBEV3], [1], [We have libev3])])

dnl Check that we've got a usable libev4
AC_CACHE_CHECK([for libev4], [ac_cv_have_libev4],
  [ saved_libs="$LIBS"
    LIBS=-lev
    AC_TRY_LINK([
      #include <sys/types.h>
      #ifdef HAVE_LIBEV_EV_H
      #include <libev/ev.h>
      #else
      #include <ev.h>
      #endif
            ],[
      struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO|EVFLAG_NOENV);
      ev_run(loop, 0);
            ],[
      ac_cv_have_libev4="yes"
            ], [
      ac_cv_have_libev4="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBEV4, [test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libev4}" = "xyes" ])
AS_IF([test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libev4}" = "xyes"],
      [AC_DEFINE([HAVE_LIBEV4], [1], [We have libev4])])

AM_CONDITIONAL(HAVE_LIBEV, [test "x$ac_cv_enable_plugins" = "xyes" -a \( "x${ac_cv_have_libev3}" = "xyes" -o "x${ac_cv_have_libev4}" = "xyes" \)])

dnl Check that we've got a usable libevent
AC_CACHE_CHECK([for libevent >= 1.4], [ac_cv_have_libevent],
  [ saved_libs="$LIBS"
    LIBS=-levent
    AC_TRY_LINK([
      #include <sys/types.h>
      #include <event.h>
            ],[
      event_base_new();
            ],[
      ac_cv_have_libevent="yes"
            ], [
      ac_cv_have_libevent="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBEVENT, [test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libevent}" = "xyes"])
AS_IF([test "x$ac_cv_enable_plugins" = "xyes" -a "x${ac_cv_have_libevent}" = "xyes"],
      [AC_DEFINE([HAVE_LIBEVENT], [1], [We have libevent])])

AC_CACHE_CHECK([for libevent2], [ac_cv_have_libevent2],
  [ saved_libs="$LIBS"
    LIBS=-levent
    AC_TRY_LINK([
      #include <stdlib.h>
      #include <sys/types.h>
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
AS_IF([test "x${ac_cv_enable_plugins}" = "xyes" -a "x${ac_cv_have_libevent2}" = "xyes"],
      [AC_DEFINE([HAVE_LIBEVENT2], [1], [We have libevent2])])

AC_ARG_ENABLE([libuv],
              [AS_HELP_STRING([--disable-libuv], [Build without libuv. You might need this when building package in development environment.])],
              [ac_cv_enable_libuv="no"],
              [ac_cv_enable_libuv="yes"])
AC_CACHE_CHECK([for libuv], [ac_cv_have_libuv],
  [ saved_libs="$LIBS"
    LIBS=-luv
    AC_TRY_LINK([
      #include <uv.h>
            ],[
      uv_timer_init(NULL, NULL);
            ],[
      ac_cv_have_libuv="yes"
            ], [
      ac_cv_have_libuv="no"
      ])
    LIBS="$saved_libs"
  ])
AM_CONDITIONAL(HAVE_LIBUV, [test "x${ac_cv_have_libuv}" = "xyes" -a "x${ac_cv_enable_libuv}" = "xyes"])
AS_IF([test "x${ac_cv_enable_plugins}" = "xyes" -a "x${ac_cv_have_libuv}" = "xyes"],
      [AC_DEFINE([HAVE_LIBUV], [1], [We have libuv])])

dnl Fail if libevent is the only networking backend accessible
AS_IF([test "x$ac_cv_enable_plugins" = "xyes" -a \
       "x${ac_cv_have_winsock2}" != "xyes" -a \
       "x${ac_cv_have_libuv}" != "xyes" -a \
       "x${ac_cv_have_libevent}" != "xyes" -a \
       "x${ac_cv_have_libevent2}" != "xyes" -a \
       "x${ac_cv_have_libev3}" != "xyes" -a \
       "x${ac_cv_have_libev4}" != "xyes"],
      [AC_MSG_ERROR(Failed to locate usable event library. You must install either libev or libevent dev package or use --disable-plugins option)])

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

AC_CHECK_FUNCS_ONCE([gethrtime clock_gettime gettimeofday
                     QueryPerformanceCounter alarm setitimer])
AM_CONDITIONAL(HAVE_GETHRTIME, [test "x${ac_cv_func_gethrtime}" = "xyes"])

# On HP-UX we need to link libxnet(3lib)
AC_CHECK_DECL([__hpux])
AS_IF([test "x$ac_cv_have_decl___hpux" = "xyes"],
      [AC_CHECK_LIB(xnet, t_error, ,
                    AC_MSG_ERROR([*** -lxnet needed on HP-UX ***]))])

#
# SystemTap and DTrace support
#
AC_CHECK_PROGS([DTRACE], [dtrace])

# On Solaris we need to instrument all of the object files, but this isn't
# true with DTrace on MacOSX or SystemTap. Instead of doing the hard
# work of trying to check if we have to do this, just do it if __sun is
# defined...
AC_CHECK_DECL([__sun])
AC_CHECK_DECL([__APPLE__])
AS_IF([test "x$ac_cv_have_decl___APPLE__" != "xyes"],
      [DTRACE_DASH_G="-G"])
AC_SUBST(DTRACE_DASH_G)
AC_CACHE_CHECK([for SystemTap/DTrace requirements], [ac_cv_enable_dtrace], [
   AS_IF([test "x$ac_cv_prog_DTRACE" != "xno" -a "x$ac_cv_header_sys_sdt_h" = "xyes"], [
         AS_IF([test "x$ac_cv_have_decl___APPLE__" = "xyes"],
               [ ac_cv_enable_dtrace=no ],
               [ ac_cv_enable_dtrace=yes ])
      ], [
         ac_cv_enable_dtrace=no
      ])
])
AC_CACHE_CHECK([if dtrace works], [ac_cv_dtrace_works],
               [
                 cat > conftest.d <<EOF
provider ConfTest {
    probe ac_test(int);
};
EOF
                 $DTRACE -h -o conftest.h -s conftest.d 2>/dev/zero
                 AS_IF([test $? -eq 0],
                       [ac_cv_dtrace_works=yes],
                       [ac_cv_dtrace_works=no])
                 rm -f conftest.h conftest.d
               ])
AS_IF([test "x$ac_cv_enable_dtrace" = "xyes" -a "x$ac_cv_dtrace_works" = "xyes"],
      [AC_DEFINE([HAVE_DTRACE], [1], [Enables SystemTap / DTrace Support])])

AM_CONDITIONAL([ENABLE_DTRACE], [test "x$ac_cv_enable_dtrace" = "xyes" -a "x$ac_cv_dtrace_works" = "xyes" ])
AM_CONDITIONAL([DTRACE_INSTRUMENT_OBJECT],
               [test "x$ac_cv_have_decl___sun" = "xyes"])
AM_CONDITIONAL([APPLE_DTRACE], [test "x$ac_cv_have_decl__APPLE__" = "xyes"])

AM_CONDITIONAL(MANPAGE_BSD_LAYOUT, [test "x$ac_cv_have_decl___sun" != "xyes"])

AC_CACHE_CHECK([if EWOULDBLOCK != EAGAIN],[ac_cv_eagain_neq_ewouldblock],
               [AC_COMPILE_IFELSE([AC_LANG_SOURCE([
                    #include <errno.h>
                    int error = EAGAIN;
                    int main()
                    {
                        switch(error)
                        {
                        case EWOULDBLOCK:
                        case EAGAIN:
                            error = 1;
                            break;
                        default:
                            error = 0;
                        }
                        return 0;
                    }
                ])],
                [ ac_cv_eagain_neq_ewouldblock=yes ],
                [ ac_cv_eagain_neq_ewouldblock=no])])

AS_IF([test "x$ac_cv_eagain_neq_ewouldblock" = "xyes"],[
       AC_DEFINE([USE_EAGAIN], [1], [Defined for systems where EAGAIN != EWOULDBLOCK])])

AH_TOP([
#if defined(_WIN32) && !defined(HAVE_CONFIG_H)
  /* skip config.h contents on a non-autotools win32 build */
  #ifndef _CRT_SECURE_NO_WARNINGS
  #define _CRT_SECURE_NO_WARNINGS
  #endif

  #include <string.h>

  #define HAVE_WINSOCK2_H 1
  #define HAVE_WS2TCPIP_H 1
  #define HAVE_QUERYPERFORMANCECOUNTER 1
  #include "config_static.h"
  #define CONFIG_H
#endif

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
AC_CONFIG_FILES([Makefile include/libcouchbase/configuration.h VERSION])
AC_OUTPUT
