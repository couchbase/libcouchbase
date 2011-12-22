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

#
# Automake file used to build libcouchbase. Please avoid using propritary
# make constructs, but keep the syntax portable. To reduce the posibility
# for merge conflicts all list of files should be sorted aphabetically
# (If everyone always add their files to the end of the list that line will
# always result in a conflict..)
#
# @author Trond Norbye
#
ACLOCAL_AMFLAGS = -I m4 --force

lib_LTLIBRARIES = libcouchbase.la libcouchbase_libevent.la
noinst_LTLIBRARIES =

pkginclude_HEADERS = \
                     include/libcouchbase/callbacks.h \
                     include/libcouchbase/configuration.h \
                     include/libcouchbase/couchbase.h \
                     include/libcouchbase/libevent_io_opts.h \
                     include/libcouchbase/tap_filter.h \
                     include/libcouchbase/timings.h \
                     include/libcouchbase/types.h \
                     include/libcouchbase/visibility.h \
                     include/libcouchbase/winsock_io_opts.h

libcouchbase_la_SOURCES = \
                        src/arithmetic.c \
                        src/base64.c \
                        src/config_static.h \
                        src/cookie.c \
                        src/error.c \
                        src/event.c \
                        src/flush.c \
                        src/get.c \
                        src/handler.c \
                        src/instance.c \
                        src/internal.h \
                        src/iofactory.c \
                        src/packet.c \
                        src/remove.c \
                        src/ringbuffer.c \
                        src/ringbuffer.h \
                        src/server.c \
                        src/stats.c \
                        src/store.c \
                        src/strerror.c \
                        src/tap.c \
                        src/timings.c \
                        src/touch.c \
                        src/utilities.c \
                        src/wait.c

if !HAVE_GETHRTIME
libcouchbase_la_SOURCES += src/gethrtime.c
endif

#if HAVE_LIBEVENT2
#libcouchbase_la_SOURCES += src/views.c
#endif

# Please remember to update the version info before each release if you
# add / remove functions.
libcouchbase_la_LDFLAGS=-version-info 0:0:0
libcouchbase_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1
libcouchbase_la_LIBADD=-lvbucket $(LIBSASL)

libcouchbase_libevent_la_SOURCES = src/plugin-libevent.c
libcouchbase_libevent_la_LDFLAGS=-version-info 1:0:0
libcouchbase_libevent_la_LIBADD=-levent
libcouchbase_libevent_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1

tests/CouchbaseMock.jar:
	@echo "+---------------------------------------------+"
	@echo "| Download CouchbaseMock for functional tests |"
	@echo "+---------------------------------------------+"
	${WGET} -nv http://files.couchbase.com/maven2/org/couchbase/mock/CouchbaseMock/0.5-SNAPSHOT/CouchbaseMock-0.5-20111128.191335-3.jar
	mv CouchbaseMock-0.5-20111128.191335-3.jar tests/CouchbaseMock.jar

libmockserver_la_DEPENDENCIES = tests/CouchbaseMock.jar
libmockserver_la_SOURCES = \
                         tests/server.c tests/server.h


#
# Example programs using the library
#
noinst_PROGRAMS = \
               example/memcat \
               example/memcp \
               example/memdump \
               example/memflush \
               example/memrm \
               example/memstat

#if HAVE_LIBEVENT2
#noinst_PROGRAMS += example/couchview
#if HAVE_LIBYAJL
#noinst_PROGRAMS += example/couchview_yajl
#endif
#endif

example_memcat_SOURCES = example/memcat.c
example_memcat_LDADD = libcouchbase.la
example_memcat_LDFLAGS = -levent

example_memcp_SOURCES = example/memcp.c
example_memcp_LDADD = libcouchbase.la
example_memcp_LDFLAGS = -levent

example_memdump_SOURCES = example/memdump.c
example_memdump_LDADD = libcouchbase.la
example_memdump_LDFLAGS = -levent

example_memflush_SOURCES = example/memflush.c
example_memflush_LDADD = libcouchbase.la
example_memflush_LDFLAGS = -levent

example_memrm_SOURCES = example/memrm.c
example_memrm_LDADD = libcouchbase.la
example_memrm_LDFLAGS = -levent

example_memstat_SOURCES = example/memstat.c
example_memstat_LDADD = libcouchbase.la
example_memstat_LDFLAGS = -levent

#example_couchview_SOURCES = example/couchview.c
#example_couchview_LDADD = libcouchbase.la
#example_couchview_LDFLAGS = -levent

#example_couchview_yajl_SOURCES = example/couchview_yajl.c
#example_couchview_yajl_LDADD = libcouchbase.la
#example_couchview_yajl_LDFLAGS = -levent -lyajl

check_PROGRAMS = tests/base64-test \
                 tests/getopt-test \
                 tests/ringbuffer-test \
                 tests/strerror-test

if HAVE_COUCHBASEMOCK
noinst_LTLIBRARIES += libmockserver.la
check_PROGRAMS += tests/arithmetic-test \
                  tests/flags-test \
                  tests/timings-test \
                  tests/config-test \
                  tests/smoke-test
endif

tests_base64_test_SOURCES = tests/base64-test.c src/base64.c
tests_getopt_test_SOURCES = tests/getopt-test.cc

tests_config_test_SOURCES = tests/test.h tests/config-test.c
tests_config_test_LDADD = libcouchbase.la libmockserver.la
tests_config_test_LDFLAGS = -ldl -levent -lvbucket

tests_ringbuffer_test_SOURCES = tests/ringbuffer-test.c src/ringbuffer.c

tests_timings_test_SOURCES = tests/timings-test.c
tests_timings_test_LDADD = libcouchbase.la libmockserver.la
tests_timings_test_LDFLAGS = -levent

tests_smoke_test_SOURCES = tests/test.h tests/smoke-test.c
tests_smoke_test_LDADD = libcouchbase.la libmockserver.la
tests_smoke_test_LDFLAGS = -levent

tests_strerror_test_SOURCES = tests/strerror-test.c
tests_strerror_test_LDADD = ${libcouchbase_la_OBJECTS} -levent -lvbucket $(LIBSASL)

tests_arithmetic_test_SOURCES = tests/arithmetic.c
tests_arithmetic_test_LDADD = libcouchbase.la libmockserver.la
tests_arithmetic_test_LDFLAGS = -levent
tests_arithmetic_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

tests_flags_test_SOURCES = tests/flags-test.c
tests_flags_test_LDADD = libcouchbase.la libmockserver.la
tests_flags_test_LDFLAGS = -levent
tests_flags_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

TESTS=${check_PROGRAMS}

EXTRA_DIST = \
             LICENSE \
             NMakefile \
             include/libcouchbase/configuration.h.in \
             src/iofactory_win32.c \
             tests/start_mock.sh \
             win32

sinclude packaging/*/package.mk
