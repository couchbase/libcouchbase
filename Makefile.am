#
#     Copyright 2010 Couchbase, Inc.
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
                        src/views.c \
                        src/wait.c

if !HAVE_GETHRTIME
libcouchbase_la_SOURCES += src/gethrtime.c
endif


# Please remember to update the version info before each release if you
# add / remove functions.
libcouchbase_la_LDFLAGS=$(LTLIBVBUCKET) $(LTLIBSASL) $(LTLIBSASL2) \
                      -version-info 0:0:0
libcouchbase_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1


libcouchbase_libevent_la_SOURCES = src/plugin-libevent.c
libcouchbase_libevent_la_LDFLAGS=$(LTLIBEVENT) -version-info 1:0:0
libcouchbase_libevent_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1

tests/CouchbaseMock.jar:
	@echo "+---------------------------------------------+"
	@echo "| Download CouchbaseMock for functional tests |"
	@echo "+---------------------------------------------+"
	${WGET} -nv http://files.couchbase.com/maven2/org/couchbase/mock/CouchbaseMock/0.5-SNAPSHOT/CouchbaseMock-0.5-20110830.073020-1.jar
	mv CouchbaseMock-0.5-20110830.073020-1.jar tests/CouchbaseMock.jar

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
               example/memstat \
               example/couchview

example_memcat_SOURCES = example/memcat.c
example_memcat_LDADD = libcouchbase.la
example_memcat_LDFLAGS = $(LTLIBEVENT)

example_memcp_SOURCES = example/memcp.c
example_memcp_LDADD = libcouchbase.la
example_memcp_LDFLAGS = $(LTLIBEVENT)

example_memdump_SOURCES = example/memdump.c
example_memdump_LDADD = libcouchbase.la
example_memdump_LDFLAGS = $(LTLIBEVENT)

example_memflush_SOURCES = example/memflush.c
example_memflush_LDADD = libcouchbase.la
example_memflush_LDFLAGS = $(LTLIBEVENT)

example_memrm_SOURCES = example/memrm.c
example_memrm_LDADD = libcouchbase.la
example_memrm_LDFLAGS = $(LTLIBEVENT)

example_memstat_SOURCES = example/memstat.c
example_memstat_LDADD = libcouchbase.la
example_memstat_LDFLAGS = $(LTLIBEVENT)

example_couchview_SOURCES = example/couchview.c
example_couchview_LDADD = libcouchbase.la
example_couchview_LDFLAGS = $(LTLIBEVENT)

if HAVE_LIBYAJL
noinst_PROGRAMS += example/couchview_yajl
endif

example_couchview_yajl_SOURCES = example/couchview_yajl.c
example_couchview_yajl_LDADD = libcouchbase.la
example_couchview_yajl_LDFLAGS = $(LTLIBEVENT) $(LTLIBYAJL)

check_PROGRAMS = base64-test \
                 getopt-test \
                 ringbuffer-test \
                 strerror-test \
                 timings-test

if HAVE_COUCHBASEMOCK
noinst_LTLIBRARIES += libmockserver.la
check_PROGRAMS += arithmetic-test
endif

base64_test_SOURCES = tests/base64-test.c src/base64.c
getopt_test_SOURCES = tests/getopt-test.cc

ringbuffer_test_SOURCES = tests/ringbuffer-test.c src/ringbuffer.c

timings_test_SOURCES = tests/timings-test.c
timings_test_LDADD = libcouchbase.la libmockserver.la
timings_test_LDFLAGS = $(LTLIBEVENT)

strerror_test_SOURCES = tests/strerror-test.c
strerror_test_LDADD = ${libcouchbase_la_OBJECTS} $(LTLIBEVENT) $(LTLIBVBUCKET) $(LTLIBSASL) $(LTLIBSASL2)

arithmetic_test_SOURCES = tests/arithmetic.c
arithmetic_test_LDADD = libcouchbase.la libmockserver.la
arithmetic_test_LDFLAGS = $(LTLIBEVENT)
arithmetic_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

TESTS=${check_PROGRAMS} tests/check-mans.sh

LIBMANPAGE = man/man3lib/libcouchbase.3lib
HEADMANPAGE = man/man3head/couchbase.3head \
              man/man3head/couchbase.h.3head
FUNCMANPAGE = \
   man/man3couchbase/callbacks.3couchbase \
   man/man3couchbase/libcouchbase_arithmetic.3couchbase \
   man/man3couchbase/libcouchbase_arithmetic_by_key.3couchbase \
   man/man3couchbase/libcouchbase_connect.3couchbase \
   man/man3couchbase/libcouchbase_create.3couchbase \
   man/man3couchbase/libcouchbase_create_io_ops.3couchbase \
   man/man3couchbase/libcouchbase_destroy.3couchbase \
   man/man3couchbase/libcouchbase_disable_timings.3couchbase \
   man/man3couchbase/libcouchbase_enable_timings.3couchbase \
   man/man3couchbase/libcouchbase_get_cookie.3couchbase \
   man/man3couchbase/libcouchbase_get_last_error.3couchbase \
   man/man3couchbase/libcouchbase_get_timings.3couchbase \
   man/man3couchbase/libcouchbase_flush.3couchbase \
   man/man3couchbase/libcouchbase_mget.3couchbase \
   man/man3couchbase/libcouchbase_mget_by_key.3couchbase \
   man/man3couchbase/libcouchbase_mtouch.3couchbase \
   man/man3couchbase/libcouchbase_mtouch_by_key.3couchbase \
   man/man3couchbase/libcouchbase_remove.3couchbase \
   man/man3couchbase/libcouchbase_remove_by_key.3couchbase \
   man/man3couchbase/libcouchbase_set_arithmetic_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_cookie.3couchbase \
   man/man3couchbase/libcouchbase_set_error_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_get_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_flush_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_remove_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_storage_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_tap_deletion_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_tap_flush_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_tap_mutation_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_tap_opaque_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_tap_vbucket_set_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_touch_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_view_complete_callback.3couchbase \
   man/man3couchbase/libcouchbase_set_view_data_callback.3couchbase \
   man/man3couchbase/libcouchbase_store.3couchbase \
   man/man3couchbase/libcouchbase_store_by_key.3couchbase \
   man/man3couchbase/libcouchbase_strerror.3couchbase \
   man/man3couchbase/libcouchbase_tap_cluster.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_create.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_destroy.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_get_backfill.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_get_keys_only.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_set_backfill.3couchbase \
   man/man3couchbase/libcouchbase_tap_filter_set_keys_only.3couchbase \
   man/man3couchbase/libcouchbase_view_execute.3couchbase \
   man/man3couchbase/libcouchbase_wait.3couchbase \
   man/man3couchbase/missing.3couchbase

# Manual pages!
if USE_STRUCTURED_MANPAGES
man3headdir = $(mandir)/man3head
man3libdir = $(mandir)/man3lib
man3couchbasedir = $(mandir)/man3couchbase

man3head_DATA = $(HEADMANPAGE)
man3lib_DATA = $(LIBMANPAGE)
man3couchbase_DATA = $(FUNCMANPAGE)
else
man_MANS = $(HEADMANPAGE) $(LIBMANPAGE) $(FUNCMANPAGE)
endif

EXTRA_DIST = \
             NMakefile \
             include/libcouchbase/configuration.h.in \
             man \
             src/iofactory_win32.c \
             tests/check-mans.sh \
             tests/start_mock.sh \
             win32
