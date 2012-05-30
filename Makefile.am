#
#     Copyright 2010, 2011, 2012 Couchbase, Inc.
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

lib_LTLIBRARIES = libcouchbase.la
noinst_LTLIBRARIES = libhttpparser.la
if BUILD_TOOLS
bin_PROGRAMS = tools/cbc
endif


pkginclude_HEADERS = \
                     include/libcouchbase/behavior.h \
                     include/libcouchbase/callbacks.h \
                     include/libcouchbase/compat.h \
                     include/libcouchbase/configuration.h \
                     include/libcouchbase/couchbase.h \
                     include/libcouchbase/libevent_io_opts.h \
                     include/libcouchbase/tap_filter.h \
                     include/libcouchbase/timings.h \
                     include/libcouchbase/types.h \
                     include/libcouchbase/visibility.h \
                     include/libcouchbase/winsock_io_opts.h

libhttpparser_la_SOURCES = \
                        contrib/http_parser/http_parser.c \
                        contrib/http_parser/http_parser.h

libcouchbase_la_SOURCES = \
                        include/ep-engine/command_ids.h \
                        include/memcached/protocol_binary.h \
                        include/memcached/vbucket.h \
                        src/arithmetic.c \
                        src/base64.c \
                        src/behavior.c \
                        src/compat.c \
                        src/config_static.h \
                        src/cookie.c \
                        src/couch.c \
                        src/error.c \
                        src/event.c \
                        src/flush.c \
                        src/get.c \
                        src/handler.c \
                        src/hashset.c \
                        src/hashset.h \
                        src/instance.c \
                        src/internal.h \
                        src/packet.c \
                        src/remove.c \
                        src/ringbuffer.c \
                        src/ringbuffer.h \
                        src/server.c \
                        src/stats.c \
                        src/store.c \
                        src/strerror.c \
                        src/synchandler.c \
                        src/tap.c \
                        src/timeout.c \
                        src/timings.c \
                        src/touch.c \
                        src/utilities.c \
                        src/wait.c

if !HAVE_SYSTEM_LIBSASL
libcouchbase_la_SOURCES += src/isasl.c src/isasl.h
endif

if !HAVE_GETHRTIME
libcouchbase_la_SOURCES += src/gethrtime.c
endif

libcouchbase_la_LDFLAGS= $(AM_LDFLAGS) -version-info $(LIBCOUCHBASE_API_CURRENT):$(LIBCOUCHBASE_API_REVISION):$(LIBCOUCHBASE_API_AGE) -no-undefined $(AM_PROFILE_SOLDFLAGS)
libcouchbase_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1
libcouchbase_la_DEPENDENCIES=libhttpparser.la
libcouchbase_la_LIBADD=libhttpparser.la -lvbucket $(LIBSASL)

if LIBCOUCHBASE_ENABLE_TRACE
libcouchbase_la_SOURCES += \
                        src/debug.c \
                        src/debug.h

libcouchbase_la_CPPFLAGS += -DLIBCOUCHBASE_DEBUG_NOCTX
endif

if HAVE_WINSOCK2
if !HAVE_LIBEVENT
libcouchbase_la_SOURCES += src/plugin-win32.c src/iofactory_win32.c
libcouchbase_la_CPPFLAGS += -Iwin32
endif
else
libcouchbase_la_SOURCES += src/iofactory.c
if LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
libcouchbase_la_SOURCES += src/plugin-libevent.c
libcouchbase_la_LIBADD += -levent
libcouchbase_la_CPPFLAGS += -DLIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
else
lib_LTLIBRARIES += libcouchbase_libevent.la
libcouchbase_libevent_la_SOURCES = src/plugin-libevent.c
libcouchbase_libevent_la_LDFLAGS=-version-info 1:0:0 $(AM_LDFLAGS) $(AM_PROFILE_SOLDFLAGS)
libcouchbase_libevent_la_LIBADD=-levent
libcouchbase_libevent_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1
endif
endif

tests_unit_tests_SOURCES = tests/unit_tests.cc \
                           tests/base64-unit-test.cc src/base64.c \
                           tests/hashset-unit-test.cc src/hashset.c \
                           tests/strerror-unit-test.cc \
                           tests/memcached-compat-unit-test.cc \
                           tests/ringbuffer-unit-test.cc src/ringbuffer.c


tests_unit_tests_DEPENDENCIES = libcouchbase.la
tests_unit_tests_LDADD = libcouchbase.la

if HAVE_GOOGLETEST_SRC
noinst_LTLIBRARIES += libgtest.la
libgtest_la_SOURCES = tests/gtest-sources.cc
libgtest_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(GTEST_ROOT) -I$(GTEST_ROOT)/include \
                       $(NO_WERROR)
tests_unit_tests_DEPENDENCIES += libgtest.la
tests_unit_tests_LDADD += libgtest.la
tests_unit_tests_CPPFLAGS = $(AM_CPPFLAGS) -I$(GTEST_ROOT) -I$(GTEST_ROOT)/include
endif

if !HAVE_GOOGLETEST_SRC
tests_unit_tests_LDADD += -lgtest -lpthread
endif

tests/CouchbaseMock.jar:
	@echo "+---------------------------------------------+"
	@echo "| Download CouchbaseMock for functional tests |"
	@echo "+---------------------------------------------+"
	${DOWNLOAD} tests/CouchbaseMock.jar http://files.couchbase.com/maven2/org/couchbase/mock/CouchbaseMock/0.5-SNAPSHOT/CouchbaseMock-0.5-20120202.071818-12.jar

libmockserver_la_LDFLAGS = $(AM_LDFLAGS) $(AM_PROFILE_SOLDFLAGS)
libmockserver_la_DEPENDENCIES = tests/CouchbaseMock.jar
libmockserver_la_SOURCES = \
                         tests/server.c tests/loopfactory.c tests/server.h


#
# Example programs using the library
#
if BUILD_TOOLS
noinst_PROGRAMS = example/pillowfight example/couchview
if HAVE_LIBYAJL2
noinst_PROGRAMS += example/couchview_yajl
endif
endif

example_couchview_SOURCES = example/couchview.c
example_couchview_LDADD = libcouchbase.la

example_couchview_yajl_SOURCES = example/couchview_yajl.c
example_couchview_yajl_LDADD = libcouchbase.la -lyajl

check_PROGRAMS =

if BUILD_TOOLS
# we can't build the test program without a C++ compiler
check_PROGRAMS += tests/unit-tests
endif

if HAVE_COUCHBASEMOCK
noinst_LTLIBRARIES += libmockserver.la
check_PROGRAMS += tests/arithmetic-test \
                  tests/double-free-test \
                  tests/flags-test \
                  tests/timings-test \
                  tests/timeout-test \
                  tests/config-test \
                  tests/smoke-test \
                  tests/syncmode-test
endif

if BUILD_TOOLS
# and therefore have C++ compiler to build this test
check_PROGRAMS += tests/getopt-test
endif

tests_getopt_test_SOURCES = tests/getopt-test.cc

tests_config_test_SOURCES = tests/test.h tests/config-test.c
tests_config_test_LDADD = libcouchbase.la libmockserver.la
tests_config_test_LDFLAGS = $(AM_LDFLAGS) -lvbucket

tests_timings_test_SOURCES = tests/timings-test.c
tests_timings_test_LDADD = libcouchbase.la libmockserver.la

tests_smoke_test_SOURCES = tests/test.h tests/smoke-test.c
tests_smoke_test_LDADD = libcouchbase.la libmockserver.la

tests_syncmode_test_SOURCES = tests/test.h tests/syncmode-test.c
tests_syncmode_test_LDADD = libcouchbase.la libmockserver.la

tests_arithmetic_test_SOURCES = tests/arithmetic.c
tests_arithmetic_test_LDADD = libcouchbase.la libmockserver.la
tests_arithmetic_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

tests_double_free_test_SOURCES = tests/test.h tests/double-free-test.c
tests_double_free_test_LDADD = libcouchbase.la libmockserver.la

tests_flags_test_SOURCES = tests/flags-test.c
tests_flags_test_LDADD = libcouchbase.la libmockserver.la
tests_flags_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

tests_timeout_test_SOURCES = tests/timeout-test.c
tests_timeout_test_LDADD = libcouchbase.la libmockserver.la
tests_timeout_test_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -Itests

tools_cbc_LDADD = libcouchbase.la
if HAVE_LIBYAJL2
tools_cbc_LDADD += -lyajl
endif
tools_cbc_SOURCES = tools/cbc.cc tools/cbc-receive.cc                   \
                    tools/cbc-send.cc tools/cbc-util.cc                 \
                    tools/cbc-util.h tools/commandlineparser.cc         \
                    tools/commandlineparser.h tools/configuration.cc    \
                    tools/configuration.h

TESTS=${check_PROGRAMS}

example_pillowfight_SOURCES = tools/commandlineparser.cc example/pillowfight.cc
example_pillowfight_LDADD = libcouchbase.la

if BUILD_TOOLS
CBC_LINKS = cbc-cat cbc-rm cbc-cp cbc-stats cbc-flush cbc-create	\
            cbc-send cbc-receive cbc-version cbc-verify cbc-lock 	\
            cbc-unlock

install-exec-hook:
	cd $(DESTDIR)$(bindir) && \
               $(RM) $(CBC_LINKS) && \
               for f in $(CBC_LINKS); do $(LN_S) cbc$(EXEEXT) $$f$(EXEEXT); done
endif

EXTRA_DIST = \
             README.markdown \
             LICENSE \
             NMakefile \
             include/libcouchbase/configuration.h.in \
             src/iofactory_win32.c \
             tests/start_mock.sh \
             win32

LINTFLAGS=-Iinclude -b -c -errchk=%all \
          -erroff=E_INCL_NUSD,E_CAST_INT_TO_SMALL_INT,E_PTRDIFF_OVERFLOW  \
          -errtags=yes -errhdr=%user \
          -errsecurity=extended -fd -Ncheck=%all -Nlevel=4 -n -Xc99=none
lint:
	$(LINT.c) $(libcouchbase_la_SOURCES)

reformat:
	astyle --mode=c \
               --quiet \
               --style=1tbs \
               --indent=spaces=4 \
               --indent-namespaces \
               --indent-col1-comments \
               --max-instatement-indent=78 \
               --pad-oper \
               --pad-header \
               --add-brackets \
               --unpad-paren \
               --align-pointer=name \
               --align-reference=name \
               $(top_srcdir)/include/libcouchbase/*.[ch] \
               $(top_srcdir)/src/*.[ch] \
               $(top_srcdir)/example/*.cc  \
               $(top_srcdir)/example/*.[ch]  \
               $(top_srcdir)/tools/*.cc \
               $(top_srcdir)/tools/*.h \
               $(top_srcdir)/win32/*.[ch]

sinclude packaging/*/package.mk
