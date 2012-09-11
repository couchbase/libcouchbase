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
noinst_LTLIBRARIES = libhttpparser.la libvbucket.la libketama.la libcrc32.la
if BUILD_TOOLS
bin_PROGRAMS = tools/cbc
endif

pkginclude_HEADERS = \
                     include/libcouchbase/behavior.h \
                     include/libcouchbase/callbacks.h \
                     include/libcouchbase/compat.h \
                     include/libcouchbase/configuration.h \
                     include/libcouchbase/couchbase.h \
                     include/libcouchbase/timings.h \
                     include/libcouchbase/types.h \
                     include/libcouchbase/arguments.h \
                     include/libcouchbase/visibility.h \
                     plugins/io/libevent/libevent_io_opts.h \
                     plugins/io/win32/winsock_io_opts.h

libhttpparser_la_SOURCES = \
                        contrib/http_parser/http_parser.c \
                        contrib/http_parser/http_parser.h
libhttpparser_la_CFLAGS =  $(AM_NOWARN_CFLAGS)
libhttpparser_la_CPPFLAGS =  $(AM_NOWARN_CPPFLAGS)

libvbucket_la_SOURCES = \
                        include/libvbucket/vbucket.h \
                        include/libvbucket/visibility.h \
                        contrib/libvbucket/hash.h \
                        contrib/libvbucket/cJSON.c \
                        contrib/libvbucket/cJSON.h \
                        contrib/libvbucket/vbucket.c
libvbucket_la_LIBADD = libketama.la libcrc32.la
libvbucket_la_DEPENDENCIES = libketama.la libcrc32.la
libvbucket_la_CFLAGS =  $(AM_NOWARN_CFLAGS)
libvbucket_la_CPPFLAGS =  $(AM_NOWARN_CPPFLAGS)

libketama_la_SOURCES = contrib/libvbucket/ketama.c
libketama_la_CFLAGS =  $(AM_NOWARN_CFLAGS)
libketama_la_CPPFLAGS =  $(AM_NOWARN_CPPFLAGS)


libcrc32_la_SOURCES = contrib/libvbucket/crc32.c
libcrc32_la_CFLAGS = $(AM_NOWARN_CFLAGS)
libcrc32_la_CPPFLAGS = $(AM_NOWARN_CPPFLAGS)

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
                        src/error.c \
                        src/event.c \
                        src/flush.c \
                        src/get.c \
                        src/handler.c \
                        src/handler.h \
                        src/hashset.c \
                        src/hashset.h \
                        src/http.c \
                        src/instance.c \
                        src/internal.h \
                        src/observe.c \
                        src/packet.c \
                        src/remove.c \
                        src/ringbuffer.c \
                        src/ringbuffer.h \
                        src/server.c \
                        src/stats.c \
                        src/store.c \
                        src/strerror.c \
                        src/synchandler.c \
                        src/timeout.c \
                        src/timer.c \
                        src/timings.c \
                        src/touch.c \
                        src/utilities.c \
                        src/verbosity.c \
                        src/wait.c

if !HAVE_SYSTEM_LIBSASL
libcouchbase_la_SOURCES += src/isasl.c src/isasl.h
endif

if !HAVE_GETHRTIME
libcouchbase_la_SOURCES += src/gethrtime.c
endif

libcouchbase_la_LDFLAGS= $(AM_LDFLAGS) -version-info $(API_CURRENT):$(API_REVISION):$(API_AGE) -no-undefined $(AM_PROFILE_SOLDFLAGS)
libcouchbase_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1
libcouchbase_la_DEPENDENCIES=libhttpparser.la libvbucket.la
libcouchbase_la_LIBADD=libhttpparser.la libvbucket.la $(LIBSASL)

if LIBCOUCHBASE_ENABLE_TRACE
libcouchbase_la_SOURCES += \
                        src/debug.c \
                        src/debug.h

libcouchbase_la_CPPFLAGS += -DLIBCOUCHBASE_DEBUG_NOCTX
endif

if HAVE_WINSOCK2
if !HAVE_LIBEVENT
libcouchbase_la_SOURCES += plugins/io/win32/plugin-win32.c src/iofactory_win32.c
libcouchbase_la_CPPFLAGS += -Iwin32 -Iplugins/io/win32
endif
else
libcouchbase_la_SOURCES += src/iofactory.c
if LIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
libcouchbase_la_SOURCES += plugins/io/libevent/plugin-libevent.c
libcouchbase_la_LIBADD += -levent
libcouchbase_la_CPPFLAGS += -DLIBCOUCHBASE_LIBEVENT_PLUGIN_EMBED
else
lib_LTLIBRARIES += libcouchbase_libevent.la
libcouchbase_libevent_la_SOURCES = plugins/io/libevent/plugin-libevent.c
libcouchbase_libevent_la_LDFLAGS=-version-info 1:0:0 $(AM_LDFLAGS) $(AM_PROFILE_SOLDFLAGS)
libcouchbase_libevent_la_LIBADD=-levent
libcouchbase_libevent_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1
endif
endif

tests_unit_tests_SOURCES = \
                           src/base64.c \
                           src/hashset.c \
                           src/ringbuffer.c \
                           tests/base64-unit-test.cc \
                           tests/behavior-unit-tests.cc \
                           tests/hashset-unit-test.cc \
                           tests/memcached-compat-unit-test.cc \
                           tests/ringbuffer-unit-test.cc \
                           tests/strerror-unit-test.cc \
                           tests/unit_tests.cc

tests_unit_tests_DEPENDENCIES = libcouchbase.la
tests_unit_tests_LDADD = libcouchbase.la
tests_unit_tests_CFLAGS = $(AM_NOWARN_CFLAGS)
tests_unit_tests_CPPFLAGS = $(AM_NOWARN_CPPFLAGS)
tests_unit_tests_CXXFLAGS = $(AM_NOWARN_CXXFLAGS)

gtest-1.6.0.zip:
	@echo "+--------------------------------+"
	@echo "| Download Google test framework |"
	@echo "+--------------------------------+"
	${DOWNLOAD} gtest-1.6.0.zip http://googletest.googlecode.com/files/gtest-1.6.0.zip


if HAVE_GOOGLETEST_SRC
noinst_LTLIBRARIES += libgtest.la
libgtest_la_SOURCES = tests/gtest-sources.cc
libgtest_la_CPPFLAGS = $(AM_NOWARN_CPPFLAGS) -I$(GTEST_ROOT) -I$(GTEST_ROOT)/include
libgtest_la_CXXFLAGS = $(AM_NOWARN_CXXFLAGS)

tests_unit_tests_DEPENDENCIES += libgtest.la
tests_unit_tests_LDADD += libgtest.la -lpthread
tests_unit_tests_CPPFLAGS += -I$(GTEST_ROOT) -I$(GTEST_ROOT)/include $(NO_WERROR)
endif

CLEANFILES = tests/CouchbaseMock.jar
BUILT_SOURCES=
if DOWNLOAD_GTEST
gtest-1.6.0: gtest-1.6.0.zip
	${UNZIP} -o -qq gtest-1.6.0.zip
BUILT_SOURCES += gtest-1.6.0
CLEANFILES += gtest-1.6.0.zip
endif

distclean-local:
	@rm -rf gtest-1.6.0

if !HAVE_GOOGLETEST_SRC
tests_unit_tests_LDADD += -lgtest -lpthread
endif

tests/CouchbaseMock.jar:
	@echo "+---------------------------------------------+"
	@echo "| Download CouchbaseMock for functional tests |"
	@echo "+---------------------------------------------+"
	${DOWNLOAD} tests/CouchbaseMock.jar http://files.couchbase.com/maven2/org/couchbase/mock/CouchbaseMock/0.5-SNAPSHOT/CouchbaseMock-0.5-20120726.220757-19.jar

libmockserver_la_LDFLAGS = $(AM_LDFLAGS) $(AM_PROFILE_SOLDFLAGS)
libmockserver_la_DEPENDENCIES = tests/CouchbaseMock.jar
libmockserver_la_SOURCES = \
                         tests/server.c tests/loopfactory.c tests/server.h


noinst_PROGRAMS =
#
# Example programs using the library
#
if BUILD_TOOLS
noinst_PROGRAMS += example/pillowfight
if HAVE_LIBYAJL2
noinst_PROGRAMS += example/couchview_yajl
endif
endif

example_couchview_yajl_SOURCES = example/couchview_yajl.c
example_couchview_yajl_LDADD = libcouchbase.la -lyajl

check_PROGRAMS =

if BUILD_TOOLS
if HAVE_GOOGLETEST
# we can't build the test program without a C++ compiler
check_PROGRAMS += tests/unit-tests
endif
endif

if HAVE_COUCHBASEMOCK
noinst_LTLIBRARIES += libmockserver.la
tests_unit_tests_SOURCES += \
                            tests/arithmetic-unit-test.cc \
                            tests/get-unit-test.cc \
                            tests/getopt-unit-tests.cc \
                            tests/http-tests.cc \
                            tests/lock-unit-test.cc \
                            tests/loopfactory.c \
                            tests/mock-environment.cc \
                            tests/mock-environment.h \
                            tests/mock-unit-test.cc \
                            tests/mock-unit-test.h \
                            tests/mutate-unit-test.cc \
                            tests/server.c \
                            tests/server.h \
                            tests/serverops-unit-test.cc \
                            tests/serverparams.h \
                            tests/testutil.cc \
                            tests/testutil.h

check_PROGRAMS += \
                  tests/config-test \
                  tests/smoke-test
endif

tests_config_test_SOURCES = tests/test.h tests/config-test.c
tests_config_test_DEPENDENCIES = libcouchbase.la libmockserver.la libvbucket.la
tests_config_test_LDADD = $(tests_config_test_DEPENDENCIES)
tests_config_test_LDFLAGS = $(AM_LDFLAGS)

tests_smoke_test_SOURCES = tests/test.h tests/smoke-test.c
tests_smoke_test_LDADD = libcouchbase.la libmockserver.la

tools_cbc_DEPENDENCIES = libcouchbase.la libvbucket.la
tools_cbc_LDADD = $(tools_cbc_DEPENDENCIES)

if HAVE_LIBYAJL2
tools_cbc_LDADD += -lyajl
endif
tools_cbc_SOURCES =	\
					tools/cbc.cc \
					tools/cbc-util.cc \
					tools/cbc-util.h \
					tools/configuration.cc	\
					tools/commandlineparser.cc \
					tools/commandlineparser.h \
					tools/configuration.h

TESTS=${check_PROGRAMS}

example_pillowfight_SOURCES = tools/commandlineparser.cc example/pillowfight.cc
example_pillowfight_LDADD = libcouchbase.la

if BUILD_TOOLS
CBC_LINKS = \
			cbc-admin \
			cbc-cat \
			cbc-bucket-create \
			cbc-bucket-delete \
			cbc-cp \
			cbc-create \
			cbc-flush \
			cbc-hash \
			cbc-lock \
			cbc-rm \
			cbc-stats \
			cbc-unlock \
			cbc-verify \
			cbc-verbosity \
			cbc-version \
			cbc-view

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
             include/memcached/COPYING \
             include/memcached/README \
             include/ep-engine/README \
             src/iofactory_win32.c \
             contrib/libvbucket/rfc1321 \
             tests/start_mock.sh \
             win32

if HAVE_DOXYGEN
docs:
	(cd tests; $(DOXYGEN))
else
docs:
	@echo "You need doxygen to generate test documentation"
endif


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
               $(top_srcdir)/tests/*.{cc,c,h} \
               $(top_srcdir)/plugins/io/*/*.[ch] \
               $(top_srcdir)/win32/*.[ch]

sinclude packaging/*/package.mk
