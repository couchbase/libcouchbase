# vim: set expandtab:
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
bin_PROGRAMS =
noinst_PROGRAMS =
noinst_LTLIBRARIES =

BUILT_SOURCES =
CLEANFILES =
libcouchbase_la_CPPFLAGS =
libcouchbase_la_DEPENDENCIES =
libcouchbase_la_LIBADD =
libcouchbase_la_SOURCES =
include filelist.mk

if BUILD_TOOLS
if HAVE_CXX
bin_PROGRAMS += tools/cbc tools/cbc-pillowfight
endif
endif

nobase_pkginclude_HEADERS = \
                             plugins/io/libuv/plugin-internal.h \
                             plugins/io/libuv/libuv_compat.h \
                             plugins/io/libuv/plugin-libuv.c

pkginclude_HEADERS += plugins/io/libuv/libuv_io_opts.h \
                      plugins/io/select/select_io_opts.h \
                      plugins/io/libev/libev_io_opts.h \
                      plugins/io/libevent/libevent_io_opts.h

libcouchbase_la_LDFLAGS= $(AM_LDFLAGS) -version-info $(API_CURRENT):$(API_REVISION):$(API_AGE) -no-undefined $(AM_PROFILE_SOLDFLAGS)
libcouchbase_la_CPPFLAGS += $(AM_CPPFLAGS) $(CPPFLAGS) -DLIBCOUCHBASE_INTERNAL=1 -DLCB_LIBDIR="\"${libdir}\""

if ENABLE_SSL
libcouchbase_la_LDFLAGS+=$(OPENSSL_LDFLAGS)
libcouchbase_la_CPPFLAGS+=$(OPENSSL_INCLUDES)
libcouchbase_la_LIBADD+=$(OPENSSL_LIBS)
endif

if !ENABLE_SSL
libcouchbase_la_CPPFLAGS+=-DLCB_NO_SSL
endif

if ENABLE_SNAPPY
if BUILD_STATIC_SNAPPY
libcouchbase_la_SOURCES += config/dummy-cxx.cc
else
libcouchbase_la_CPPFLAGS += $(SNAPPY_INCLUDES)
libcouchbase_la_LDFLAGS += $(SNAPPY_LDFLAGS)
libcouchbase_la_LIBADD += -lsnappy
endif
else
libcouchbase_la_CPPFLAGS += -DLCB_NO_SNAPPY=1
endif

if BUILD_TOOLS
tools_cbc_SOURCES =    tools/cbc.cc tools/cbc-handlers.h
tools_cbc_LDADD = libcouchbase.la liblcbtools.la
tools_cbc_pillowfight_SOURCES = tools/cbc-pillowfight.cc
tools_cbc_pillowfight_LDADD = libcouchbase.la liblcbtools.la -lpthread

CBC_LINKS = cbc-admin cbc-cat cbc-bucket-create cbc-bucket-delete cbc-cp cbc-create cbc-mcflush cbc-hash \
			cbc-lock cbc-rm cbc-stats cbc-unlock cbc-verify cbc-verbosity cbc-version cbc-view

install-exec-hook:
	cd $(DESTDIR)$(bindir) && \
               $(RM) $(CBC_LINKS) && \
               for f in $(CBC_LINKS); do $(LN_S) cbc$(EXEEXT) $$f$(EXEEXT); done

uninstall-local:
	cd $(DESTDIR)$(bindir) && $(RM) $(CBC_LINKS)
endif

EXTRA_DIST += LICENSE README.markdown \
              RELEASE_NOTES.markdown \
              include/libcouchbase/configuration.h.in \
              include/memcached/README include/memcached/COPYING \
              VERSION src/probes.d

LINTFLAGS=-Iinclude -b -c -errchk=%all \
          -erroff=E_INCL_NUSD,E_CAST_INT_TO_SMALL_INT,E_PTRDIFF_OVERFLOW  \
          -errtags=yes -errhdr=%user \
          -errsecurity=extended -fd -Ncheck=%all -Nlevel=4 -n -Xc99=none
lint:
	$(LINT.c) $(libcouchbase_la_SOURCES)
