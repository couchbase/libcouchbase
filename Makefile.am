#
#     Copyright 2010 Membase, Inc.
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
# Automake file used to build libmembase. Please avoid using propritary
# make constructs, but keep the syntax portable. To reduce the posibility
# for merge conflicts all list of files should be sorted aphabetically
# (If everyone always add their files to the end of the list that line will
# always result in a conflict..)
#
# @author Trond Norbye
#
ACLOCAL_AMFLAGS = -I m4 --force

lib_LTLIBRARIES = libmembase.la

pkginclude_HEADERS = \
                     include/libmembase/callbacks.h \
                     include/libmembase/membase.h \
                     include/libmembase/types.h

libmembase_la_SOURCES = \
                        src/arithmetic.c \
                        src/base64.c \
                        src/cookie.c \
                        src/create.c \
                        src/event.c \
                        src/execute.c \
                        src/get.c \
                        src/handler.c \
                        src/store.c \
                        src/tap.c \
                        src/utilities.c

# Please remember to update the version info before each release if you
# add / remove functions.
libmembase_la_LDFLAGS=$(LTLIBEVENT) $(LTLIBVBUCKET) $(LTLIBSASL) $(LTLIBSASL2) \
                      -version-info 0:0:0
libmembase_la_CPPFLAGS=$(AM_CPPFLAGS) $(CPPFLAGS) -DLIBMEMBASE_INTERNAL=1

#
# Example programs using the library
#
noinst_PROGRAMS = \
               example/memcat \
               example/memcp \
               example/memdump

example_memcat_SOURCES = example/memcat.c
example_memcat_LDADD = libmembase.la
example_memcat_LDFLAGS = $(LTLIBEVENT)

example_memcp_SOURCES = example/memcp.c
example_memcp_LDADD = libmembase.la
example_memcp_LDFLAGS = $(LTLIBEVENT)

example_memdump_SOURCES = example/memdump.c
example_memdump_LDADD = libmembase.la
example_memdump_LDFLAGS = $(LTLIBEVENT)

