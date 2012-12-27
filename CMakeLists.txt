# libcouchbase
# Copyright (C) 2013 Couchbase, Inc
# All rights reserved.
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

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
# Currently this file is only used for Windows

### BEGIN CONFIGURABLES ###
# These variables can be modified as needed

# Gtest source archive to use
SET(GTEST_ARCHIVE gtest-1.6.0.zip)
# Where to download archive (if it doesn't exist)
SET(GTEST_DLSERVER http://googletest.googlecode.com/files)

# Couchbase mock path to download
SET(COUCHBASE_MOCK_VERSION
    0.6-SNAPSHOT/CouchbaseMock-0.6-20130805.230415-1)

# Maven repository where ${COUCHBASE_MOCK_VERSION} is to be found
SET(COUCHBASE_MOCK_DLSERVER
    http://files.couchbase.com/maven2/org/couchbase/mock/CouchbaseMock)
project(libcouchbase)

# Enable/Disable tests
OPTION(LCB_NO_TESTS "Disable building of tests" OFF)

# Enable/Disable tools
OPTION(LCB_NO_TOOLS "Disable building of additional tools" OFF)

# library version
IF(EXISTS ${CMAKE_SOURCE_DIR}/VERSION)
    FILE(STRINGS ${CMAKE_SOURCE_DIR}/VERSION lines)
    FOREACH(line ${lines})
        STRING(REGEX REPLACE "^([^=]+)=(.*)" "\\1" varname "${line}")
        STRING(REGEX REPLACE "^([^=]+)=(.*)" "\\2" varvalue "${line}")
        SET(LCB_${varname} "${varvalue}")
    ENDFOREACH()
ENDIF()

IF (NOT LCB_VERSION)
    SET(LCB_VERSION "2.1.0")
ENDIF()

### END CONFIGURABLES ###

SET(NT_REQUIRED_VERSION 0x0501)

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    ${PROJECT_BINARY_DIR}/lib)

# Figure out how we're building!
IF(MSVC)
    IF(CMAKE_CL_64)
        SET(lcb_arch_string "amd64")
    ELSE()
        SET(lcb_arch_string "x86")
    ENDIF(CMAKE_CL_64)

    IF(MSVC80)
        SET(lcb_cc_string "vs8")
    ELSEIF(MSVC90)
        SET(lcb_cc_string "vc9")
    ELSEIF(MSVC_VERSION EQUAL 1600)
        SET(lcb_cc_string "vc10")
    ENDIF()
ELSE()
    SET(lcb_arch_string "x86") #mingw
    SET(lcb_cc_string "mingw")
ENDIF()

SET(lcb_package_name "libcouchbase-${LCB_VERSION}_${lcb_arch_string}_${lcb_cc_string}")
SET(LCB_INSTDIR ${PROJECT_BINARY_DIR}/${lcb_package_name})

SET(SOURCE_ROOT ${CMAKE_SOURCE_DIR})
INCLUDE_DIRECTORIES(BEFORE ${SOURCE_ROOT}/include
                           ${SOURCE_ROOT}/contrib
                           ${SOURCE_ROOT}/plugins/io/iocp
                           ${SOURCE_ROOT}/src
                           ${SOURCE_ROOT}/win32
                           ${SOURCE_ROOT})

IF(${MSVC})
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    SET(COMMON_FLAGS "/W3 /EHsc /FD /MP")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /TC")
ELSE()
    SET(COMMON_FLAGS "-Wall -gstabs")
ENDIF()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")


# These files are bundled in a static library.
# They export no symbols of their own and may
# be considered as 'static'
ADD_LIBRARY(lcbutils STATIC
            contrib/libvbucket/cJSON.c
            src/base64.c
            src/gethrtime.c
            src/genhash.c
            src/hashtable.c
            src/hashset.c
            src/list.c
            src/ringbuffer.c
            src/url_encoding.c
            win32/getopt.c)

ADD_LIBRARY(couchbase SHARED
            contrib/http_parser/http_parser.c
            contrib/libvbucket/crc32.c
            contrib/libvbucket/ketama.c
            contrib/libvbucket/rfc1321/md5c.c
            contrib/libvbucket/vbucket.c
            plugins/io/iocp/iocp_iops.c
            plugins/io/iocp/iocp_loop.c
            plugins/io/iocp/iocp_timer.c
            plugins/io/iocp/iocp_util.c
            plugins/io/select/plugin-select.c
            src/arithmetic.c
            src/bucketconfig/bconf_io.c
            src/bucketconfig/bconf_parse.c
            src/bucketconfig/bconf_io.c
            src/bucketconfig/bconf_parse.c
            src/cntl.c
            src/compat.c
            src/config_cache.c
            src/cookie.c
            src/durability.c
            src/error.c
            src/flush.c
            src/get.c
            src/handler.c
            src/http.c
            src/http/http_io.c
            src/http/http_parse.c
            src/instance.c
            src/io/connect.c
            src/io/readwrite.c
            src/iofactory.c
            src/isasl.c
            src/observe.c
            src/packet.c
            src/remove.c
            src/sanitycheck.c
            src/server.c
            src/server/server_io.c
            src/server/server_connect.c
            src/server/server_parse.c
            src/stats.c
            src/store.c
            src/strerror.c
            src/synchandler.c
            src/timeout.c
            src/timer.c
            src/timings.c
            src/touch.c
            src/utilities.c
            src/verbosity.c
            src/wait.c)

SET_TARGET_PROPERTIES(couchbase PROPERTIES
                      COMPILE_FLAGS -DLIBCOUCHBASE_INTERNAL=1)
ADD_DEFINITIONS(-DWINVER=${NT_REQUIRED_VERSION})
SET_TARGET_PROPERTIES(couchbase PROPERTIES PREFIX "lib")
SET_TARGET_PROPERTIES(couchbase PROPERTIES IMPORT_PREFIX "lib")
TARGET_LINK_LIBRARIES(couchbase ws2_32.lib lcbutils)


IF(NOT LCB_NO_TESTS)
    ADD_EXECUTABLE(unit-tests
            tests/arithmetic-unit-test.cc
            tests/base64-unit-test.cc
            tests/behavior-unit-tests.cc
            tests/ccbc_103.cc
            tests/cluster-unit-tests.cc
            tests/durability-unit-test.cc
            tests/get-unit-test.cc
            tests/getopt-unit-tests.cc
            tests/hashset-unit-test.cc
            tests/hostname-unit-test.cc
            tests/http-tests.cc
            tests/lock-unit-test.cc
            tests/memcached-compat-unit-test.cc
            tests/mock-unit-test.cc
            tests/mutate-unit-test.cc
            tests/regression-unit-test.cc
            tests/ringbuffer-unit-test.cc
            tests/serverops-unit-test.cc
            tests/strerror-unit-test.cc
            tests/syncmode-unit-tests.cc
            tests/url_encoding-tests.cc

    # Support files
            tests/server.c
            tests/timeout.c
            tests/testutil.cc
            tests/unit_tests.cc
            tests/mock-environment.cc)


    # Normally defined by config.h
    SET_PROPERTY(
        TARGET unit-tests
        APPEND PROPERTY COMPILE_DEFINITIONS
            HAVE_COUCHBASEMOCK
            BUILD_PLUGINS
    )

    IF(CMAKE_COMPILER_IS_GNUCXX)
        SET_TARGET_PROPERTIES(unit-tests
            PROPERTIES
            COMPILE_FLAGS "-Wno-sign-compare -Wno-missing-field-initializers")
    ENDIF(CMAKE_COMPILER_IS_GNUCXX)

    IF(NOT EXISTS ${CMAKE_SOURCE_DIR}/${GTEST_ARCHIVE})
        file(DOWNLOAD ${GTEST_DLSERVER}/${GTEST_ARCHIVE}
            ${CMAKE_SOURCE_DIR}/${GTEST_ARCHIVE})

        execute_process(COMMAND cmake -E tar zxf ${GTEST_ARCHIVE}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    ENDIF(NOT EXISTS ${CMAKE_SOURCE_DIR}/${GTEST_ARCHIVE})

    IF(NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)
        file(DOWNLOAD ${COUCHBASE_MOCK_DLSERVER}/${COUCHBASE_MOCK_VERSION}
            ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)
    ENDIF(NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)

    execute_process(COMMAND
        cmake -E tar zxf ${GTEST_ARCHIVE}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    # We're a library using the shared CRT. Don't use the static one
    SET(gtest_force_shared_crt ON CACHE BOOL
        "Use shared (DLL) runtime library event Google Test built as static library")

    ADD_SUBDIRECTORY(gtest-1.6.0 gtest-1.6.0)

    INCLUDE_DIRECTORIES(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    TARGET_LINK_LIBRARIES(unit-tests couchbase lcbutils gtest)
    enable_testing()
    ADD_TEST(tests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit-tests)
ENDIF(NOT LCB_NO_TESTS)


IF(NOT LCB_NO_TOOLS)
    ADD_EXECUTABLE(cbc
                tools/cbc-util.cc
                tools/cbc.cc
                tools/commandlineparser.cc
                tools/configuration.cc)

    TARGET_LINK_LIBRARIES(cbc couchbase lcbutils)

    ADD_EXECUTABLE(cbc-pillowfight
                tools/cbc-pillowfight.cc
                tools/commandlineparser.cc)

    TARGET_LINK_LIBRARIES(cbc-pillowfight couchbase lcbutils)

    INSTALL(TARGETS cbc cbc-pillowfight RUNTIME
            DESTINATION ${LCB_INSTDIR}/bin)
ENDIF(NOT LCB_NO_TOOLS)

INSTALL(TARGETS couchbase
        RUNTIME DESTINATION ${LCB_INSTDIR}/bin
        LIBRARY DESTINATION ${LCB_INSTDIR}/lib
        ARCHIVE DESTINATION ${LCB_INSTDIR}/lib)


INSTALL(FILES include/libcouchbase/arguments.h
              include/libcouchbase/behavior.h
              include/libcouchbase/callbacks.h
              include/libcouchbase/cntl.h
              include/libcouchbase/durability.h
              include/libcouchbase/compat.h
              include/libcouchbase/couchbase.h
              include/libcouchbase/error.h
              include/libcouchbase/http.h
              include/libcouchbase/sanitycheck.h
              include/libcouchbase/timings.h
              include/libcouchbase/types.h
              include/libcouchbase/visibility.h
              win32/libcouchbase/configuration.h
            DESTINATION ${LCB_INSTDIR}/include/libcouchbase)
