SET(GTEST_ZIP_PATH ${SOURCE_ROOT}/${GTEST_ARCHIVE})
IF(NOT EXISTS ${GTEST_ZIP_PATH})
    MESSAGE(STATUS "${GTEST_ARCHIVE} not found. Downloading")
    IF(UNIX)
        EXECUTE_PROCESS(
            COMMAND
                wget -O "${GTEST_ZIP_PATH}" "${GTEST_DLSERVER}/${GTEST_ARCHIVE}")
        EXECUTE_PROCESS(
            COMMAND
                unzip "${GTEST_ZIP_PATH}"
            WORKING_DIRECTORY
                ${SOURCE_ROOT})
    ELSE()
        FILE(DOWNLOAD ${GTEST_DLSERVER}/${GTEST_ARCHIVE}
            ${SOURCE_ROOT}/${GTEST_ARCHIVE})
        EXECUTE_PROCESS(
            COMMAND cmake -E tar xf ${GTEST_ARCHIVE}
            WORKING_DIRECTORY ${SOURCE_ROOT})
    ENDIF()
ENDIF(NOT EXISTS ${GTEST_ZIP_PATH})

SET(gtest_force_shared_crt ON CACHE BOOL "" )
SET(BUILD_SHARED_LIBS ON)
ADD_SUBDIRECTORY(${SOURCE_ROOT}/gtest-1.7.0 gtest-1.7.0)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_EXECUTABLE(check-all EXCLUDE_FROM_ALL
    check-all.cc
    ${SOURCE_ROOT}/tools/commandlineparser.cc
    procutil.c)

SET_PROPERTY(TARGET check-all
    APPEND PROPERTY INCLUDE_DIRECTORIES
    ${lcb_plat_includes}
    ${SOURCE_ROOT}/tools)
TARGET_LINK_LIBRARIES(check-all couchbase_utils couchbase)

ADD_EXECUTABLE(smoke-test EXCLUDE_FROM_ALL
    smoke-test.c
    server.c
    timeout.c
    procutil.c)

FILE(GLOB T_BASIC_SRC basic/*.cc)
ADD_EXECUTABLE(nonio-tests EXCLUDE_FROM_ALL nonio_tests.cc ${T_BASIC_SRC})

FILE(GLOB T_IO_SRC iotests/*.cc)
ADD_EXECUTABLE(unit-tests EXCLUDE_FROM_ALL
    ${T_IO_SRC}

    # Support files
    procutil.c
    server.c
    timeout.c
    testutil.cc
    unit_tests.cc
    mock-environment.cc)


# Normally defined by config.h
SET_PROPERTY(
    TARGET unit-tests smoke-test
    APPEND PROPERTY COMPILE_DEFINITIONS
    HAVE_COUCHBASEMOCK
    BUILD_PLUGINS
    )

IF(CMAKE_COMPILER_IS_GNUCXX)
    SET_TARGET_PROPERTIES(unit-tests smoke-test
        PROPERTIES
        COMPILE_FLAGS "-Wno-sign-compare -Wno-missing-field-initializers")
ENDIF(CMAKE_COMPILER_IS_GNUCXX)



IF(NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)
    file(DOWNLOAD ${COUCHBASE_MOCK_DLSERVER}/${COUCHBASE_MOCK_VERSION}
        ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)
ENDIF(NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/CouchbaseMock.jar)

# We're a library using the shared CRT. Don't use the static one
INCLUDE_DIRECTORIES(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
TARGET_LINK_LIBRARIES(unit-tests couchbase couchbase_utils gtest)
TARGET_LINK_LIBRARIES(nonio-tests couchbase couchbase_utils gtest)
TARGET_LINK_LIBRARIES(smoke-test couchbase couchbase_utils)


MACRO(BUILD_TEST target)
    ADD_TEST(NAME BUILD-${target}
        COMMAND ${CMAKE_COMMAND} --build "${CMAKE_BINARY_DIR}" --target ${target})
ENDMACRO()

BUILD_TEST(check-all)
BUILD_TEST(smoke-test)
BUILD_TEST(unit-tests)
BUILD_TEST(nonio-tests)

MACRO(DEFINE_MOCKTEST plugin test)
    ADD_TEST(
        NAME
            check-${plugin}-${test}
        COMMAND
            $<TARGET_FILE:check-all>
            --srcdir "${CMAKE_SOURCE_DIR}"
            --testdir "$<TARGET_FILE_DIR:check-all>"
            --opt_plugins ${plugin}
            --tests ${test}
            --verbose
            --
            --gtest_print_time=1
            --gtest_output=xml:"${CMAKE_BINARY_DIR}/REPORT_${plugin}_${test}.xml")
ENDMACRO()


ADD_TEST(NAME check-nonio COMMAND $<TARGET_FILE:nonio-tests>)

DEFINE_MOCKTEST("select" "unit-tests")
DEFINE_MOCKTEST("select" "smoke-test")
IF(WIN32)
    DEFINE_MOCKTEST("iocp" "unit-tests")
    DEFINE_MOCKTEST("iocp" "smoke-test")
ENDIF()
IF(HAVE_LIBEVENT)
    DEFINE_MOCKTEST("libevent" "unit-tests")
    DEFINE_MOCKTEST("libevent" "smoke-test")
ENDIF()
IF(HAVE_LIBEV)
    DEFINE_MOCKTEST("libev" "unit-tests")
    DEFINE_MOCKTEST("libev" "smoke-test")
ENDIF()
IF(HAVE_LIBUV)
    DEFINE_MOCKTEST("libuv" "unit-tests")
    DEFINE_MOCKTEST("libuv" "smoke-test")
ENDIF()
