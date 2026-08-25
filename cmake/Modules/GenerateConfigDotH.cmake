# Writes the 'config.h' header..
INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)

IF(UNIX)
    CHECK_FUNCTION_EXISTS(gethrtime HAVE_GETHRTIME)
    CHECK_FUNCTION_EXISTS(gettimeofday HAVE_GETTIMEOFDAY)
    CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
    CHECK_FUNCTION_EXISTS(setitimer HAVE_SETITIMER)
    CHECK_SYMBOL_EXISTS(htonll arpa/inet.h HAVE_HTONLL)
    CHECK_SYMBOL_EXISTS(res_search "netinet/in.h;resolv.h" HAVE_RES_SEARCH)
    # res_ninit is a macro on glibc and CHECK_SYMBOL_EXISTS is satisfied by the
    # macro alone, without linking anything. The bounded lookup also calls
    # res_nsearch, which lives in libresolv rather than libc before glibc 2.34,
    # so the probe compiles and links all three calls against the library the
    # build links.
    SET(CMAKE_REQUIRED_LIBRARIES resolv)
    CHECK_C_SOURCE_COMPILES("
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
int main(void)
{
    struct __res_state state;
    unsigned char buf[16];
    if (res_ninit(&state) != 0) {
        return 1;
    }
    (void)res_nsearch(&state, \"example.com\", ns_c_in, ns_t_srv, buf, sizeof(buf));
    res_nclose(&state);
    return 0;
}" HAVE_RES_NINIT)
    UNSET(CMAKE_REQUIRED_LIBRARIES)
    CHECK_INCLUDE_FILES(dlfcn.h HAVE_DLFCN_H)
    CHECK_INCLUDE_FILES(netdb.h HAVE_NETDB_H)
    CHECK_INCLUDE_FILES(stdint.h HAVE_STDINT_H)
    CHECK_INCLUDE_FILES(stddef.h HAVE_STDDEF_H)
    CHECK_INCLUDE_FILES(strings.h HAVE_STRINGS_H)
    CHECK_INCLUDE_FILES(sys/socket.h HAVE_SYS_SOCKET_H)
    CHECK_INCLUDE_FILES(sys/stat.h HAVE_SYS_STAT_H)
    CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
    CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
    CHECK_INCLUDE_FILES(sys/uio.h HAVE_SYS_UIO_H)
    CHECK_INCLUDE_FILES(fcntl.h HAVE_FCNTL_H)
    CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
    CHECK_INCLUDE_FILES(arpa/inet.h HAVE_ARPA_INET_H)
    CHECK_INCLUDE_FILES(inttypes.h HAVE_INTTYPES_H)
    CHECK_INCLUDE_FILES(arpa/nameser.h HAVE_ARPA_NAMESER_H)
ENDIF()

IF (WIN32)
    CHECK_FUNCTION_EXISTS(_ftime64_s HAVE__FTIME64_S)
ENDIF()

CONFIGURE_FILE(
    ${PROJECT_SOURCE_DIR}/cmake/config-cmake.h.in
    ${LCB_GENSRCDIR}/config.h)
CONFIGURE_FILE(
    ${PROJECT_SOURCE_DIR}/cmake/build-timestamp.h.in
    ${LCB_GENSRCDIR}/build-timestamp.h)
