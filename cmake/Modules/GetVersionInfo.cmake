# Gets the libcouchbase version
# Sets:
#  LCB_VERSION: Version string
#  LCB_CHANGESET: SCM Revision number
#  LCB_VERSION_HEX Numeric hex version
#  LCB_VERSION_MAJOR
#  LCB_VERSION_MINOR
#  LCB_VERSION_PATCH

## Try git first ##
FIND_PROGRAM(GIT_EXECUTABLE NAMES git git.exe)
MACRO(RUNGIT outvar)
    EXECUTE_PROCESS(COMMAND git ${ARGN}
        OUTPUT_VARIABLE ${outvar}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_STRIP_TRAILING_WHITESPACE)
ENDMACRO()

if (GIT_EXECUTABLE AND NOT LCB_SKIP_GIT_VERSION)
    RUNGIT(LCB_REVDESCRIBE describe --long --abbrev=10)
    RUNGIT(LCB_VERSION describe --abbrev=10)
    STRING(REPLACE "-" "_" LCB_VERSION "${LCB_VERSION}")
    MESSAGE(STATUS "Sanitized VERSION=${LCB_VERSION}")
    RUNGIT(LCB_VERSION_CHANGESET rev-parse HEAD)

    # Only when describe produced something. Given an empty version awk prints
    # the literal 0x000000, which CMake reads as true, and the fallback below
    # is then skipped and the zero reaches the generated header.
    IF(LCB_VERSION)
        EXECUTE_PROCESS(
            COMMAND echo ${LCB_VERSION}
            COMMAND awk -F. "{printf \"0x%0.2d%0.2d%0.2d\", $1, $2, $3}"
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE LCB_VERSION_HEX)
    ENDIF()
ENDIF()

IF(LCB_VERSION)
    # Have the version information
    CONFIGURE_FILE(${LCB_GENINFODIR}/distinfo.cmake.in ${LCB_GENINFODIR}/distinfo.cmake)
ENDIF()

# library version
IF(NOT LCB_VERSION AND EXISTS ${LCB_GENINFODIR}/distinfo.cmake)
    INCLUDE(${LCB_GENINFODIR}/distinfo.cmake)
ENDIF()

IF (NOT LCB_VERSION)
    SET(LCB_NOGITVERSION ON)
    SET(LCB_VERSION ${libcouchbase_VERSION})
ENDIF()
IF (NOT LCB_VERSION_CHANGESET)
    SET(LCB_VERSION_CHANGESET "0xdeadbeef")
ENDIF()
IF (NOT LCB_VERSION_HEX)
    # Two decimal digits per field, concatenated and read as hex, which is the
    # encoding the awk branch above produces: 3.3.19 is 0x030319.
    MATH(EXPR LCB_VERSION_HEX
         "(${libcouchbase_VERSION_MAJOR} / 10) * 0x100000 + (${libcouchbase_VERSION_MAJOR} % 10) * 0x10000 + (${libcouchbase_VERSION_MINOR} / 10) * 0x1000 + (${libcouchbase_VERSION_MINOR} % 10) * 0x100 + (${libcouchbase_VERSION_PATCH} / 10) * 0x10 + (${libcouchbase_VERSION_PATCH} % 10)"
         OUTPUT_FORMAT HEXADECIMAL)
ENDIF()

# Now parse the version string
STRING(REPLACE "." ";" LCB_VERSION_LIST "${LCB_VERSION}")
LIST(GET LCB_VERSION_LIST 0 LCB_VERSION_MAJOR)
LIST(GET LCB_VERSION_LIST 1 LCB_VERSION_MINOR)
LIST(GET LCB_VERSION_LIST 2 LCB_VERSION_PATCH)

# Determine the SONAME for the library
IF(APPLE)
    SET(LCB_SONAME_MAJOR "9")
ELSE()
    SET(LCB_SONAME_MAJOR "8")
ENDIF()
SET(LCB_SONAME_FULL "${LCB_SONAME_MAJOR}.0.27")

MESSAGE(STATUS "libcouchbase ${LCB_VERSION_MAJOR},${LCB_VERSION_MINOR},${LCB_VERSION_PATCH}")
MESSAGE(STATUS "Building libcouchbase ${LCB_VERSION}/${LCB_VERSION_CHANGESET}")
