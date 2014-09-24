CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/contrib/cliopts)
FILE(GLOB T_COMMONSRC common/*.cc)
ADD_LIBRARY(lcbtools STATIC ${T_COMMONSRC} ${SOURCE_ROOT}/contrib/cliopts/cliopts.c)

ADD_EXECUTABLE(cbc cbc.cc)
TARGET_LINK_LIBRARIES(cbc couchbase lcbtools)

ADD_EXECUTABLE(cbc-pillowfight cbc-pillowfight.cc)
TARGET_LINK_LIBRARIES(cbc-pillowfight couchbase lcbtools)

INSTALL(TARGETS cbc cbc-pillowfight RUNTIME
    DESTINATION bin)
INSTALL_PDBS(cbc)
INSTALL_PDBS(cbc-pillowfight)
