CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
ADD_EXECUTABLE(cbc
    cbc-util.cc
    cbc.cc
    commandlineparser.cc
    configuration.cc)


TARGET_LINK_LIBRARIES(cbc couchbase)

ADD_EXECUTABLE(cbc-pillowfight
    cbc-pillowfight.cc
    commandlineparser.cc)

TARGET_LINK_LIBRARIES(cbc-pillowfight couchbase)

INSTALL(TARGETS cbc cbc-pillowfight RUNTIME
    DESTINATION bin)
