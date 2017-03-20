INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_JSON JSON)

FIND_PATH(
    JSON_INCLUDE_DIRS
    NAMES libjson.h
    HINTS ${PC_JSON_INCLUDEDIR}
    PATHS $ENV{JSON_DIR}
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    JSON_LIBRARIES
    NAMES json
    HINTS $ENV{JSON_DIR}
        ${PC_JSON_LIBDIR}
    JSON_LIBRARIES
    PATHS $ENV{JSON_DIR}
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBJSON DEFAULT_MSG JSON_LIBRARIES JSON_INCLUDE_DIRS)
MARK_AS_ADVANCED(JSON_LIBRARIES JSON_INCLUDE_DIRS)
