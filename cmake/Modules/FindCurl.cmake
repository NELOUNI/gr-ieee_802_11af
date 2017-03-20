INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_CURL curl)

FIND_PATH(
    CURL_INCLUDE_DIRS
    NAMES curl/curl.h
    HINTS ${PC_CURL_INCLUDEDIR}
    PATHS /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    CURL_LIBRARIES
    NAMES curl
    HINTS ${PC_CURL_LIBDIR}
    PATHS /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CURL DEFAULT_MSG CURL_LIBRARIES CURL_INCLUDE_DIRS)
MARK_AS_ADVANCED(CURL_LIBRARIES CURL_INCLUDE_DIRS)

