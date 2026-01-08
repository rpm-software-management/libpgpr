
IF (RPM_LIBVERSION)
INCLUDE (CMakeLists-rpm.txt)
ELSE (RPM_LIBVERSION)

CMAKE_MINIMUM_REQUIRED (VERSION 3.5)

PROJECT (libpgpr C)

SET(LIBPGPR_SOVERSION "1")

INCLUDE (FindPkgConfig)

OPTION (WITH_OPENSSL "Use openssl instead of libgcrypt for internal crypto" OFF)

SET (libpgpr_SRCS
    api.c pgp.c armor.c lint.c pubkey.c merge.c util.c
)

if (WITH_OPENSSL)
    SET (libpgpr_SRCS ${libpgpr_SRCS} openssl.c)
else()
    SET (libpgpr_SRCS ${libpgpr_SRCS} libgcrypt.c)
endif()


ADD_LIBRARY (libpgpr SHARED ${libpgpr_SRCS})

SET_TARGET_PROPERTIES(libpgpr PROPERTIES OUTPUT_NAME "pgpr")
SET_TARGET_PROPERTIES(libpgpr PROPERTIES SOVERSION ${LIBPGPR_SOVERSION})


if (WITH_OPENSSL)
    FIND_PACKAGE(OpenSSL 1.0.2 REQUIRED)
    TARGET_LINK_LIBRARIES(libpgpr PRIVATE OpenSSL::Crypto)
else()
    PKG_CHECK_MODULES(LIBGCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
    TARGET_LINK_LIBRARIES(libpgpr PRIVATE PkgConfig::LIBGCRYPT)
endif()

ENABLE_TESTING ()
ADD_SUBDIRECTORY (test)

ENDIF (RPM_LIBVERSION)

