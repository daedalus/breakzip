cmake_minimum_required (VERSION 3.5.2 FATAL_ERROR)
project (breakzip CXX CUDA)
set (breakzip_VERSION_MAJOR 1)
set (breakzip_VERSION_MINOR 0)
set (breakzip_VERSION_PATCH 0)

set (WITH_TCMALLOC 0)

include(CTest)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")

include (CheckCXXCompilerFlag)

CHECK_CXX_COMPILER_FLAG("-std=c++14" COMPILER_SUPPORTS_CXX14)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)

if (COMPILER_SUPPORTS_CXX14)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
elseif (COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif (COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else ()
    message(STATUS "No C++11 support from compile! Get a real compiler!")
endif ()

# Disable certain warnings.
# TODO(leaf): Fix up all instances of these printf warnings.
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")
# TODO(leaf): Fix up all the unused result warnings.
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-reserved-user-defined-literal")

# Warnings should always be errors.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

set(THIRD_PARTY_BUILD build.out)

function(find_third_party_pkg argName)
    find_package(${argName} PATHS ${THIRD_PARTY_BUILD})
    include_directories("${${argName}_INCLUDE_DIRS}")
    set(LIBS ${LIBS} ${${argName}_LIBRARY} PARENT_SCOPE)
    set(LIB_FILES ${LIB_FILES} ${${argName}_LIB_FILES} PARENT_SCOPE)
endfunction(find_third_party_pkg)

# Find a package in third-party like this:
find_third_party_pkg(check)

file(GLOB SHARE_FILES "share/*")

install(FILES ${LIBS} DESTINATION lib/breakziplib)
install(FILES ${LIB_FILES} DESTINATION lib/breakziplib)
install(FILES ${SHARE_FILES} DESTINATION share/breakzip)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
set(LIBS ${LIBS} Threads::Threads)

if (WITH_TCMALLOC)
    find_package(TCMALLOC REQUIRED)
    include_directories(${TCMALLOC_INCLUDE_DIRS})
    set(LIBS ${LIBS} ${TCMALLOC_LIBRARIES})
ENDIF()

find_package(GFLAGS REQUIRED)
include_directories(${GFLAGS_INCLUDE_DIRS})
set(LIBS ${LIBS} ${GFLAGS_LIBRARIES})

find_package(LIBRT REQUIRED)
include_directories(${LIBRT_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBRT_LIBRARIES})

find_package(Readline REQUIRED)
include_directories(${Readline_INCLUDE_DIRS})
set(LIBS ${LIBS} ${Readline_LIBRARY})

#find_package(ICU REQUIRED)
#include_directories(${ICU_INCLUDE_DIRS})
#set(LIBS ${LIBS} ${ICU_LIBRARIES})

message(STATUS "Linking: ${LIBS}")

include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/src/cuda_common/inc")

# So that cmake can find breakzip_config.h
include_directories("${CMAKE_CURRENT_BINARY_DIR}/src")
add_subdirectory (src)

#configure_file (
#    "${PROJECT_SOURCE_DIR}/src/breakzip_config.h.in"
#    "${PROJECT_BINARY_DIR}/src/breakzip_config.h"
#    )

include_directories("${PROJECT_BINARY_DIR}")

INCLUDE(InstallRequiredSystemLibraries)

SET(CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES src/cuda_common/inc /usr/local/cuda/include)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "BreakZip - cracking utils for old zip archives")
SET(CPACK_PACKAGE_VENDOR "Pyrofex Corporation")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/Copyright.txt")
SET(CPACK_PACKAGE_VERSION_MAJOR ${breakzip_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${breakzip_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${breakzip_VERSION_PATCH})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")

# Just Unix so far.
SET(CPACK_STRIP_FILES "build.out/src/breakzip")
SET(CPACK_SOURCE_STRIP_FILES "")

SET(CPACK_PACKAGE_EXECUTABLES "build.out/src/breakzip" "breakzip")

SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nash Foster")
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS
    "automake (>= 1:1.15-4), \
    build-essential (>= 12.2), \
    cmake (>= 3.6.2-1), \
    debian-keyring (>= 2016.09.04), \
    doxygen (>= 1.8.12-1), \
    g++-6-multilib (>= 6.1.1-11), \
    g++-multilib (>= 4:6.1.1-1), \
    libgflags-dev (>= 2.1.2-3), \
    libstdc++6-6-dbg:amd64 (>= 6.1.1-11), \
    pkg-config (>= 0.29-4), \
    texinfo (>= 6.3.0.dfsg.1-1+b1)")

INCLUDE(CPack)

