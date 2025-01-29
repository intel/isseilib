# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2025 Intel Corporation
cmake_minimum_required(VERSION 3.15)
project(issei)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}")
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

option(BUILD_MSVC_RUNTIME_STATIC "Build with static runtime libraries on MSVC" NO)
option(BUILD_SHARED_LIBS "Build shared library" NO)
option(BUILD_SAMPLES "Build samples" NO)
option(BUILD_TESTS "Build tests" NO)
option(BUILD_DOCS "Build docs" NO)
option(BUILD_USE_CONAN "Use Conan for dependencies download" NO)
option(CONSOLE_OUTPUT "Push debug and error output to console (instead of syslog)" YES)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)

include(GNUInstallDirs)

set(LICENSE Apache)
include(version.cmake)

if(BUILD_USE_CONAN)
  include(conan)
  conan_cmake_autodetect(settings)
  # conan.cmake failed to detect MT, force-replace it
  string(REPLACE "compiler.runtime=MD" "compiler.runtime=MT" flags "${settings}")
  if(BUILD_TESTS)
    set(BUILD_TESTS_OPTION True)
  else()
    set(BUILD_TESTS_OPTION False)
  endif()
  conan_cmake_install(PATH_OR_REFERENCE ${CMAKE_CURRENT_SOURCE_DIR} SETTINGS ${flags} OPTIONS build_tests=${BUILD_TESTS_OPTION})
endif()

set(COMPILE_OPTIONS_NX
    -Wall
    -Wextra
    -Werror
    -Wsign-compare
    -Wformat
    -Wformat-security
    -Winit-self
    -Wstrict-prototypes
    -Wconversion
    -Woverflow
    -fwrapv
    -fPIC
    -fstack-protector-strong
    -D_GNU_SOURCE
    "$<$<CONFIG:Debug>:-DDEBUG;-D_DEBUG>"
    "$<$<CONFIG:Debug>:-O0;-g3;-ggdb>"
    "$<$<CONFIG:Release>:-O2;-D_FORTIFY_SOURCE=2>"
)
include(CheckCCompilerFlag)
check_c_compiler_flag(-Wshadow WARNING_SHADOW)
if(WARNING_SHADOW)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wshadow)
endif()
check_c_compiler_flag(-Wnull-dereference WARNING_NULL_DEREFERENCE)
if(WARNING_NULL_DEREFERENCE)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wnull-dereference)
endif()
check_c_compiler_flag(-Wfloat-conversion WARNING_FLOAT_CONVERSION)
if(WARNING_FLOAT_CONVERSION)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wfloat-conversion)
endif()
check_c_compiler_flag(-Wsign-conversion WARNING_SIGN_CONVERSION)
if(WARNING_SIGN_CONVERSION)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wsign-conversion)
endif()
check_c_compiler_flag(-Wstringop-truncation WARNING_STRINGOP_TRUNCATION)
if(WARNING_STRINGOP_TRUNCATION)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wstringop-truncation)
endif()
check_c_compiler_flag(-Wjump-misses-init WARNING_JUMP_MISSES_INIT)
if(WARNING_JUMP_MISSES_INIT)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wjump-misses-init)
endif()
check_c_compiler_flag(-Wunsuffixed-float-constants WARNING_UNSUFFIXED_FLOAT_CONSTANTS)
if(WARNING_UNSUFFIXED_FLOAT_CONSTANTS)
  set(COMPILE_OPTIONS_NX ${COMPILE_OPTIONS} -Wunsuffixed-float-constants)
endif()
set(COMPILE_OPTIONS_GCC
    -fno-strict-overflow
    -fno-delete-null-pointer-checks
)

set(COMPILE_OPTIONS_WIN
    /DUNICODE
    /D_UNICODE
    /W4
    /WX
    /GS
    /sdl
    "$<$<CONFIG:Release>:/Zi>"
    "$<$<CONFIG:Debug>:-DDEBUG;-D_DEBUG>"
)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(LINK_OPTIONS_NX "-z noexecstack -z relro -z now")
set(LINK_EXE_OPTIONS_NX "-pie")
set(LINK_OPTIONS_WIN "/NXCompat /DynamicBase /GUARD:CF /INCREMENTAL:NO /DEBUG:FULL /OPT:REF /OPT:ICF")

if(CMAKE_C_COMPILER_ID MATCHES Clang OR
   CMAKE_C_COMPILER_ID MATCHES AppleClang)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_NX})
    set(LINK_OPTIONS ${LINK_OPTIONS_NX})
    set(LINX_EXE_OPTIONS ${LINK_EXE_OPTIONS_NX})
elseif(CMAKE_C_COMPILER_ID MATCHES GNU)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_NX} ${COMPILE_OPTIONS_GCC})
    set(LINK_OPTIONS ${LINK_OPTIONS_NX})
    set(LINX_EXE_OPTIONS ${LINK_EXE_OPTIONS_NX})
elseif(CMAKE_C_COMPILER_ID MATCHES MSVC)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_WIN})
    set(LINK_OPTIONS ${LINK_OPTIONS_WIN})
endif()

set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${LINK_OPTIONS} ${LINX_EXE_OPTIONS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINK_OPTIONS}")

if(BUILD_MSVC_RUNTIME_STATIC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_subdirectory(lib)

# Documentation
if(BUILD_DOCS)
  find_package(Doxygen)
  if(DOXYGEN_FOUND)
    set(DOXYGEN_INPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/include/Doxyfile.in
      ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY
    )

    add_custom_target(
      doc ALL
      ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating documentation with Doxygen"
      VERBATIM
    )

    if(UNIX)
      install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/man/man3
            DESTINATION ${CMAKE_INSTALL_MANDIR}
      )
      install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
              DESTINATION ${CMAKE_INSTALL_DOCDIR}
      )
    else()
      install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION doc)
    endif()
  endif()
endif()

# CPack
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION_MAJOR ${ISSEI_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${ISSEI_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${ISSEI_VERSION_PATCH})
set(CPACK_PACKAGE_VENDOR "Intel, Inc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Intel(R) Silicon Security Engine Interface Library")
set(CPACK_PACKAGE_CONTACT "TBD")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${PROJECT_SOURCE_DIR}/DESCRIPTION)
set(CPACK_SOURCE_GENERATOR "TBZ2;ZIP")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_NAME}-${ISSEI_VERSION_STRING})
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

# RPM Specific
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_LICENSE ${LICENSE})
set(CPACK_RPM_PACKAGE_GROUP "Development")

# Debian Specific
set(CPACK_DEBIAN_PACKAGE_VERSION 1)
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")

if(UNIX)
  set(CPACK_GENERATOR "TGZ")

  find_program(RPM_EXE rpmbuild)
  if(RPM_EXE)
    list(APPEND CPACK_GENERATOR "RPM")
  endif(RPM_EXE)

  find_program(DEB_EXE debuild)
  if(DEB_EXE)
    list(APPEND CPACK_GENERATOR "DEB")
  endif(DEB_EXE)
else(UNIX)
  set(CPACK_GENERATOR "ZIP")
endif(UNIX)

include(CPack)

if(BUILD_SAMPLES)
  add_subdirectory(samples)
endif(BUILD_SAMPLES)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif(BUILD_TESTS)
