# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024 Intel Corporation
project(isseilib)

set(ISSEI_SOURCES
  isseilib.c
  $<$<BOOL:${UNIX}>:linux/isseilib_linux.c>
  $<$<BOOL:${UNIX}>:linux/isseilib_sysfs.c>
  $<$<BOOL:${WIN32}>:win/isseilib_win.c>
  $<$<BOOL:${WIN32}>:win/isseilib_wmi.c>
  $<$<BOOL:${WIN32}>:${PROJECT_BINARY_DIR}/isseilib.rc>
)

set(ISSEI_LINK_LIBS
  $<$<BOOL:${WIN32}>:CfgMgr32.lib>
  $<$<BOOL:${WIN32}>:wbemuuid.lib>
)


if(WIN32)
    configure_file (
        "${PROJECT_SOURCE_DIR}/isseilib.rc.in"
        "${PROJECT_BINARY_DIR}/isseilib.rc"
    )
endif()

add_library(${PROJECT_NAME} ${ISSEI_SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ${CMAKE_SOURCE_DIR}/include/isseilib.h)
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${ISSEI_VERSION_STRING})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${ISSEI_VERSION_STRING})

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(${PROJECT_NAME} PRIVATE .)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} ${ISSEI_LINK_LIBS})
target_compile_definitions(${PROJECT_NAME} PRIVATE
                           $<$<BOOL:BUILD_SHARED_LIBS>:ISSEILIB_DLL>
                           $<$<BOOL:BUILD_SHARED_LIBS>:ISSEILIB_DLL_EXPORT>
)

set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)

if(NOT CONSOLE_OUTPUT)
  target_compile_definitions(${PROJECT_NAME} PRIVATE -DSYSLOG)
endif()

install(
  TARGETS ${PROJECT_NAME}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  PUBLIC_HEADER DESTINATION include
)
