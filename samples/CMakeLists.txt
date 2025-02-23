# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2025 Intel Corporation
cmake_minimum_required(VERSION 3.15)
project(isseilib_samples)

add_executable(isseilib_enumerate_status enumerate_status.c)
target_compile_options(isseilib_enumerate_status PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(isseilib_enumerate_status isseilib)
install(TARGETS isseilib_enumerate_status RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(isseilib_basic_flow basic_flow.c)
target_compile_options(isseilib_basic_flow PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(isseilib_basic_flow isseilib)
install(TARGETS isseilib_basic_flow RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(isseilib_cpp_basic_flow cpp_basic_flow.cpp)
target_compile_options(isseilib_cpp_basic_flow PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(isseilib_cpp_basic_flow isseilib)
install(TARGETS isseilib_cpp_basic_flow RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(isseilib_spdm_get_version spdm_get_version.c)
target_compile_options(isseilib_spdm_get_version PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(isseilib_spdm_get_version isseilib)
install(TARGETS isseilib_spdm_get_version RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
