# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2025 Intel Corporation

include(gtest.cmake)

add_executable(isseilib_basic_tests
  isseilib_tests.cpp
  isseilib_cpp_tests.cpp
)

target_link_libraries(isseilib_basic_tests
  GTest::GTest
  isseilib
)

install (TARGETS isseilib_basic_tests
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
