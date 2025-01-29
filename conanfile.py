#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2025 Intel Corporation
from conans import ConanFile
import os

class ISSEILIBConan(ConanFile):
    name = "isseilib"
    generators = "cmake", "cmake_find_package", "visual_studio"
    settings = "os"
    options = {"build_tests": [True, False]}
    default_options = {"build_tests": False}

    def requirements(self):
        if self.options.build_tests:
            self.requires("gtest/1.12.1@mesw/stable")