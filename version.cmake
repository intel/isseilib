# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023 Intel Corporation

file(READ VERSION VER_FILE)
string(STRIP "${VER_FILE}" VER_FILE)
string(REPLACE "." ";" VER_LIST ${VER_FILE})
list(GET VER_LIST 0 ISSEI_VERSION_MAJOR)
list(GET VER_LIST 1 ISSEI_VERSION_MINOR)
list(GET VER_LIST 2 ISSEI_VERSION_PATCH)
set(ISSEI_VERSION_STRING
    ${ISSEI_VERSION_MAJOR}.${ISSEI_VERSION_MINOR}.${ISSEI_VERSION_PATCH})
set(ISSEI_VERSION_COMM
    ${ISSEI_VERSION_MAJOR},${ISSEI_VERSION_MINOR},${ISSEI_VERSION_PATCH},0)