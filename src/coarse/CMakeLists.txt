# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(COARSE_SOURCES coarse.c ../ravl/ravl.c ${BA_SOURCES})

add_umf_library(
    NAME coarse
    TYPE STATIC
    SRCS ${COARSE_SOURCES}
    LIBS ${UMF_LIBS})

target_include_directories(
    coarse
    PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/ravl>)

add_library(${PROJECT_NAME}::coarse ALIAS coarse)

install(TARGETS coarse EXPORT ${PROJECT_NAME}-targets)
