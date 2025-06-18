# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_level_zero_shared_memory LANGUAGES C)
enable_testing()

set(UMF_EXAMPLE_DIR "${CMAKE_SOURCE_DIR}/..")
list(APPEND CMAKE_MODULE_PATH "${UMF_EXAMPLE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")

find_package(PkgConfig)

# pkg_check_modules(UMF libumf)
# if(NOT UMF_FOUND)
#     find_package(UMF REQUIRED libumf)
# endif()

include("find_umf.cmake")
set(UMF_LIBRARIES umf::umf umf::headers)

pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()

pkg_check_modules(ZE_LOADER ze_loader)
if(NOT ZE_LOADER_FOUND)
    find_package(ZE_LOADER REQUIRED ze_loader)
endif()

set(EXAMPLE_NAME umf_example_level_zero_shared_memory)
set(LEVEL_ZERO_SM_LIBRARY_DIRS ${UMF_LIBRARY_DIRS} ${LIBHWLOC_LIBRARY_DIRS}
                               ${ZE_LOADER_LIBRARY_DIRS})

# build the example
add_executable(
    ${EXAMPLE_NAME} level_zero_shared_memory.c
                    ${UMF_EXAMPLE_DIR}/common/examples_level_zero_helpers.c)

target_include_directories(
    ${EXAMPLE_NAME} PRIVATE ${UMF_INCLUDE_DIRS} ${ZE_LOADER_INCLUDE_DIRS}
                            ${UMF_EXAMPLE_DIR}/common)
target_link_directories(${EXAMPLE_NAME} PRIVATE ${LEVEL_ZERO_SM_LIBRARY_DIRS})
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--start-group")
target_link_libraries(${EXAMPLE_NAME} PRIVATE ze_loader ${UMF_LIBRARIES})
if(LINUX)
    target_link_libraries(${EXAMPLE_NAME} PRIVATE stdc++)
endif()
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--end-group")

# an optional part - adds a test of this example
add_test(
    NAME ${EXAMPLE_NAME}
    COMMAND ${EXAMPLE_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example-standalone")

if(LINUX)
    # set LD_LIBRARY_PATH
    string(JOIN ":" LEVEL_ZERO_SM_LIBRARY_DIRS_JOINED
           ${LEVEL_ZERO_SM_LIBRARY_DIRS})
    set_property(
        TEST ${EXAMPLE_NAME}
        PROPERTY
            ENVIRONMENT_MODIFICATION
            "LD_LIBRARY_PATH=path_list_append:${LEVEL_ZERO_SM_LIBRARY_DIRS_JOINED}"
    )
endif()
