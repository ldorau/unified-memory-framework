# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'libhwloc' using find_library()")

find_library(LIBHWLOC_LIBRARY NAMES libhwloc hwloc)
set(LIBHWLOC_LIBRARIES ${LIBHWLOC_LIBRARY})

find_file(LIBHWLOC_HEADER NAMES hwloc.h HINTS /usr/include/ ${CMAKE_PREFIX_PATH}/include)
get_filename_component(LIBHWLOC_INCLUDE_DIR ${LIBHWLOC_HEADER} DIRECTORY)
set(LIBHWLOC_INCLUDE_DIRS ${LIBHWLOC_INCLUDE_DIR})

if(LIBHWLOC_LIBRARY)
	message(STATUS "  Found libhwloc using find_library()")
else()
	set(MSG_NOT_FOUND "libhwloc NOT found (set CMAKE_PREFIX_PATH to point the location)")
	if(LIBHWLOC_FIND_REQUIRED)
		message(FATAL_ERROR ${MSG_NOT_FOUND})
	else()
		message(WARNING ${MSG_NOT_FOUND})
	endif()
endif()
