# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'libtbb' using find_library()")

find_library(LIBTBB_LIBRARY NAMES libtbbmalloc tbbmalloc)
set(LIBTBB_LIBRARIES ${LIBTBB_LIBRARY})

find_file(LIBTBB_HEADER NAMES "tbb/scalable_allocator.h")
if(LIBTBB_HEADER)
	get_filename_component(LIBTBB_INCLUDE_DIR_TBB ${LIBTBB_HEADER} DIRECTORY)
	get_filename_component(LIBTBB_INCLUDE_DIR ${LIBTBB_INCLUDE_DIR_TBB} DIRECTORY)
	set(LIBTBB_INCLUDE_DIRS ${LIBTBB_INCLUDE_DIR})
else()
	set(MSG_NOT_FOUND "<tbb/scalable_allocator.h> header NOT found (set CMAKE_PREFIX_PATH to point the location)")
	if(LIBTBB_FIND_REQUIRED)
		message(FATAL_ERROR ${MSG_NOT_FOUND})
	else()
		message(WARNING ${MSG_NOT_FOUND})
	endif()
endif()

if(WINDOWS)
	find_file(LIBTBB_DLL NAMES "bin/tbbmalloc.dll")
	get_filename_component(LIBTBB_DLL_DIR ${LIBTBB_DLL} DIRECTORY)
	set(LIBTBB_DLL_DIRS ${LIBTBB_DLL_DIR})
endif()

if(LIBTBB_LIBRARY)
	message(STATUS "  Found libtbb using find_library()")
	message(STATUS "    LIBTBB_LIBRARIES = ${LIBTBB_LIBRARIES}")
	message(STATUS "    LIBTBB_INCLUDE_DIRS = ${LIBTBB_INCLUDE_DIRS}")
	if(WINDOWS)
		message(STATUS "    LIBTBB_DLL_DIRS = ${LIBTBB_DLL_DIRS}")
	endif()
else()
	set(MSG_NOT_FOUND "libtbb NOT found (set CMAKE_PREFIX_PATH to point the location)")
	if(LIBTBB_FIND_REQUIRED)
		message(FATAL_ERROR ${MSG_NOT_FOUND})
	else()
		message(WARNING ${MSG_NOT_FOUND})
	endif()
endif()
