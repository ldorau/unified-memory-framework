# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(FindThreads)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(WARNING "The benchmarks SHOULD NOT be run in the Debug build type!")
endif()

if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
	set(LIBS_OPTIONAL ${LIBS_OPTIONAL} disjoint_pool)
endif()

if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
	set(LIBS_OPTIONAL ${LIBS_OPTIONAL} jemalloc_pool)
endif()

if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
	set(LIBS_OPTIONAL ${LIBS_OPTIONAL} scalable_pool)
endif()

add_executable(ubench ubench.c)

if(LINUX)
	set(LIBS_LINUX m)
endif()

add_dependencies(ubench
	umf
	${LIBS_OPTIONAL})

target_include_directories(ubench PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include/ ${UMF_CMAKE_SOURCE_DIR}/src/utils/)

target_link_libraries(ubench
	umf
	${LIBS_OPTIONAL}
	${CMAKE_THREAD_LIBS_INIT}
	${LIBS_LINUX})

if (UMF_BUILD_BENCHMARKS_MT)
	add_executable(multithread_bench multithread.cpp)
	target_link_libraries(multithread_bench
		umf
		${LIBS_OPTIONAL}
		pthread
		${LIBS_LINUX})
	target_include_directories(multithread_bench PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include/)
endif()

if (UMF_BUILD_OS_MEMORY_PROVIDER)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_OS_MEMORY_PROVIDER=1)

	if (UMF_BUILD_BENCHMARKS_MT)
		target_compile_definitions(multithread_bench PRIVATE UMF_BUILD_OS_MEMORY_PROVIDER=1)
	endif()
endif()

if (UMF_BUILD_OS_MEMORY_PROVIDER)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_OS_MEMORY_PROVIDER=1)
endif()

if (UMF_BUILD_LIBUMF_POOL_DISJOINT)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_LIBUMF_POOL_DISJOINT=1)

	if (UMF_BUILD_BENCHMARKS_MT)
		target_compile_definitions(multithread_bench PRIVATE UMF_BUILD_LIBUMF_POOL_DISJOINT=1)
	endif()
endif()

if (UMF_BUILD_LIBUMF_POOL_JEMALLOC)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_LIBUMF_POOL_JEMALLOC=1)

	if (UMF_BUILD_BENCHMARKS_MT)
		target_compile_definitions(multithread_bench PRIVATE UMF_BUILD_LIBUMF_POOL_JEMALLOC=1)
	endif()
endif()

if (UMF_BUILD_LIBUMF_POOL_SCALABLE)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_LIBUMF_POOL_SCALABLE=1)

	if (UMF_BUILD_BENCHMARKS_MT)
		target_compile_definitions(multithread_bench PRIVATE UMF_BUILD_LIBUMF_POOL_SCALABLE=1)
	endif()
endif()

# make that ubench can be run using ctest
add_test(NAME ubench
	COMMAND ubench
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(ubench PROPERTIES
	LABELS "benchmark"
	PASS_REGULAR_EXPRESSION "PASSED")

if(WINDOWS)
	# append PATH to DLLs
	set(DLL_PATH_LIST "PATH=path_list_append:../bin/$<CONFIG>")
	if(LIBHWLOC_DLL_DIRS)
		set(DLL_PATH_LIST "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_DLL_DIRS}")
	endif()
	if(LIBTBB_DLL_DIRS)
		set(DLL_PATH_LIST "${DLL_PATH_LIST};PATH=path_list_append:${LIBTBB_DLL_DIRS}")
	endif()
	set_property(TEST ubench PROPERTY ENVIRONMENT_MODIFICATION "${DLL_PATH_LIST}")
endif()
