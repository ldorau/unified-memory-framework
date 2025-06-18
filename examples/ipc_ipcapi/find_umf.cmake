#
# Copyright (C) 2025 Intel Corporation
#
# SPDX-License-Identifier: MIT
#

message(STATUS "Downloading Unified Memory Framework from github.com")

if(NOT DEFINED UMF_REPO)
  # set(UMF_REPO "https://github.com/oneapi-src/unified-memory-framework.git")
  set(UMF_REPO "https://github.com/ldorau/unified-memory-framework.git")
endif()

if(NOT DEFINED UMF_TAG)
  # set(UMF_TAG level-zero)
  set(UMF_TAG cdb6ca6506e998e0061bc23f71fc236eb9b62f80)
endif()

message(STATUS "Will fetch Unified Memory Framework from ${UMF_REPO} at ${UMF_TAG}")
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")

include(FetchContent)

message(STATUS ">>> Unified Memory Framework: FetchContent_Declare(unified-memory-framework)")
FetchContent_Declare(unified-memory-framework
                     GIT_REPOSITORY ${UMF_REPO}
                     GIT_TAG ${UMF_TAG}
)

set(L0_USE_EXTERNAL_UMF OFF CACHE BOOL "Use a pre-built UMF")

if(L0_USE_EXTERNAL_UMF)
  find_package(UMF REQUIRED umf)
  # Add an alias matching the FetchContent case
  add_library(umf::headers ALIAS umf::umf_headers)
else()
  set(UMF_BUILD_TESTS OFF CACHE INTERNAL "Build UMF tests")
  set(UMF_BUILD_EXAMPLES OFF CACHE INTERNAL "Build UMF examples")
  set(UMF_BUILD_SHARED_LIBRARY OFF CACHE INTERNAL "Build UMF shared library")
  set(UMF_BUILD_LIBUMF_POOL_DISJOINT ON CACHE INTERNAL "Build Disjoint Pool")
  set(UMF_BUILD_CUDA_PROVIDER OFF CACHE INTERNAL "Do not build CUDA provider")
  set(UMF_DISABLE_HWLOC ON CACHE INTERNAL "UMF_DISABLE_HWLOC=ON")
  set(UMF_LINK_HWLOC_STATICALLY OFF CACHE INTERNAL "UMF_LINK_HWLOC_STATICALLY=OFF")

  message(STATUS ">>> Unified Memory Framework: FetchContent_MakeAvailable(unified-memory-framework)")
  FetchContent_MakeAvailable(unified-memory-framework)
  message(STATUS ">>> Unified Memory Framework: FetchContent_GetProperties(unified-memory-framework)")
  FetchContent_GetProperties(unified-memory-framework)

  set(UMF_INCLUDE_DIRS ${unified-memory-framework_SOURCE_DIR}/include)
  message(STATUS ">>> Unified Memory Framework: UMF_INCLUDE_DIRS=${UMF_INCLUDE_DIRS}")
endif()
