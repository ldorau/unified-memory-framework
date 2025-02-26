// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memory_provider.h>
#include <umf/providers/provider_fixed_memory.h>
#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif

#include "ipcFixtures.hpp"

using umf_test::test;

#define FIXED_BUFFER_SIZE (1024 * utils_get_page_size()) // 4MB for 4KB pages

void *defaultFixedParamsCreate() {
    // Allocate a memory buffer to use with the fixed memory provider
    size_t memory_size = FIXED_BUFFER_SIZE; // Allocate 512 pages
    void *memory_buffer = malloc(memory_size);
    if (memory_buffer == nullptr) {
        throw std::runtime_error(
            "Failed to allocate a buffer for Fixed Memory Provider");
    }

    umf_fixed_memory_provider_params_handle_t params = NULL;
    umf_result_t res =
        umfFixedMemoryProviderParamsCreate(&params, memory_buffer, memory_size);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create Fixed Memory Provider params");
    }

    return params;
}

umf_result_t defaultFixedParamsDestroy(void *params) {
    return umfFixedMemoryProviderParamsDestroy(
        (umf_fixed_memory_provider_params_handle_t)params);
}

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> getIpcProxyPoolTestParamsList(void) {
    std::vector<ipcTestParams> ipcProxyPoolTestParamsList = {};

    ipcProxyPoolTestParamsList = {
        {umfProxyPoolOps(), nullptr, nullptr, umfFixedMemoryProviderOps(),
         defaultFixedParamsCreate, defaultFixedParamsDestroy, &hostAccessor},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), nullptr, nullptr, umfFixedMemoryProviderOps(),
         defaultFixedParamsCreate, defaultFixedParamsDestroy, &hostAccessor},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, nullptr, umfFixedMemoryProviderOps(),
         defaultFixedParamsCreate, defaultFixedParamsDestroy, &hostAccessor},
#endif
    };

    return ipcProxyPoolTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(FixedProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcProxyPoolTestParamsList()));
