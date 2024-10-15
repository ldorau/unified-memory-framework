// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_coarse.h"
#include "umf/providers/provider_file_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

using umf_test::test;
using namespace umf_test;

#define INIT_BUFFER_SIZE 4096
#define FILE_PATH ((char *)"/tmp/file_provider")

umf_memory_provider_handle_t getFileProvider(void) {
    umf_memory_provider_handle_t FileProvider = nullptr;
    auto defaultFileParams = umfFileMemoryProviderParamsDefault(FILE_PATH);
    (void)umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                  &defaultFileParams, &FileProvider);
    return FileProvider;
}

coarse_memory_provider_params_t
getCoarseParams(umf_memory_provider_handle_t upstream_memory_provider,
                size_t init_buffer_size) {
    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.upstream_memory_provider =
        upstream_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    return coarse_memory_provider_params;
}

auto coarseParams = getCoarseParams(getFileProvider(), INIT_BUFFER_SIZE);
INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfJemallocPoolOps(), nullptr,
                             umfCoarseMemoryProviderOps(), &coarseParams}));
