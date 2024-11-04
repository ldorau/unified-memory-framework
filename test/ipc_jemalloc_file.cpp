// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "cpp_helpers.hpp"
#include "test_helpers.h"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

#include <umf/memory_provider.h>
#include <umf/pools/pool_jemalloc.h>
#include <umf/providers/provider_file_memory.h>

#define UMF_TEST_PROVIDER_FREE_NOT_SUPPORTED 1
#include "ipcFixtures.hpp"
#undef UMF_TEST_PROVIDER_FREE_NOT_SUPPORTED

using umf_test::test;

#define FILE_PATH ((char *)"tmp_file")

umf_file_memory_provider_params_t get_file_params_shared(char *path) {
    umf_file_memory_provider_params_t file_params =
        umfFileMemoryProviderParamsDefault(path);
    file_params.visibility = UMF_MEM_MAP_SHARED;
    return file_params;
}

umf_file_memory_provider_params_t file_params_shared =
    get_file_params_shared(FILE_PATH);

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> ipcJemallocPoolTestParamsList = {
    {umfJemallocPoolOps(), nullptr, umfFileMemoryProviderOps(),
     &file_params_shared, &hostAccessor, false},
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(FileProviderJemallocPoolTest, umfIpcTest,
                         ::testing::ValuesIn(ipcJemallocPoolTestParamsList));
