// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_devdax_memory.h"

#include "ipcFixtures.hpp"

HostMemoryAccessor hostAccessor;

auto defaultDevDaxParams = umfDevDaxMemoryProviderParamsDefault(
    getenv("UMF_TESTS_DEVDAX_PATH"),
    atol(getenv("UMF_TESTS_DEVDAX_SIZE") ? getenv("UMF_TESTS_DEVDAX_SIZE")
                                         : "0"));

static std::vector<ipcTestParams> ipcJemallocPoolTestParamsList = {
    {umfJemallocPoolOps(), nullptr, umfDevDaxMemoryProviderOps(),
     &defaultDevDaxParams, &hostAccessor, false},
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(DevDaxProviderProxyPoolTest, umfIpcTest,
                         ::testing::ValuesIn(ipcJemallocPoolTestParamsList));
