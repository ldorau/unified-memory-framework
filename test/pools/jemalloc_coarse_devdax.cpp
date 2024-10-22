// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"

#include "pool_coarse_devdax.hpp"

auto coarseParams = umfCoarseMemoryProviderParamsDefault();
auto devdaxParams = umfDevDaxMemoryProviderParamsDefault(
    getenv("UMF_TESTS_DEVDAX_PATH"), getenv("UMF_TESTS_DEVDAX_SIZE")
                                         ? atol(getenv("UMF_TESTS_DEVDAX_SIZE"))
                                         : 0);

INSTANTIATE_TEST_SUITE_P(jemallocCoarseDevDaxTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfJemallocPoolOps(), nullptr,
                             umfDevDaxMemoryProviderOps(), &devdaxParams,
                             &coarseParams}));
