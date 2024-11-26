// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_file_memory.h"

#include "pool_coarse.hpp"

auto fileParams = umfFileMemoryProviderParamsDefault(FILE_PATH);

INSTANTIATE_TEST_SUITE_P(scalableCoarseFileTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfFileMemoryProviderOps(), &fileParams}));
