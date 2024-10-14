// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains helpers for tests for UMF pool API

#ifndef UMF_TEST_HELPERS_HPP
#define UMF_TEST_HELPERS_HPP 1

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider_ops.h>

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

void test_alloc_free_success(umf_memory_provider_handle_t provider, size_t size,
                             size_t alignment, purge_t purge);

// test used only in providers that do not support the free() operation (file and devdax provider)
void test_alloc_success_not_free(umf_memory_provider_handle_t provider,
                                 size_t size, size_t alignment, purge_t purge);

#endif /* UMF_TEST_HELPERS_HPP */
