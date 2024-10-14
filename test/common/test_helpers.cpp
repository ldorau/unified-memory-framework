// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include "test_helpers.hpp"
#include "base.hpp"
#include "umf/memory_provider.h"

static void
test_alloc_success_with_result(umf_memory_provider_handle_t provider,
                               size_t size, size_t alignment, purge_t purge,
                               umf_result_t expected_result) {
    umf_result_t umf_result;
    void *ptr = nullptr;
    void *ptr2 = nullptr;

    umf_result = umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    umf_result = umfMemoryProviderAlloc(provider, size, alignment, &ptr2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    ASSERT_NE(ptr, ptr2);

    memset(ptr, 0xFF, size);
    memset(ptr2, 0xFF, size);

    if (purge == PURGE_LAZY) {
        umf_result = umfMemoryProviderPurgeLazy(provider, ptr, size);
        ASSERT_EQ(umf_result, expected_result);
    } else if (purge == PURGE_FORCE) {
        umf_result = umfMemoryProviderPurgeForce(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, expected_result);

    umf_result = umfMemoryProviderFree(provider, ptr2, size);
    ASSERT_EQ(umf_result, expected_result);
}

void test_alloc_free_success(umf_memory_provider_handle_t provider, size_t size,
                             size_t alignment, purge_t purge) {
    test_alloc_success_with_result(provider, size, alignment, purge,
                                   UMF_RESULT_SUCCESS);
}

// test used only in providers that do not support the free() operation (file and devdax provider)
void test_alloc_success_not_free(umf_memory_provider_handle_t provider,
                                 size_t size, size_t alignment, purge_t purge) {
    test_alloc_success_with_result(provider, size, alignment, purge,
                                   UMF_RESULT_ERROR_NOT_SUPPORTED);
}
