/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <cstdio>
#include <cstdlib>
#include <thread>

#include "base_alloc_linear.h"
#include "utils_common.h"

#include "base.hpp"
#include "test_helpers.h"

using umf_test::test;

TEST_F(test, baseAllocLinearAllocMoreThanPoolSize) {
    auto pool = std::shared_ptr<umf_ba_linear_pool_t>(
        umf_ba_linear_create(0 /* minimal pool size (page size) */),
        umf_ba_linear_destroy);

    size_t new_size = 20 * 1024 * 1024; // = 20 MB
    void *ptr = umf_ba_linear_alloc(pool.get(), new_size);
    UT_ASSERTne(ptr, NULL);
    memset(ptr, 0, new_size);

    umf_ba_linear_free(pool.get(), ptr);
}

TEST_F(test, baseAllocLinearPoolContainsPointer) {
    auto pool = std::shared_ptr<umf_ba_linear_pool_t>(
        umf_ba_linear_create(0 /* minimal pool size (page size) */),
        umf_ba_linear_destroy);

    size_t size = 16;
    void *ptr = umf_ba_linear_alloc(pool.get(), size);
    UT_ASSERTne(ptr, NULL);
    memset(ptr, 0, size);

    // assert pool contains pointer ptr
    UT_ASSERTne(umf_ba_linear_pool_contains_pointer(pool.get(), ptr), 0);

    // assert pool does NOT contain pointer 0x0123
    UT_ASSERTeq(umf_ba_linear_pool_contains_pointer(pool.get(), (void *)0x0123),
                0);

    umf_ba_linear_free(pool.get(), ptr);
}

TEST_F(test, baseAllocLinearMultiThreadedAllocMemset) {
    static constexpr int NTHREADS = 10;
    static constexpr int ITERATIONS = 1000;
    static constexpr int MAX_ALLOCATION_SIZE = 1024;

    srand(0);

    // The first pool should be bigger than one page,
    // but not big enough to hold all allocations,
    // so that there were more pools allocated.
    // This is needed to test freeing the first pool.
    size_t pool_size = 2 * util_get_page_size();

    auto pool = std::shared_ptr<umf_ba_linear_pool_t>(
        umf_ba_linear_create(pool_size), umf_ba_linear_destroy);

    auto poolAlloc = [](int TID, umf_ba_linear_pool_t *pool) {
        struct buffer_t {
            unsigned char *ptr;
            size_t size;
        } buffer[ITERATIONS];

        int n_allocs = 0;
        int n_frees = 0;

        for (int i = 0; i < ITERATIONS; i++) {
            buffer[i].size =
                (size_t)((rand() / (double)RAND_MAX) * MAX_ALLOCATION_SIZE);
            buffer[i].ptr =
                (unsigned char *)umf_ba_linear_alloc(pool, buffer[i].size);
            UT_ASSERTne(buffer[i].ptr, NULL);
            memset(buffer[i].ptr, (i + TID) & 0xFF, buffer[i].size);
            n_allocs++;
            if (buffer[i].size == 0) {
                fprintf(stderr, "buffer[i = %i].size = 0, .ptr = %p\n", i,
                        buffer[i].ptr);
            }
        }

        for (int i = 0; i < ITERATIONS; i++) {
            UT_ASSERTne(buffer[i].ptr, NULL);
            for (size_t k = 0; k < buffer[i].size; k++) {
                UT_ASSERTeq(*(buffer[i].ptr + k), (i + TID) & 0xFF);
            }
        }

        for (int i = 0; i < ITERATIONS; i++) {
            if (umf_ba_linear_free(pool, buffer[i].ptr)) {
                fprintf(stderr,
                        "FAILED umf_ba_linear_free(pool = %p, buffer[i = "
                        "%i].ptr = %p)\n",
                        (void *)pool, i, buffer[i].ptr);
            } else {
                n_frees++;
            }
        }
        if (n_allocs != n_frees) {
            fprintf(stderr, "n_allocs = %i n_frees = %i\n", n_allocs, n_frees);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolAlloc, i, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
}
