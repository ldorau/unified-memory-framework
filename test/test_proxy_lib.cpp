/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#include "base.hpp"
#include "test_helpers.h"

using umf_test::test;

TEST_F(test, proxyLibBasic) {

    fprintf(stderr, ">>> proxyLibBasic #1 \n");

    ::free(::malloc(64));

    fprintf(stderr, ">>> proxyLibBasic #2 \n");

    // a check to verify we are running the proxy library
    void *ptr = (void *)0x01;
#ifdef _WIN32
    size_t size = _msize(ptr);
#elif __APPLE__
    size_t size = ::malloc_size(ptr);
#else
    size_t size = ::malloc_usable_size(ptr);
#endif

    fprintf(stderr, ">>> proxyLibBasic #3 \n");

    UT_ASSERTeq(size, 0xDEADBEEF);
}
