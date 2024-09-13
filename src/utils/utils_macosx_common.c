/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <sys/mman.h>

#include <umf/base.h>
#include <umf/memory_provider.h>

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

void *utils_devdax_mmap(void *hint_addr, size_t length, int prot, int fd) {
    (void)hint_addr; // unused
    (void)length;    // unused
    (void)prot;      // unused
    (void)fd;        // unused
    return NULL;     // not supported
}
