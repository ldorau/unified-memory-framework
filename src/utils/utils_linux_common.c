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

#include "utils_common.h"
#include "utils_log.h"

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        *out_flag = MAP_SHARED;
        return UMF_RESULT_SUCCESS;
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

/*
 * MMap a /dev/dax device.
 * First try to mmap with (MAP_SHARED_VALIDATE | MAP_SYNC) flags
 * which allows flushing from the user-space. If MAP_SYNC fails
 * try to mmap with MAP_SHARED flag (without MAP_SYNC).
 */
void *utils_devdax_mmap(void *hint_addr, size_t length, int prot, int fd) {
    void *ptr = utils_mmap(hint_addr, length, prot,
                           MAP_SHARED_VALIDATE | MAP_SYNC, fd, 0);
    if (ptr) {
        LOG_DEBUG(
            "devdax mapped with the (MAP_SHARED_VALIDATE | MAP_SYNC) flags");
        return ptr;
    }

    ptr = utils_mmap(hint_addr, length, prot, MAP_SHARED, fd, 0);
    if (ptr) {
        LOG_DEBUG("devdax mapped with the MAP_SHARED flag");
        return ptr;
    }

    return NULL;
}
