/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include <umf.h>
#include <umf/memory_pool.h>

#include "base_alloc/base_alloc.h"
#include "critnib/critnib.h"
#include "utils/utils_concurrency.h"

#ifndef UMF_TRACKER_H
#define UMF_TRACKER_H 1

typedef struct umf_memory_tracker_t {
    umf_ba_pool_t *tracker_allocator;
    critnib *map;
    utils_mutex_t splitMergeMutex;
} umf_memory_tracker_t, *umf_memory_tracker_handle_t;

typedef struct umf_tracker_value_t {
    umf_memory_pool_handle_t pool;
    size_t size;
} umf_tracker_value_t;

typedef struct umf_alloc_info_t {
    void *base;
    size_t baseSize;
    umf_memory_pool_handle_t pool;
} umf_alloc_info_t;

umf_memory_tracker_handle_t umfMemoryTrackerCreate(void);
void umfMemoryTrackerDestroy(umf_memory_tracker_handle_t handle);

umf_result_t umfMemoryTrackerGetAllocInfo(const void *ptr,
                                          //umf_memory_tracker_handle_t tracker,
                                          umf_alloc_info_t *pAllocInfo);

umf_result_t
umfMemoryTrackerGetAllocInfoTracker(const void *ptr,
                                    umf_memory_tracker_handle_t tracker,
                                    umf_alloc_info_t *pAllocInfo);

umf_memory_pool_handle_t umfMemoryTrackerGetPool(const void *ptr);

void clear_tracker_for_the_pool(umf_memory_tracker_handle_t hTracker,
                                umf_memory_pool_handle_t pool,
                                bool upstreamDoesNotFree);

#endif // UMF_TRACKER_H

#ifdef __cplusplus
}
#endif
