/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_COARSE_H
#define UMF_COARSE_H

#include <stdbool.h>
#include <string.h>

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coarse_t coarse_t;

typedef void *coarse_handle_t;

typedef struct coarse_callbacks_t {
    // alloc() is optional (can be NULL for the fixed-size memory provider)
    umf_result_t (*alloc)(void *provider, size_t size, size_t alignment,
                          void **ptr);
    // free() is optional (can be NULL)
    umf_result_t (*free)(void *provider, void *ptr, size_t size);
    umf_result_t (*split)(void *provider, void *ptr, size_t totalSize,
                          size_t firstSize);
    umf_result_t (*merge)(void *provider, void *lowPtr, void *highPtr,
                          size_t totalSize);
} coarse_callbacks_t;

// Coarse Memory Provider allocation strategy
typedef enum coarse_strategy_t {
    // Always allocate a free block of the (size + alignment) size
    // and cut out the properly aligned part leaving two remaining parts.
    // It is the fastest strategy but causes memory fragmentation
    // when alignment is greater than 0.
    // It is the best strategy when alignment always equals 0.
    UMF_COARSE_MEMORY_STRATEGY_FASTEST = 0,

    // Check if the first free block of the 'size' size has the correct alignment.
    // If not, use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
    UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE,

    // Look through all free blocks of the 'size' size
    // and choose the first one with the correct alignment.
    // If none of them had the correct alignment,
    // use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
    UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE,

    // The maximum value (it has to be the last one).
    UMF_COARSE_MEMORY_STRATEGY_MAX
} coarse_strategy_t;

// Coarse Memory Provider settings struct.
typedef struct coarse_params_t {
    // handle of the memory provider
    void *provider;

    // coarse callbacks
    coarse_callbacks_t cb;

    // Memory allocation strategy.
    // See coarse_strategy_t for details.
    coarse_strategy_t allocation_strategy;

    // page size of the memory provider
    size_t page_size;
} coarse_params_t;

// Coarse Memory Provider stats (TODO move to CTL)
typedef struct coarse_stats_t {
    // Total allocation size.
    size_t alloc_size;

    // Size of used memory.
    size_t used_size;

    // Number of memory blocks allocated from the upstream provider.
    size_t num_upstream_blocks;

    // Total number of allocated memory blocks.
    size_t num_all_blocks;

    // Number of free memory blocks.
    size_t num_free_blocks;
} coarse_stats_t;

// TODO use CTL
coarse_stats_t umfCoarseMemoryProviderGetStats(coarse_t *coarse);

// Create default params for the coarse memory provider
static inline coarse_params_t umfCoarseMemoryProviderParamsDefault(void) {
    coarse_params_t coarse_params;
    memset(&coarse_params, 0, sizeof(coarse_params));
    return coarse_params;
}

umf_result_t coarse_new(coarse_params_t *coarse_params, coarse_t **pcoarse);
void coarse_delete(coarse_t *coarse);
umf_result_t coarse_add_memory_block(coarse_t *coarse, void *addr, size_t size);
umf_result_t coarse_alloc(coarse_t *coarse, size_t size, size_t alignment,
                          void **resultPtr);
umf_result_t coarse_free(coarse_t *coarse, void *ptr, size_t bytes);
umf_result_t coarse_merge(coarse_t *coarse, void *lowPtr, void *highPtr,
                          size_t totalSize);
umf_result_t coarse_split(coarse_t *coarse, void *ptr, size_t totalSize,
                          size_t firstSize);

#ifdef __cplusplus
}
#endif

#endif // UMF_COARSE_H
