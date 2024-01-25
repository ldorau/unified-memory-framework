/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>

#include "base_alloc.h"
#include "base_alloc_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"

// minimum size of a single pool of the base allocator,
#define MINIMUM_POOL_SIZE (ba_os_get_page_size())

// minimum number of chunks used to calculate the size of pools
#define MINIMUM_CHUNK_COUNT (128)

// alignment of the base allocator
#define MEMORY_ALIGNMENT (8)

typedef struct umf_ba_chunk_t umf_ba_chunk_t;
typedef struct umf_ba_next_pool_t umf_ba_next_pool_t;

// memory chunk of size 'chunk_size'
struct umf_ba_chunk_t {
    umf_ba_chunk_t *next;
    char user_data[];
};

// metadata is set and used only in the main (the first) pool
struct umf_ba_main_pool_meta_t {
    size_t pool_size; // size of each pool (argument of each ba_os_alloc() call)
    size_t chunk_size;         // size of all memory chunks in this pool
    umf_ba_chunk_t *free_list; // list of free chunks
#ifndef NDEBUG
    size_t n_allocated;
#endif /* NDEBUG */
};

struct umf_ba_pool_t {
    // address of the beginning of the next pool (a list of allocated pools to be freed in umf_ba_destroy())
    umf_ba_next_pool_t *next_pool;

    // metadata is set and used only in the main (the first) pool
    struct umf_ba_main_pool_meta_t metadata;

    // data area of of the main (the first one) starts here
    char data[];
};

struct umf_ba_next_pool_t {
    // address of the beginning of the next pool (a list of allocated pools to be freed in umf_ba_destroy())
    umf_ba_next_pool_t *next_pool;

    // data area of all pools except of the main (the first one) starts here
    char data[];
};

// ba_divide_memory_into_chunks - divide given memory into chunks of chunk_size and add them to the free_list
static void ba_divide_memory_into_chunks(umf_ba_pool_t *pool, void *ptr,
                                         size_t size) {
    assert(size > pool->metadata.chunk_size);

    char *data_ptr = ptr;
    size_t size_left = size;

    umf_ba_chunk_t *current_chunk = (umf_ba_chunk_t *)data_ptr;
    umf_ba_chunk_t *prev_chunk = current_chunk;

    while (size_left >= pool->metadata.chunk_size) {
        current_chunk = (umf_ba_chunk_t *)data_ptr;
        prev_chunk->next = current_chunk;

        data_ptr += pool->metadata.chunk_size;
        size_left -= pool->metadata.chunk_size;
        prev_chunk = current_chunk;
    }

    // attach old free_list (may be NULL) at the of the new free list
    umf_ba_chunk_t *old_free_list;
    do {
        old_free_list = pool->metadata.free_list;
        current_chunk->next = old_free_list;
        // ptr is the address of the first chunk
    } while (!__sync_bool_compare_and_swap(&pool->metadata.free_list,
                                           old_free_list, ptr));
}

umf_ba_pool_t *umf_ba_create(size_t size) {
    size_t chunk_size = align_size(size, MEMORY_ALIGNMENT);

    size_t metadata_size = sizeof(struct umf_ba_main_pool_meta_t);
    size_t pool_size =
        sizeof(void *) + metadata_size + (MINIMUM_CHUNK_COUNT * chunk_size);
    if (pool_size < MINIMUM_POOL_SIZE) {
        pool_size = MINIMUM_POOL_SIZE;
    }

    pool_size = align_size(pool_size, ba_os_get_page_size());

    umf_ba_pool_t *pool = (umf_ba_pool_t *)ba_os_alloc(pool_size);
    if (!pool) {
        return NULL;
    }

    pool->metadata.pool_size = pool_size;
    pool->metadata.chunk_size = chunk_size;
    pool->next_pool = NULL; // this is the only pool now
#ifndef NDEBUG
    pool->metadata.n_allocated = 0;
#endif /* NDEBUG */

    char *data_ptr = (char *)&pool->data;
    size_t size_left = pool_size - offsetof(umf_ba_pool_t, data);

    pool->metadata.free_list = NULL;
    ba_divide_memory_into_chunks(pool, data_ptr, size_left);

    return pool;
}

static void *ba_add_next_pool(umf_ba_pool_t *pool) {
    umf_ba_next_pool_t *new_pool =
        (umf_ba_next_pool_t *)ba_os_alloc(pool->metadata.pool_size);
    if (!new_pool) {
        return NULL;
    }

    // add the new pool to the list of pools
    new_pool->next_pool = pool->next_pool;
    pool->next_pool = new_pool;

    size_t size = pool->metadata.pool_size - offsetof(umf_ba_next_pool_t, data);
    ba_divide_memory_into_chunks(pool, &new_pool->data, size);

    return pool;
}

void *umf_ba_alloc(umf_ba_pool_t *pool) {
    umf_ba_chunk_t *old_free_list;
    umf_ba_chunk_t *new_free_list;

    do {
        old_free_list = pool->metadata.free_list;
        if (old_free_list == NULL) {
            if (ba_add_next_pool(pool) == NULL) {
                return NULL;
            }
            old_free_list = pool->metadata.free_list;
        }
        assert(old_free_list != NULL);
        new_free_list = old_free_list->next;
    } while (!__sync_bool_compare_and_swap(&pool->metadata.free_list,
                                           old_free_list, new_free_list));

#ifndef NDEBUG
    __sync_fetch_and_add(&pool->metadata.n_allocated, 1);
#endif /* NDEBUG */

    return old_free_list;
}

void umf_ba_free(umf_ba_pool_t *pool, void *ptr) {
    if (ptr == NULL) {
        return;
    }

    umf_ba_chunk_t *chunk = (umf_ba_chunk_t *)ptr;
    umf_ba_chunk_t *old_free_list;
    do {
        old_free_list = pool->metadata.free_list;
        chunk->next = old_free_list;
    } while (!__sync_bool_compare_and_swap(&pool->metadata.free_list,
                                           old_free_list, chunk));

#ifndef NDEBUG
    __sync_fetch_and_sub(&pool->metadata.n_allocated, 1);
#endif /* NDEBUG */
}

void umf_ba_destroy(umf_ba_pool_t *pool) {
#ifndef NDEBUG
    assert(pool->metadata.n_allocated == 0);
#endif /* NDEBUG */
    size_t size = pool->metadata.pool_size;
    umf_ba_next_pool_t *current_pool;
    umf_ba_next_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        current_pool = next_pool;
        next_pool = next_pool->next_pool;
        ba_os_free(current_pool, size);
    }

    ba_os_free(pool, size);
}
