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
    os_mutex_t *free_lock;     // lock of free_list
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
    assert(pool->metadata.free_list == NULL);
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

    current_chunk->next = NULL;
    pool->metadata.free_list = ptr; // address of the first chunk
}

umf_ba_pool_t *umf_ba_create(size_t size) {
    size_t chunk_size = align_size(size, MEMORY_ALIGNMENT);
    size_t mutex_size = align_size(util_mutex_get_size(), MEMORY_ALIGNMENT);

    size_t metadata_size = sizeof(struct umf_ba_main_pool_meta_t);
    size_t pool_size = sizeof(void *) + metadata_size + mutex_size +
                       (MINIMUM_CHUNK_COUNT * chunk_size);
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

    // allocate and init free_lock
    pool->metadata.free_lock = util_mutex_init(data_ptr);
    if (!pool->metadata.free_lock) {
        ba_os_free(pool, pool_size);
        return NULL;
    }

    data_ptr += mutex_size;  // free_lock is here
    size_left -= mutex_size; // for free_lock

    pool->metadata.free_list = NULL;
    ba_divide_memory_into_chunks(pool, data_ptr, size_left);

    return pool;
}

void *umf_ba_alloc(umf_ba_pool_t *pool) {
    util_mutex_lock(pool->metadata.free_lock);
    if (pool->metadata.free_list == NULL) {
        umf_ba_next_pool_t *new_pool =
            (umf_ba_next_pool_t *)ba_os_alloc(pool->metadata.pool_size);
        if (!new_pool) {
            util_mutex_unlock(pool->metadata.free_lock);
            return NULL;
        }

        // add the new pool to the list of pools
        new_pool->next_pool = pool->next_pool;
        pool->next_pool = new_pool;

        size_t size =
            pool->metadata.pool_size - offsetof(umf_ba_next_pool_t, data);
        ba_divide_memory_into_chunks(pool, &new_pool->data, size);
    }

    umf_ba_chunk_t *chunk = pool->metadata.free_list;
    pool->metadata.free_list = pool->metadata.free_list->next;
#ifndef NDEBUG
    pool->metadata.n_allocated++;
#endif /* NDEBUG */
    util_mutex_unlock(pool->metadata.free_lock);

    return chunk;
}

void umf_ba_free(umf_ba_pool_t *pool, void *ptr) {
    if (ptr == NULL) {
        return;
    }

    umf_ba_chunk_t *chunk = (umf_ba_chunk_t *)ptr;

    util_mutex_lock(pool->metadata.free_lock);
    chunk->next = pool->metadata.free_list;
    pool->metadata.free_list = chunk;
#ifndef NDEBUG
    pool->metadata.n_allocated--;
#endif /* NDEBUG */
    util_mutex_unlock(pool->metadata.free_lock);
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

    util_mutex_destroy_not_free(pool->metadata.free_lock);
    ba_os_free(pool, size);
}
