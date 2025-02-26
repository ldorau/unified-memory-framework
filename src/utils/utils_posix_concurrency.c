/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "utils_concurrency.h"
#include "utils_log.h"

size_t utils_mutex_get_size(void) { return sizeof(pthread_mutex_t); }

utils_mutex_t *utils_mutex_init(utils_mutex_t *ptr) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)ptr;
    int ret = pthread_mutex_init(mutex, NULL);
    return ret == 0 ? ((utils_mutex_t *)mutex) : NULL;
}

void utils_mutex_destroy_not_free(utils_mutex_t *m) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)m;
    int ret = pthread_mutex_destroy(mutex);
    if (ret) {
        LOG_ERR("pthread_mutex_destroy failed");
    }
}

int utils_mutex_lock(utils_mutex_t *m) {
    return pthread_mutex_lock((pthread_mutex_t *)m);
}

int utils_mutex_unlock(utils_mutex_t *m) {
    return pthread_mutex_unlock((pthread_mutex_t *)m);
}

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*oneCb)(void)) {
    pthread_once(flag, oneCb);
}

utils_rwlock_t *utils_rwlock_init(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    int ret = pthread_rwlock_init(rwlock, NULL);
    return ret == 0 ? ((utils_rwlock_t *)rwlock) : NULL;
}

void utils_rwlock_destroy_not_free(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    int ret = pthread_rwlock_destroy(rwlock);
    if (ret) {
        LOG_ERR("pthread_rwlock_destroy failed");
    }
}

int utils_read_lock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_rdlock((pthread_rwlock_t *)rwlock);
}

int utils_write_lock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_wrlock((pthread_rwlock_t *)rwlock);
}

int utils_read_unlock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock);
}

int utils_write_unlock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock);
}

void utils_atomic_load_acquire_u64(uint64_t *ptr, uint64_t *out) {
    utils_annotate_acquire(ptr);
    __atomic_load(ptr, out, memory_order_acquire);
}

void utils_atomic_load_acquire_ptr(void **ptr, void **out) {
    utils_annotate_acquire((void *)ptr);
    *out = (void *)__atomic_load_n((uintptr_t *)ptr, memory_order_acquire);
}

void utils_atomic_store_release_u64(uint64_t *ptr, uint64_t *val) {
    __atomic_store(ptr, val, memory_order_release);
    utils_annotate_release(ptr);
}

void utils_atomic_store_release_ptr(void **ptr, void *val) {
    __atomic_store_n((uintptr_t *)ptr, (uintptr_t)val, memory_order_release);
    utils_annotate_release(ptr);
}

uint64_t utils_atomic_increment_u64(uint64_t *val) {
    // return incremented value
    return __atomic_add_fetch(val, 1, memory_order_acq_rel);
}

uint64_t utils_atomic_decrement_u64(uint64_t *val) {
    // return decremented value
    return __atomic_sub_fetch(val, 1, memory_order_acq_rel);
}

uint64_t utils_fetch_and_add_u64(uint64_t *ptr, uint64_t val) {
    // return the value that had previously been in *ptr
    return __atomic_fetch_add(ptr, val, memory_order_acq_rel);
}

uint64_t utils_fetch_and_sub_u64(uint64_t *ptr, uint64_t val) {
    // return the value that had previously been in *ptr
    return __atomic_fetch_sub(ptr, val, memory_order_acq_rel);
}

bool utils_compare_exchange_u64(uint64_t *ptr, uint64_t *expected,
                                uint64_t *desired) {
    // if (*ptr == *expected)
    //   *ptr = *desired
    //   return true
    // else
    //  *expected = *ptr
    // return false
    return __atomic_compare_exchange(ptr, expected, desired, 0 /* strong */,
                                     memory_order_acq_rel,
                                     memory_order_relaxed);
}
