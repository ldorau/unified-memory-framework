/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_common.h"
#include "utils_concurrency.h"

size_t utils_mutex_get_size(void) { return sizeof(utils_mutex_t); }

utils_mutex_t *utils_mutex_init(utils_mutex_t *mutex) {
    InitializeCriticalSection(&mutex->lock);
    return mutex;
}

void utils_mutex_destroy_not_free(utils_mutex_t *mutex) {
    DeleteCriticalSection(&mutex->lock);
}

int utils_mutex_lock(utils_mutex_t *mutex) {
    EnterCriticalSection(&mutex->lock);

    if (mutex->lock.RecursionCount > 1) {
        LeaveCriticalSection(&mutex->lock);
        /* deadlock detected */
        abort();
    }
    return 0;
}

int utils_mutex_unlock(utils_mutex_t *mutex) {
    LeaveCriticalSection(&mutex->lock);
    return 0;
}

utils_rwlock_t *utils_rwlock_init(utils_rwlock_t *rwlock) {
    InitializeSRWLock(&rwlock->lock);
    return 0; // never fails
}

void utils_rwlock_destroy_not_free(utils_rwlock_t *rwlock) {
    // there is no call to destroy SWR lock
    (void)rwlock;
}

int utils_read_lock(utils_rwlock_t *rwlock) {
    AcquireSRWLockShared(&rwlock->lock);
    return 0; // never fails
}

int utils_write_lock(utils_rwlock_t *rwlock) {
    AcquireSRWLockExclusive(&rwlock->lock);
    return 0; // never fails
}

int utils_read_unlock(utils_rwlock_t *rwlock) {
    ReleaseSRWLockShared(&rwlock->lock);
    return 0; // never fails
}

int utils_write_unlock(utils_rwlock_t *rwlock) {
    ReleaseSRWLockExclusive(&rwlock->lock);
    return 0; // never fails
}

// There is no good way to do atomic_load on windows...
void utils_atomic_load_acquire_u64(uint64_t *ptr, uint64_t *out) {
    // NOTE: Windows cl complains about direct accessing 'ptr' which is next
    // accessed using Interlocked* functions (warning 28112 - disabled)
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    utils_annotate_acquire(ptr);
    LONG64 ret = InterlockedCompareExchange64((LONG64 volatile *)ptr, 0, 0);
    *out = *(uint64_t *)&ret;
}

void utils_atomic_load_acquire_ptr(void **ptr, void **out) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    utils_annotate_acquire((void *)ptr);
    uintptr_t ret = (uintptr_t)InterlockedCompareExchangePointer(ptr, 0, 0);
    *(uintptr_t *)out = ret;
}

void utils_atomic_store_release_u64(uint64_t *ptr, uint64_t *val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)val, 8);
    InterlockedExchange64((LONG64 volatile *)ptr, *(LONG64 *)val);
    utils_annotate_release(ptr);
}

void utils_atomic_store_release_ptr(void **ptr, void *val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    InterlockedExchangePointer(ptr, val);
    utils_annotate_release(ptr);
}

uint64_t utils_atomic_increment_u64(uint64_t *ptr) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return incremented value
    return InterlockedIncrement64((LONG64 volatile *)ptr);
}

uint64_t utils_atomic_decrement_u64(uint64_t *ptr) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return decremented value
    return InterlockedDecrement64((LONG64 volatile *)ptr);
}

uint64_t utils_fetch_and_add_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)&val, 8);
    // return the value that had previously been in *ptr
    return InterlockedExchangeAdd64((LONG64 volatile *)(ptr), val);
}

uint64_t utils_fetch_and_sub_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)&val, 8);
    // return the value that had previously been in *ptr
    // NOTE: on Windows there is no *Sub* version of InterlockedExchange
    return InterlockedExchangeAdd64((LONG64 volatile *)(ptr), -(LONG64)val);
}

bool utils_compare_exchange_u64(uint64_t *ptr, uint64_t *expected,
                                uint64_t *desired) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)desired, 8);
    ASSERT_IS_ALIGNED((uintptr_t)expected, 8);

    // if (*ptr == *desired)
    //   *ptr = *expected
    //   return true
    // else
    //  *expected = *ptr
    // return false

    LONG64 out = InterlockedCompareExchange64(
        (LONG64 volatile *)ptr, *(LONG64 *)desired, *(LONG64 *)expected);
    if (out == *(LONG64 *)expected) {
        return true;
    }

    // else
    *expected = out;
    return false;
}

static BOOL CALLBACK initOnceCb(PINIT_ONCE InitOnce, PVOID Parameter,
                                PVOID *lpContext) {
    (void)InitOnce;  // unused
    (void)lpContext; // unused

    void (*onceCb)(void) = (void (*)(void))(Parameter);
    onceCb();
    return TRUE;
}

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void)) {
    InitOnceExecuteOnce(flag, initOnceCb, (void *)onceCb, NULL);
}
