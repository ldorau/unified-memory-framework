/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stddef.h>

#include "base_alloc_global.h"
#include "memspace_host_all_internal.h"
#include "provider_tracking.h"
#include "utils_concurrency.h"

static UTIL_ONCE_FLAG umf_is_initialized = UTIL_ONCE_FLAG_INIT;
umf_memory_tracker_handle_t TRACKER = NULL;

static void umfCreateOnce(void) { TRACKER = umfMemoryTrackerCreate(); }

static void umfDestroyOnce(void) {
    umf_memory_tracker_handle_t t = TRACKER;
    // make sure TRACKER is not used after being destroyed
    TRACKER = NULL;
    umfMemoryTrackerDestroy(t);

#if defined(UMF_BUILD_OS_MEMORY_PROVIDER)
    umfMemspaceHostAllDestroy();
#endif
}

static void libumfInitOnce(void) {
    umfCreateOnce();
    atexit(umfDestroyOnce);
}

void libumfInit(void) { util_init_once(&umf_is_initialized, libumfInitOnce); }

void __attribute__((constructor)) umfCreate(void) {
    util_init_once(&umf_is_initialized, umfCreateOnce);
}

void __attribute__((destructor)) umfDestroy(void) { umfDestroyOnce(); }
