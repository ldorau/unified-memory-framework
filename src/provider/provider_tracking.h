/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_TRACKER_INTERNAL_H
#define UMF_MEMORY_TRACKER_INTERNAL_H 1

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include "base_alloc.h"
#include "critnib.h"
#include "tracker.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_tracking_memory_provider_t {
    umf_memory_provider_handle_t hUpstream;
    umf_memory_tracker_handle_t hTracker;
    umf_memory_pool_handle_t pool;
    critnib *ipcCache;

    // the upstream provider does not support the free() operation
    bool upstreamDoesNotFree;
} umf_tracking_memory_provider_t;

typedef struct umf_tracking_memory_provider_t umf_tracking_memory_provider_t;

// Creates a memory provider that tracks each allocation/deallocation through
// umf_memory_tracker_handle_t and forwards all requests to hUpstream memory
// Provider. hUpstream lifetime should be managed by the user of this function.
// The tracker param is optional - if NULL is passed, the default one is used
umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider,
    umf_memory_tracker_handle_t tracker, bool upstreamDoesNotFree);

void umfTrackingMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t hTrackingProvider,
    umf_memory_provider_handle_t *hUpstream);

umf_memory_provider_ops_t *umfTrackingMemoryProviderOps(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_TRACKER_INTERNAL_H */
