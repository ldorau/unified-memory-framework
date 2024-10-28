/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include "base_alloc_global.h"
#include "critnib.h"
#include "ipc_internal.h"
#include "memory_pool_internal.h"
#include "provider_tracking.h"
#include "tracker.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#ifdef __cplusplus
extern "C" {
#endif

extern umf_memory_tracker_handle_t TRACKER;

// TODO clearing the tracker is a temporary solution and should be removed.
// The tracker should be cleared using the provider's free() operation.
void clear_tracker_for_the_pool(umf_memory_tracker_handle_t hTracker,
                                umf_memory_pool_handle_t pool,
                                bool upstreamDoesNotFree) {
    uintptr_t rkey;
    void *rvalue;
    size_t n_items = 0;
    uintptr_t last_key = 0;

    while (1 == critnib_find((critnib *)hTracker->map, last_key, FIND_G, &rkey,
                             &rvalue)) {
        umf_tracker_value_t *value = (umf_tracker_value_t *)rvalue;
        if (value->pool != pool && pool != NULL) {
            last_key = rkey;
            continue;
        }

        n_items++;

        void *removed_value = critnib_remove(hTracker->map, rkey);
        assert(removed_value == rvalue);
        umf_ba_free(hTracker->tracker_allocator, removed_value);

        last_key = rkey;
    }

#ifndef NDEBUG
    // print error messages only if provider supports the free() operation
    if (n_items && !upstreamDoesNotFree) {
        if (pool) {
            LOG_ERR(
                "tracking provider of pool %p is not empty! (%zu items left)",
                (void *)pool, n_items);
        } else {
            LOG_ERR("tracking provider is not empty! (%zu items left)",
                    n_items);
        }
    }
#else  /* DEBUG */
    (void)upstreamDoesNotFree; // unused in DEBUG build
    (void)n_items;             // unused in DEBUG build
#endif /* DEBUG */
}

void clear_tracker(umf_memory_tracker_handle_t hTracker) {
    clear_tracker_for_the_pool(hTracker, NULL, false);
}

void umfTrackingMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t hTrackingProvider,
    umf_memory_provider_handle_t *hUpstream) {
    assert(hUpstream);
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hTrackingProvider;
    *hUpstream = p->hUpstream;
}

umf_memory_tracker_handle_t umfMemoryTrackerCreate(void) {
    umf_memory_tracker_handle_t handle =
        umf_ba_global_alloc(sizeof(umf_memory_tracker_t));
    if (!handle) {
        return NULL;
    }

    umf_ba_pool_t *tracker_allocator =
        umf_ba_create(sizeof(umf_tracker_value_t));
    if (!tracker_allocator) {
        goto err_free_handle;
    }

    handle->tracker_allocator = tracker_allocator;

    void *mutex_ptr = utils_mutex_init(&handle->splitMergeMutex);
    if (!mutex_ptr) {
        goto err_destroy_tracker_allocator;
    }

    handle->map = critnib_new();
    if (!handle->map) {
        goto err_destroy_mutex;
    }

    LOG_DEBUG("tracker created, handle=%p, segment map=%p", (void *)handle,
              (void *)handle->map);

    return handle;

err_destroy_mutex:
    utils_mutex_destroy_not_free(&handle->splitMergeMutex);
err_destroy_tracker_allocator:
    umf_ba_destroy(tracker_allocator);
err_free_handle:
    umf_ba_global_free(handle);
    return NULL;
}

void umfMemoryTrackerDestroy(umf_memory_tracker_handle_t handle) {
    if (!handle) {
        return;
    }

    // Do not destroy the tracker if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (utils_is_running_in_proxy_lib()) {
        return;
    }

    clear_tracker(handle);

    // We have to zero all inner pointers,
    // because the tracker handle can be copied
    // and used in many places.
    critnib_delete(handle->map);
    handle->map = NULL;
    utils_mutex_destroy_not_free(&handle->splitMergeMutex);
    umf_ba_destroy(handle->tracker_allocator);
    handle->tracker_allocator = NULL;
    umf_ba_global_free(handle);
}

#ifdef __cplusplus
}
#endif
