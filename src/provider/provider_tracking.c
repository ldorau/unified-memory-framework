/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
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
#include "libumf.h"
#include "memory_pool_internal.h"
#include "provider_tracking.h"
#include "tracker.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

static umf_result_t umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker,
                                        umf_memory_pool_handle_t pool,
                                        const void *ptr, size_t size) {
    assert(ptr);

    umf_tracker_value_t *value = umf_ba_alloc(hTracker->tracker_allocator);
    if (value == NULL) {
        LOG_ERR("failed to allocate tracker value, ptr=%p, size=%zu", ptr,
                size);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    value->pool = pool;
    value->size = size;

    int ret = critnib_insert(hTracker->map, (uintptr_t)ptr, value, 0);

    if (ret == 0) {
        LOG_DEBUG(
            "memory region is added, tracker=%p, ptr=%p, pool=%p, size=%zu",
            (void *)hTracker, ptr, (void *)pool, size);
        return UMF_RESULT_SUCCESS;
    }

    LOG_ERR("failed to insert tracker value, ret=%d, ptr=%p, pool=%p, size=%zu",
            ret, ptr, (void *)pool, size);

    umf_ba_free(hTracker->tracker_allocator, value);

    if (ret == ENOMEM) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    return UMF_RESULT_ERROR_UNKNOWN;
}

static umf_result_t umfMemoryTrackerRemove(umf_memory_tracker_handle_t hTracker,
                                           const void *ptr) {
    assert(ptr);

    // TODO: there is no support for removing partial ranges (or multiple entries
    // in a single remove call) yet.
    // Every umfMemoryTrackerAdd(..., ptr, ...) should have a corresponding
    // umfMemoryTrackerRemove call with the same ptr value.

    void *value = critnib_remove(hTracker->map, (uintptr_t)ptr);
    if (!value) {
        LOG_ERR("pointer %p not found in the map", ptr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_tracker_value_t *v = value;
    LOG_DEBUG("memory region removed: tracker=%p, ptr=%p, pool=%p, size=%zu",
              (void *)hTracker, ptr, (void *)v->pool, v->size);

    umf_ba_free(hTracker->tracker_allocator, value);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMemoryTrackerGetAllocInfo(const void *ptr,
                                          umf_alloc_info_t *pAllocInfo) {
    umf_memory_tracker_handle_t tracker = umfMemoryTrackerGet();
    return umfMemoryTrackerGetAllocInfoTracker(ptr, tracker, pAllocInfo);
}

umf_memory_pool_handle_t umfMemoryTrackerGetPool(const void *ptr) {
    umf_alloc_info_t allocInfo = {NULL, 0, NULL};
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        return NULL;
    }

    return allocInfo.pool;
}

// Cache entry structure to store provider-specific IPC data.
// providerIpcData is a Flexible Array Member because its size varies
// depending on the provider.
typedef struct ipc_cache_value_t {
    uint64_t ipcDataSize;
    char providerIpcData[];
} ipc_cache_value_t;

static umf_result_t trackingAlloc(void *hProvider, size_t size,
                                  size_t alignment, void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    assert(p->hUpstream);

    ret = umfMemoryProviderAlloc(p->hUpstream, size, alignment, ptr);
    if (ret != UMF_RESULT_SUCCESS || !*ptr) {
        return ret;
    }

    LOG_DEBUG("allocated %p, provider: %p, size: %zu", *ptr,
              (void *)p->hUpstream, size);

    // check if the allocation was already added to the tracker
    // (in case of using ProxyLib)
    umf_tracker_value_t *value =
        (umf_tracker_value_t *)critnib_get(p->hTracker->map, *(uintptr_t *)ptr);
    if (value) {
        LOG_ERR("ptr already exists in the tracker ptr=%p, old size=%zu, new "
                "size=%zu, old pool %p, new pool %p, tracker %p",
                *ptr, value->size, size, (void *)value->pool, (void *)p->pool,
                (void *)p->hTracker);

        value->pool = p->pool;
        value->size = size;
        int crit_ret = critnib_insert(p->hTracker->map, *(uintptr_t *)ptr,
                                      value, 1 /* update */);

        // this cannot fail since we know the element exists and there is
        // nothing to allocate
        assert(crit_ret == 0);
        (void)crit_ret;
    } else {
        umf_result_t ret2 =
            umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, size);
        if (ret2 != UMF_RESULT_SUCCESS) {
            LOG_ERR(
                "failed to add allocated region to the tracker, ptr = %p, size "
                "= %zu, ret = %d",
                *ptr, size, ret2);
        }
    }

    return ret;
}

static umf_result_t trackingAllocationSplit(void *hProvider, void *ptr,
                                            size_t totalSize,
                                            size_t firstSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;

    umf_tracker_value_t *splitValue =
        umf_ba_alloc(provider->hTracker->tracker_allocator);
    if (!splitValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    splitValue->pool = provider->pool;
    splitValue->size = firstSize;

    int r = utils_mutex_lock(&provider->hTracker->splitMergeMutex);
    if (r) {
        goto err_lock;
    }

    void *highPtr = (void *)(((uintptr_t)ptr) + firstSize);
    size_t secondSize = totalSize - firstSize;

    LOG_DEBUG("trying to split (%p, %zu) to (%p, %zu) and (%p, %zu)", ptr,
              totalSize, ptr, firstSize, highPtr, secondSize);

    umf_tracker_value_t *value = (umf_tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)ptr);
    if (!value) {
        LOG_ERR("region for split is not found in the tracker");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (value->size != totalSize) {
        LOG_ERR("tracked size %zu does not match requested size to split: %zu",
                value->size, totalSize);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationSplit(provider->hUpstream, ptr, totalSize,
                                           firstSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to split the region");
        goto err;
    }

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    ret = umfMemoryTrackerAdd(provider->hTracker, provider->pool, highPtr,
                              secondSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to add split region to the tracker, ptr = %p, size "
                "= %zu, ret = %d",
                highPtr, secondSize, ret);
        // TODO: what now? should we rollback the split? This can only happen due to ENOMEM
        // so it's unlikely but probably the best solution would be to try to preallocate everything
        // (value and critnib nodes) before calling umfMemoryProviderAllocationSplit.
        goto err;
    }

    LOG_DEBUG("update split region ptr=%p, pool=%p size=%zu", ptr,
              (void *)splitValue->pool, splitValue->size);

    int cret = critnib_insert(provider->hTracker->map, (uintptr_t)ptr,
                              (void *)splitValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free the original value
    umf_ba_free(provider->hTracker->tracker_allocator, value);
    utils_mutex_unlock(&provider->hTracker->splitMergeMutex);

    return UMF_RESULT_SUCCESS;

err:
    utils_mutex_unlock(&provider->hTracker->splitMergeMutex);
err_lock:
    umf_ba_free(provider->hTracker->tracker_allocator, splitValue);
    return ret;
}

static umf_result_t trackingAllocationMerge(void *hProvider, void *lowPtr,
                                            void *highPtr, size_t totalSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;

    umf_tracker_value_t *mergedValue =
        umf_ba_alloc(provider->hTracker->tracker_allocator);

    if (!mergedValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    mergedValue->pool = provider->pool;
    mergedValue->size = totalSize;

    int r = utils_mutex_lock(&provider->hTracker->splitMergeMutex);
    if (r) {
        goto err_lock;
    }

    umf_tracker_value_t *lowValue = (umf_tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)lowPtr);
    if (!lowValue) {
        LOG_ERR("no left value (%p) found in tracker!", lowPtr);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    umf_tracker_value_t *highValue = (umf_tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)highPtr);
    if (!highValue) {
        LOG_ERR("no right value (%p) found in tracker!", highPtr);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    if (lowValue->pool != highValue->pool) {
        LOG_ERR("pool mismatch: %p vs %p", (void *)lowValue->pool,
                (void *)highValue->pool);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    if (lowValue->size + highValue->size != totalSize) {
        LOG_ERR("lowValue->size + highValue->size != totalSize");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationMerge(provider->hUpstream, lowPtr, highPtr,
                                           totalSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to merge regions");
        goto err;
    }

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    int cret = critnib_insert(provider->hTracker->map, (uintptr_t)lowPtr,
                              (void *)mergedValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free old value that we just replaced with mergedValue
    umf_ba_free(provider->hTracker->tracker_allocator, lowValue);

    void *erasedhighValue =
        critnib_remove(provider->hTracker->map, (uintptr_t)highPtr);
    assert(erasedhighValue == highValue);

    umf_ba_free(provider->hTracker->tracker_allocator, erasedhighValue);

    utils_mutex_unlock(&provider->hTracker->splitMergeMutex);

    return UMF_RESULT_SUCCESS;

err:
    utils_mutex_unlock(&provider->hTracker->splitMergeMutex);

    // TODO we should never go here in our CI but jemalloc_coarse_devdax tests
    // do something bad - we need to debug this
    // assert(0);

err_lock:
    umf_ba_free(provider->hTracker->tracker_allocator, mergedValue);
    return ret;
}

static umf_result_t trackingFree(void *hProvider, void *ptr, size_t size) {
    umf_result_t ret;
    umf_result_t ret_remove = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        LOG_DEBUG("calling umfMemoryTrackerRemove ptr=%p, size=%zu", ptr, size);
        ret_remove = umfMemoryTrackerRemove(p->hTracker, ptr);
        if (ret_remove != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            LOG_ERR("failed to remove the region from the tracker, ptr=%p, "
                    "size=%zu, ret=%d",
                    ptr, size, ret_remove);
        }
    }

    void *value = critnib_remove(p->ipcCache, (uintptr_t)ptr);
    if (value) {
        ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
        ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                            cache_value->providerIpcData);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("upstream provider failed to put IPC handle, ptr=%p, "
                    "size=%zu, ret = %d",
                    ptr, size, ret);
        }
        umf_ba_global_free(value);
    }

    LOG_DEBUG("calling umfMemoryProviderFree ptr=%p, size=%zu", ptr, size);
    ret = umfMemoryProviderFree(p->hUpstream, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to free the memory");
        // Do not add memory back to the tracker,
        // if it had not been removed.
        if (ret_remove != UMF_RESULT_SUCCESS) {
            return ret;
        }

        if (umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size) !=
            UMF_RESULT_SUCCESS) {
            LOG_ERR(
                "cannot add memory back to the tracker, ptr = %p, size = %zu",
                ptr, size);
        }
        return ret;
    }

    return ret;
}

static umf_result_t trackingInitialize(void *params, void **ret) {
    umf_tracking_memory_provider_t *provider =
        umf_ba_global_alloc(sizeof(umf_tracking_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *provider = *((umf_tracking_memory_provider_t *)params);
    if (provider->hUpstream == NULL || provider->hTracker == NULL ||
        provider->pool == NULL || provider->ipcCache == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *ret = provider;
    return UMF_RESULT_SUCCESS;
}

static void trackingFinalize(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    critnib_delete(p->ipcCache);

    // Do not clear the tracker if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (!utils_is_running_in_proxy_lib()) {
        clear_tracker_for_the_pool(p->hTracker, p->pool,
                                   p->upstreamDoesNotFree);
    }

    umf_ba_global_free(provider);
}

static void trackingGetLastError(void *provider, const char **msg,
                                 int32_t *pError) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umfMemoryProviderGetLastNativeError(p->hUpstream, msg, pError);
}

static umf_result_t trackingGetRecommendedPageSize(void *provider, size_t size,
                                                   size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetRecommendedPageSize(p->hUpstream, size,
                                                   pageSize);
}

static umf_result_t trackingGetMinPageSize(void *provider, void *ptr,
                                           size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetMinPageSize(p->hUpstream, ptr, pageSize);
}

static umf_result_t trackingPurgeLazy(void *provider, void *ptr, size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeLazy(p->hUpstream, ptr, size);
}

static umf_result_t trackingPurgeForce(void *provider, void *ptr, size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeForce(p->hUpstream, ptr, size);
}

static const char *trackingName(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetName(p->hUpstream);
}

static umf_result_t trackingGetIpcHandleSize(void *provider, size_t *size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetIPCHandleSize(p->hUpstream, size);
}

static umf_result_t trackingGetIpcHandle(void *provider, const void *ptr,
                                         size_t size, void *providerIpcData) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t ipcDataSize = 0;
    int cached = 0;
    do {
        void *value = critnib_get(p->ipcCache, (uintptr_t)ptr);
        if (value) { //cache hit
            ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
            memcpy(providerIpcData, cache_value->providerIpcData,
                   cache_value->ipcDataSize);
            cached = 1;
        } else {
            ret = umfMemoryProviderGetIPCHandle(p->hUpstream, ptr, size,
                                                providerIpcData);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("upstream provider failed to get IPC handle");
                return ret;
            }

            ret = umfMemoryProviderGetIPCHandleSize(p->hUpstream, &ipcDataSize);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("upstream provider failed to get the size of IPC "
                        "handle");
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("upstream provider failed to put IPC handle");
                }
                return ret;
            }

            size_t value_size = sizeof(ipc_cache_value_t) + ipcDataSize;
            ipc_cache_value_t *cache_value = umf_ba_global_alloc(value_size);
            if (!cache_value) {
                LOG_ERR("failed to allocate cache_value");
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("upstream provider failed to put IPC handle");
                }
                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }

            cache_value->ipcDataSize = ipcDataSize;
            memcpy(cache_value->providerIpcData, providerIpcData, ipcDataSize);

            int insRes = critnib_insert(p->ipcCache, (uintptr_t)ptr,
                                        (void *)cache_value, 0 /*update*/);
            if (insRes == 0) {
                cached = 1;
            } else {
                // critnib_insert might fail in 2 cases:
                // 1. Another thread created cache entry. So we need to
                //    clean up allocated handle and try to read again from
                //    the cache. Alternative approach could be insert empty
                //    cache_value and only if insert succeed get actual IPC
                //    handle and fill the cache_value structure under the lock.
                //    But this case should be rare enough.
                // 2. critnib failed to allocate memory internally. We need
                //    to cleanup and return corresponding error.
                umf_ba_global_free(cache_value);
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("upstream provider failed to put IPC handle");
                    return ret;
                }
                if (insRes == ENOMEM) {
                    LOG_ERR("insert to IPC cache failed due to OOM");
                    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                }
            }
        }
    } while (!cached);

    return ret;
}

static umf_result_t trackingPutIpcHandle(void *provider,
                                         void *providerIpcData) {
    (void)provider;
    (void)providerIpcData;
    // We just keep providerIpcData in the provider->ipcCache.
    // The actual Put is called inside trackingFree
    return UMF_RESULT_SUCCESS;
}

static size_t getDataSizeFromIpcHandle(const void *providerIpcData) {
    // This is hack to get size of memory pointed by IPC handle.
    // tracking memory provider gets only provider-specific data
    // pointed by providerIpcData, but the size of allocation tracked
    // by umf_ipc_data_t. We use this trick to get pointer to
    // umf_ipc_data_t data because the providerIpcData is
    // the Flexible Array Member of umf_ipc_data_t.
    const umf_ipc_data_t *ipcUmfData =
        (const umf_ipc_data_t *)((const uint8_t *)providerIpcData -
                                 sizeof(umf_ipc_data_t));
    return ipcUmfData->baseSize;
}

static umf_result_t trackingOpenIpcHandle(void *provider, void *providerIpcData,
                                          void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    assert(p->hUpstream);

    ret = umfMemoryProviderOpenIPCHandle(p->hUpstream, providerIpcData, ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to open IPC handle");
        return ret;
    }
    size_t bufferSize = getDataSizeFromIpcHandle(providerIpcData);
    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, bufferSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to add IPC region to the tracker, ptr=%p, size=%zu, "
                "ret = %d",
                *ptr, bufferSize, ret);
        if (umfMemoryProviderCloseIPCHandle(p->hUpstream, *ptr, bufferSize)) {
            LOG_ERR("upstream provider failed to close IPC handle, ptr=%p, "
                    "size=%zu",
                    *ptr, bufferSize);
        }
    }
    return ret;
}

static umf_result_t trackingCloseIpcHandle(void *provider, void *ptr,
                                           size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderCloseIPCHandle
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        LOG_DEBUG("calling umfMemoryTrackerRemove ptr=%p, size=%zu", ptr, size);
        umf_result_t ret = umfMemoryTrackerRemove(p->hTracker, ptr);
        if (ret != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            LOG_ERR("failed to remove the region from the tracker, ptr=%p, "
                    "size=%zu, ret = %d",
                    ptr, size, ret);
        }
    }
    return umfMemoryProviderCloseIPCHandle(p->hUpstream, ptr, size);
}

umf_memory_provider_ops_t UMF_TRACKING_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = trackingInitialize,
    .finalize = trackingFinalize,
    .alloc = trackingAlloc,
    .get_last_native_error = trackingGetLastError,
    .get_min_page_size = trackingGetMinPageSize,
    .get_recommended_page_size = trackingGetRecommendedPageSize,
    .get_name = trackingName,
    .ext.free = trackingFree,
    .ext.purge_force = trackingPurgeForce,
    .ext.purge_lazy = trackingPurgeLazy,
    .ext.allocation_split = trackingAllocationSplit,
    .ext.allocation_merge = trackingAllocationMerge,
    .ipc.get_ipc_handle_size = trackingGetIpcHandleSize,
    .ipc.get_ipc_handle = trackingGetIpcHandle,
    .ipc.put_ipc_handle = trackingPutIpcHandle,
    .ipc.open_ipc_handle = trackingOpenIpcHandle,
    .ipc.close_ipc_handle = trackingCloseIpcHandle,
};

umf_memory_provider_ops_t *umfTrackingMemoryProviderOps(void) {
    return &UMF_TRACKING_MEMORY_PROVIDER_OPS;
}

umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider,
    umf_memory_tracker_handle_t tracker, bool upstreamDoesNotFree) {

    umf_tracking_memory_provider_t params;
    params.hUpstream = hUpstream;
    params.upstreamDoesNotFree = upstreamDoesNotFree;
    // if the tracker passed by arg is NULL use the default one
    params.hTracker = tracker ? tracker : umfMemoryTrackerGet();
    if (!params.hTracker) {
        LOG_ERR("failed, tracker is NULL");
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    params.pool = hPool;
    params.ipcCache = critnib_new();
    if (!params.ipcCache) {
        LOG_ERR("failed to create IPC cache");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    LOG_DEBUG("upstream=%p, tracker=%p, "
              "pool=%p, ipcCache=%p",
              (void *)params.hUpstream, (void *)params.hTracker,
              (void *)params.pool, (void *)params.ipcCache);

    return umfMemoryProviderCreate(umfTrackingMemoryProviderOps(), &params,
                                   hTrackingProvider);
}

umf_result_t
umfMemoryTrackerGetAllocInfoTracker(const void *ptr,
                                    umf_memory_tracker_handle_t tracker,
                                    umf_alloc_info_t *pAllocInfo) {
    assert(ptr);
    assert(pAllocInfo);

    if (tracker == NULL) {
        LOG_ERR("tracker is NULL");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    if (tracker->map == NULL) {
        LOG_ERR("tracker's map is not created");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    uintptr_t rkey;
    umf_tracker_value_t *rvalue;
    int found = critnib_find(tracker->map, (uintptr_t)ptr, FIND_LE,
                             (void *)&rkey, (void **)&rvalue);
    if (!found || (uintptr_t)ptr >= rkey + rvalue->size) {
        LOG_WARN("pointer %p not found in the tracker, tracker=%p", ptr,
                 (void *)tracker);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    pAllocInfo->base = (void *)rkey;
    pAllocInfo->baseSize = rvalue->size;
    // TODO proxy pool?
    pAllocInfo->pool = rvalue->pool;

    return UMF_RESULT_SUCCESS;
}
