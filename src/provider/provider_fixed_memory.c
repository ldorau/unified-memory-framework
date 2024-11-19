/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_fixed_memory.h>

#if defined(_WIN32) || defined(UMF_NO_HWLOC)

umf_memory_provider_ops_t *umfFixedMemoryProviderOps(void) {
    // not supported
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define FIXED_PAGE_SIZE_2MB ((size_t)(2 * 1024 * 1024)) // == 2 MB

#define TLS_MSG_BUF_LEN 1024

typedef struct fixed_memory_provider_t {
    void *base;          // base address of the memory buffer
    size_t size;         // size of the file used for memory mapping
    size_t offset;       // offset in the file used for memory mapping
    utils_mutex_t lock;  // lock of ptr and offset
    unsigned protection; // combination of OS-specific protection flags
} fixed_memory_provider_t;

typedef struct fixed_last_native_error_t {
    int32_t native_error;
    int errno_value;
    char msg_buff[TLS_MSG_BUF_LEN];
} fixed_last_native_error_t;

static __TLS fixed_last_native_error_t TLS_last_native_error;

// helper values used only in the Native_error_str array
#define _UMF_FIXED_RESULT_SUCCESS                                              \
    (UMF_FIXED_RESULT_SUCCESS - UMF_FIXED_RESULT_SUCCESS)
#define _UMF_FIXED_RESULT_ERROR_ALLOC_FAILED                                   \
    (UMF_FIXED_RESULT_ERROR_ALLOC_FAILED - UMF_FIXED_RESULT_SUCCESS)
#define _UMF_FIXED_RESULT_ERROR_ADDRESS_NOT_ALIGNED                            \
    (UMF_FIXED_RESULT_ERROR_ADDRESS_NOT_ALIGNED - UMF_FIXED_RESULT_SUCCESS)
#define _UMF_FIXED_RESULT_ERROR_FREE_FAILED                                    \
    (UMF_FIXED_RESULT_ERROR_FREE_FAILED - UMF_FIXED_RESULT_SUCCESS)
#define _UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED                             \
    (UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED - UMF_FIXED_RESULT_SUCCESS)

static const char *Native_error_str[] = {
    [_UMF_FIXED_RESULT_SUCCESS] = "success",
    [_UMF_FIXED_RESULT_ERROR_ALLOC_FAILED] = "memory allocation failed",
    [_UMF_FIXED_RESULT_ERROR_ADDRESS_NOT_ALIGNED] =
        "allocated address is not aligned",
    [_UMF_FIXED_RESULT_ERROR_FREE_FAILED] = "memory deallocation failed",
    [_UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed",
};

static void fixed_store_last_native_error(int32_t native_error,
                                          int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t fixed_initialize(void *params, void **provider) {
    umf_result_t ret;

    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_fixed_memory_provider_params_t *in_params =
        (umf_fixed_memory_provider_params_t *)params;

    if (in_params->addr == NULL) {
        LOG_ERR("memory address is missing");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (in_params->size == 0) {
        LOG_ERR("memory size is 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    fixed_memory_provider_t *fixed_provider =
        umf_ba_global_alloc(sizeof(*fixed_provider));
    if (!fixed_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(fixed_provider, 0, sizeof(*fixed_provider));

    fixed_provider->size = in_params->size;
    fixed_provider->base = in_params->addr;

    if (utils_mutex_init(&fixed_provider->lock) == NULL) {
        LOG_ERR("lock init failed");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_free_fixed_provider;
    }

    *provider = fixed_provider;

    return UMF_RESULT_SUCCESS;

err_free_fixed_provider:
    umf_ba_global_free(fixed_provider);
    return ret;
}

static void fixed_finalize(void *provider) {
    fixed_memory_provider_t *fixed_provider = provider;
    utils_mutex_destroy_not_free(&fixed_provider->lock);
    utils_munmap(fixed_provider->base, fixed_provider->size);
    umf_ba_global_free(fixed_provider);
}

static int fixed_alloc_aligned(size_t length, size_t alignment, void *base,
                               size_t size, utils_mutex_t *lock,
                               void **out_addr, size_t *offset) {
    assert(out_addr);

    if (utils_mutex_lock(lock)) {
        LOG_ERR("locking file offset failed");
        return -1;
    }

    uintptr_t ptr = (uintptr_t)base + *offset;
    uintptr_t rest_of_div = alignment ? (ptr % alignment) : 0;

    if (alignment > 0 && rest_of_div > 0) {
        ptr += alignment - rest_of_div;
    }

    size_t new_offset = ptr - (uintptr_t)base + length;

    if (new_offset > size) {
        utils_mutex_unlock(lock);
        LOG_ERR("cannot allocate more memory than the file size: %zu", size);
        return -1;
    }

    *offset = new_offset;
    *out_addr = (void *)ptr;

    utils_mutex_unlock(lock);

    return 0;
}

static umf_result_t fixed_alloc(void *provider, size_t size, size_t alignment,
                                void **resultPtr) {
    int ret;

    // alignment must be a power of two and a multiple or a divider of the page size
    if (alignment && ((alignment & (alignment - 1)) ||
                      ((alignment % FIXED_PAGE_SIZE_2MB) &&
                       (FIXED_PAGE_SIZE_2MB % alignment)))) {
        LOG_ERR("wrong alignment: %zu (not a power of 2 or a multiple or a "
                "divider of the page size (%zu))",
                alignment, FIXED_PAGE_SIZE_2MB);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (IS_NOT_ALIGNED(alignment, FIXED_PAGE_SIZE_2MB)) {
        alignment = ALIGN_UP(alignment, FIXED_PAGE_SIZE_2MB);
    }

    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;

    void *addr = NULL;
    errno = 0;
    ret = fixed_alloc_aligned(size, alignment, fixed_provider->base,
                              fixed_provider->size, &fixed_provider->lock,
                              &addr, &fixed_provider->offset);
    if (ret) {
        fixed_store_last_native_error(UMF_FIXED_RESULT_ERROR_ALLOC_FAILED, 0);
        LOG_ERR("memory allocation failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    *resultPtr = addr;

    return UMF_RESULT_SUCCESS;
}

static void fixed_get_last_native_error(void *provider, const char **ppMessage,
                                        int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    *pError = TLS_last_native_error.native_error;
    if (TLS_last_native_error.errno_value == 0) {
        *ppMessage = Native_error_str[*pError - UMF_FIXED_RESULT_SUCCESS];
        return;
    }

    const char *msg;
    size_t len;
    size_t pos = 0;

    msg = Native_error_str[*pError - UMF_FIXED_RESULT_SUCCESS];
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    msg = ": ";
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    utils_strerror(TLS_last_native_error.errno_value,
                   TLS_last_native_error.msg_buff + pos, TLS_MSG_BUF_LEN - pos);

    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t fixed_get_recommended_page_size(void *provider, size_t size,
                                                    size_t *page_size) {
    (void)provider; // unused
    (void)size;     // unused

    *page_size = FIXED_PAGE_SIZE_2MB;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_get_min_page_size(void *provider, void *ptr,
                                            size_t *page_size) {
    (void)ptr; // unused

    return fixed_get_recommended_page_size(provider, 0, page_size);
}

static umf_result_t fixed_purge_lazy(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)ptr;      // unused
    (void)size;     // unused
    // purge_lazy is unsupported in case of the file memory provider,
    // because the MADV_FREE operation can be applied
    // only to private anonymous pages (see madvise(2)).
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t fixed_purge_force(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    errno = 0;
    if (utils_purge(ptr, size, UMF_PURGE_FORCE)) {
        fixed_store_last_native_error(UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED,
                                      errno);
        LOG_PERR("force purging failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static const char *fixed_get_name(void *provider) {
    (void)provider; // unused
    return "FIXED";
}

static umf_result_t fixed_allocation_split(void *provider, void *ptr,
                                           size_t totalSize, size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_allocation_merge(void *provider, void *lowPtr,
                                           void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    return UMF_RESULT_SUCCESS;
}

typedef struct fixed_ipc_data_t {
    unsigned protection; // combination of OS-specific memory protection flags
    // offset of the data (from the beginning of the file mapping) - see fixed_get_ipc_handle()
    size_t offset;
    size_t length; // length of the data
} fixed_ipc_data_t;

static umf_result_t fixed_get_ipc_handle_size(void *provider, size_t *size) {
    (void)provider;

    *size = sizeof(fixed_ipc_data_t);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_get_ipc_handle(void *provider, const void *ptr,
                                         size_t size, void *providerIpcData) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;

    fixed_ipc_data_t *fixed_ipc_data = (fixed_ipc_data_t *)providerIpcData;
    fixed_ipc_data->protection = fixed_provider->protection;
    fixed_ipc_data->offset =
        (size_t)((uintptr_t)ptr - (uintptr_t)fixed_provider->base);
    fixed_ipc_data->length = size;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_put_ipc_handle(void *provider,
                                         void *providerIpcData) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;
    fixed_ipc_data_t *fixed_ipc_data = (fixed_ipc_data_t *)providerIpcData;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_open_ipc_handle(void *provider, void *providerIpcData,
                                          void **ptr) {
    (void)provider; // unused
    *ptr = NULL;

    fixed_ipc_data_t *fixed_ipc_data = (fixed_ipc_data_t *)providerIpcData;

    // It is just a workaround for case when
    // fixed_alloc() was called with the size argument
    // that is not a multiplier of FIXED_PAGE_SIZE_2MB.
    size_t offset_aligned = fixed_ipc_data->offset;
    size_t length_aligned = fixed_ipc_data->length;
    utils_align_ptr_down_size_up((void **)&offset_aligned, &length_aligned,
                                 FIXED_PAGE_SIZE_2MB);

    *ptr = NULL; // addr;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_close_ipc_handle(void *provider, void *ptr,
                                           size_t size) {
    (void)provider; // unused
    size = ALIGN_UP(size, FIXED_PAGE_SIZE_2MB);

    errno = 0;
    int ret = utils_munmap(ptr, size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        fixed_store_last_native_error(UMF_FIXED_RESULT_ERROR_FREE_FAILED,
                                      errno);
        LOG_PERR("memory unmapping failed (ptr: %p, size: %zu)", ptr, size);

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_provider_ops_t UMF_FIXED_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = fixed_initialize,
    .finalize = fixed_finalize,
    .alloc = fixed_alloc,
    .get_last_native_error = fixed_get_last_native_error,
    .get_recommended_page_size = fixed_get_recommended_page_size,
    .get_min_page_size = fixed_get_min_page_size,
    .get_name = fixed_get_name,
    .ext.purge_lazy = fixed_purge_lazy,
    .ext.purge_force = fixed_purge_force,
    .ext.allocation_merge = fixed_allocation_merge,
    .ext.allocation_split = fixed_allocation_split,
    .ipc.get_ipc_handle_size = fixed_get_ipc_handle_size,
    .ipc.get_ipc_handle = fixed_get_ipc_handle,
    .ipc.put_ipc_handle = fixed_put_ipc_handle,
    .ipc.open_ipc_handle = fixed_open_ipc_handle,
    .ipc.close_ipc_handle = fixed_close_ipc_handle};

umf_memory_provider_ops_t *umfFixedMemoryProviderOps(void) {
    return &UMF_FIXED_MEMORY_PROVIDER_OPS;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
