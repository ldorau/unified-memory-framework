/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_POOL_HPP
#define UMF_TEST_POOL_HPP 1

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#include <stdlib.h>
#endif

#include <umf/base.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>

#include "base.hpp"
#include "provider.hpp"
#include "utils/cpp_helpers.hpp"

typedef void *(*pfnPoolParamsCreate)();
typedef umf_result_t (*pfnPoolParamsDestroy)(void *);

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using poolCreateExtParams =
    std::tuple<const umf_memory_pool_ops_t *, pfnPoolParamsCreate,
               pfnPoolParamsDestroy, const umf_memory_provider_ops_t *,
               pfnProviderParamsCreate, pfnProviderParamsDestroy>;

std::string poolCreateExtParamsNameGen(
    const testing::TestParamInfo<poolCreateExtParams> &info) {

    const umf_memory_pool_ops_t *pool_ops = std::get<0>(info.param);
    const umf_memory_provider_ops_t *provider_ops = std::get<3>(info.param);

    const char *poolName = NULL;
    pool_ops->get_name(NULL, &poolName);

    const char *providerName = NULL;
    provider_ops->get_name(NULL, &providerName);

    // if there are multiple cases with the same pool and provider combination,
    // add the index to the name
    std::string poolParams = std::get<1>(info.param)
                                 ? "_w_params_" + std::to_string(info.index)
                                 : "";

    return std::string(poolName) + poolParams + "_" + providerName;
}

namespace umf_test {

umf_memory_pool_handle_t
createPoolChecked(const umf_memory_pool_ops_t *ops,
                  umf_memory_provider_handle_t hProvider, const void *params,
                  umf_pool_create_flags_t flags = 0) {
    umf_memory_pool_handle_t hPool;
    auto ret = umfPoolCreate(ops, hProvider, params, flags, &hPool);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    return hPool;
}

auto wrapPoolUnique(umf_memory_pool_handle_t hPool) {
    return umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

bool isReallocSupported(umf_memory_pool_handle_t hPool) {
    static constexpr size_t allocSize = 8;
    bool supported = false;
    auto *ptr = umfPoolMalloc(hPool, allocSize);
    memset(ptr, 0, allocSize);
    auto *new_ptr = umfPoolRealloc(hPool, ptr, allocSize * 2);

    if (new_ptr) {
        supported = true;
        umfPoolFree(hPool, new_ptr);
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        umfPoolFree(hPool, ptr);
        supported = false;
    } else {
        umfPoolFree(hPool, new_ptr);
        throw std::runtime_error("realloc failed with unexpected error");
    }

    return supported;
}

bool isCallocSupported(umf_memory_pool_handle_t hPool) {
    static constexpr size_t num = 8;
    static constexpr size_t size = sizeof(int);
    bool supported = false;
    auto *ptr = umfPoolCalloc(hPool, num, size);

    if (ptr) {
        supported = true;
        umfPoolFree(hPool, ptr);
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        supported = false;
    } else {
        umfPoolFree(hPool, ptr);
        throw std::runtime_error("calloc failed with unexpected error");
    }

    return supported;
}

bool isAlignedAllocSupported([[maybe_unused]] umf_memory_pool_handle_t hPool) {
#ifdef _WIN32
    // On Windows, aligned allocation is not supported
    return false;
#else
    static constexpr size_t allocSize = 8;
    static constexpr size_t alignment = 8;
    auto *ptr = umfPoolAlignedMalloc(hPool, allocSize, alignment);

    if (ptr) {
        umfPoolFree(hPool, ptr);
        return true;
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        return false;
    } else {
        throw std::runtime_error("AlignedMalloc failed with unexpected error");
    }
#endif
}

typedef struct pool_base_t {
    umf_result_t initialize(umf_memory_provider_handle_t) noexcept {
        return UMF_RESULT_SUCCESS;
    };
    void *malloc(size_t) noexcept { return nullptr; }
    void *calloc(size_t, size_t) noexcept { return nullptr; }
    void *realloc(void *, size_t) noexcept { return nullptr; }
    void *aligned_malloc(size_t, size_t) noexcept { return nullptr; }
    umf_result_t malloc_usable_size(const void *, size_t *) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t free(void *) noexcept { return UMF_RESULT_ERROR_UNKNOWN; }
    umf_result_t get_last_allocation_error() noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t get_name(const char **) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t ext_ctl(umf_ctl_query_source_t, const char *, void *, size_t,
                         umf_ctl_query_type_t, va_list) noexcept {
        return UMF_RESULT_ERROR_INVALID_CTL_PATH;
    }
    umf_result_t ext_trim_memory(size_t) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
} pool_base_t;

struct malloc_pool : public pool_base_t {
    void *malloc(size_t size) noexcept { return ::malloc(size); }

    void *calloc(size_t num, size_t size) noexcept {
        return ::calloc(num, size);
    }

    void *realloc(void *ptr, size_t size) noexcept {
        return ::realloc(ptr, size);
    }

    void *aligned_malloc(size_t size, size_t alignment) noexcept {
#ifdef _WIN32
        (void)size;      // unused
        (void)alignment; // unused

        // we could use _aligned_malloc but it requires using _aligned_free...
        return nullptr;
#else
        return ::aligned_alloc(alignment, size);
#endif
    }

    umf_result_t malloc_usable_size(const void *ptr, size_t *size) noexcept {
        if (size) {
#ifdef _WIN32
            *size = _msize((void *)ptr);
#elif __APPLE__
            *size = ::malloc_size((void *)ptr);
#else
            *size = ::malloc_usable_size((void *)ptr);
#endif
        }
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t free(void *ptr) noexcept {
        ::free(ptr);
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t get_name(const char **name) noexcept {
        if (name) {
            *name = "malloc_pool";
        }
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_trim_memory(size_t) noexcept {
        // malloc_pool frees all memory immediately, so we have nothing to trim
        return UMF_RESULT_SUCCESS;
    }
};

umf_memory_pool_ops_t MALLOC_POOL_OPS =
    umf_test::poolMakeCOps<umf_test::malloc_pool, void>();

static constexpr size_t DEFAULT_DISJOINT_SLAB_MIN_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_MAX_POOLABLE_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_CAPACITY = 4;
static constexpr size_t DEFAULT_DISJOINT_MIN_BUCKET_SIZE = 64;

inline void *defaultDisjointPoolConfig() {
    umf_disjoint_pool_params_handle_t config = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&config);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create pool params");
    }
    res = umfDisjointPoolParamsSetSlabMinSize(config,
                                              DEFAULT_DISJOINT_SLAB_MIN_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set slab min size");
    }
    res = umfDisjointPoolParamsSetMaxPoolableSize(
        config, DEFAULT_DISJOINT_MAX_POOLABLE_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set max poolable size");
    }
    res = umfDisjointPoolParamsSetCapacity(config, DEFAULT_DISJOINT_CAPACITY);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set capacity");
    }
    res = umfDisjointPoolParamsSetMinBucketSize(
        config, DEFAULT_DISJOINT_MIN_BUCKET_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(config);
        throw std::runtime_error("Failed to set min bucket size");
    }

    return config;
}

inline umf_result_t defaultDisjointPoolConfigDestroy(void *config) {
    return umfDisjointPoolParamsDestroy(
        static_cast<umf_disjoint_pool_params_handle_t>(config));
}

} // namespace umf_test

#endif /* UMF_TEST_POOL_HPP */
