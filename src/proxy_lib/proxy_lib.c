/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/*
 * UMF proxy library - a library for intercepting user allocation requests
 *
 * It intercepts following APIs:
 * - aligned_alloc()
 * - calloc()
 * - free()
 * - malloc()
 * - malloc_usable_size()
 * - realloc()
 */

#if (defined PROXY_LIB_USES_JEMALLOC_POOL)
#include <umf/pools/pool_jemalloc.h>
#define umfPoolManagerOps umfJemallocPoolOps
#elif (defined PROXY_LIB_USES_SCALABLE_POOL)
#include <umf/pools/pool_scalable.h>
#define umfPoolManagerOps umfScalablePoolOps
#else
#error Pool manager not defined
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#include "base_alloc_linear.h"
#include "proxy_lib.h"
#include "utils_common.h"
#include "utils_concurrency.h"

/*
 * The UMF proxy library uses two memory allocators:
 * 1) the "LEAK" internal linear base allocator based on the anonymous mapped
 *    memory that will NOT be destroyed (with API ba_leak_*()).
 * 2) the main one - UMF pool allocator.
 *
 * Ad 1)
 * The "LEAK" internal linear base allocator is used from the very beginning
 * to the creation of a UMF pool in the constructor of the proxy library.
 * It is used to allocate memory for OS specific data used during loading and unloading
 * applications (for example _dl_init() and _dl_fini() on Linux storing data of all
 * constructors and destructors that have to be called) and also memory needed
 * by umfMemoryProviderCreate() and umfPoolCreate().
 * That memory will be leaked on purpose (OS will have to free it during destroying
 * the process), because we cannot free the memory containing data of destructors
 * that have to be called at the end (for example memory allocated by _dl_init()
 * and used internally by _dl_fini() on Linux).
 * The "LEAK" internal linear base allocator uses about 900 kB on Linux.
 *
 * Ad 2)
 * The UMF pool allocator (the main one) is used from the creation to the destruction
 * of a UMF pool to allocate memory needed by an application. It should be freed
 * by an application.
 */

static UTIL_ONCE_FLAG Base_alloc_leak_initialized = UTIL_ONCE_FLAG_INIT;
static umf_ba_linear_pool_t *Base_alloc_leak = NULL;
static umf_memory_provider_handle_t OS_memory_provider = NULL;
static umf_memory_pool_handle_t Proxy_pool = NULL;

// it protects us from recursion in umfPool*()
static __TLS int was_called_from_umfPool = 0;

/*****************************************************************************/
/*** The constructor and destructor of the proxy library *********************/
/*****************************************************************************/

void proxy_lib_create_common(void) {
    umf_os_memory_provider_params_t os_params =
        umfOsMemoryProviderParamsDefault();
    enum umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating OS memory provider failed\n");
        exit(-1);
    }

    umf_result = umfPoolCreate(umfPoolManagerOps(), OS_memory_provider, NULL, 0,
                               &Proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating UMF pool manager failed\n");
        exit(-1);
    }
    // The UMF pool has just been created (Proxy_pool != NULL). Stop using
    // the linear allocator and start using the UMF pool allocator from now on.
}

void proxy_lib_destroy_common(void) {
    umf_memory_pool_handle_t pool = Proxy_pool;
    Proxy_pool = NULL;
    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(OS_memory_provider);
    // the "LEAK" linear base allocator is not destroyed at all
}

/*****************************************************************************/
/*** Generic version of realloc() of linear base allocator *******************/
/*****************************************************************************/

static inline void *ba_generic_realloc(umf_ba_linear_pool_t *pool, void *ptr,
                                       size_t size) {
    if (size == 0) {
        // it means free(ptr), but linear base allocator does not implement free()
        return NULL;
    }

    assert(ptr); // it is verified in the main realloc()

    size_t max_size = umf_ba_linear_pool_contains_pointer(pool, ptr);
    assert(max_size > 0); // assert that pool contains the pointer

    void *new_ptr = umf_ba_linear_alloc(pool, size);
    if (!new_ptr) {
        return NULL;
    }

    if (size > max_size) {
        size = max_size;
    }

    memcpy(new_ptr, ptr, size);

    return new_ptr;
}

/*****************************************************************************/
/*** The "LEAK" linear base allocator functions ******************************/
/*****************************************************************************/

static void ba_leak_create(void) { Base_alloc_leak = umf_ba_linear_create(0); }

// it does not implement destroy(), because it will not free memory at all

static inline void *ba_leak_malloc(size_t size) {
    util_init_once(&Base_alloc_leak_initialized, ba_leak_create);
    return umf_ba_linear_alloc(Base_alloc_leak, size);
}

static inline void *ba_leak_calloc(size_t nmemb, size_t size) {
    util_init_once(&Base_alloc_leak_initialized, ba_leak_create);
    // umf_ba_linear_alloc() returns zeroed memory
    return umf_ba_linear_alloc(Base_alloc_leak, nmemb * size);
}

static inline void *ba_leak_realloc(void *ptr, size_t size) {
    util_init_once(&Base_alloc_leak_initialized, ba_leak_create);
    return ba_generic_realloc(Base_alloc_leak, ptr, size);
}

static inline void *ba_leak_aligned_alloc(size_t alignment, size_t size) {
    util_init_once(&Base_alloc_leak_initialized, ba_leak_create);
    void *ptr = umf_ba_linear_alloc(Base_alloc_leak, size + alignment);
    return (void *)ALIGN_UP((uintptr_t)ptr, alignment);
}

static inline size_t ba_leak_pool_contains_pointer(void *ptr) {
    return umf_ba_linear_pool_contains_pointer(Base_alloc_leak, ptr);
}

/*****************************************************************************/
/*** The UMF pool allocator functions (the public API) ***********************/
/*****************************************************************************/

void *malloc(size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolMalloc(Proxy_pool, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolCalloc(Proxy_pool, nmemb, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return malloc(size);
    }

    if (ba_leak_pool_contains_pointer(ptr)) {
        return ba_leak_realloc(ptr, size);
    }

    if (Proxy_pool) {
        was_called_from_umfPool = 1;
        void *new_ptr = umfPoolRealloc(Proxy_pool, ptr, size);
        was_called_from_umfPool = 0;
        return new_ptr;
    }

    assert(0);
    return NULL;
}

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    if (ba_leak_pool_contains_pointer(ptr)) {
        // allocations from the leak linear base allocator will not be freed at all
        return;
    }

    if (Proxy_pool) {
        if (umfPoolFree(Proxy_pool, ptr) != UMF_RESULT_SUCCESS) {
            fprintf(stderr, "error: umfPoolFree() failed\n");
            assert(0);
        }
        return;
    }

    assert(0);
    return;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolAlignedMalloc(Proxy_pool, size, alignment);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_aligned_alloc(alignment, size);
}

size_t malloc_usable_size(void *ptr) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        size_t size = umfPoolMallocUsableSize(Proxy_pool, ptr);
        was_called_from_umfPool = 0;
        return size;
    }

    return 0; // unsupported in this case
}
