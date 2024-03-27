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

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#include "base_alloc_linear.h"
#include "proxy_lib.h"
#include "utils_common.h"
#include "utils_sanitizers.h"

#ifdef _WIN32 /* Windows ***************************************/

#define _X86_
#include <process.h>
#include <synchapi.h>

#define UTIL_ONCE_FLAG INIT_ONCE
#define UTIL_ONCE_FLAG_INIT INIT_ONCE_STATIC_INIT

void util_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void));

#else /* Linux *************************************************/

#include <stdlib.h>
#include <string.h>

#include "utils_concurrency.h"

#endif /* _WIN32 ***********************************************/

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
    fprintf(stderr, ">>> proxy_lib_create_common START\n");
    umf_os_memory_provider_params_t os_params =
        umfOsMemoryProviderParamsDefault();
    enum umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating OS memory provider failed\n");
        exit(-1);
    }

    umf_result =
        umfPoolCreate(umfPoolManagerOps(), OS_memory_provider, NULL,
                      UMF_POOL_CREATE_FLAG_DISABLE_TRACKING, &Proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating UMF pool manager failed\n");
        exit(-1);
    }
    // The UMF pool has just been created (Proxy_pool != NULL). Stop using
    // the linear allocator and start using the UMF pool allocator from now on.
    fprintf(stderr, ">>> proxy_lib_create_common END\n");
}

void proxy_lib_destroy_common(void) {
    if (util_is_running_in_proxy_lib()) {
        // We cannot destroy 'Base_alloc_leak' nor 'Proxy_pool' nor 'OS_memory_provider',
        // because it could lead to use-after-free in the program's unloader
        // (for example _dl_fini() on Linux).
        return;
    }

    umf_memory_pool_handle_t pool = Proxy_pool;
    Proxy_pool = NULL;
    umfPoolDestroy(pool);

    umf_memory_provider_handle_t provider = OS_memory_provider;
    OS_memory_provider = NULL;
    umfMemoryProviderDestroy(provider);
}

/*****************************************************************************/
/*** Generic version of realloc() of linear base allocator *******************/
/*****************************************************************************/

static inline void *ba_generic_realloc(umf_ba_linear_pool_t *pool, void *ptr,
                                       size_t new_size, size_t old_size) {
    assert(ptr);      // it should be verified in the main realloc()
    assert(new_size); // it should be verified in the main realloc()
    assert(old_size); // old_size should be set in the main realloc()

    if (new_size <= old_size) {
        return ptr;
    }

    void *new_ptr = umf_ba_linear_alloc(pool, new_size);
    if (!new_ptr) {
        return NULL;
    }

    memcpy(new_ptr, ptr, old_size);

    // we can free the old ptr now
    umf_ba_linear_free(pool, ptr);

    return new_ptr;
}

/*****************************************************************************/
/*** The "LEAK" linear base allocator functions ******************************/
/*****************************************************************************/

static void ba_leak_create(void) { Base_alloc_leak = umf_ba_linear_create(0); }

// it does not implement destroy(), because we cannot destroy non-freed memory

static void ba_leak_init_once(void) {
    util_init_once(&Base_alloc_leak_initialized, ba_leak_create);
}

static inline void *ba_leak_alloc(size_t size) {
    ba_leak_init_once();
    return umf_ba_linear_alloc(Base_alloc_leak, size);
}

static inline void *ba_leak_realloc(void *ptr, size_t size, size_t old_size) {
    ba_leak_init_once();
    return ba_generic_realloc(Base_alloc_leak, ptr, size, old_size);
}

static inline int ba_leak_free(void *ptr) {
    ba_leak_init_once();
    return umf_ba_linear_free(Base_alloc_leak, ptr);
}

#ifndef NDEBUG
static inline size_t ba_leak_pool_contains_pointer(void *ptr) {
    ba_leak_init_once();
    return umf_ba_linear_pool_contains_pointer(Base_alloc_leak, ptr);
}
#endif

/*****************************************************************************/
/*** The UMF pool allocator helper functions *********************************/
/*****************************************************************************/

#define ALLOC_METADATA_SIZE (sizeof(size_t))
#define ALIGNMENT_BITS 24
#define OWNER_LINEAR_ALLOCATOR 0x11
#define OWNER_POOL_ALLOCATOR 0x22

// Stores metadata just before 'ptr' and returns beginning of usable
// space to the user. Metadata consists of 'size' that is the allocation
// size, 'offset' that specifies how far is the returned ptr from
// the origin ptr (used for aligned alloc) and the owner's marker.
static void *add_metadata_and_align(void *ptr, size_t size, size_t alignment,
                                    unsigned char owner) {
    assert(size < (1ULL << 32));
    assert(alignment < (1ULL << ALIGNMENT_BITS));
    assert(ptr);

    void *user_ptr;
    if (alignment <= ALLOC_METADATA_SIZE) {
        user_ptr = (void *)((uintptr_t)ptr + ALLOC_METADATA_SIZE);
    } else {
        user_ptr =
            (void *)ALIGN_UP((uintptr_t)ptr + ALLOC_METADATA_SIZE, alignment);
    }

    size_t ptr_offset_from_original = (uintptr_t)user_ptr - (uintptr_t)ptr;
    assert(ptr_offset_from_original < (1ULL << ALIGNMENT_BITS));

    size_t *metadata_loc = (size_t *)((char *)user_ptr - ALLOC_METADATA_SIZE);

    // mark entire allocation as undefined memory so that we can store metadata
    utils_annotate_memory_undefined(ptr, size);

    *metadata_loc = size | (ptr_offset_from_original << 32) |
                    ((size_t)owner << (32 + ALIGNMENT_BITS));

    // mark the metadata part as inaccessible
    utils_annotate_memory_inaccessible(ptr, ptr_offset_from_original);

    return user_ptr;
}

// Return original ptr (the one that has been passed to add_metadata_and_align())
// along with total allocation size (needed by realloc()) and usable size.
static void *get_original_alloc(void *user_ptr, size_t *total_size,
                                size_t *usable_size, unsigned char *owner) {
    assert(user_ptr);

    size_t *metadata_loc = (size_t *)((char *)user_ptr - ALLOC_METADATA_SIZE);

    // mark the metadata as defined to read the size, offset and owner
    utils_annotate_memory_defined(metadata_loc, ALLOC_METADATA_SIZE);

    size_t stored_size = *metadata_loc & ((1ULL << 32) - 1);
    size_t ptr_offset_from_original =
        (*metadata_loc >> 32) & ((1ULL << ALIGNMENT_BITS) - 1);
    unsigned char marker = *metadata_loc >> (32 + ALIGNMENT_BITS);

    // restore the original access mode
    utils_annotate_memory_inaccessible(metadata_loc, ALLOC_METADATA_SIZE);

    void *original_ptr =
        (void *)((uintptr_t)user_ptr - ptr_offset_from_original);

    if (total_size) {
        *total_size = stored_size;
    }

    if (usable_size) {
        *usable_size = stored_size - ptr_offset_from_original;
    }

    if (owner) {
        *owner = marker;
    }

    return original_ptr;
}

static void add_size_for_metadata_and_alignment(size_t *psize,
                                                size_t alignment) {
    assert(psize);

    // for metadata
    *psize += ALLOC_METADATA_SIZE;

    if (alignment > ALLOC_METADATA_SIZE) {
        *psize += alignment;
    }
}

/*****************************************************************************/
/*** The UMF pool allocator functions (the public API) ***********************/
/*****************************************************************************/

void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    add_size_for_metadata_and_alignment(&size, ALLOC_METADATA_SIZE);

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        fprintf(stderr, ">>> umfPoolMalloc() START\n");
        void *ptr = umfPoolMalloc(Proxy_pool, size);
        fprintf(stderr, ">>> umfPoolMalloc() END\n");
        was_called_from_umfPool = 0;
        return add_metadata_and_align(ptr, size, 0, OWNER_POOL_ALLOCATOR);
    }

    return add_metadata_and_align(ba_leak_alloc(size), size, 0,
                                  OWNER_LINEAR_ALLOCATOR);
}

void *calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    if (total_size == 0) {
        return NULL;
    }

    add_size_for_metadata_and_alignment(&total_size, ALLOC_METADATA_SIZE);

    if (!was_called_from_umfPool && Proxy_pool) {
        // count new value of nmemb, because total_size has been increased
        nmemb = (total_size / size) + ((total_size % size) ? 1 : 0);
        was_called_from_umfPool = 1;
        fprintf(stderr, ">>> umfPoolCalloc() START\n");
        void *ptr = umfPoolCalloc(Proxy_pool, nmemb, size);
        fprintf(stderr, ">>> umfPoolCalloc() END\n");
        was_called_from_umfPool = 0;
        return add_metadata_and_align(ptr, nmemb * size, 0,
                                      OWNER_POOL_ALLOCATOR);
    }

    // ba_leak_alloc() returns zeroed memory
    return add_metadata_and_align(ba_leak_alloc(total_size), total_size, 0,
                                  OWNER_LINEAR_ALLOCATOR);
}

static unsigned long long i_free = 0;

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    fprintf(stderr, ">>> free(orig: %p) START #%llu\n", ptr, ++i_free);

    unsigned char owner;
    void *orig_ptr = ptr;
    ptr = get_original_alloc(ptr, NULL, NULL, &owner);

    if (owner == OWNER_POOL_ALLOCATOR) {
        if (Proxy_pool == NULL) {
            fprintf(stderr, "free(): proxy pool had already been destroyed\n");
            assert(0);
            return;
        }
        fprintf(stderr, ">>> umfPoolFree() START\n");
        if (umfPoolFree(Proxy_pool, ptr) != UMF_RESULT_SUCCESS) {
            fprintf(stderr, "free(): umfPoolFree() failed\n");
            assert(0);
        }
        fprintf(stderr, ">>> umfPoolFree() END\n");
        return;
    }

    if (owner == OWNER_LINEAR_ALLOCATOR) {
        if (ba_leak_free(ptr) != 0) {
            fprintf(stderr, "free(): ba_leak_free() failed\n");
            assert(0);
        }
        return;
    }

    // The pointer comes from another unknown allocator.
    // It can happen when the proxy library is not loaded via LD_PRELOAD
    // but it is linked dynamically.
    // We can do nothing in such case but return.
    fprintf(stderr, ">>> ba_leak_pool_contains_pointer() START\n");
    assert(ba_leak_pool_contains_pointer(orig_ptr) == 0);
    fprintf(stderr, ">>> ba_leak_pool_contains_pointer() END\n");
    (void)orig_ptr; // unused

    return;
}

#ifdef _WIN32
void _free_dbg(void *userData, int blockType) {
    (void)blockType; // unused
    free(userData);
}
#endif

void *realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return malloc(size);
    }

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    fprintf(stderr, ">>> realloc() START\n");

    size_t old_size;
    unsigned char owner;
    ptr = get_original_alloc(ptr, &old_size, NULL, &owner);

    if (owner == OWNER_POOL_ALLOCATOR) {
        if (Proxy_pool == NULL) {
            fprintf(stderr,
                    "realloc(): proxy pool had already been destroyed\n");
            assert(0);
            return NULL;
        }
        was_called_from_umfPool = 1;
        fprintf(stderr, ">>> umfPoolRealloc() START\n");
        void *new_ptr = umfPoolRealloc(Proxy_pool, ptr, size);
        fprintf(stderr, ">>> umfPoolRealloc() END\n");
        was_called_from_umfPool = 0;
        return add_metadata_and_align(new_ptr, size, 0, OWNER_POOL_ALLOCATOR);
    }

    if (owner == OWNER_LINEAR_ALLOCATOR) {
        fprintf(stderr, ">>> ba_leak_realloc() START\n");
        assert(ba_leak_pool_contains_pointer(ptr) > 0);
        return add_metadata_and_align(ba_leak_realloc(ptr, size, old_size),
                                      size, 0, OWNER_LINEAR_ALLOCATOR);
    }

    fprintf(stderr, "realloc(): invalid pointer: %p\n", ptr);
    assert(0);

    return NULL;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (size == 0) {
        return NULL;
    }

    add_size_for_metadata_and_alignment(&size, alignment);

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolAlignedMalloc(Proxy_pool, size, alignment);
        was_called_from_umfPool = 0;
        return add_metadata_and_align(ptr, size, alignment,
                                      OWNER_POOL_ALLOCATOR);
    }

    return add_metadata_and_align(ba_leak_alloc(size), size, alignment,
                                  OWNER_LINEAR_ALLOCATOR);
}

#ifdef _WIN32
size_t _msize(void *ptr) {
#else
size_t malloc_usable_size(void *ptr) {
#endif

    // a check to verify we are running the proxy library
    if (ptr == (void *)0x01) {
        return 0xDEADBEEF;
    }

    size_t usable_size;
    unsigned char owner;
    ptr = get_original_alloc(ptr, NULL, &usable_size, &owner);

    if (owner == OWNER_POOL_ALLOCATOR) {
        if (Proxy_pool == NULL) {
            fprintf(stderr, "malloc_usable_size(): proxy pool had already been "
                            "destroyed\n");
            assert(0);
            return 0;
        }
        was_called_from_umfPool = 1;
        size_t size = umfPoolMallocUsableSize(Proxy_pool, ptr);
        was_called_from_umfPool = 0;
        return size;
    }

    if (owner == OWNER_LINEAR_ALLOCATOR) {
        return usable_size;
    }

    fprintf(stderr, "malloc_usable_size(): invalid pointer: %p\n", ptr);
    assert(0);

    return 0;
}
