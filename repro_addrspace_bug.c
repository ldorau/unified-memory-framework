/*
 * Reproducer for Issue #1 (CRITICAL):
 *
 *   "Address-space partitioning silently defeats overlap/ambiguity
 *    detection when a real host-memory provider does not implement
 *    the new (optional) get_address_space op."
 *
 * Root cause (src/provider/provider_tracking.c, umfTrackingMemoryProviderCreate):
 *
 *      umf_result_t ret =
 *          umfMemoryProviderGetAddressSpace(hUpstream, &address_space_id);
 *      if (ret == UMF_RESULT_ERROR_NOT_SUPPORTED) {
 *          address_space_id.namespace_token = hUpstream;   // <-- BUG
 *          address_space_id.context = 0;
 *          address_space_id.device = 0;
 *      }
 *
 * Any provider that does not implement get_address_space() (the default for
 * every provider written before this feature was added, since the op is
 * optional and defaults to returning UMF_RESULT_ERROR_NOT_SUPPORTED) is
 * placed into a *unique* tracker bucket keyed by its own pointer, instead of
 * the shared "host default" bucket ({NULL,0,0}) used by every other
 * plain-host-memory provider (os_memory, fixed_memory, etc. all correctly
 * implement get_address_space() and return the default identity for host
 * memory).
 *
 * This program builds two pools that both back onto ordinary process heap
 * memory (glibc malloc), i.e. genuinely the *same* address space:
 *
 *   - pool0 is backed by a hand-written "legacy" provider that forgets to
 *     implement get_address_space() (very common: every third-party/legacy
 *     provider not yet updated for this feature behaves this way).
 *   - pool1 is backed by umfFixedMemoryProviderOps(), pinned at the exact
 *     [ptr0, ptr0+size) range pool0 just allocated. FixedMemoryProvider
 *     *does* implement get_address_space() and reports the default host
 *     identity.
 *
 * Because pool0's upstream provider does not implement get_address_space(),
 * UMF puts pool0's allocation and pool1's (numerically identical) allocation
 * into two different tracker buckets, even though they are the exact same
 * bytes of real host memory. As a result:
 *
 *   1. umfPoolByPtr() on the shared address silently resolves to an
 *      arbitrary pool instead of reporting UMF_RESULT_ERROR_AMBIGUOUS.
 *   2. umfPoolFree(pool0, ptr0) is allowed to actually free() the real
 *      backing memory while pool1 is completely unaware and still believes
 *      ptr1 (== ptr0) is a live, valid allocation it owns.
 *   3. Any subsequent use of ptr1 through pool1 (or a raw dereference) is a
 *      genuine, tool-detectable use-after-free of the same heap chunk pool0
 *      already returned to glibc.
 *
 * Build & run (from repo root, against the build/ dir):
 *
 *   gcc -g -O0 -fsanitize=address -Iinclude -o repro_addrspace_bug \
 *       repro_addrspace_bug.c -Lbuild/lib -lumf -Wl,-rpath,build/lib
 *   ./repro_addrspace_bug
 *
 * Expected (buggy) output: umfPoolFree(pool0,...) returns SUCCESS, and
 * AddressSanitizer reports a heap-use-after-free when ptr1 is subsequently
 * touched through pool1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_fixed_memory.h>

/* ---- minimal "legacy" host provider: no get_address_space ---- */

static umf_result_t legacy_initialize(const void *params, void **provider) {
    (void)params;
    *provider = (void *)1; /* no real state needed */
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_finalize(void *provider) {
    (void)provider;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_alloc(void *provider, size_t size, size_t alignment,
                                 void **ptr) {
    (void)provider;
    if (alignment == 0) {
        alignment = sizeof(void *);
    }
    void *p = NULL;
    if (alignment < 4096) { alignment = 4096; } if (posix_memalign(&p, alignment, size) != 0) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    *ptr = p;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_free(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)size;
    printf("[legacy provider] real free(%p)\n", ptr);
    free(ptr);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_get_last_native_error(void *provider,
                                                 const char **msg,
                                                 int32_t *err) {
    (void)provider;
    *msg = "no error";
    *err = 0;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_get_recommended_page_size(void *provider,
                                                     size_t size,
                                                     size_t *pageSize) {
    (void)provider;
    (void)size;
    *pageSize = 4096;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_get_min_page_size(void *provider, const void *ptr,
                                             size_t *pageSize) {
    (void)provider;
    (void)ptr;
    *pageSize = 4096;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_get_cache_line_size(void *provider, size_t *size) {
    (void)provider;
    *size = 64;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t legacy_get_name(void *provider, const char **name) {
    (void)provider;
    *name = "legacy_no_address_space_provider";
    return UMF_RESULT_SUCCESS;
}
/* NOTE: get_address_space intentionally left unset (NULL) below, exactly
 * like any provider written before this feature existed. */

static const umf_memory_provider_ops_t LEGACY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = legacy_initialize,
    .finalize = legacy_finalize,
    .alloc = legacy_alloc,
    .free = legacy_free,
    .get_last_native_error = legacy_get_last_native_error,
    .get_recommended_page_size = legacy_get_recommended_page_size,
    .get_min_page_size = legacy_get_min_page_size,
    .get_cache_line_size = legacy_get_cache_line_size,
    .get_name = legacy_get_name,
    /* .get_address_space = NULL -- not implemented, matches the vast
     * majority of pre-existing providers. */
};

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAILED: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    umf_result_t res;
    const size_t size = 4096; /* one page; must be page-aligned for the fixed-memory provider's internal coarse allocator */

    /* --- pool0: backed by the "legacy" provider (no get_address_space) --- */
    umf_memory_provider_handle_t provider0 = NULL;
    res = umfMemoryProviderCreate(&LEGACY_PROVIDER_OPS, NULL, &provider0);
    CHECK(res == UMF_RESULT_SUCCESS, "create legacy provider0");

    umf_memory_pool_handle_t pool0 = NULL;
    res = umfPoolCreate(umfProxyPoolOps(), provider0, NULL,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool0);
    CHECK(res == UMF_RESULT_SUCCESS, "create pool0");

    void *ptr0 = umfPoolMalloc(pool0, size);
    CHECK(ptr0 != NULL, "umfPoolMalloc(pool0)");
    printf("pool0 (legacy provider, no get_address_space) allocated ptr0=%p\n",
          ptr0);

    /* --- pool1: FixedMemoryProvider pinned at the exact same [ptr0,ptr0+size)
     * range. FixedMemoryProvider *does* implement get_address_space() and
     * reports the default host identity {NULL,0,0} -- i.e. real host memory,
     * exactly what pool0's memory also is. --- */
    umf_fixed_memory_provider_params_handle_t params = NULL;
    res = umfFixedMemoryProviderParamsCreate(ptr0, size, &params);
    CHECK(res == UMF_RESULT_SUCCESS, "create fixed provider params");

    umf_memory_provider_handle_t provider1 = NULL;
    res = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                  &provider1);
    CHECK(res == UMF_RESULT_SUCCESS, "create fixed provider1");
    umfFixedMemoryProviderParamsDestroy(params);

    umf_memory_pool_handle_t pool1 = NULL;
    res = umfPoolCreate(umfProxyPoolOps(), provider1, NULL,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool1);
    CHECK(res == UMF_RESULT_SUCCESS, "create pool1");

    void *ptr1 = umfPoolMalloc(pool1, size);
    CHECK(ptr1 != NULL, "umfPoolMalloc(pool1)");
    printf("pool1 (FixedMemoryProvider, default host address space) "
          "allocated ptr1=%p\n",
          ptr1);
    CHECK(ptr1 == ptr0,
         "ptr1 must alias ptr0 -- both are the same real host memory");

    /* --- Step 1: pointer resolution silently picks an arbitrary pool --- */
    umf_memory_pool_handle_t found_pool = NULL;
    res = umfPoolByPtr(ptr0, &found_pool);
    printf("umfPoolByPtr(ptr0) -> result=%d, found_pool=%p "
          "(pool0=%p, pool1=%p) -- no ambiguity reported!\n",
          res, (void *)found_pool, (void *)pool0, (void *)pool1);

    /* --- Step 2: pool0 is allowed to really free the memory while pool1
     * still believes ptr1 is a live, valid allocation it owns. --- */
    printf("\nCalling umfPoolFree(pool0, ptr0) -- pool1 has NOT freed ptr1 "
          "yet and still tracks it as valid...\n");
    res = umfPoolFree(pool0, ptr0);
    printf("umfPoolFree(pool0, ptr0) -> result=%d (SUCCESS means the real "
          "memory was released even though pool1 still owns ptr1)\n",
          res);
    CHECK(res == UMF_RESULT_SUCCESS, "umfPoolFree(pool0, ptr0) should "
                                     "'succeed' -- that's the bug");

    /* --- Step 3: pool1 still thinks ptr1 is valid; touching it is a
     * genuine use-after-free of memory pool0 already returned to glibc. --- */
    found_pool = NULL;
    res = umfPoolByPtr(ptr1, &found_pool);
    printf("umfPoolByPtr(ptr1) -> result=%d, found_pool=%p (pool1=%p) -- "
          "pool1 still believes ptr1 is a live allocation it owns!\n",
          res, (void *)found_pool, (void *)pool1);

    printf("\nWriting through ptr1 (already free()'d by pool0) -- "
          "this is a heap-use-after-free:\n");
    memset(ptr1, 0x41, size); /* <-- AddressSanitizer should flag this */
    printf("(if you see this without an ASan report, rerun built with "
          "-fsanitize=address to observe the UAF)\n");

    /* cleanup (best effort; pool1 will now double-account for memory
     * pool0 already freed) */
    umfPoolDestroy(pool1);
    umfPoolDestroy(pool0);

    printf("\nDone. Issue #1 reproduced: address-space bucketing based on "
          "an unimplemented get_address_space() silently split what is "
          "really the *same* host memory into two disjoint tracker "
          "buckets, defeating both the ambiguity check and use-after-free "
          "protection.\n");
    return 0;
}
