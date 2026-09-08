/*
 * Reproducer for Issue #2 (HIGH):
 *
 *   "Pointer-resolution APIs silently pick an arbitrary allocation on
 *    address overlap, inconsistent with umfFree's explicit ambiguity
 *    check."
 *
 * Files involved:
 *   - src/provider/provider_tracking.c:655-685 (umfMemoryTrackerGetAllocInfo)
 *   - src/memory_properties.c:21-40           (umfGetMemoryPropertiesHandle)
 *   - src/memory_pool.c:573-586               (umfPoolByPtr)
 *   - src/ipc.c:58-100                         (umfGetIPCHandle)
 *
 * Unlike Issue #1 (which involved an *unintentional* address-space
 * misclassification caused by a provider not implementing
 * get_address_space), this reproducer uses the address-space feature
 * exactly as *designed and documented*: two providers that legitimately
 * report two different, explicitly-configured address spaces (e.g.
 * modelling host memory vs. a distinct "device" mapping) which happen to
 * expose the same numeric pointer value -- this is precisely the scenario
 * umf_memory_provider_address_space_t exists to disambiguate.
 *
 * umfFree() correctly detects this designed-for ambiguity (via
 * umfMemoryTrackerGetAllocInfoExactCount()) and returns
 * UMF_RESULT_ERROR_AMBIGUOUS, refusing to guess which allocation the
 * caller means.
 *
 * However umfMemoryTrackerGetAllocInfo() -- the function underlying
 * umfGetMemoryPropertiesHandle(), umfPoolByPtr(), and umfGetIPCHandle() --
 * performs no equivalent check. It just walks every address-space bucket
 * and keeps whichever candidate has the highest internal `props.id`
 * (i.e. "the most recently created allocation"), and returns
 * UMF_RESULT_SUCCESS with *no* indication that the result was ambiguous.
 *
 * This program demonstrates the inconsistency directly:
 *   1. umfFree(ptr) on the shared address correctly reports
 *      UMF_RESULT_ERROR_AMBIGUOUS.
 *   2. umfPoolByPtr(ptr, &pool) on the very same address instead reports
 *      UMF_RESULT_SUCCESS and silently returns an arbitrary pool (in
 *      practice, the most-recently-created one), giving calling code no
 *      way to know the pointer was ambiguous.
 *   3. Because callers naturally expect umfPoolByPtr() to behave
 *      consistently with umfFree() (both are "resolve ptr -> owner"
 *      operations), code that does
 *          umfPoolByPtr(ptr, &pool); ... umfPoolFree(pool, ptr);
 *      silently frees/operates on the WRONG logical allocation's pool
 *      whenever this ambiguity occurs, without any error ever being
 *      surfaced.
 *
 * Build (from repo root, against the build/ dir):
 *
 *   gcc -g -O0 -Iinclude -o repro_ambiguous_ptr_resolution \
 *       repro_ambiguous_ptr_resolution.c -Lbuild/lib -lumf \
 *       -Wl,-rpath,$(pwd)/build/lib
 *   LD_LIBRARY_PATH="" ./repro_ambiguous_ptr_resolution
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_fixed_memory.h>

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAILED: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

/* Creates a pool backed by umfFixedMemoryProviderOps(), pinned at [ptr,ptr+size).
 * If address_space is non-NULL, the provider is explicitly configured to
 * report that (legitimately distinct) address space instead of the default
 * host identity. */
static void create_fixed_pool(
    void *ptr, size_t size, const char *name,
    const umf_memory_provider_address_space_t *address_space,
    umf_memory_pool_handle_t *out_pool) {
    umf_fixed_memory_provider_params_handle_t params = NULL;
    umf_result_t res = umfFixedMemoryProviderParamsCreate(ptr, size, &params);
    CHECK(res == UMF_RESULT_SUCCESS, "umfFixedMemoryProviderParamsCreate");

    res = umfFixedMemoryProviderParamsSetName(params, name);
    CHECK(res == UMF_RESULT_SUCCESS, "umfFixedMemoryProviderParamsSetName");

    if (address_space) {
        res = umfFixedMemoryProviderParamsSetAddressSpace(params,
                                                          address_space);
        CHECK(res == UMF_RESULT_SUCCESS,
             "umfFixedMemoryProviderParamsSetAddressSpace");
    }

    umf_memory_provider_handle_t provider = NULL;
    res = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                  &provider);
    CHECK(res == UMF_RESULT_SUCCESS, "umfMemoryProviderCreate(fixed)");
    umfFixedMemoryProviderParamsDestroy(params);

    umf_memory_pool_handle_t pool = NULL;
    res = umfPoolCreate(umfProxyPoolOps(), provider, NULL,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool);
    CHECK(res == UMF_RESULT_SUCCESS, "umfPoolCreate");

    *out_pool = pool;
}

static void print_pool_provider_name(const char *label,
                                     umf_memory_pool_handle_t pool) {
    umf_memory_provider_handle_t provider = NULL;
    umf_result_t res = umfPoolGetMemoryProvider(pool, &provider);
    CHECK(res == UMF_RESULT_SUCCESS, "umfPoolGetMemoryProvider");

    const char *name = NULL;
    res = umfMemoryProviderGetName(provider, &name);
    CHECK(res == UMF_RESULT_SUCCESS, "umfMemoryProviderGetName");

    printf("%s -> provider name = \"%s\"\n", label, name);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const size_t size = 4096; /* one page, required by the fixed-memory
                                 provider's internal coarse allocator */
    void *buf = NULL;
    CHECK(posix_memalign(&buf, size, size) == 0, "posix_memalign(buf)");

    /* "device" address space: an explicit, legitimately distinct namespace,
     * exactly as intended for e.g. host vs. device memory that can validly
     * expose the same numeric pointer value. */
    static const char device_namespace_token;
    umf_memory_provider_address_space_t device_address_space = {
        &device_namespace_token, /* namespace_token */
        0,                       /* context */
        0                        /* device */
    };

    /* pool0: default host address space ({NULL,0,0}). */
    umf_memory_pool_handle_t pool0 = NULL;
    create_fixed_pool(buf, size, "host_provider", NULL, &pool0);

    /* pool1: explicit, legitimately distinct "device" address space. */
    umf_memory_pool_handle_t pool1 = NULL;
    create_fixed_pool(buf, size, "device_provider", &device_address_space,
                      &pool1);

    void *ptr0 = umfPoolMalloc(pool0, size);
    CHECK(ptr0 != NULL, "umfPoolMalloc(pool0)");
    void *ptr1 = umfPoolMalloc(pool1, size);
    CHECK(ptr1 != NULL, "umfPoolMalloc(pool1)");
    CHECK(ptr1 == ptr0,
         "ptr1 must alias ptr0 -- same numeric address, two distinct, "
         "legitimately-configured address spaces");

    printf("pool0 (\"host\" address space)   allocated ptr0=%p\n", ptr0);
    printf("pool1 (\"device\" address space) allocated ptr1=%p\n", ptr1);
    printf("(ptr0 == ptr1, but they are two DIFFERENT logical allocations "
          "in two DIFFERENT, deliberately configured address spaces)\n\n");

    /* --- Step 1: umfFree correctly detects the ambiguity --- */
    umf_result_t res = umfFree(ptr0);
    printf("umfFree(ptr0)       -> result=%d %s\n", res,
          res == UMF_RESULT_ERROR_AMBIGUOUS
              ? "(UMF_RESULT_ERROR_AMBIGUOUS -- correctly refuses to guess)"
              : "(unexpected!)");
    CHECK(res == UMF_RESULT_ERROR_AMBIGUOUS,
         "umfFree must report ambiguity for this address");

    /* --- Step 2: umfPoolByPtr silently picks an arbitrary pool for the
     * exact same address, with no ambiguity signal at all. --- */
    umf_memory_pool_handle_t found_pool = NULL;
    res = umfPoolByPtr(ptr0, &found_pool);
    printf("umfPoolByPtr(ptr0)  -> result=%d (%s), found_pool=%p\n", res,
          res == UMF_RESULT_SUCCESS ? "SUCCESS -- no ambiguity reported!"
                                    : "unexpected",
          (void *)found_pool);
    printf("                       pool0=%p (host), pool1=%p (device)\n",
          (void *)pool0, (void *)pool1);
    CHECK(res == UMF_RESULT_SUCCESS,
         "umfPoolByPtr silently succeeds instead of reporting ambiguity "
         "(this is the bug)");

    print_pool_provider_name("umfPoolByPtr(ptr0) result", found_pool);
    printf("\n");

    /* --- Step 3: demonstrate the real-world consequence: code that
     * trusts umfPoolByPtr() to resolve the "owning" pool, then acts on
     * that pool, silently operates on the WRONG logical allocation
     * (whichever pool umfPoolByPtr arbitrarily picked) without ever
     * being told the pointer was ambiguous. --- */
    printf("Caller pattern: \"umfPoolByPtr(ptr, &pool); "
          "umfPoolFree(pool, ptr);\"\n");
    printf("This will silently free through pool=%p (%s) even if the "
          "caller actually meant the *other* allocation:\n",
          (void *)found_pool,
          found_pool == pool0 ? "host" : "device");
    res = umfPoolFree(found_pool, ptr1);
    printf("umfPoolFree(found_pool, ptr) -> result=%d\n", res);

    umf_memory_pool_handle_t other_pool = (found_pool == pool0) ? pool1 : pool0;
    printf("\nThe OTHER pool (%p, %s) still believes its allocation is "
          "live and was never told about the free:\n",
          (void *)other_pool, other_pool == pool0 ? "host" : "device");
    found_pool = NULL;
    res = umfPoolByPtr(ptr0, &found_pool);
    printf("umfPoolByPtr(ptr0)  -> result=%d, found_pool=%p (still resolves "
          "to a pool, no error, even though one side already freed)\n",
          res, (void *)found_pool);

    printf("\nIssue #2 reproduced: umfFree() and umfPoolByPtr() disagree "
          "on whether this pointer is ambiguous -- umfFree() refuses to "
          "guess (UMF_RESULT_ERROR_AMBIGUOUS), while umfPoolByPtr() "
          "silently picks an arbitrary pool and reports SUCCESS.\n");

    /* best-effort cleanup */
    umfPoolFree(other_pool, ptr0);
    umfPoolDestroy(pool1);
    umfPoolDestroy(pool0);
    free(buf);

    return 0;
}
