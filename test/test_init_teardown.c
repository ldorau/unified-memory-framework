/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <dlfcn.h>
#include <numa.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SIZE_ALLOC 4096

typedef int (*umfMemoryProviderCreateFromMemspace_t)(void *hMemspace,
                                                     void *hPolicy,
                                                     void **hPool);
typedef int (*umfPoolCreate_t)(void *ops, void *provider, void *params,
                               uint32_t flags, void **hPool);
typedef void (*umfDestroy_t)(void *handle);
typedef void (*umfVoidVoid_t)(void);
typedef void *(*umfGetPtr_t)(void);

static umfVoidVoid_t umfTearDown;
static umfDestroy_t umfMemoryProviderDestroy;
static umfDestroy_t umfPoolDestroy;
static const char *umf_lib_name;
static void *h_umf;
static void *umf_provider_default;
static void *umf_provider_large_cap;
static void *umf_provider_high_bw;
static void *umf_provider_low_lat;
static void *umf_pool_default;
static void *umf_pool_large_cap;
static void *umf_pool_high_bw;
static void *umf_pool_low_lat;

// UMF memspaces
static void *umf_default;
static void *umf_large_cap;
static void *umf_high_bw;
static void *umf_low_lat;

// UMF alloc
static void *(*umf_alloc)(void *pool, size_t size);

// UMF free
static void (*umf_free)(void *pool, void *ptr);

static void load_symbol(void *handle, const char *name, void **dest) {
    void *symbol = dlsym(handle, name);
    if (symbol == NULL) {
        fprintf(stderr, "umf_load: symbol %s NOT found\n", name);
        *dest = NULL;
        return;
    }

    fprintf(stderr, "umf_load: symbol found: %s\n", name);

    *dest = symbol;
}

static int umf_load(void) {
    umfMemoryProviderCreateFromMemspace_t umfMemoryProviderCreateFromMemspace;
    umfGetPtr_t umfMemspaceHostAllGet; // the default memspace
    umfGetPtr_t umfMemspaceHighestCapacityGet;
    umfGetPtr_t umfMemspaceHighestBandwidthGet;
    umfGetPtr_t umfMemspaceLowestLatencyGet;
    umfGetPtr_t umfScalablePoolOps;
    umfPoolCreate_t umfPoolCreate;
    umfVoidVoid_t umfInit;
    void *memspaceHostAll;
    void *memspaceHighestCapacity;
    void *memspaceHighestBandwidth;
    void *memspaceLowestLatency;
    int ret;

    umf_lib_name = "libumf.so";
    h_umf = dlopen(umf_lib_name, RTLD_LAZY);
    if (h_umf == NULL) {
        fprintf(stderr, "umf_load: UMF library not found (%s)\n", umf_lib_name);
        return -1;
    }

    load_symbol(h_umf, "umfInit", (void **)&umfInit);
    if (umfInit == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfTearDown", (void **)&umfTearDown);
    if (umfTearDown == NULL) {
        goto err_dlclose;
    }

    // initialize libumf (increment the reference counter of users)
    (*umfInit)();

    load_symbol(h_umf, "umfMemoryProviderCreateFromMemspace",
                (void **)&umfMemoryProviderCreateFromMemspace);
    if (umfMemoryProviderCreateFromMemspace == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfMemoryProviderDestroy",
                (void **)&umfMemoryProviderDestroy);
    if (umfMemoryProviderDestroy == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolCreate", (void **)&umfPoolCreate);
    if (umfPoolCreate == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolDestroy", (void **)&umfPoolDestroy);
    if (umfPoolDestroy == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolMalloc", (void **)&umf_alloc);
    if (umf_alloc == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolFree", (void **)&umf_free);
    if (umf_free == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfScalablePoolOps", (void **)&umfScalablePoolOps);
    if (umfScalablePoolOps == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfMemspaceHostAllGet",
                (void **)&umfMemspaceHostAllGet);
    if (umfMemspaceHostAllGet == NULL) {
        goto err_dlclose;
    }

    memspaceHostAll = (*umfMemspaceHostAllGet)();
    if (memspaceHostAll == NULL) {
        fprintf(stderr, "umf_load: cannot get the memspaceHostAll memspace\n");
        goto err_dlclose;
    }
    fprintf(stderr, "umf_load: got memspace: memspaceHostAll\n");

    ret = (*umfMemoryProviderCreateFromMemspace)(memspaceHostAll, NULL,
                                                 &umf_provider_default);
    if (ret || umf_provider_default == NULL) {
        fprintf(stderr, "umf_load: error creating the default provider: %i\n",
                ret);
        goto err_dlclose;
    }
    fprintf(stderr, "umf_load: the default provider created from memspace\n");

    umf_default = NULL;
    ret = (*umfPoolCreate)((*umfScalablePoolOps)(), umf_provider_default, NULL,
                           0, &umf_pool_default);
    if (ret || umf_pool_default == NULL) {
        fprintf(stderr, "umf_load: error creating the default pool: %i\n", ret);
        goto err_destroy_provider;
    }
    fprintf(stderr,
            "umf_load: the default pool created from the All Nodes provider\n");

    umf_default = umf_pool_default; // umf pool using the default memspace

    // the highest capacity memspace
    umf_large_cap = NULL;
    load_symbol(h_umf, "umfMemspaceHighestCapacityGet",
                (void **)&umfMemspaceHighestCapacityGet);
    if (umfMemspaceHighestCapacityGet == NULL) {
        goto err_destroy_pool;
    }

    memspaceHighestCapacity = (*umfMemspaceHighestCapacityGet)();
    if (memspaceHighestCapacity == NULL) {
        fprintf(stderr,
                "umf_load: cannot get memspace: memspaceHighestCapacity\n");
    } else {
        fprintf(stderr, "umf_load: got memspace: memspaceHighestCapacity\n");
        ret = (*umfMemoryProviderCreateFromMemspace)(
            memspaceHighestCapacity, NULL, &umf_provider_large_cap);
        if (ret || umf_provider_large_cap == NULL) {
            fprintf(
                stderr,
                "umf_load: error creating the highest capacity provider: %i\n",
                ret);
        } else {
            fprintf(stderr, "umf_load: the highest capacity provider created "
                            "from memspace\n");
            ret = (*umfPoolCreate)((*umfScalablePoolOps)(),
                                   umf_provider_large_cap, NULL, 0,
                                   &umf_pool_large_cap);
            if (ret || umf_pool_large_cap == NULL) {
                fprintf(
                    stderr,
                    "umf_load: error creating the highest capacity pool: %i\n",
                    ret);
                (*umfMemoryProviderDestroy)(umf_provider_large_cap);
            } else {
                fprintf(stderr, "umf_load: the highest capacity pool created "
                                "from the highest capacity provider\n");
                umf_large_cap = umf_pool_large_cap;
            }
        }
    }

    // the highest bandwidth memspace (umfMemspaceHighestBandwidthGet)
    umf_high_bw = NULL;
    load_symbol(h_umf, "umfMemspaceHighestBandwidthGet",
                (void **)&umfMemspaceHighestBandwidthGet);
    if (umfMemspaceHighestBandwidthGet == NULL) {
        goto err_destroy_pool;
    }

    memspaceHighestBandwidth = (*umfMemspaceHighestBandwidthGet)();
    if (memspaceHighestBandwidth == NULL) {
        fprintf(stderr,
                "umf_load: cannot get memspace: memspaceHighestBandwidth\n");
    } else {
        fprintf(stderr, "umf_load: got memspace: memspaceHighestBandwidth\n");
        ret = (*umfMemoryProviderCreateFromMemspace)(
            memspaceHighestBandwidth, NULL, &umf_provider_high_bw);
        if (ret || umf_provider_high_bw == NULL) {
            fprintf(
                stderr,
                "umf_load: error creating the highest bandwidth provider: %i\n",
                ret);
        } else {
            fprintf(stderr, "umf_load: the highest bandwidth provider created "
                            "from memspace\n");
            ret =
                (*umfPoolCreate)((*umfScalablePoolOps)(), umf_provider_high_bw,
                                 NULL, 0, &umf_pool_high_bw);
            if (ret || umf_pool_high_bw == NULL) {
                fprintf(
                    stderr,
                    "umf_load: error creating the highest bandwidth pool: %i\n",
                    ret);
                (*umfMemoryProviderDestroy)(umf_provider_high_bw);
            } else {
                fprintf(stderr, "umf_load: the highest bandwidth pool created "
                                "from the highest bandwidth provider\n");
                umf_high_bw = umf_pool_high_bw;
            }
        }
    }

    // the lowest latency memspace (umfMemspaceLowestLatencyGet)
    umf_low_lat = NULL;
    load_symbol(h_umf, "umfMemspaceLowestLatencyGet",
                (void **)&umfMemspaceLowestLatencyGet);
    if (umfMemspaceLowestLatencyGet) {
        memspaceLowestLatency = (*umfMemspaceLowestLatencyGet)();
        if (memspaceLowestLatency == NULL) {
            fprintf(stderr, "umf_load: memspaceLowestLatency NOT found\n");
        } else {
            fprintf(stderr, "umf_load: got memspace: memspaceLowestLatency\n");
            ret = (*umfMemoryProviderCreateFromMemspace)(
                memspaceLowestLatency, NULL, &umf_provider_low_lat);
            if (ret || umf_provider_low_lat == NULL) {
                fprintf(stderr,
                        "umf_load: error creating the lowest latency "
                        "provider: %i\n",
                        ret);
            } else {
                fprintf(stderr, "umf_load: the lowest latency "
                                "provider created from memspace\n");
                ret = (*umfPoolCreate)((*umfScalablePoolOps)(),
                                       umf_provider_low_lat, NULL, 0,
                                       &umf_pool_low_lat);
                if (ret || umf_pool_low_lat == NULL) {
                    fprintf(stderr,
                            "umf_load: error creating the lowest "
                            "latency pool: %i\n",
                            ret);
                    (*umfMemoryProviderDestroy)(umf_provider_low_lat);
                } else {
                    fprintf(stderr,
                            "umf_load: the lowest latency pool "
                            "created from the lowest latency provider\n");
                    umf_low_lat = umf_pool_low_lat;
                }
            }
        }
    }

    fprintf(stderr, "umf_load: umf initialized\n");

    return 0;

err_destroy_pool:
    (*umfPoolDestroy)(umf_pool_default);
err_destroy_provider:
    (*umfMemoryProviderDestroy)(umf_provider_default);
err_dlclose:
    dlclose(h_umf);

    return -1;
}

static void umf_unload(void) {
    fprintf(stderr, "umf_unload: finalizing UMF ...\n");
    umf_low_lat = NULL;
    umf_high_bw = NULL;
    umf_large_cap = NULL;
    umf_default = NULL;

    fprintf(stderr, "umf_unload: destroying umf memory pools ...\n");
    if (umf_pool_low_lat) {
        fprintf(stderr, "umf_unload: destroying the lowest latency umf "
                        "memory pool ...\n");
        (*umfPoolDestroy)(umf_pool_low_lat);
        fprintf(stderr, "umf_unload: the lowest latency umf memory "
                        "pool destroyed\n");
    }

    if (umf_pool_high_bw) {
        fprintf(stderr, "umf_unload: destroying the highest bandwidth umf "
                        "memory pool ...\n");
        (*umfPoolDestroy)(umf_pool_high_bw);
        fprintf(stderr, "umf_unload: the highest bandwidth umf "
                        "memory pool destroyed\n");
    }

    if (umf_pool_large_cap) {
        fprintf(stderr, "umf_unload: destroying the highest capacity umf "
                        "memory pool ...\n");
        (*umfPoolDestroy)(umf_pool_large_cap);
        fprintf(stderr, "umf_unload: the highest capacity umf "
                        "memory pool destroyed\n");
    }

    if (umf_pool_default) {
        fprintf(stderr,
                "umf_unload: destroying the default umf memory pool ...\n");
        (*umfPoolDestroy)(umf_pool_default);
        fprintf(stderr, "umf_unload: the default umf memory pool "
                        "destroyed\n");
    }

    fprintf(stderr, "umf_unload: destroying umf memory providers ...\n");
    if (umf_provider_low_lat) {
        (*umfMemoryProviderDestroy)(umf_provider_low_lat);
        fprintf(stderr, "umf_unload: the lowest latency umf memory "
                        "provider destroyed\n");
    }

    if (umf_provider_high_bw) {
        (*umfMemoryProviderDestroy)(umf_provider_high_bw);
        fprintf(stderr, "umf_unload: the highest bandwidth umf "
                        "memory provider destroyed\n");
    }

    if (umf_provider_large_cap) {
        (*umfMemoryProviderDestroy)(umf_provider_large_cap);
        fprintf(stderr, "umf_unload: the highest capacity umf "
                        "memory provider destroyed\n");
    }

    if (umf_provider_default) {
        (*umfMemoryProviderDestroy)(umf_provider_default);
        fprintf(stderr, "umf_unload: the default umf memory "
                        "provider destroyed\n");
    }

    // deinitialize libumf (decrement the reference counter of users)
    fprintf(stderr, "umf_unload: calling umfTearDown() ...\n");
    (*umfTearDown)();

    fprintf(stderr, "umf_unload: closing umf library ...\n");
    dlclose(h_umf);
    fprintf(stderr, "umf_unload: umf library closed\n");
}

static int run_test(int wrong_dtor_order) {

    if (wrong_dtor_order) {
        fprintf(stderr, "\n\n*** Running test with INCORRECT order of "
                        "destructors ***\n\n\n");
    } else {
        fprintf(
            stderr,
            "\n\n*** Running test with CORRECT order of destructors ***\n\n\n");
    }

    if (umf_load()) {
        return -1;
    }

    assert(umf_default);
    void *ptr = (*umf_alloc)(umf_default, SIZE_ALLOC);
    (*umf_free)(umf_default, ptr);

    if (umf_large_cap) {
        ptr = (*umf_alloc)(umf_large_cap, SIZE_ALLOC);
        (*umf_free)(umf_large_cap, ptr);
    }

    if (umf_high_bw) {
        ptr = (*umf_alloc)(umf_high_bw, SIZE_ALLOC);
        (*umf_free)(umf_high_bw, ptr);
    }

    if (umf_low_lat) {
        ptr = (*umf_alloc)(umf_low_lat, SIZE_ALLOC);
        (*umf_free)(umf_low_lat, ptr);
    }

    // simulate incorrect order of destructors (an additional, unwanted destructor call)
    if (wrong_dtor_order) {
        fprintf(stderr,
                "*** Simulating incorrect order of destructors !!! ***\n");
        (*umfTearDown)();
    }

    umf_unload();

    return 0;
}

int is_HMAT_supported() {
    struct stat info;
    const int MAXNODE_ID = numa_max_node();
    for (int node_id = 0; node_id <= MAXNODE_ID; ++node_id) {
        if (numa_bitmask_isbitset(numa_nodes_ptr, node_id)) {
            char access_path[256];
            sprintf(access_path, "/sys/devices/system/node/node%d/access0/",
                    node_id);
            if (!stat(access_path, &info)) {
                return 1;
            }
        }
    }
    return 0;
}

int main(void) {

    // The libtbbmalloc.so.2 library is required to run this test,
    // because it uses umfScalablePoolOps.
    // Skip this test if the libtbbmalloc.so.2 library is not found.
    void *tbb = dlopen("libtbbmalloc.so.2", RTLD_LAZY);
    if (tbb == NULL) {
        fprintf(stderr, "SKIP: required libtbbmalloc.so.2 library not found\n");
        return 0; // skip this test
    }

    dlclose(tbb);

    fprintf(stderr, "is_HMAT_supported?: %s\n",
            (is_HMAT_supported()) ? "YES" : "NO");

    if (run_test(0)) { // correct order of destructors
        return -1;
    }

    return 0;
}
