/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_FIXED_MEMORY_PROVIDER_H
#define UMF_FIXED_MEMORY_PROVIDER_H

#include <umf/providers/provider_os_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @cond
#define UMF_FIXED_RESULTS_START_FROM 4000
/// @endcond

/// @brief Memory provider settings struct
typedef struct umf_fixed_memory_provider_params_t {
    /// address of the memory buffer
    void *addr;
    /// size of the memory buffer in bytes
    size_t size;
} umf_fixed_memory_provider_params_t;

/// @brief Devdax Memory Provider operation results
typedef enum umf_fixed_memory_provider_native_error {
    UMF_FIXED_RESULT_SUCCESS = UMF_FIXED_RESULTS_START_FROM, ///< Success
    UMF_FIXED_RESULT_ERROR_ALLOC_FAILED,        ///< Memory allocation failed
    UMF_FIXED_RESULT_ERROR_ADDRESS_NOT_ALIGNED, ///< Allocated address is not aligned
    UMF_FIXED_RESULT_ERROR_FREE_FAILED,         ///< Memory deallocation failed
    UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED, ///< Force purging failed
} umf_fixed_memory_provider_native_error_t;

umf_memory_provider_ops_t *umfFixedMemoryProviderOps(void);

/// @brief Create default params for the devdax memory provider
static inline umf_fixed_memory_provider_params_t
umfFixedMemoryProviderParamsDefault(void *addr, size_t size) {
    umf_fixed_memory_provider_params_t params = {
        addr, /* address of the memory buffer */
        size, /* size of the memory buffer in bytes */
    };

    return params;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_FIXED_MEMORY_PROVIDER_H */
