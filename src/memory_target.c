/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include "memory_target.h"
#include "memory_target_ops.h"

umf_result_t umfMemoryTargetCreate(const umf_memory_target_ops_t *ops,
                                   void *params,
                                   umf_memory_target_handle_t *memoryTarget) {
    if (!ops || !memoryTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_target_handle_t target =
        (umf_memory_target_t *)malloc(sizeof(umf_memory_target_t));
    if (!target) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    target->ops = ops;

    void *target_priv;
    umf_result_t ret = ops->initialize(params, &target_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        free(target);
        return ret;
    }

    target->priv = target_priv;

    *memoryTarget = target;

    return UMF_RESULT_SUCCESS;
}

void umfMemoryTargetDestroy(umf_memory_target_handle_t memoryTarget) {
    assert(memoryTarget);
    memoryTarget->ops->finalize(memoryTarget->priv);
    free(memoryTarget);
}