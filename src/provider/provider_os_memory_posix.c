/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

// maximum value of the off_t type
#define OFF_T_MAX                                                              \
    (sizeof(off_t) == sizeof(long long)                                        \
         ? LLONG_MAX                                                           \
         : (sizeof(off_t) == sizeof(long) ? LONG_MAX : INT_MAX))

size_t get_max_file_size(void) { return OFF_T_MAX; }
