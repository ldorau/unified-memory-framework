/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <windows.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sysinfoapi.h>

#include <umf/providers/provider_os_memory.h>

#include "utils_concurrency.h"
#include "utils_log.h"

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

// create a shared memory file
int os_shm_create(const char *shm_name, size_t size) {
    (void)shm_name; // unused
    (void)size;     // unused
    return 0;       // ignored on Windows
}

// open a shared memory file
int os_shm_open(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on Windows
}

// unlink a shared memory file
int os_shm_unlink(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on Windows
}

int os_create_anonymous_fd(void) {
    return 0; // ignored on Windows
}

size_t get_max_file_size(void) { return SIZE_MAX; }

int os_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on Windows
}
