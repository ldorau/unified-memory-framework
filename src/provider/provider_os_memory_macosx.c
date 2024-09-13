/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"

// create a shared memory file
int os_shm_create(const char *shm_name, size_t size) {
    (void)shm_name; // unused
    (void)size;     // unused
    return 0;       // ignored on MacOSX
}

// open a shared memory file
int os_shm_open(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// unlink a shared memory file
int os_shm_unlink(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// create an anonymous file descriptor
int os_create_anonymous_fd(void) {
    return 0; // ignored on MacOSX
}

int utils_get_file_size(int fd, size_t *size) {
    (void)fd;   // unused
    (void)size; // unused
    return -1;  // not supported on MacOSX
}

int os_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on MacOSX
}

int utils_fallocate(int fd, long offset, long len) {
    (void)fd;     // unused
    (void)offset; // unused
    (void)len;    // unused

    return -1;
}
