/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"

// create a shared memory file
int os_shm_create(const char *shm_name, size_t size) {
    if (shm_name == NULL) {
        LOG_ERR("empty name of a shared memory file");
        return -1;
    }

    (void)shm_unlink(shm_name);

    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        LOG_PERR("cannot create a shared memory file /dev/shm/%s", shm_name);
        return fd;
    }

    int ret = os_set_file_size(fd, size);
    if (ret) {
        LOG_ERR("setting size (%zu) of a file /dev/shm/%s failed", size,
                shm_name);
        close(fd);
        (void)shm_unlink(shm_name);
        return -1;
    }

    return fd;
}

// open a shared memory file
int os_shm_open(const char *shm_name) {
    if (shm_name == NULL) {
        LOG_ERR("empty name of a shared memory file");
        return -1;
    }

    int fd = shm_open(shm_name, O_RDWR, 0600);
    if (fd == -1) {
        LOG_PERR("cannot open a shared memory file /dev/shm/%s", shm_name);
    }

    return fd;
}

// unlink a shared memory file
int os_shm_unlink(const char *shm_name) { return shm_unlink(shm_name); }

static int syscall_memfd_secret(void) {
    int fd = -1;
#ifdef __NR_memfd_secret
    // SYS_memfd_secret is supported since Linux 5.14
    // not using SYS_memfd_secret as SLES does not define it
    fd = syscall(__NR_memfd_secret, 0);
    if (fd == -1) {
        LOG_PERR("memfd_secret() failed");
    }
    if (fd > 0) {
        LOG_DEBUG("anonymous file descriptor created using memfd_secret()");
    }
#endif /* __NR_memfd_secret */
    return fd;
}

static int syscall_memfd_create(void) {
    int fd = -1;
#ifdef __NR_memfd_create
    // SYS_memfd_create is supported since Linux 3.17, glibc 2.27
    // not using SYS_memfd_create for consistency with syscall_memfd_secret
    fd = syscall(__NR_memfd_create, "anon_fd_name", 0);
    if (fd == -1) {
        LOG_PERR("memfd_create() failed");
    }
    if (fd > 0) {
        LOG_DEBUG("anonymous file descriptor created using memfd_create()");
    }
#endif /* __NR_memfd_create */
    return fd;
}

// create an anonymous file descriptor
int os_create_anonymous_fd(void) {
    int fd = -1;

    if (!util_env_var_has_str("UMF_MEM_FD_FUNC", "memfd_create")) {
        fd = syscall_memfd_secret();
        if (fd > 0) {
            return fd;
        }
    }

    // The SYS_memfd_secret syscall can fail with errno == ENOTSYS (function not implemented).
    // We should try to call the SYS_memfd_create syscall in this case.

    fd = syscall_memfd_create();

#if !(defined __NR_memfd_secret) && !(defined __NR_memfd_create)
    if (fd == -1) {
        LOG_ERR("cannot create an anonymous file descriptor - neither "
                "memfd_secret() nor memfd_create() are defined");
    }
#endif /* !(defined __NR_memfd_secret) && !(defined __NR_memfd_create) */

    return fd;
}

int utils_get_file_size(int fd, size_t *size) {
    struct stat statbuf;
    int ret = fstat(fd, &statbuf);
    if (ret) {
        LOG_PERR("fstat(%i) failed", fd);
        return ret;
    }

    *size = statbuf.st_size;
    return 0;
}

int os_set_file_size(int fd, size_t size) {
    errno = 0;
    int ret = ftruncate(fd, size);
    if (ret) {
        LOG_PERR("ftruncate(%i, %zu) failed", fd, size);
    }
    return ret;
}

int utils_fallocate(int fd, long offset, long len) {
    return posix_fallocate(fd, offset, len);
}
