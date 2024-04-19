/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"

umf_result_t os_translate_mem_protection_one_flag(unsigned in_protection,
                                                  unsigned *out_protection) {
    switch (in_protection) {
    case UMF_PROTECTION_NONE:
        *out_protection = PROT_NONE;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_READ:
        *out_protection = PROT_READ;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_WRITE:
        *out_protection = PROT_WRITE;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_EXEC:
        *out_protection = PROT_EXEC;
        return UMF_RESULT_SUCCESS;
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

umf_result_t os_translate_memory_flag(unsigned in_flag, unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
#ifdef __APPLE__
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
#else
        *out_flag = MAP_SHARED;
        return UMF_RESULT_SUCCESS;
#endif
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

int os_create_memory_fd(unsigned translated_memory_flag) {
#ifdef __APPLE__
    (void)translated_memory_flag; // unused
    return 0;                     // ignored on MacOSX
#else
    // fd is created only for MAP_SHARED
    if (translated_memory_flag != MAP_SHARED) {
        return 0;
    }

    int fd = -1;

#ifdef __NR_memfd_secret
    // SYS_memfd_secret is supported since Linux 5.14
    fd = syscall(SYS_memfd_secret, 0);
    if (fd == -1) {
        LOG_PDEBUG("memfd_secret()");
    }
    if (fd > 0) {
        LOG_DEBUG("file descriptor created using memfd_secret()");
        return fd;
    }
    // syscall(SYS_memfd_secret) can fail with errno == ENOTSYS (function not implemented).
    // We should try to call syscall(SYS_memfd_create) in this case.
#endif /* __NR_memfd_secret */

#ifdef __NR_memfd_create
    // SYS_memfd_create is supported since Linux 3.17, glibc 2.27
    fd = syscall(SYS_memfd_create, "fd_name", 0);
    if (fd == -1) {
        LOG_PDEBUG("memfd_create()");
    }
    if (fd > 0) {
        LOG_DEBUG("file descriptor created using memfd_create()");
    }
#endif /* __NR_memfd_create */

    return fd;

#endif /* __APPLE__ */
}

int os_set_file_size(int fd, size_t size) {
#ifdef __APPLE__
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on MacOSX
#else
    return ftruncate(fd, size);
#endif /* __APPLE__ */
}

umf_result_t os_translate_mem_protection_flags(unsigned in_protection,
                                               unsigned *out_protection) {
    // translate protection - combination of 'umf_mem_protection_flags_t' flags
    return os_translate_flags(in_protection, UMF_PROTECTION_MAX,
                              os_translate_mem_protection_one_flag,
                              out_protection);
}

static int os_translate_purge_advise(umf_purge_advise_t advise) {
    switch (advise) {
    case UMF_PURGE_LAZY:
        return MADV_FREE;
    case UMF_PURGE_FORCE:
        return MADV_DONTNEED;
    }
    assert(0);
    return -1;
}

void *os_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
              size_t fd_offset) {
    fd = (fd == 0) ? -1 : fd;
    if (fd == -1) {
        // MAP_ANONYMOUS - the mapping is not backed by any file
        flag |= MAP_ANONYMOUS;
    }

    void *ptr = mmap(hint_addr, length, prot, flag, fd, fd_offset);
    if (ptr == MAP_FAILED) {
        return NULL;
    }

    return ptr;
}

int os_munmap(void *addr, size_t length) { return munmap(addr, length); }

size_t os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

int os_purge(void *addr, size_t length, int advice) {
    return madvise(addr, length, os_translate_purge_advise(advice));
}

void os_strerror(int errnum, char *buf, size_t buflen) {
    strerror_r(errnum, buf, buflen);
}

int os_getpid(void) { return getpid(); }

umf_result_t os_duplicate_fd(int pid, int fd_in, int *fd_out) {
    errno = 0;
// SYS_pidfd_open is supported since Linux 5.3
// SYS_pidfd_getfd is supported since Linux 5.6
#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
    int pid_fd = syscall(SYS_pidfd_open, pid, 0);
    if (pid_fd == -1) {
        LOG_PDEBUG("SYS_pidfd_open");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    int fd_dup = syscall(SYS_pidfd_getfd, pid_fd, fd_in, 0);
    close(pid_fd);
    if (fd_dup == -1) {
        LOG_PDEBUG("SYS_pidfd_getfd");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    *fd_out = fd_dup;

    return UMF_RESULT_SUCCESS;
#else
    (void)pid;                             // unused
    (void)fd_in;                           // unused
    (void)fd_out;                          // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED; // unsupported
                                           // TODO: find another way
#endif /* defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd) */
}
