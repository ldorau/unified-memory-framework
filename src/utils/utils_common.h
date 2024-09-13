/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_COMMON_H
#define UMF_COMMON_H 1

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "umf/memory_provider.h"
#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NAME_MAX 255

#define DO_WHILE_EMPTY                                                         \
    do {                                                                       \
    } while (0)

#define DO_WHILE_EXPRS(expression)                                             \
    do {                                                                       \
        expression;                                                            \
    } while (0)

#define ALIGN_UP(value, align) (((value) + (align)-1) & ~((align)-1))
#define ALIGN_DOWN(value, align) ((value) & ~((align)-1))

#define VALGRIND_ANNOTATE_NEW_MEMORY(p, s) DO_WHILE_EMPTY
#define VALGRIND_HG_DRD_DISABLE_CHECKING(p, s) DO_WHILE_EMPTY

#ifdef _WIN32 /* Windows */

#define __TLS __declspec(thread)

#else /* Linux */

#define __TLS __thread

#endif /* _WIN32 */

typedef enum umf_purge_advise_t {
    UMF_PURGE_LAZY,
    UMF_PURGE_FORCE,
} umf_purge_advise_t;

// Check if the environment variable contains the given string.
int util_env_var_has_str(const char *envvar, const char *str);

// util_parse_var - Parses var for a prefix,
//                   optionally identifying a following argument.
// Parameters:
//   - var: String to parse  in "option1;option2,arg2;..." format, with options
//          separated by ';' and optional arguments by ','.
//   - option: Option to search for within var.
//   - extraArg: If not NULL, function expects an argument after the option and
//               updates this pointer to the argument's position within var.
//               If NULL, function expects option without an argument.
// Return Value:
// Pointer to option within var if found; NULL otherwise.
//
// IMPORTANT: Both extraArg and return values are pointers within var,
// and are not null-terminated.
const char *util_parse_var(const char *var, const char *option,
                           const char **extraArg);

// check if we are running in the proxy library
int util_is_running_in_proxy_lib(void);

size_t util_get_page_size(void);

// align a pointer and a size
void util_align_ptr_size(void **ptr, size_t *size, size_t alignment);

// get the current process ID
int utils_getpid(void);

// get the current thread ID
int utils_gettid(void);

// close file descriptor
int utils_close_fd(int fd);

// obtain a duplicate of another process's file descriptor
umf_result_t utils_duplicate_fd(int pid, int fd_in, int *fd_out);

int util_copy_path(const char *in_path, char out_path[], size_t path_max);

umf_result_t utils_translate_flags(unsigned in_flags, unsigned max,
                                   umf_result_t (*translate_flag)(unsigned,
                                                                  unsigned *),
                                   unsigned *out_flags);

umf_result_t utils_translate_mem_protection_flags(unsigned in_protection,
                                                  unsigned *out_protection);

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag);

void *utils_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
                 size_t fd_offset);

int utils_munmap(void *addr, size_t length);

int utils_devdax_open(const char *path);

void *utils_devdax_mmap(void *hint_addr, size_t length, int prot, int fd);

void utils_strerror(int errnum, char *buf, size_t buflen);

int utils_purge(void *addr, size_t length, int advice);

int utils_get_file_size(int fd, size_t *size);

int utils_file_open(const char *path);

int utils_file_open_or_create(const char *path, size_t size);

int utils_fallocate(int fd, long offset, long len);

#ifdef __cplusplus
}
#endif

#endif /* UMF_COMMON_H */
