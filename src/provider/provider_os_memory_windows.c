/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <Windows.h>

#include <assert.h>
#include <stdio.h>

#include <umf/providers/provider_os_memory.h>

int os_translate_mem_protection_flags(unsigned protection) {
    switch (protection) {
    case UMF_PROTECTION_NONE:
        return PAGE_NOACCESS;
    case UMF_PROTECTION_EXEC:
        return PAGE_EXECUTE;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ):
        return PAGE_EXECUTE_READ;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        return PAGE_EXECUTE_READWRITE;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_WRITE):
        return PAGE_EXECUTE_WRITECOPY;
    case UMF_PROTECTION_READ:
        return PAGE_READONLY;
    case (UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        return PAGE_READWRITE;
    case UMF_PROTECTION_WRITE:
        return PAGE_WRITECOPY;
    }
    fprintf(stderr,
            "os_translate_mem_protection_flags(): unsupported protection flag: "
            "%u\n",
            protection);
    assert(0);
    return -1;
}

void *os_mmap(void *hint_addr, size_t length, int prot) {
    return VirtualAlloc(hint_addr, length, MEM_RESERVE | MEM_COMMIT, prot);
}

int os_munmap(void *addr, size_t length) {
    // If VirtualFree() succeeds, the return value is nonzero.
    // If VirtualFree() fails, the return value is 0 (zero).
    (void)length; // unused
    return (VirtualFree(addr, 0, MEM_RELEASE) == 0);
}

int os_purge(void *addr, size_t length, int advice) {
    fprintf(stderr, "os_purge() NOT IMPLEMENTED\n");
    // assert(0);
    return -1;
}

size_t os_get_page_size(void) { return 4096; } // TODO fix this

void os_strerror(int errnum, char *buf, size_t buflen) {
    fprintf(stderr, "os_strerror() NOT IMPLEMENTED\n");
    // assert(0);
}
