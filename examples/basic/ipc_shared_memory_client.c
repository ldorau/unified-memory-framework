/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <umf/providers/provider_os_memory.h>

#define INET_ADDR "127.0.0.1"
#define MSG_SIZE 1024

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    char server_message[MSG_SIZE];
    int client_socket;
    int ret = -1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    umf_memory_provider_handle_t OS_memory_provider = NULL;
    umf_os_memory_provider_params_t os_params;
    enum umf_result_t umf_result;

    os_params = umfOsMemoryProviderParamsDefault();
    os_params.flag = UMF_MEM_MAP_SHARED;

    // create OS memory provider
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[client] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    size_t page_size;
    umf_result =
        umfMemoryProviderGetMinPageSize(OS_memory_provider, NULL, &page_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[client] ERROR: getting the minimum page size failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    // Make 3 allocations of size: 1 page, 2 pages and 3 pages
    void *ptr1, *ptr2, *IPC_shared_memory;
    size_t ptr1_size = 1 * page_size;
    size_t ptr2_size = 2 * page_size;
    size_t size_IPC_shared_memory = 3 * page_size;

    umf_result =
        umfMemoryProviderAlloc(OS_memory_provider, ptr1_size, 0, &ptr1);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[client] ERROR: allocating 1 page failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    umf_result =
        umfMemoryProviderAlloc(OS_memory_provider, ptr2_size, 0, &ptr2);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[client] ERROR: allocating 2 pages failed\n");
        goto err_free_ptr1;
    }

    umf_result = umfMemoryProviderAlloc(
        OS_memory_provider, size_IPC_shared_memory, 0, &IPC_shared_memory);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[client] ERROR: allocating 3 pages failed\n");
        goto err_free_ptr2;
    }

    // get size of the IPC handle
    size_t IPC_handle_size;
    umf_result =
        umfMemoryProviderGetIPCHandleSize(OS_memory_provider, &IPC_handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[client] ERROR: getting size of the IPC handle failed\n");
        goto err_free_IPC_shared_memory;
    }

    // allocate data for IPC provider
    void *IPC_handle;
    umf_result = umfMemoryProviderAlloc(OS_memory_provider, IPC_handle_size, 0,
                                        &IPC_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[client] ERROR: allocating data for IPC provider failed\n");
        goto err_free_IPC_shared_memory;
    }

    // zero the IPC handle and the shared memory
    memset(IPC_handle, 0, IPC_handle_size);
    memset(IPC_shared_memory, 0, size_IPC_shared_memory);

    // save a random number (&OS_memory_provider) in the shared memory
    unsigned long long SHM_number_1 = (unsigned long long)&OS_memory_provider;
    *(unsigned long long *)IPC_shared_memory = SHM_number_1;

    fprintf(stderr, "[client] My shared memory contains a number: %llu\n",
            *(unsigned long long *)IPC_shared_memory);

    // get the IPC handle from the OS memory provider
    umf_result =
        umfMemoryProviderGetIPCHandle(OS_memory_provider, IPC_shared_memory,
                                      size_IPC_shared_memory, IPC_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[client] ERROR: getting the IPC handle from the OS memory "
                "provider failed\n");
        goto err_free_IPC_handle;
    }

    fprintf(stderr, "[client] Got the IPC handle\n");

    // create a client socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        fprintf(stderr, "[client] ERROR: Unable to create socket\n");
        goto err_PutIPCHandle;
    }

    fprintf(stderr, "[client] Socket created\n");

    // set IP address and port the same as for the server
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(INET_ADDR);

    // send connection request to the server
    if (connect(client_socket, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        fprintf(stderr, "[client] ERROR: unable to connect to the server\n");
        goto err_close_client_socket;
    }

    fprintf(stderr, "[client] Connected to the server\n");

    // send the IPC_handle of IPC_handle_size to the server
    if (send(client_socket, IPC_handle, IPC_handle_size, 0) < 0) {
        fprintf(stderr, "[client] ERROR: unable to send the message\n");
        goto err_close_client_socket;
    }

    fprintf(stderr, "[client] Sent the IPC handle to the server\n");

    // zero the server_message buffer
    memset(server_message, 0, sizeof(server_message));

    // receive the server's response
    if (recv(client_socket, server_message, sizeof(server_message), 0) < 0) {
        fprintf(stderr,
                "[client] ERROR: error while receiving the server's message\n");
        goto err_close_client_socket;
    }

    fprintf(stderr, "[client] Received the server's response: \"%s\"\n",
            server_message);

    // read a new value from the shared memory
    unsigned long long SHM_number_2 = *(unsigned long long *)IPC_shared_memory;

    // the expected correct value is: SHM_number_2 == (SHM_number_1 / 2)
    if (SHM_number_2 == (SHM_number_1 / 2)) {
        ret = 0; // got the correct value - success!
        fprintf(stderr,
                "[client] The server wrote the correct value (the old one / 2) "
                "to my shared memory: %llu\n",
                SHM_number_2);
    } else {
        fprintf(stderr,
                "[client] ERROR: The server did NOT write the correct value "
                "(the old one / 2 = %llu) to my shared memory: %llu\n",
                (SHM_number_1 / 2), SHM_number_2);
    }

err_close_client_socket:
    close(client_socket);

err_PutIPCHandle:
    umf_result = umfMemoryProviderPutIPCHandle(OS_memory_provider, IPC_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[client] ERROR: putting the IPC handle failed\n");
    }

    fprintf(stderr, "[client] Put the IPC handle\n");

err_free_IPC_handle:
    (void)umfMemoryProviderFree(OS_memory_provider, IPC_handle,
                                IPC_handle_size);
err_free_IPC_shared_memory:
    (void)umfMemoryProviderFree(OS_memory_provider, IPC_shared_memory,
                                size_IPC_shared_memory);
err_free_ptr2:
    (void)umfMemoryProviderFree(OS_memory_provider, ptr2, ptr2_size);
err_free_ptr1:
    (void)umfMemoryProviderFree(OS_memory_provider, ptr1, ptr1_size);
err_umfMemoryProviderDestroy:
    umfMemoryProviderDestroy(OS_memory_provider);

    if (ret == 0) {
        fprintf(stderr, "[client] Shutting down (status OK) ...\n");
    } else {
        fprintf(stderr, "[client] Shutting down (status ERROR) ...\n");
    }

    return ret;
}
