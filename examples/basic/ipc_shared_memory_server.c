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

// server's response message
#define SERVER_MSG                                                             \
    "This is the server. I just wrote a new number directly into your shared " \
    "memory!"

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    char server_message[MSG_SIZE];
    int client_socket;
    int client_addr_len;
    int server_socket;
    int ret = -1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s port\n", argv[0]);
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
        fprintf(stderr, "[server] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    // get size of the IPC handle
    size_t IPC_handle_size;
    umf_result =
        umfMemoryProviderGetIPCHandleSize(OS_memory_provider, &IPC_handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[server] ERROR: getting size of the IPC handle failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    // allocate data for the IPC handle
    void *IPC_handle;
    umf_result = umfMemoryProviderAlloc(OS_memory_provider, IPC_handle_size, 0,
                                        &IPC_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[server] ERROR: allocating data for IPC provider failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    // create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        fprintf(stderr, "[server] ERROR: creating socket failed\n");
        goto err_free_IPC_handle;
    }

    fprintf(stderr, "[server] Socket created\n");

    // set port and IP address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(INET_ADDR);

    // bind to the IP address and port
    if (bind(server_socket, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        fprintf(stderr, "[server] ERROR: cannot bind to the port\n");
        goto err_close_server_socket;
    }

    fprintf(stderr, "[server] Binding done\n");

    // listen for the client
    if (listen(server_socket, 1) < 0) {
        fprintf(stderr, "[server] ERROR: listen() failed\n");
        goto err_close_server_socket;
    }

    fprintf(stderr, "[server] Listening for incoming connections ...\n");

    // accept an incoming connection
    client_addr_len = sizeof(client_addr);
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr,
                           (socklen_t *)&client_addr_len);
    if (client_socket < 0) {
        fprintf(stderr, "[server] ERROR: accept() failed\n");
        goto err_close_server_socket;
    }

    fprintf(stderr, "[server] Client connected at IP %s and port %i\n",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // zero the IPC_handle buffer
    memset(IPC_handle, 0, IPC_handle_size);

    // receive a client's message
    if (recv(client_socket, IPC_handle, IPC_handle_size, 0) < 0) {
        fprintf(stderr, "[server] ERROR: recv() failed\n");
        goto err_close_client_socket;
    }

    fprintf(stderr, "[server] Received an IPC handle from the client\n");

    void *SHM_ptr;
    umf_result = umfMemoryProviderOpenIPCHandle(OS_memory_provider, IPC_handle,
                                                &SHM_ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[server] ERROR: opening the IPC handle failed\n");
        goto err_close_client_socket;
    }

    fprintf(stderr,
            "[server] Opened the IPC handle received from the client\n");

    // read the current value from the shared memory
    unsigned long long SHM_number_1 = *(unsigned long long *)SHM_ptr;
    // calculate the new value
    unsigned long long SHM_number_2 = SHM_number_1 / 2;
    // write the new number directly to the client's shared memory
    *(unsigned long long *)SHM_ptr = SHM_number_2;

    fprintf(
        stderr,
        "[server] Wrote a new number directly to the client's shared memory\n");

    // write the response to the server_message buffer
    memset(server_message, 0, sizeof(server_message));
    strcpy(server_message, SERVER_MSG);

    // send response to the client
    if (send(client_socket, server_message, strlen(server_message), 0) < 0) {
        fprintf(stderr, "[server] ERROR: send() failed\n");
        goto err_CloseIPCHandle;
    }

    fprintf(stderr, "[server] Sent response to the client\n");

    ret = 0; // SUCCESS

err_CloseIPCHandle:
    // we do NOT know the exact size of the remote shared memory! - TODO: the API should be changed
    umf_result = umfMemoryProviderCloseIPCHandle(OS_memory_provider, SHM_ptr,
                                                 4096 /* TODO: change API */);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[server] ERROR: closing the IPC handle failed\n");
    }

    fprintf(stderr,
            "[server] Closed the IPC handle received from the client\n");

err_close_client_socket:
    close(client_socket);

err_close_server_socket:
    close(server_socket);

err_free_IPC_handle:
    (void)umfMemoryProviderFree(OS_memory_provider, IPC_handle,
                                IPC_handle_size);
err_umfMemoryProviderDestroy:
    umfMemoryProviderDestroy(OS_memory_provider);

    if (ret == 0) {
        fprintf(stderr, "[server] Shutting down (status OK) ...\n");
    } else {
        fprintf(stderr, "[server] Shutting down (status ERROR) ...\n");
    }

    return ret;
}
