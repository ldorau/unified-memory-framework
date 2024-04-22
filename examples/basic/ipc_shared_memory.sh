#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

PTRACE_SCOPE_FILE="/proc/sys/kernel/yama/ptrace_scope"
VAL=0
if [ -f $PTRACE_SCOPE_FILE ]; then
	PTRACE_SCOPE_VAL=$(cat $PTRACE_SCOPE_FILE)
	if [ $PTRACE_SCOPE_VAL -ne $VAL ]; then
		echo "Setting ptrace_scope to 0 (classic ptrace permissions) ..."
		echo "$ sudo bash -c \"echo $VAL > $PTRACE_SCOPE_FILE\""
		sudo bash -c "echo $VAL > $PTRACE_SCOPE_FILE"
	fi
	PTRACE_SCOPE_VAL=$(cat $PTRACE_SCOPE_FILE)
	if [ $PTRACE_SCOPE_VAL -ne $VAL ]; then
		echo "SKIP: setting ptrace_scope to 0 (classic ptrace permissions) FAILED - skipping the test"
		exit 0
	fi
fi

echo "Starting ipc_shared_memory SERVER on port $PORT ..."
./umf_example_ipc_shared_memory_server $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_shared_memory CLIENT on port $PORT ..."
./umf_example_ipc_shared_memory_client $PORT
