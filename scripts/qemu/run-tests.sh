#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

CONFIG_NAME=$(echo $1 | cut -d. -f1) # remove the '.xml' extension
COVERAGE_DIR=${HOME}/coverage
SOURCE_DIR=$(pwd)

# This is ${UMF_DIR}/scripts/qemu/run-build.sh file, so
UMF_DIR=$(dirname $0)/../..
cd $UMF_DIR
pwd

# Drop caches, restores free memory on NUMA nodes
echo password | sudo sync;
echo password | sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
# Set ptrace value for IPC test
echo password | sudo bash -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"

numactl -H

cd build
ctest --verbose

# run tests bound to a numa node
numactl -N 0 ctest --output-on-failure
numactl -N 1 ctest --output-on-failure

COVERAGE_FILE_NAME=exports-coverage-qemu-$CONFIG_NAME
echo "COVERAGE_FILE_NAME: $COVERAGE_FILE_NAME"
../scripts/coverage/coverage_capture.sh $COVERAGE_FILE_NAME
mkdir -p $COVERAGE_DIR
mv ./$COVERAGE_FILE_NAME $COVERAGE_DIR
ls -al $COVERAGE_DIR

# run tests under valgrind
echo "Running tests under valgrind memcheck ..."
../test/test_valgrind.sh .. . memcheck
