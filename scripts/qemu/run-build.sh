#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

repo=$1
branch=$2

echo password | sudo -Sk apt update
echo password | sudo -Sk apt install -y git cmake gcc g++ numactl libnuma-dev libhwloc-dev libjemalloc-dev libtbb-dev pkg-config valgrind hwloc ndctl

set -x
ls -al /dev/nmem* || true
echo password | sudo -Sk dmesg | grep -e persistent || true
echo password | sudo -Sk ndctl list --dimm -i
echo password | sudo -Sk ndctl list --regions
echo password | sudo -Sk ndctl list --namespaces --bus=all --region=all
echo password | sudo -Sk ndctl create-namespace --mode=devdax --align=2M --force || ( echo password | sudo -Sk ndctl create-namespace --mode=raw || true )
echo password | sudo -Sk ndctl list --namespaces --bus=all --region=all
ls -al /dev/dax*

git clone $repo umf
cd umf
git checkout $branch

mkdir build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DUMF_BUILD_LEVEL_ZERO_PROVIDER=ON \
    -DUMF_FORMAT_CODE_STYLE=OFF \
    -DUMF_DEVELOPER_MODE=ON \
    -DUMF_BUILD_LIBUMF_POOL_DISJOINT=ON \
    -DUMF_BUILD_LIBUMF_POOL_JEMALLOC=ON \
    -DUMF_BUILD_EXAMPLES=ON \
    -DUMF_TESTS_FAIL_ON_SKIP=ON

make -j $(nproc)
