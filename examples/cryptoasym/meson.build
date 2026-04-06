# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2018 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true
ext_deps += dependency('libcrypto', required: true, method: 'pkg-config')
ext_deps += dependency('libssl', required: true, method: 'pkg-config')
deps += ['cryptodev']
sources = files(
        'main.c',
)
