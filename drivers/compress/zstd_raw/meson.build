# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026

dep = dependency('libzstd', required: false, method: 'pkg-config')
if not dep.found()
    build = false
    reason = 'missing dependency, "libzstd"'
endif

deps += 'bus_vdev'
sources = files('zstd_raw_pmd.c', 'zstd_raw_pmd_ops.c')
ext_deps += dep
cflags += '-DZSTD_STATIC_LINKING_ONLY'
