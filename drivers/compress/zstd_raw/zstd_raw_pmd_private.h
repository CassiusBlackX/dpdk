/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#ifndef ZSTD_RAW_PMD_PRIVATE_H
#define ZSTD_RAW_PMD_PRIVATE_H

#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>

/*
 * Must not start with "compress_zstd" + continuation: vdev bus matches drivers
 * with strncmp(driver->name, vdev_name, strlen(driver->name)), so names like
 * compress_zstdraw are claimed by the compress_zstd PMD first.
 */
#define COMPRESSDEV_NAME_ZSTD_RAW_PMD compress_lz77_zstd

/** Match UADK hisi_zip lz77_zstd layout (uadk_compress_pmd_private.h). */
#define ZSTD_RAW_ZSTD_HW_MAX_IN	(1u << 17)
#define ZSTD_RAW_ZSTD_LIT_RSV		16
#define ZSTD_RAW_ZSTD_FREQ_SZ		784
#define ZSTD_RAW_ZSTD_SEQ_ROOM		(8 * 1024 * 1024)

extern int zstd_raw_logtype_driver;
#define RTE_LOGTYPE_ZSTD_RAW_DRIVER zstd_raw_logtype_driver
#define ZSTD_RAW_PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZSTD_RAW_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#define ZSTD_RAW_PMD_INFO(fmt, ...) ZSTD_RAW_PMD_LOG(INFO, fmt, ##__VA_ARGS__)
#define ZSTD_RAW_PMD_ERR(fmt, ...) ZSTD_RAW_PMD_LOG(ERR, fmt, ##__VA_ARGS__)

struct __rte_cache_aligned zstd_raw_private {
	struct rte_mempool *mp;
};

struct __rte_cache_aligned zstd_raw_qp {
	struct rte_ring *processed_pkts;
	struct rte_compressdev_stats qp_stats;
	uint16_t id;
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
};

struct __rte_cache_aligned zstd_raw_sess {
	void *cctx; /* ZSTD_CCtx * */
	int is_compress;
	int compress_level;
	uint8_t window_log;
	uint8_t *src_linear;
	void *seq_buf; /* ZSTD_Sequence * */
	size_t seq_cap;
};

struct __rte_cache_aligned zstd_raw_priv_xform {
	struct zstd_raw_sess sess;
};

/** Hardware tuple layout (examples/uadk_zstd_compress/main.c). */
struct zstd_raw_hw_seqdef {
	uint32_t offset;
	uint16_t litLength;
	uint16_t matchLength;
};

void zstd_raw_sess_fini(struct zstd_raw_sess *sess);

int zstd_raw_set_session_parameters(const struct rte_comp_xform *xform,
		struct zstd_raw_sess *sess);

void zstd_raw_process_compress_op(struct rte_comp_op *op,
		struct zstd_raw_sess *sess);

extern struct rte_compressdev_ops *rte_zstd_raw_pmd_ops;

#endif /* ZSTD_RAW_PMD_PRIVATE_H */
