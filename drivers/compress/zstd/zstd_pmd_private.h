/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#ifndef ZSTD_PMD_PRIVATE_H
#define ZSTD_PMD_PRIVATE_H

#include <zstd.h>

#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>

#define COMPRESSDEV_NAME_ZSTD_PMD compress_zstd

extern int zstd_logtype_driver;
#define RTE_LOGTYPE_ZSTD_DRIVER zstd_logtype_driver
#define ZSTD_PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZSTD_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#define ZSTD_PMD_INFO(fmt, ...) ZSTD_PMD_LOG(INFO, fmt, ##__VA_ARGS__)
#define ZSTD_PMD_ERR(fmt, ...) ZSTD_PMD_LOG(ERR, fmt, ##__VA_ARGS__)

struct zstd_private {
	struct rte_mempool *mp;
};

struct __rte_cache_aligned zstd_qp {
	struct rte_ring *processed_pkts;
	struct rte_compressdev_stats qp_stats;
	uint16_t id;
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
};

struct __rte_cache_aligned zstd_sess {
	union {
		ZSTD_CCtx *cctx;
		ZSTD_DCtx *dctx;
	};
	int is_compress;
	int compress_level;
	/* Linear buffer: ZSTD_decompressStream may need >= ZSTD_DStreamOutSize() out
	 * in one call; mbuf segments are capped at UINT16_MAX-1.
	 */
	uint8_t *d_scratch;
	size_t d_scratch_sz;
};

struct __rte_cache_aligned zstd_priv_xform {
	struct zstd_sess sess;
};

void zstd_process_compress(struct rte_comp_op *op, struct zstd_sess *sess);
void zstd_process_decompress(struct rte_comp_op *op, struct zstd_sess *sess);

int zstd_set_session_parameters(const struct rte_comp_xform *xform,
		struct zstd_sess *sess, int use_stream_init);

void zstd_sess_fini(struct zstd_sess *sess);

extern struct rte_compressdev_ops *rte_zstd_pmd_ops;

#endif /* ZSTD_PMD_PRIVATE_H */
