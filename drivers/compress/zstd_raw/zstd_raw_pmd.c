/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#include <string.h>

#include <zstd.h>

#include <bus_vdev_driver.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_compressdev_pmd.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "zstd_raw_pmd_private.h"

int zstd_raw_logtype_driver;

static uint32_t
zstd_raw_mbuf_chain_data_len(const struct rte_mbuf *m)
{
	uint32_t t = 0;

	for (; m != NULL; m = m->next)
		t += rte_pktmbuf_data_len(m);
	return t;
}

static int
zstd_raw_mbuf_dst_write_linear(struct rte_mbuf *head, uint32_t *linear_off_p,
		const void *src, size_t len, struct rte_comp_op *op)
{
	const uint8_t *s = src;
	size_t copied = 0;

	while (copied < len) {
		struct rte_mbuf *m = head;
		uint32_t skip = *linear_off_p;
		uint32_t room, take;

		while (m != NULL && skip >= rte_pktmbuf_data_len(m)) {
			skip -= rte_pktmbuf_data_len(m);
			m = m->next;
		}
		if (m == NULL) {
			op->status = RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
			return -1;
		}
		room = rte_pktmbuf_data_len(m) - skip;
		take = (uint32_t)RTE_MIN((size_t)room, len - copied);
		memcpy(rte_pktmbuf_mtod_offset(m, void *, skip), s + copied, take);
		*linear_off_p += take;
		copied += take;
	}
	return 0;
}

static uint32_t
zstd_raw_seq_off_chain(const struct rte_mbuf *dst, uint32_t chunk)
{
	uint32_t seq_off = 0;
	const struct rte_mbuf *seg;

	for (seg = dst; seg != NULL &&
			seq_off < chunk + ZSTD_RAW_ZSTD_LIT_RSV;
			seg = seg->next)
		seq_off += rte_pktmbuf_data_len(seg);
	return seq_off;
}

static uint32_t
zstd_raw_uadk_dst_min(uint32_t in_len)
{
	return in_len + ZSTD_RAW_ZSTD_LIT_RSV + ZSTD_RAW_ZSTD_FREQ_SZ +
		ZSTD_RAW_ZSTD_SEQ_ROOM;
}

static int
zstd_raw_map_level(int level)
{
	int lo = ZSTD_minCLevel();
	int hi = ZSTD_maxCLevel();

	switch (level) {
	case RTE_COMP_LEVEL_PMD_DEFAULT:
		return ZSTD_CLEVEL_DEFAULT;
	case RTE_COMP_LEVEL_NONE:
		return 0;
	case RTE_COMP_LEVEL_MIN:
		return lo;
	case RTE_COMP_LEVEL_MAX:
		return hi;
	default:
		if (level >= RTE_COMP_LEVEL_MIN && level <= RTE_COMP_LEVEL_MAX)
			return lo + ((hi - lo) * (level - RTE_COMP_LEVEL_MIN)) /
				(RTE_COMP_LEVEL_MAX - RTE_COMP_LEVEL_MIN);
		return ZSTD_CLEVEL_DEFAULT;
	}
}

static int
zstd_raw_set_window(ZSTD_CCtx *cctx, uint8_t wlog)
{
	size_t zst;

	if (wlog == 0)
		return 0;
	zst = ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int)wlog);
	if (ZSTD_isError(zst)) {
		ZSTD_RAW_PMD_ERR("ZSTD_c_windowLog: %s", ZSTD_getErrorName(zst));
		return -1;
	}
	return 0;
}

void
zstd_raw_sess_fini(struct zstd_raw_sess *sess)
{
	if (sess == NULL)
		return;
	if (sess->cctx != NULL)
		ZSTD_freeCCtx((ZSTD_CCtx *)sess->cctx);
	rte_free(sess->src_linear);
	rte_free(sess->seq_buf);
	memset(sess, 0, sizeof(*sess));
}

int
zstd_raw_set_session_parameters(const struct rte_comp_xform *xform,
		struct zstd_raw_sess *sess)
{
	ZSTD_CCtx *cctx;
	size_t zst;
	size_t seq_cap;
	void *seq_buf = NULL;
	uint8_t *src_linear = NULL;

	memset(sess, 0, sizeof(*sess));

	if (xform->type == RTE_COMP_COMPRESS) {
		if (xform->compress.algo != RTE_COMP_ALGO_ZSTD) {
			ZSTD_RAW_PMD_ERR("Compression algorithm not supported");
			return -1;
		}
		if (xform->compress.chksum != RTE_COMP_CHECKSUM_NONE ||
				xform->compress.hash_algo != RTE_COMP_HASH_ALGO_NONE) {
			ZSTD_RAW_PMD_ERR("Checksum/hash not supported for ZSTD raw");
			return -1;
		}
		sess->is_compress = 1;
	} else if (xform->type == RTE_COMP_DECOMPRESS) {
		if (xform->decompress.algo == RTE_COMP_ALGO_ZSTD) {
			ZSTD_RAW_PMD_ERR("ZSTD decompression is not supported");
			return -1;
		}
		ZSTD_RAW_PMD_ERR("Decompression algorithm not supported");
		return -1;
	} else {
		return -1;
	}

	cctx = ZSTD_createCCtx();
	if (cctx == NULL) {
		ZSTD_RAW_PMD_ERR("ZSTD_createCCtx failed");
		return -1;
	}

	sess->compress_level = zstd_raw_map_level(xform->compress.level);
	sess->window_log = xform->compress.window_size;

	zst = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
			sess->compress_level);
	if (ZSTD_isError(zst)) {
		ZSTD_RAW_PMD_ERR("ZSTD_c_compressionLevel: %s",
				ZSTD_getErrorName(zst));
		goto err;
	}

	if (zstd_raw_set_window(cctx, sess->window_log) < 0)
		goto err;

	zst = ZSTD_CCtx_setParameter(cctx, ZSTD_c_minMatch, ZSTD_MINMATCH_MIN);
	if (ZSTD_isError(zst)) {
		ZSTD_RAW_PMD_ERR("ZSTD_c_minMatch: %s", ZSTD_getErrorName(zst));
		goto err;
	}

	src_linear = rte_zmalloc_socket(NULL, ZSTD_RAW_ZSTD_HW_MAX_IN, 0,
			SOCKET_ID_ANY);
	if (src_linear == NULL) {
		ZSTD_RAW_PMD_ERR("src_linear alloc failed");
		goto err;
	}

	seq_cap = ZSTD_sequenceBound(ZSTD_RAW_ZSTD_HW_MAX_IN);
	if (seq_cap == 0 || seq_cap > SIZE_MAX / sizeof(ZSTD_Sequence)) {
		ZSTD_RAW_PMD_ERR("ZSTD_sequenceBound invalid");
		goto err;
	}
	seq_buf = rte_zmalloc_socket(NULL, seq_cap * sizeof(ZSTD_Sequence), 0,
			SOCKET_ID_ANY);
	if (seq_buf == NULL) {
		ZSTD_RAW_PMD_ERR("seq_buf alloc failed");
		goto err;
	}

	sess->cctx = (void *)cctx;
	sess->src_linear = src_linear;
	sess->seq_buf = seq_buf;
	sess->seq_cap = seq_cap;
	return 0;

err:
	rte_free(src_linear);
	rte_free(seq_buf);
	ZSTD_freeCCtx(cctx);
	memset(sess, 0, sizeof(*sess));
	return -1;
}

static int
zstd_raw_pad_zeros(struct rte_mbuf *dst, uint32_t *linear_off_p, uint32_t n,
		struct rte_comp_op *op)
{
	static const uint8_t z[256];

	while (n > 0) {
		uint32_t chunk = RTE_MIN(n, (uint32_t)sizeof(z));

		if (zstd_raw_mbuf_dst_write_linear(dst, linear_off_p, z, chunk,
				op) < 0)
			return -1;
		n -= chunk;
	}
	return 0;
}

void
zstd_raw_process_compress_op(struct rte_comp_op *op, struct zstd_raw_sess *sess)
{
	ZSTD_CCtx *cctx = (ZSTD_CCtx *)sess->cctx;
	uint8_t *src_linear = sess->src_linear;
	ZSTD_Sequence *seq_buf = sess->seq_buf;
	uint32_t src_len = op->src.length;
	uint32_t seq_off;
	uint32_t linear_off;
	uint32_t lit_num;
	size_t n_seq;
	size_t i;
	uint32_t src_pos;
	size_t zst;

	if (unlikely(cctx == NULL || src_linear == NULL || seq_buf == NULL)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	op->status = RTE_COMP_OP_STATUS_SUCCESS;
	op->consumed = 0;
	op->produced = 0;
	op->debug_status = 0;

	if (op->op_type != RTE_COMP_OP_STATELESS) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}
	if (op->flush_flag != RTE_COMP_FLUSH_FULL &&
			op->flush_flag != RTE_COMP_FLUSH_FINAL) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}
	if (op->dst.offset != 0) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}
	if (src_len > ZSTD_RAW_ZSTD_HW_MAX_IN || src_len == 0) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	if (zstd_raw_mbuf_chain_data_len(op->m_dst) - op->dst.offset <
			zstd_raw_uadk_dst_min(src_len)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	{
		const void *p = rte_pktmbuf_read(op->m_src, op->src.offset, src_len,
				src_linear);

		if (p == NULL) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
			return;
		}
		if (p != (const void *)src_linear)
			memcpy(src_linear, p, src_len);
	}

	ZSTD_CCtx_reset(cctx, ZSTD_reset_session_only);

	zst = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
			sess->compress_level);
	if (ZSTD_isError(zst)) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		ZSTD_RAW_PMD_ERR("ZSTD_c_compressionLevel: %s",
				ZSTD_getErrorName(zst));
		return;
	}
	if (zstd_raw_set_window(cctx, sess->window_log) < 0) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		ZSTD_RAW_PMD_ERR("ZSTD_c_windowLog not accepted");
		return;
	}
	zst = ZSTD_CCtx_setParameter(cctx, ZSTD_c_minMatch, ZSTD_MINMATCH_MIN);
	if (ZSTD_isError(zst)) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		ZSTD_RAW_PMD_ERR("ZSTD_c_minMatch: %s", ZSTD_getErrorName(zst));
		return;
	}

	n_seq = ZSTD_generateSequences(cctx, seq_buf, sess->seq_cap, src_linear,
			src_len);
	if (ZSTD_isError(n_seq)) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		ZSTD_RAW_PMD_ERR("ZSTD_generateSequences: %s",
				ZSTD_getErrorName(n_seq));
		return;
	}

	n_seq = ZSTD_mergeBlockDelimiters(seq_buf, n_seq);

	seq_off = zstd_raw_seq_off_chain(op->m_dst, src_len);

	if (zstd_raw_mbuf_chain_data_len(op->m_dst) <
			(uint64_t)seq_off + (uint64_t)n_seq * 8ull +
			ZSTD_RAW_ZSTD_FREQ_SZ) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	linear_off = op->dst.offset;
	src_pos = 0;
	lit_num = 0;

	for (i = 0; i < n_seq; i++) {
		unsigned int ll = seq_buf[i].litLength;
		unsigned int ml = seq_buf[i].matchLength;

		if (ll > UINT16_MAX || ml > UINT16_MAX) {
			op->status = RTE_COMP_OP_STATUS_ERROR;
			return;
		}
		if (seq_buf[i].offset > UINT32_MAX) {
			op->status = RTE_COMP_OP_STATUS_ERROR;
			return;
		}

		if (ll > 0) {
			if ((uint64_t)src_pos + ll > src_len) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				return;
			}
			if (zstd_raw_mbuf_dst_write_linear(op->m_dst, &linear_off,
					src_linear + src_pos, ll, op) < 0)
				return;
			lit_num += ll;
			src_pos += ll;
		}
		if (ml > 0) {
			if ((uint64_t)src_pos + ml > src_len) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				return;
			}
			src_pos += ml;
		}
	}

	if (src_pos < src_len) {
		uint32_t trail = src_len - src_pos;

		if (zstd_raw_mbuf_dst_write_linear(op->m_dst, &linear_off,
				src_linear + src_pos, trail, op) < 0)
			return;
		lit_num += trail;
		src_pos += trail;
	} else if (src_pos > src_len) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		return;
	}

	if (lit_num > seq_off) {
		op->status = RTE_COMP_OP_STATUS_ERROR;
		ZSTD_RAW_PMD_ERR("lit_num %u > seq_off %u", lit_num, seq_off);
		return;
	}

	if (seq_off > lit_num) {
		if (zstd_raw_pad_zeros(op->m_dst, &linear_off, seq_off - lit_num,
				op) < 0)
			return;
	}

	for (i = 0; i < n_seq; i++) {
		struct zstd_raw_hw_seqdef hw = {
			.offset = (uint32_t)seq_buf[i].offset,
			.litLength = (uint16_t)seq_buf[i].litLength,
			.matchLength = (uint16_t)seq_buf[i].matchLength,
		};

		if (zstd_raw_mbuf_dst_write_linear(op->m_dst, &linear_off, &hw,
				sizeof(hw), op) < 0)
			return;
	}

	{
		static const uint8_t freq[ZSTD_RAW_ZSTD_FREQ_SZ];

		if (zstd_raw_mbuf_dst_write_linear(op->m_dst, &linear_off, freq,
				sizeof(freq), op) < 0)
			return;
	}

	op->produced = seq_off + (uint32_t)n_seq * 8u + ZSTD_RAW_ZSTD_FREQ_SZ;
	op->debug_status = (uint64_t)lit_num |
			((uint64_t)(uint32_t)n_seq << 32);
	op->consumed = src_len;
}

static int
process_zstd_raw_op(struct zstd_raw_qp *qp, struct rte_comp_op *op)
{
	struct zstd_raw_priv_xform *priv;

	if (op->src.offset + op->src.length > rte_pktmbuf_pkt_len(op->m_src)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		goto enq;
	}

	if (op->dst.offset > zstd_raw_mbuf_chain_data_len(op->m_dst)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		goto enq;
	}

	if (op->op_type == RTE_COMP_OP_STATEFUL) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		goto enq;
	}

	priv = (struct zstd_raw_priv_xform *)op->private_xform;
	if (unlikely(priv == NULL || !priv->sess.is_compress)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		goto enq;
	}

	zstd_raw_process_compress_op(op, &priv->sess);

enq:
	return rte_ring_enqueue(qp->processed_pkts, (void *)op);
}

static uint16_t
zstd_raw_pmd_enqueue_burst(void *queue_pair, struct rte_comp_op **ops,
		uint16_t nb_ops)
{
	struct zstd_raw_qp *qp = queue_pair;
	int ret;
	uint16_t i, enqd = 0;

	for (i = 0; i < nb_ops; i++) {
		ret = process_zstd_raw_op(qp, ops[i]);
		if (unlikely(ret < 0))
			qp->qp_stats.enqueue_err_count++;
		else {
			qp->qp_stats.enqueued_count++;
			enqd++;
		}
	}
	return enqd;
}

static uint16_t
zstd_raw_pmd_dequeue_burst(void *queue_pair, struct rte_comp_op **ops,
		uint16_t nb_ops)
{
	struct zstd_raw_qp *qp = queue_pair;
	unsigned int n;

	n = rte_ring_dequeue_burst(qp->processed_pkts, (void **)ops, nb_ops,
			NULL);
	qp->qp_stats.dequeued_count += n;
	return (uint16_t)n;
}

static int
zstd_raw_create(const char *name, struct rte_vdev_device *vdev,
		struct rte_compressdev_pmd_init_params *init_params)
{
	struct rte_compressdev *dev;

	dev = rte_compressdev_pmd_create(name, &vdev->device,
			sizeof(struct zstd_raw_private), init_params);
	if (dev == NULL) {
		ZSTD_RAW_PMD_ERR("driver %s: create failed", init_params->name);
		return -ENODEV;
	}
	dev->dev_ops = rte_zstd_raw_pmd_ops;
	dev->dequeue_burst = zstd_raw_pmd_dequeue_burst;
	dev->enqueue_burst = zstd_raw_pmd_enqueue_burst;
	return 0;
}

static int
zstd_raw_probe(struct rte_vdev_device *vdev)
{
	struct rte_compressdev_pmd_init_params init_params = {
		"",
		rte_socket_id()
	};
	const char *name;
	const char *input_args;
	int retval;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;
	input_args = rte_vdev_device_args(vdev);
	retval = rte_compressdev_pmd_parse_input_args(&init_params, input_args);
	if (retval < 0) {
		ZSTD_RAW_PMD_ERR("Failed to parse initialisation arguments[%s]",
				input_args);
		return -EINVAL;
	}
	return zstd_raw_create(name, vdev, &init_params);
}

static int
zstd_raw_remove(struct rte_vdev_device *vdev)
{
	struct rte_compressdev *compressdev;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;
	compressdev = rte_compressdev_pmd_get_named_dev(name);
	if (compressdev == NULL)
		return -ENODEV;
	return rte_compressdev_pmd_destroy(compressdev);
}

static struct rte_vdev_driver zstd_raw_pmd_drv = {
	.probe = zstd_raw_probe,
	.remove = zstd_raw_remove
};

RTE_PMD_REGISTER_VDEV(COMPRESSDEV_NAME_ZSTD_RAW_PMD, zstd_raw_pmd_drv);
RTE_LOG_REGISTER_DEFAULT(zstd_raw_logtype_driver, INFO);
