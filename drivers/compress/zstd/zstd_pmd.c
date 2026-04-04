/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#include <string.h>

#include <bus_vdev_driver.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "zstd_pmd_private.h"

static uint32_t
zstd_mbuf_chain_data_len(const struct rte_mbuf *m)
{
	uint32_t t = 0;

	for (; m != NULL; m = m->next)
		t += rte_pktmbuf_data_len(m);
	return t;
}

/*
 * Write len bytes using a linear byte offset from the start of the destination
 * packet (see rte_comp_op::dst.offset). Do not mix with a separate cursor mbuf;
 * that can desync and make data_len <= off true for every segment when off > 64K.
 */
static int
zstd_mbuf_dst_write_linear(struct rte_mbuf *head, uint32_t *linear_off_p,
		const uint8_t *src, size_t len, struct rte_comp_op *op)
{
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
			op->status =
				RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
			return -1;
		}
		room = rte_pktmbuf_data_len(m) - skip;
		take = (uint32_t)RTE_MIN((size_t)room, len - copied);
		memcpy(rte_pktmbuf_mtod_offset(m, void *, skip), src + copied,
				take);
		*linear_off_p += take;
		copied += take;
	}
	return 0;
}

static int
zstd_map_level(int level)
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
zstd_set_window_cctx(ZSTD_CCtx *cctx, uint8_t wlog)
{
	if (wlog == 0)
		return 0;
	if (ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int)wlog) != 0)
		return -1;
	return 0;
}

static int
zstd_set_window_dctx(ZSTD_DCtx *dctx, uint8_t wlog)
{
	if (wlog == 0)
		return 0;
	if (ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, (int)wlog) != 0)
		return -1;
	return 0;
}

void
zstd_sess_fini(struct zstd_sess *sess)
{
	if (sess == NULL)
		return;
	if (sess->is_compress && sess->cctx != NULL)
		ZSTD_freeCCtx(sess->cctx);
	else if (!sess->is_compress && sess->dctx != NULL)
		ZSTD_freeDCtx(sess->dctx);
	sess->cctx = NULL;
	sess->dctx = NULL;
	rte_free(sess->d_scratch);
	sess->d_scratch = NULL;
	sess->d_scratch_sz = 0;
}

int
zstd_set_session_parameters(const struct rte_comp_xform *xform,
		struct zstd_sess *sess, int use_stream_init)
{
	int zlevel;
	size_t zst;

	memset(sess, 0, sizeof(*sess));

	if (xform->type == RTE_COMP_COMPRESS) {
		if (xform->compress.algo != RTE_COMP_ALGO_ZSTD) {
			ZSTD_PMD_ERR("Compression algorithm not supported");
			return -1;
		}
		if (xform->compress.chksum != RTE_COMP_CHECKSUM_NONE ||
				xform->compress.hash_algo != RTE_COMP_HASH_ALGO_NONE) {
			ZSTD_PMD_ERR("Checksum/hash not supported for ZSTD");
			return -1;
		}
		sess->is_compress = 1;
		sess->cctx = ZSTD_createCCtx();
		if (sess->cctx == NULL) {
			ZSTD_PMD_ERR("ZSTD_createCCtx failed");
			return -1;
		}
		zlevel = zstd_map_level(xform->compress.level);
		if (zstd_set_window_cctx(sess->cctx, xform->compress.window_size) < 0) {
			ZSTD_PMD_ERR("ZSTD_c_windowLog not accepted");
			goto err;
		}
		/* Init streaming session (required before ZSTD_compressStream2). */
		sess->compress_level = zlevel;
		zst = ZSTD_initCStream(sess->cctx, zlevel);
		if (ZSTD_isError(zst)) {
			ZSTD_PMD_ERR("ZSTD_initCStream: %s",
					ZSTD_getErrorName(zst));
			goto err;
		}
		(void)use_stream_init;
	} else if (xform->type == RTE_COMP_DECOMPRESS) {
		if (xform->decompress.algo != RTE_COMP_ALGO_ZSTD) {
			ZSTD_PMD_ERR("Decompression algorithm not supported");
			return -1;
		}
		if (xform->decompress.chksum != RTE_COMP_CHECKSUM_NONE ||
				xform->decompress.hash_algo != RTE_COMP_HASH_ALGO_NONE) {
			ZSTD_PMD_ERR("Checksum/hash not supported for ZSTD");
			return -1;
		}
		sess->is_compress = 0;
		sess->dctx = ZSTD_createDCtx();
		if (sess->dctx == NULL) {
			ZSTD_PMD_ERR("ZSTD_createDCtx failed");
			return -1;
		}
		if (zstd_set_window_dctx(sess->dctx,
				xform->decompress.window_size) < 0) {
			ZSTD_PMD_ERR("ZSTD_d_windowLogMax not accepted");
			goto err;
		}
		sess->compress_level = 0;
		zst = ZSTD_initDStream(sess->dctx);
		if (ZSTD_isError(zst)) {
			ZSTD_PMD_ERR("ZSTD_initDStream: %s",
					ZSTD_getErrorName(zst));
			goto err;
		}
		sess->d_scratch_sz = ZSTD_DStreamOutSize();
		if (sess->d_scratch_sz == 0) {
			ZSTD_PMD_ERR("ZSTD_DStreamOutSize invalid");
			goto err;
		}
		sess->d_scratch = rte_zmalloc_socket(NULL, sess->d_scratch_sz, 0,
				SOCKET_ID_ANY);
		if (sess->d_scratch == NULL) {
			ZSTD_PMD_ERR("decompress scratch alloc failed");
			goto err;
		}
		(void)use_stream_init;
	} else {
		return -1;
	}
	return 0;
err:
	zstd_sess_fini(sess);
	return -1;
}

static ZSTD_EndDirective
compress_flush_to_directive(struct rte_comp_op *op)
{
	if (op->op_type == RTE_COMP_OP_STATEFUL) {
		switch (op->flush_flag) {
		case RTE_COMP_FLUSH_NONE:
			return ZSTD_e_continue;
		case RTE_COMP_FLUSH_SYNC:
			return ZSTD_e_flush;
		case RTE_COMP_FLUSH_FULL:
		case RTE_COMP_FLUSH_FINAL:
			return ZSTD_e_end;
		default:
			return (ZSTD_EndDirective)-1;
		}
	}
	switch (op->flush_flag) {
	case RTE_COMP_FLUSH_FULL:
	case RTE_COMP_FLUSH_FINAL:
		return ZSTD_e_end;
	default:
		return (ZSTD_EndDirective)-1;
	}
}

static int
compress_drain(ZSTD_CCtx *cctx, struct rte_comp_op *op,
		struct rte_mbuf **mdp, uint32_t *dst_off_p, ZSTD_EndDirective ed,
		uint32_t *produced)
{
	ZSTD_inBuffer in = { NULL, 0, 0 };
	struct rte_mbuf *md = *mdp;
	size_t ret;

	for (;;) {
		ZSTD_outBuffer out;

		if (rte_pktmbuf_data_len(md) <= *dst_off_p) {
			if (md->next == NULL) {
				op->status =
					RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
				return -1;
			}
			md = md->next;
			*dst_off_p = 0;
			*mdp = md;
			continue;
		}
		out.dst = rte_pktmbuf_mtod_offset(md, void *, *dst_off_p);
		out.size = rte_pktmbuf_data_len(md) - *dst_off_p;
		out.pos = 0;
		ret = ZSTD_compressStream2(cctx, &out, &in, ed);
		if (ZSTD_isError(ret)) {
			op->status = RTE_COMP_OP_STATUS_ERROR;
			ZSTD_PMD_ERR("ZSTD_compressStream2 drain: %s",
					ZSTD_getErrorName(ret));
			return -1;
		}
		*dst_off_p += (uint32_t)out.pos;
		*produced += (uint32_t)out.pos;
		if (ret == 0)
			return 0;
		if (out.pos == out.size) {
			if (md->next == NULL) {
				op->status =
					RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
				return -1;
			}
			md = md->next;
			*dst_off_p = 0;
			*mdp = md;
		}
	}
}

static int
zstd_reinit_compress_stream(struct zstd_sess *sess)
{
	size_t zst = ZSTD_initCStream(sess->cctx, sess->compress_level);

	if (ZSTD_isError(zst)) {
		ZSTD_PMD_ERR("ZSTD_initCStream after reset: %s",
				ZSTD_getErrorName(zst));
		return -1;
	}
	return 0;
}

static int
zstd_reinit_decompress_stream(struct zstd_sess *sess)
{
	size_t zst = ZSTD_initDStream(sess->dctx);

	if (ZSTD_isError(zst)) {
		ZSTD_PMD_ERR("ZSTD_initDStream after reset: %s",
				ZSTD_getErrorName(zst));
		return -1;
	}
	return 0;
}

void
zstd_process_compress(struct rte_comp_op *op, struct zstd_sess *sess)
{
	ZSTD_CCtx *cctx = sess->cctx;
	struct rte_mbuf *ms = op->m_src;
	struct rte_mbuf *md = op->m_dst;
	uint32_t src_off = op->src.offset;
	uint32_t dst_off = op->dst.offset;
	uint32_t remaining_in = op->src.length;
	ZSTD_EndDirective fin = compress_flush_to_directive(op);
	uint32_t produced = 0;

	if (unlikely(cctx == NULL)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}
	if ((ZSTD_EndDirective)(int)fin == (ZSTD_EndDirective)-1) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		ZSTD_PMD_ERR("Invalid flush value");
		return;
	}

	op->status = RTE_COMP_OP_STATUS_SUCCESS;
	op->consumed = 0;
	op->produced = 0;

	while (remaining_in > 0) {
		ZSTD_inBuffer in;
		size_t ret;

		in.src = rte_pktmbuf_mtod_offset(ms, const void *, src_off);
		in.size = rte_pktmbuf_data_len(ms) - src_off;
		if (in.size > remaining_in)
			in.size = remaining_in;
		in.pos = 0;

		while (in.pos < in.size) {
			ZSTD_outBuffer out;

			if (rte_pktmbuf_data_len(md) <= dst_off) {
				if (md->next == NULL) {
					op->status =
					RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
					goto end;
				}
				md = md->next;
				dst_off = 0;
			}
			out.dst = rte_pktmbuf_mtod_offset(md, void *, dst_off);
			out.size = rte_pktmbuf_data_len(md) - dst_off;
			out.pos = 0;
			ret = ZSTD_compressStream2(cctx, &out, &in,
					ZSTD_e_continue);
			if (ZSTD_isError(ret)) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				ZSTD_PMD_ERR("ZSTD_compressStream2: %s",
						ZSTD_getErrorName(ret));
				goto end;
			}
			dst_off += (uint32_t)out.pos;
			produced += (uint32_t)out.pos;
			if (out.pos == out.size && in.pos < in.size) {
				if (md->next == NULL) {
					op->status =
					RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
					goto end;
				}
				md = md->next;
				dst_off = 0;
			}
		}
		remaining_in -= (uint32_t)in.size;
		op->consumed += (uint32_t)in.size;
		src_off = 0;
		if (remaining_in > 0) {
			if (ms->next == NULL) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto end;
			}
			ms = ms->next;
			src_off = 0;
		}
	}

	if (fin == ZSTD_e_continue) {
		goto end;
	}
	if (compress_drain(cctx, op, &md, &dst_off, fin, &produced) < 0)
		goto end;

	if (op->op_type == RTE_COMP_OP_STATELESS ||
	    op->flush_flag == RTE_COMP_FLUSH_FULL ||
	    op->flush_flag == RTE_COMP_FLUSH_FINAL) {
		ZSTD_CCtx_reset(cctx, ZSTD_reset_session_only);
		if (op->status == RTE_COMP_OP_STATUS_SUCCESS &&
				zstd_reinit_compress_stream(sess) < 0)
			op->status = RTE_COMP_OP_STATUS_ERROR;
	}

end:
	op->produced = produced;
	if (op->status == RTE_COMP_OP_STATUS_SUCCESS &&
	    op->consumed != op->src.length)
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
}

void
zstd_process_decompress(struct rte_comp_op *op, struct zstd_sess *sess)
{
	ZSTD_DCtx *dctx = sess->dctx;
	struct rte_mbuf *ms = op->m_src;
	uint32_t src_off = op->src.offset;
	uint32_t dst_lin = op->dst.offset;
	uint32_t remaining_in = op->src.length;
	uint32_t produced = 0;
	size_t ret = 0;
	ZSTD_inBuffer in;
	ZSTD_outBuffer out;

	if (unlikely(dctx == NULL || sess->d_scratch == NULL)) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	op->status = RTE_COMP_OP_STATUS_SUCCESS;
	op->consumed = 0;
	op->produced = 0;

	while (remaining_in > 0) {
		in.src = rte_pktmbuf_mtod_offset(ms, const void *, src_off);
		in.size = rte_pktmbuf_data_len(ms) - src_off;
		if (in.size > remaining_in)
			in.size = remaining_in;
		in.pos = 0;

		while (in.pos < in.size) {
			out.dst = sess->d_scratch;
			out.size = sess->d_scratch_sz;
			out.pos = 0;
			ret = ZSTD_decompressStream(dctx, &out, &in);
			if (ZSTD_isError(ret)) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				ZSTD_PMD_ERR("ZSTD_decompressStream: %s",
						ZSTD_getErrorName(ret));
				goto end;
			}
			if (out.pos > 0) {
				if (zstd_mbuf_dst_write_linear(op->m_dst, &dst_lin,
						sess->d_scratch, out.pos, op) < 0)
					goto end;
				produced += (uint32_t)out.pos;
			}
			if (out.pos == 0 && in.pos < in.size) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				ZSTD_PMD_ERR("decompress stalled (input left, no output)");
				goto end;
			}
		}
		/* Entire slice presented; flush pending output before more input. */
		while (ret > 0) {
			ZSTD_inBuffer in0 = { NULL, 0, 0 };

			out.dst = sess->d_scratch;
			out.size = sess->d_scratch_sz;
			out.pos = 0;
			ret = ZSTD_decompressStream(dctx, &out, &in0);
			if (ZSTD_isError(ret)) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				ZSTD_PMD_ERR("ZSTD_decompressStream (between slices): %s",
						ZSTD_getErrorName(ret));
				goto end;
			}
			if (out.pos > 0) {
				if (zstd_mbuf_dst_write_linear(op->m_dst, &dst_lin,
						sess->d_scratch, out.pos, op) < 0)
					goto end;
				produced += (uint32_t)out.pos;
			}
			if (ret == 0)
				break;
			if (out.pos == 0)
				break;
		}
		remaining_in -= (uint32_t)in.size;
		op->consumed += (uint32_t)in.size;
		src_off = 0;
		if (remaining_in > 0) {
			if (ms->next == NULL) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto end;
			}
			ms = ms->next;
			src_off = 0;
		}
	}

	/* If last slice ended with ret==0, frame is fully flushed (ZSTD API). */
	if (ret != 0) {
		for (;;) {
			ZSTD_inBuffer in0 = { NULL, 0, 0 };

			out.dst = sess->d_scratch;
			out.size = sess->d_scratch_sz;
			out.pos = 0;
			ret = ZSTD_decompressStream(dctx, &out, &in0);
			if (ZSTD_isError(ret)) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				ZSTD_PMD_ERR("ZSTD_decompressStream drain: %s",
						ZSTD_getErrorName(ret));
				goto end;
			}
			if (out.pos > 0) {
				if (zstd_mbuf_dst_write_linear(op->m_dst, &dst_lin,
						sess->d_scratch, out.pos, op) < 0)
					goto end;
				produced += (uint32_t)out.pos;
			}
			if (ret == 0)
				break;
			if (op->op_type == RTE_COMP_OP_STATEFUL && out.pos == 0)
				break;
		}
	}

	if (op->op_type == RTE_COMP_OP_STATELESS && ret != 0)
		op->status = RTE_COMP_OP_STATUS_ERROR;

	if (op->op_type == RTE_COMP_OP_STATELESS &&
			op->status == RTE_COMP_OP_STATUS_SUCCESS) {
		ZSTD_DCtx_reset(dctx, ZSTD_reset_session_only);
		if (zstd_reinit_decompress_stream(sess) < 0)
			op->status = RTE_COMP_OP_STATUS_ERROR;
	}

end:
	op->produced = produced;
	if (op->status == RTE_COMP_OP_STATUS_SUCCESS &&
	    op->consumed != op->src.length)
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
}

static int
process_zstd_op(struct zstd_qp *qp, struct rte_comp_op *op)
{
	struct zstd_sess *sess;
	struct zstd_priv_xform *priv;

	if ((op->src.offset > rte_pktmbuf_data_len(op->m_src)) ||
			(op->dst.offset > zstd_mbuf_chain_data_len(op->m_dst))) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		ZSTD_PMD_ERR("Invalid mbuf offsets");
	} else if (op->op_type == RTE_COMP_OP_STATEFUL) {
		sess = (struct zstd_sess *)op->stream;
		if (unlikely(sess == NULL)) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		} else if (sess->is_compress)
			zstd_process_compress(op, sess);
		else
			zstd_process_decompress(op, sess);
	} else {
		priv = (struct zstd_priv_xform *)op->private_xform;
		if (unlikely(priv == NULL)) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		} else if (priv->sess.is_compress)
			zstd_process_compress(op, &priv->sess);
		else
			zstd_process_decompress(op, &priv->sess);
	}
	return rte_ring_enqueue(qp->processed_pkts, (void *)op);
}

static uint16_t
zstd_pmd_enqueue_burst(void *queue_pair, struct rte_comp_op **ops,
		uint16_t nb_ops)
{
	struct zstd_qp *qp = queue_pair;
	int ret;
	uint16_t i, enqd = 0;

	for (i = 0; i < nb_ops; i++) {
		ret = process_zstd_op(qp, ops[i]);
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
zstd_pmd_dequeue_burst(void *queue_pair, struct rte_comp_op **ops,
		uint16_t nb_ops)
{
	struct zstd_qp *qp = queue_pair;
	unsigned int n;

	n = rte_ring_dequeue_burst(qp->processed_pkts, (void **)ops, nb_ops,
			NULL);
	qp->qp_stats.dequeued_count += n;
	return (uint16_t)n;
}

static int
zstd_create(const char *name, struct rte_vdev_device *vdev,
		struct rte_compressdev_pmd_init_params *init_params)
{
	struct rte_compressdev *dev;

	dev = rte_compressdev_pmd_create(name, &vdev->device,
			sizeof(struct zstd_private), init_params);
	if (dev == NULL) {
		ZSTD_PMD_ERR("driver %s: create failed", init_params->name);
		return -ENODEV;
	}
	dev->dev_ops = rte_zstd_pmd_ops;
	dev->dequeue_burst = zstd_pmd_dequeue_burst;
	dev->enqueue_burst = zstd_pmd_enqueue_burst;
	return 0;
}

static int
zstd_probe(struct rte_vdev_device *vdev)
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
		ZSTD_PMD_ERR("Failed to parse initialisation arguments[%s]",
				input_args);
		return -EINVAL;
	}
	return zstd_create(name, vdev, &init_params);
}

static int
zstd_remove(struct rte_vdev_device *vdev)
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

static struct rte_vdev_driver zstd_pmd_drv = {
	.probe = zstd_probe,
	.remove = zstd_remove
};

RTE_PMD_REGISTER_VDEV(COMPRESSDEV_NAME_ZSTD_PMD, zstd_pmd_drv);
RTE_LOG_REGISTER_DEFAULT(zstd_logtype_driver, INFO);
