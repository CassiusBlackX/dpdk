/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2025 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2024-2025 Linaro ltd.
 */

#include <errno.h>
#include <string.h>

#include <bus_vdev_driver.h>
#include <rte_compressdev_pmd.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <uadk/wd_comp.h>
#include <uadk/wd_sched.h>

#include "uadk_compress_pmd_private.h"

#define UADK_COMP_DEF_CTXS    2
#define UADK_COMP_DEF_SYNC_CTXS 1

static const char *const uadk_init_alg_kw[] = {"init_alg", NULL};

static const struct
rte_compressdev_capabilities uadk_compress_pmd_capabilities[] = {
	{   /* Deflate */
		.algo = RTE_COMP_ALGO_DEFLATE,
		.comp_feature_flags = RTE_COMP_FF_STATEFUL_COMPRESSION |
				      RTE_COMP_FF_STATEFUL_DECOMPRESSION |
				      RTE_COMP_FF_SHAREABLE_PRIV_XFORM |
				      RTE_COMP_FF_HUFFMAN_FIXED |
				      RTE_COMP_FF_HUFFMAN_DYNAMIC,
		.window_size = {
			.min = 13,
			.max = 13,
			.increment = 0,
		},
	},
	{   /* ZSTD via UADK WD_LZ77_ZSTD (literals + sequences in dst mbuf) */
		.algo = RTE_COMP_ALGO_ZSTD,
		.comp_feature_flags = RTE_COMP_FF_SHAREABLE_PRIV_XFORM,
	},

	RTE_COMP_END_OF_CAPABILITIES_LIST()
};

static enum wd_comp_level
uadk_map_comp_level(int level)
{
	if (level == RTE_COMP_LEVEL_PMD_DEFAULT || level < RTE_COMP_LEVEL_MIN)
		return WD_COMP_L8;
	if (level > (int)WD_COMP_L15)
		return WD_COMP_L15;
	return (enum wd_comp_level)level;
}

static enum wd_comp_winsz_type
uadk_map_window(uint8_t wlog)
{
	if (wlog == 0)
		return WD_COMP_WS_32K;
	if (wlog <= 12)
		return WD_COMP_WS_4K;
	if (wlog == 13)
		return WD_COMP_WS_8K;
	if (wlog == 14)
		return WD_COMP_WS_16K;
	if (wlog == 15)
		return WD_COMP_WS_32K;
	/* 24K window maps between 14 and 15 */
	if (wlog < 15)
		return WD_COMP_WS_24K;
	return WD_COMP_WS_32K;
}

static void
uadk_compress_parse_init_alg(struct rte_vdev_device *vdev,
			     struct uadk_compress_priv *priv)
{
	const char *args = rte_vdev_device_args(vdev);
	struct rte_kvargs *kv;

	strncpy(priv->init_alg, "deflate", sizeof(priv->init_alg) - 1);
	priv->init_alg[sizeof(priv->init_alg) - 1] = '\0';

	if (args == NULL || args[0] == '\0')
		return;

	kv = rte_kvargs_parse(args, uadk_init_alg_kw);
	if (kv == NULL)
		return;

	if (rte_kvargs_count(kv, "init_alg") == 1) {
		const char *v = rte_kvargs_get(kv, "init_alg");

		if (v != NULL && v[0] != '\0')
			rte_strscpy(priv->init_alg, v, sizeof(priv->init_alg));
	}

	rte_kvargs_free(kv);
}

static uint32_t
uadk_zstd_dst_min(uint32_t in_len)
{
	return in_len + UADK_ZSTD_LIT_RSV + UADK_ZSTD_FREQ_SZ +
		UADK_ZSTD_SEQ_ROOM;
}

static void
uadk_datalist_link(struct wd_datalist *nodes, int n)
{
	int i;

	for (i = 0; i < n - 1; i++)
		nodes[i].next = &nodes[i + 1];
	if (n > 0)
		nodes[n - 1].next = NULL;
}

static int
uadk_mbuf_read_datalist(const struct rte_mbuf *m, uint32_t pkt_off,
			uint32_t nbytes, struct wd_datalist *nodes, int max_nodes,
			struct wd_datalist **head_out)
{
	uint32_t skip = pkt_off;
	uint32_t rem = nbytes;
	int n = 0;
	struct wd_datalist *prev = NULL;

	*head_out = NULL;
	while (m != NULL && rem > 0) {
		uint32_t sl = rte_pktmbuf_data_len(m);

		if (skip >= sl) {
			skip -= sl;
			m = m->next;
			continue;
		}
		uint32_t so = skip;

		skip = 0;
		uint32_t take = RTE_MIN(sl - so, rem);

		if (n >= max_nodes)
			return -ENOSPC;
		nodes[n].data = rte_pktmbuf_mtod_offset(m, void *, so);
		nodes[n].len = take;
		nodes[n].next = NULL;
		if (prev)
			prev->next = &nodes[n];
		else
			*head_out = &nodes[n];
		prev = &nodes[n];
		n++;
		rem -= take;
		if (take < sl - so)
			break;
		m = m->next;
	}
	if (rem != 0)
		return -EINVAL;
	return n;
}

static int
uadk_mbuf_writable_datalist(const struct rte_mbuf *m, uint32_t pkt_off,
			    struct wd_datalist *nodes, int max_nodes,
			    struct wd_datalist **head_out, uint32_t *avail_out)
{
	uint32_t skip = pkt_off;
	int n = 0;
	struct wd_datalist *prev = NULL;
	uint32_t acc = 0;

	*head_out = NULL;
	*avail_out = 0;
	while (m != NULL) {
		uint32_t dlen = rte_pktmbuf_data_len(m);
		uint32_t tr = rte_pktmbuf_tailroom(m);
		uint32_t seg_room = dlen + tr;

		if (skip >= seg_room) {
			skip -= seg_room;
			m = m->next;
			continue;
		}
		uint32_t loff = skip;

		skip = 0;
		uint32_t chunk = seg_room - loff;

		if (n >= max_nodes)
			return -ENOSPC;
		nodes[n].data = rte_pktmbuf_mtod(m, uint8_t *) + loff;
		nodes[n].len = chunk;
		nodes[n].next = NULL;
		if (prev)
			prev->next = &nodes[n];
		else
			*head_out = &nodes[n];
		prev = &nodes[n];
		n++;
		acc += chunk;
		m = m->next;
	}
	*avail_out = acc;
	return n;
}

static unsigned int
uadk_mbuf_chain_segments(const struct rte_mbuf *m)
{
	unsigned int n = 0;

	while (m != NULL) {
		n++;
		m = m->next;
	}
	return n;
}

static enum rte_comp_op_status
uadk_compress_pmd_status_from_req(const struct wd_comp_req *req, int ret);

static int
uadk_compress_pmd_config(struct rte_compressdev *dev,
			 struct rte_compressdev_config *config __rte_unused)
{
	struct uadk_compress_priv *priv = dev->data->dev_private;
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums *ctx_set_num;
	int ret;
	if (priv->init)
		return 0;

	ctx_set_num = calloc(WD_DIR_MAX, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		UADK_LOG(ERR, "failed to alloc ctx_set_size!");
		return -WD_ENOMEM;
	}

	cparams.op_type_num = WD_DIR_MAX;
	cparams.ctx_set_num = ctx_set_num;

	for (int i = 0; i < WD_DIR_MAX; i++)
		ctx_set_num[i].sync_ctx_num = UADK_COMP_DEF_SYNC_CTXS;

	for (int i = 0; i < WD_DIR_MAX; i++)
		ctx_set_num[i].async_ctx_num = UADK_COMP_DEF_CTXS;

	ret = wd_comp_init2_(priv->init_alg, SCHED_POLICY_RR, TASK_MIX, &cparams);
	free(ctx_set_num);

	if (ret) {
		UADK_LOG(ERR, "failed to do comp init2! %d", ret);
		return ret;
	}

	priv->init = true;

	return 0;
}

static int
uadk_compress_pmd_start(struct rte_compressdev *dev __rte_unused)
{
	return 0;
}

static void
uadk_compress_pmd_stop(struct rte_compressdev *dev __rte_unused)
{
}

static int
uadk_compress_pmd_close(struct rte_compressdev *dev)
{
	struct uadk_compress_priv *priv = dev->data->dev_private;

	if (priv->init) {
		wd_comp_uninit2();
		priv->init = false;
	}

	return 0;
}

static void
uadk_compress_pmd_stats_get(struct rte_compressdev *dev,
			    struct rte_compressdev_stats *stats)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct uadk_compress_qp *qp = dev->data->queue_pairs[qp_id];

		stats->enqueued_count += qp->qp_stats.enqueued_count;
		stats->dequeued_count += qp->qp_stats.dequeued_count;
		stats->enqueue_err_count += qp->qp_stats.enqueue_err_count;
		stats->dequeue_err_count += qp->qp_stats.dequeue_err_count;
	}
}

static void
uadk_compress_pmd_stats_reset(struct rte_compressdev *dev)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct uadk_compress_qp *qp = dev->data->queue_pairs[qp_id];

		memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));
	}
}

static void
uadk_compress_pmd_info_get(struct rte_compressdev *dev,
			   struct rte_compressdev_info *dev_info)
{
	if (dev_info != NULL) {
		dev_info->driver_name = dev->device->driver->name;
		dev_info->feature_flags = dev->feature_flags;
		dev_info->capabilities = uadk_compress_pmd_capabilities;
	}
}

static int
uadk_compress_pmd_qp_release(struct rte_compressdev *dev, uint16_t qp_id)
{
	struct uadk_compress_qp *qp = dev->data->queue_pairs[qp_id];

	if (qp != NULL) {
		rte_ring_free(qp->processed_pkts);
		rte_free(qp);
		dev->data->queue_pairs[qp_id] = NULL;
	}

	return 0;
}

static int
uadk_pmd_qp_set_unique_name(struct rte_compressdev *dev,
			    struct uadk_compress_qp *qp)
{
	unsigned int n = snprintf(qp->name, sizeof(qp->name),
				 "uadk_pmd_%u_qp_%u",
				 dev->data->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -EINVAL;

	return 0;
}

static struct rte_ring *
uadk_pmd_qp_create_processed_pkts_ring(struct uadk_compress_qp *qp,
				       unsigned int ring_size, int socket_id)
{
	struct rte_ring *r = qp->processed_pkts;

	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			UADK_LOG(INFO, "Reusing existing ring %s for processed packets",
				 qp->name);
			return r;
		}

		UADK_LOG(ERR, "Unable to reuse existing ring %s for processed packets",
			 qp->name);
		return NULL;
	}

	return rte_ring_create(qp->name, ring_size, socket_id,
			       RING_F_EXACT_SZ);
}

static int
uadk_compress_pmd_qp_setup(struct rte_compressdev *dev, uint16_t qp_id,
			   uint32_t max_inflight_ops, int socket_id)
{
	struct uadk_compress_qp *qp = NULL;

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		uadk_compress_pmd_qp_release(dev, qp_id);

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc_socket("uadk PMD Queue Pair", sizeof(*qp),
				RTE_CACHE_LINE_SIZE, socket_id);
	if (qp == NULL)
		return (-ENOMEM);

	qp->id = qp_id;
	dev->data->queue_pairs[qp_id] = qp;

	if (uadk_pmd_qp_set_unique_name(dev, qp))
		goto qp_setup_cleanup;

	qp->processed_pkts = uadk_pmd_qp_create_processed_pkts_ring(qp,
						max_inflight_ops, socket_id);
	if (qp->processed_pkts == NULL)
		goto qp_setup_cleanup;

	memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));

	return 0;

qp_setup_cleanup:
	if (qp) {
		rte_free(qp);
		qp = NULL;
	}
	return -EINVAL;
}

static int
uadk_compress_pmd_xform_create(struct rte_compressdev *dev __rte_unused,
			       const struct rte_comp_xform *xform,
			       void **private_xform)
{
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	struct uadk_compress_xform *xfrm;
	handle_t handle;

	if (xform == NULL) {
		UADK_LOG(ERR, "invalid xform struct");
		return -EINVAL;
	}

	xfrm = rte_malloc(NULL, sizeof(struct uadk_compress_xform), 0);
	if (xfrm == NULL)
		return -ENOMEM;
	memset(xfrm, 0, sizeof(*xfrm));

	switch (xform->type) {
	case RTE_COMP_COMPRESS:
		switch (xform->compress.algo) {
		case RTE_COMP_ALGO_NULL:
			break;
		case RTE_COMP_ALGO_DEFLATE:
			setup.alg_type = WD_DEFLATE;
			setup.win_sz = uadk_map_window(xform->compress.window_size);
			setup.comp_lv = uadk_map_comp_level(xform->compress.level);
			setup.op_type = WD_DIR_COMPRESS;
			param.type = setup.op_type;
			param.numa_id = -1;	/* choose nearby numa node */
			setup.sched_param = &param;
			xfrm->pmd_alg = UADK_PMD_ALG_DEFLATE;
			break;
		case RTE_COMP_ALGO_ZSTD:
			setup.alg_type = WD_LZ77_ZSTD;
			setup.win_sz = uadk_map_window(xform->compress.window_size);
			setup.comp_lv = uadk_map_comp_level(xform->compress.level);
			setup.op_type = WD_DIR_COMPRESS;
			param.type = setup.op_type;
			param.numa_id = -1;
			setup.sched_param = &param;
			xfrm->pmd_alg = UADK_PMD_ALG_ZSTD;
			break;
		default:
			goto err;
		}
		break;
	case RTE_COMP_DECOMPRESS:
		switch (xform->decompress.algo) {
		case RTE_COMP_ALGO_NULL:
			break;
		case RTE_COMP_ALGO_ZSTD:
			UADK_LOG(ERR, "ZSTD decompression is not supported");
			goto err;
		case RTE_COMP_ALGO_DEFLATE:
			setup.alg_type = WD_DEFLATE;
			setup.win_sz = uadk_map_window(xform->decompress.window_size);
			setup.comp_lv = WD_COMP_L8;
			setup.op_type = WD_DIR_DECOMPRESS;
			param.type = setup.op_type;
			param.numa_id = -1;	/* choose nearby numa node */
			setup.sched_param = &param;
			xfrm->pmd_alg = UADK_PMD_ALG_DEFLATE;
			break;
		default:
			goto err;
		}
		break;
	default:
		UADK_LOG(ERR, "Algorithm %u is not supported.", xform->type);
		goto err;
	}

	handle = wd_comp_alloc_sess(&setup);
	if (!handle)
		goto err;

	xfrm->handle = handle;
	xfrm->type = xform->type;
	*private_xform = xfrm;
	return 0;

err:
	rte_free(xfrm);
	return -EINVAL;
}

static int
uadk_compress_pmd_xform_free(struct rte_compressdev *dev __rte_unused, void *xform)
{
	if (!xform)
		return -EINVAL;

	wd_comp_free_sess(((struct uadk_compress_xform *)xform)->handle);
	rte_free(xform);

	return 0;
}

static int
uadk_compress_pmd_stream_create(struct rte_compressdev *dev,
				const struct rte_comp_xform *xform,
				void **stream)
{
	return uadk_compress_pmd_xform_create(dev, xform, stream);
}

static int
uadk_compress_pmd_stream_free(struct rte_compressdev *dev, void *stream)
{
	return uadk_compress_pmd_xform_free(dev, stream);
}

static struct rte_compressdev_ops uadk_compress_pmd_ops = {
		.dev_configure		= uadk_compress_pmd_config,
		.dev_start		= uadk_compress_pmd_start,
		.dev_stop		= uadk_compress_pmd_stop,
		.dev_close		= uadk_compress_pmd_close,
		.stats_get		= uadk_compress_pmd_stats_get,
		.stats_reset		= uadk_compress_pmd_stats_reset,
		.dev_infos_get		= uadk_compress_pmd_info_get,
		.queue_pair_setup	= uadk_compress_pmd_qp_setup,
		.queue_pair_release	= uadk_compress_pmd_qp_release,
		.stream_create		= uadk_compress_pmd_stream_create,
		.stream_free		= uadk_compress_pmd_stream_free,
		.private_xform_create	= uadk_compress_pmd_xform_create,
		.private_xform_free	= uadk_compress_pmd_xform_free,
};

static void *
uadk_compress_pmd_async_cb(struct wd_comp_req *req, void *data __rte_unused)
{
	struct rte_comp_op *op = req->cb_param;
	struct uadk_compress_xform *xf = (struct uadk_compress_xform *)op->private_xform;
	uint16_t dst_len = rte_pktmbuf_data_len(op->m_dst) - op->dst.offset;
	struct wd_lz77_zstd_data *zstd = req->priv;

	if (xf && xf->pmd_alg == UADK_PMD_ALG_ZSTD) {
		if (req->status == WD_SUCCESS || req->status == WD_STREAM_END) {
			if (zstd && zstd->literals_start && zstd->freq) {
				ptrdiff_t used = (uint8_t *)zstd->freq -
						(uint8_t *)zstd->literals_start;

				if (used >= 0 &&
				    (size_t)used + UADK_ZSTD_FREQ_SZ <= UINT32_MAX)
					op->produced = (uint32_t)used +
							UADK_ZSTD_FREQ_SZ;
				else
					op->produced = 0;
			} else {
				op->produced = 0;
			}
			if (zstd)
				op->debug_status = (uint64_t)zstd->lit_num |
					((uint64_t)zstd->seq_num << 32);
			op->status = RTE_COMP_OP_STATUS_SUCCESS;
		} else {
			op->status = uadk_compress_pmd_status_from_req(req, 0);
		}
		if (zstd)
			rte_free(zstd);
		return NULL;
	}

	if (req->dst_len <= dst_len) {
		op->produced += req->dst_len;
		op->status = RTE_COMP_OP_STATUS_SUCCESS;
	} else {
		op->status = RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
	}

	return NULL;
}

static int
uadk_compress_pmd_set_stateful_last(const struct rte_comp_op *op,
					   struct wd_comp_req *req)
{
	switch (op->flush_flag) {
	case RTE_COMP_FLUSH_NONE:
	case RTE_COMP_FLUSH_SYNC:
	case RTE_COMP_FLUSH_FULL:
		req->last = 0;
		break;
	case RTE_COMP_FLUSH_FINAL:
		req->last = 1;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static enum rte_comp_op_status
uadk_compress_pmd_status_from_req(const struct wd_comp_req *req, int ret)
{
	if (ret)
		return ret == -WD_EINVAL ?
			RTE_COMP_OP_STATUS_INVALID_ARGS : RTE_COMP_OP_STATUS_ERROR;

	if (req->status == WD_IN_EPARA)
		return RTE_COMP_OP_STATUS_INVALID_ARGS;

	if (req->status == WD_SUCCESS || req->status == WD_STREAM_END)
		return RTE_COMP_OP_STATUS_SUCCESS;

	return RTE_COMP_OP_STATUS_ERROR;
}

static uint16_t
uadk_compress_pmd_enqueue_burst_async(void *queue_pair,
				      struct rte_comp_op **ops, uint16_t nb_ops)
{
	struct uadk_compress_qp *qp = queue_pair;
	struct uadk_compress_xform *xform;
	struct rte_comp_op *op;
	uint16_t enqd = 0;
	int i;

	for (i = 0; i < nb_ops; i++) {
		int ret = 0;
		int enq_ret;
		uint16_t src_len;
		uint16_t dst_len;
		struct wd_comp_req req = {0};

		op = ops[i];
		xform = op->op_type == RTE_COMP_OP_STATEFUL ?
			(struct uadk_compress_xform *)op->stream :
			(struct uadk_compress_xform *)op->private_xform;

		if (!xform) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
			goto enqueue_done;
		}

		src_len = rte_pktmbuf_data_len(op->m_src);
		dst_len = rte_pktmbuf_data_len(op->m_dst);

		if (op->src.offset > src_len || op->dst.offset > dst_len ||
		    op->src.length > src_len - op->src.offset) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
			goto enqueue_done;
		}

		req.src = rte_pktmbuf_mtod_offset(op->m_src, uint8_t *,
				op->src.offset);
		req.src_len = op->src.length;
		req.dst = rte_pktmbuf_mtod_offset(op->m_dst, uint8_t *,
				op->dst.offset);
		req.dst_len = dst_len - op->dst.offset;
		req.op_type = (enum wd_comp_op_type)xform->type;
		req.data_fmt = WD_FLAT_BUF;

		if (op->op_type == RTE_COMP_OP_STATEFUL) {
			ret = uadk_compress_pmd_set_stateful_last(op, &req);
			if (ret) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}

			ret = wd_do_comp_strm(xform->handle, &req);
			op->status = uadk_compress_pmd_status_from_req(&req, ret);
			op->consumed += req.src_len;
			op->produced += req.dst_len;
		} else if (xform->pmd_alg == UADK_PMD_ALG_ZSTD) {
			struct wd_lz77_zstd_data *zd;
			struct wd_datalist *nodes;
			struct wd_datalist *src_nodes;
			struct wd_datalist *dst_nodes;
			void *blob;
			int n_src, n_dst;
			unsigned int n_src_max;
			unsigned int n_dst_max;
			uint32_t need;
			uint32_t avail = 0;
			struct wd_datalist *src_head;
			struct wd_datalist *dst_head;

			if (xform->type != RTE_COMP_COMPRESS) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			if (op->flush_flag != RTE_COMP_FLUSH_FULL &&
			    op->flush_flag != RTE_COMP_FLUSH_FINAL) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			if (op->src.length > UADK_ZSTD_HW_MAX_IN) {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			need = uadk_zstd_dst_min(op->src.length);
			n_src_max = uadk_mbuf_chain_segments(op->m_src);
			n_dst_max = uadk_mbuf_chain_segments(op->m_dst);
			blob = rte_malloc(NULL,
				sizeof(*zd) + (size_t)(n_src_max + n_dst_max) *
				sizeof(struct wd_datalist),
				RTE_CACHE_LINE_SIZE);
			if (blob == NULL) {
				op->status = RTE_COMP_OP_STATUS_ERROR;
				goto enqueue_done;
			}
			memset(blob, 0,
			       sizeof(*zd) + (size_t)(n_src_max + n_dst_max) *
			       sizeof(struct wd_datalist));
			zd = blob;
			nodes = (struct wd_datalist *)((uint8_t *)blob + sizeof(*zd));
			src_nodes = nodes;
			dst_nodes = nodes + n_src_max;
			n_src = uadk_mbuf_read_datalist(op->m_src, op->src.offset,
					op->src.length, src_nodes,
					(int)n_src_max, &src_head);
			if (n_src < 0) {
				rte_free(blob);
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			n_dst = uadk_mbuf_writable_datalist(op->m_dst, op->dst.offset,
					dst_nodes, (int)n_dst_max, &dst_head,
					&avail);
			if (n_dst < 0) {
				rte_free(blob);
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			if (avail < need) {
				rte_free(blob);
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
				goto enqueue_done;
			}
			uadk_datalist_link(src_nodes, n_src);
			uadk_datalist_link(dst_nodes, n_dst);
			memset(&req, 0, sizeof(req));
			req.list_src = n_src ? src_nodes : NULL;
			req.list_dst = n_dst ? dst_nodes : NULL;
			req.src_len = op->src.length;
			req.dst_len = avail;
			req.data_fmt = WD_SGL_BUF;
			req.op_type = WD_DIR_COMPRESS;
			req.priv = zd;
			req.cb = uadk_compress_pmd_async_cb;
			req.cb_param = op;
			do {
				ret = wd_do_comp_async(xform->handle, &req);
			} while (ret == -WD_EBUSY);

			op->consumed += op->src.length;

			if (ret) {
				rte_free(blob);
				op->status = uadk_compress_pmd_status_from_req(&req, ret);
			} else {
				op->status = RTE_COMP_OP_STATUS_NOT_PROCESSED;
			}
		} else {
			req.cb = uadk_compress_pmd_async_cb;
			req.cb_param = op;
			do {
				ret = wd_do_comp_async(xform->handle, &req);
			} while (ret == -WD_EBUSY);

			op->consumed += req.src_len;

			if (ret)
				op->status = uadk_compress_pmd_status_from_req(&req, ret);
			else
				op->status = RTE_COMP_OP_STATUS_NOT_PROCESSED;
		}

enqueue_done:
		/* Whatever is out of op, put it into completion queue with
		 * its status
		 */
		enq_ret = rte_ring_enqueue(qp->processed_pkts, (void *)op);

		if (unlikely(enq_ret)) {
			/* increment count if failed to enqueue op */
			qp->qp_stats.enqueue_err_count++;
		} else {
			qp->qp_stats.enqueued_count++;
			enqd++;
		}
	}

	return enqd;
}

static uint16_t
uadk_compress_pmd_dequeue_burst_async(void *queue_pair,
				      struct rte_comp_op **ops,
				      uint16_t nb_ops)
{
	struct uadk_compress_qp *qp = queue_pair;
	unsigned int nb_dequeued = 0;
	unsigned int completed = 0;
	unsigned int recv = 0;
	uint16_t i;
	int ret;

	nb_dequeued = rte_ring_dequeue_burst(qp->processed_pkts,
			(void **)ops, nb_ops, NULL);
	if (nb_dequeued == 0)
		return 0;

	for (i = 0; i < nb_dequeued; i++) {
		if (ops[i]->status == RTE_COMP_OP_STATUS_NOT_PROCESSED)
			completed++;
	}

	while (completed) {
		recv = 0;
		do {
			ret = wd_comp_poll(completed, &recv);
		} while (ret == -WD_EAGAIN);

		if (ret)
			break;

		if (recv == 0)
			break;

		completed -= recv;
	}

	for (i = 0; i < nb_dequeued; i++) {
		if (ops[i]->status == RTE_COMP_OP_STATUS_NOT_PROCESSED)
			ops[i]->status = RTE_COMP_OP_STATUS_ERROR;
	}

	qp->qp_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

static int
uadk_compress_probe(struct rte_vdev_device *vdev)
{
	struct rte_compressdev_pmd_init_params init_params = {
		"",
		rte_socket_id(),
	};
	struct rte_compressdev *compressdev;
	struct uadk_compress_priv *priv;
	struct uacce_dev *udev;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	compressdev = rte_compressdev_pmd_create(name, &vdev->device,
			sizeof(struct uadk_compress_priv), &init_params);
	if (compressdev == NULL) {
		UADK_LOG(ERR, "driver %s: create failed", init_params.name);
		return -ENODEV;
	}

	priv = compressdev->data->dev_private;
	memset(priv, 0, sizeof(*priv));
	uadk_compress_parse_init_alg(vdev, priv);

	udev = wd_get_accel_dev(priv->init_alg);
	if (!udev) {
		rte_compressdev_pmd_destroy(compressdev);
		return -ENODEV;
	}

	compressdev->dev_ops = &uadk_compress_pmd_ops;
	compressdev->dequeue_burst = uadk_compress_pmd_dequeue_burst_async;
	compressdev->enqueue_burst = uadk_compress_pmd_enqueue_burst_async;
	compressdev->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED;

	return 0;
}

static int
uadk_compress_remove(struct rte_vdev_device *vdev)
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

static struct rte_vdev_driver uadk_compress_pmd = {
	.probe = uadk_compress_probe,
	.remove = uadk_compress_remove,
};

#define UADK_COMPRESS_DRIVER_NAME compress_uadk
RTE_PMD_REGISTER_VDEV(UADK_COMPRESS_DRIVER_NAME, uadk_compress_pmd);
RTE_LOG_REGISTER_DEFAULT(uadk_compress_logtype, INFO);
