/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#include <string.h>

#include <dev_driver.h>
#include <rte_common.h>
#include <rte_malloc.h>

#include "zstd_raw_pmd_private.h"

static const struct rte_compressdev_capabilities zstd_raw_pmd_capabilities[] = {
	{
		.algo = RTE_COMP_ALGO_ZSTD,
		.comp_feature_flags = RTE_COMP_FF_SHAREABLE_PRIV_XFORM,
		.window_size = {
			.min = 10,
			.max = 31,
			.increment = 1
		},
	},
	RTE_COMP_END_OF_CAPABILITIES_LIST()
};

static int
zstd_raw_pmd_config(struct rte_compressdev *dev,
		struct rte_compressdev_config *config)
{
	struct rte_mempool *mp;
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct zstd_raw_private *internals = dev->data->dev_private;

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "zstd_raw_stream_mp_%u",
			dev->data->dev_id);
	mp = internals->mp;
	if (mp == NULL) {
		mp = rte_mempool_create(mp_name,
				config->max_nb_priv_xforms +
				config->max_nb_streams,
				sizeof(struct zstd_raw_priv_xform),
				0, 0, NULL, NULL, NULL, NULL, config->socket_id,
				0);
		if (mp == NULL) {
			ZSTD_RAW_PMD_ERR("Cannot create private xform pool on socket %d",
					config->socket_id);
			return -ENOMEM;
		}
		internals->mp = mp;
	}
	return 0;
}

static int
zstd_raw_pmd_start(__rte_unused struct rte_compressdev *dev)
{
	return 0;
}

static void
zstd_raw_pmd_stop(__rte_unused struct rte_compressdev *dev)
{
}

static int
zstd_raw_pmd_close(struct rte_compressdev *dev)
{
	struct zstd_raw_private *internals = dev->data->dev_private;

	rte_mempool_free(internals->mp);
	internals->mp = NULL;
	return 0;
}

static void
zstd_raw_pmd_stats_get(struct rte_compressdev *dev,
		struct rte_compressdev_stats *stats)
{
	uint16_t qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct zstd_raw_qp *qp = dev->data->queue_pairs[qp_id];

		stats->enqueued_count += qp->qp_stats.enqueued_count;
		stats->dequeued_count += qp->qp_stats.dequeued_count;
		stats->enqueue_err_count += qp->qp_stats.enqueue_err_count;
		stats->dequeue_err_count += qp->qp_stats.dequeue_err_count;
	}
}

static void
zstd_raw_pmd_stats_reset(struct rte_compressdev *dev)
{
	uint16_t qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct zstd_raw_qp *qp = dev->data->queue_pairs[qp_id];

		memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));
	}
}

static void
zstd_raw_pmd_info_get(struct rte_compressdev *dev,
		struct rte_compressdev_info *dev_info)
{
	if (dev_info != NULL) {
		dev_info->driver_name = dev->device->driver->name;
		dev_info->feature_flags = dev->feature_flags;
		dev_info->capabilities = zstd_raw_pmd_capabilities;
	}
}

static int
zstd_raw_pmd_qp_release(struct rte_compressdev *dev, uint16_t qp_id)
{
	struct zstd_raw_qp *qp = dev->data->queue_pairs[qp_id];

	if (qp != NULL) {
		rte_ring_free(qp->processed_pkts);
		rte_free(qp);
		dev->data->queue_pairs[qp_id] = NULL;
	}
	return 0;
}

static int
zstd_raw_pmd_qp_set_unique_name(struct rte_compressdev *dev,
		struct zstd_raw_qp *qp)
{
	unsigned int n = snprintf(qp->name, sizeof(qp->name),
			"zstd_raw_pmd_%u_qp_%u",
			dev->data->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -1;
	return 0;
}

static struct rte_ring *
zstd_raw_pmd_qp_create_processed_pkts_ring(struct zstd_raw_qp *qp,
		unsigned int ring_size, int socket_id)
{
	struct rte_ring *r = qp->processed_pkts;

	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			ZSTD_RAW_PMD_INFO("Reusing existing ring %s for processed packets",
					qp->name);
			return r;
		}
		ZSTD_RAW_PMD_ERR("Unable to reuse existing ring %s", qp->name);
		return NULL;
	}
	return rte_ring_create(qp->name, ring_size, socket_id, RING_F_EXACT_SZ);
}

static int
zstd_raw_pmd_qp_setup(struct rte_compressdev *dev, uint16_t qp_id,
		uint32_t max_inflight_ops, int socket_id)
{
	struct zstd_raw_qp *qp = NULL;

	if (dev->data->queue_pairs[qp_id] != NULL)
		zstd_raw_pmd_qp_release(dev, qp_id);

	qp = rte_zmalloc_socket("ZSTD_RAW PMD Queue Pair", sizeof(*qp),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (qp == NULL)
		return -ENOMEM;

	qp->id = qp_id;
	dev->data->queue_pairs[qp_id] = qp;

	if (zstd_raw_pmd_qp_set_unique_name(dev, qp))
		goto qp_setup_cleanup;

	qp->processed_pkts = zstd_raw_pmd_qp_create_processed_pkts_ring(qp,
			max_inflight_ops, socket_id);
	if (qp->processed_pkts == NULL)
		goto qp_setup_cleanup;

	memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));
	return 0;

qp_setup_cleanup:
	if (qp) {
		rte_free(qp);
		dev->data->queue_pairs[qp_id] = NULL;
	}
	return -1;
}

static int
zstd_raw_pmd_stream_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform, void **stream)
{
	struct zstd_raw_priv_xform *px;
	struct zstd_raw_private *internals = dev->data->dev_private;

	if (xform == NULL) {
		ZSTD_RAW_PMD_ERR("invalid xform struct");
		return -EINVAL;
	}
	if (rte_mempool_get(internals->mp, stream)) {
		ZSTD_RAW_PMD_ERR("Couldn't get object from session mempool");
		return -ENOMEM;
	}
	px = *((struct zstd_raw_priv_xform **)stream);
	if (zstd_raw_set_session_parameters(xform, &px->sess) < 0) {
		memset(px, 0, sizeof(*px));
		rte_mempool_put(internals->mp, px);
		return -EINVAL;
	}
	return 0;
}

static int
zstd_raw_pmd_stream_free(__rte_unused struct rte_compressdev *dev, void *stream)
{
	struct zstd_raw_priv_xform *px = (struct zstd_raw_priv_xform *)stream;
	struct rte_mempool *mp;

	if (px == NULL)
		return -EINVAL;
	zstd_raw_sess_fini(&px->sess);
	memset(px, 0, sizeof(*px));
	mp = rte_mempool_from_obj(px);
	rte_mempool_put(mp, px);
	return 0;
}

static int
zstd_raw_pmd_private_xform_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform, void **private_xform)
{
	struct zstd_raw_priv_xform *px;
	struct zstd_raw_private *internals = dev->data->dev_private;

	if (xform == NULL) {
		ZSTD_RAW_PMD_ERR("invalid xform struct");
		return -EINVAL;
	}
	if (rte_mempool_get(internals->mp, private_xform)) {
		ZSTD_RAW_PMD_ERR("Couldn't get object from session mempool");
		return -ENOMEM;
	}
	px = *((struct zstd_raw_priv_xform **)private_xform);
	if (zstd_raw_set_session_parameters(xform, &px->sess) < 0) {
		memset(px, 0, sizeof(*px));
		rte_mempool_put(internals->mp, px);
		return -EINVAL;
	}
	return 0;
}

static int
zstd_raw_pmd_private_xform_free(struct rte_compressdev *dev, void *private_xform)
{
	return zstd_raw_pmd_stream_free(dev, private_xform);
}

struct rte_compressdev_ops zstd_raw_pmd_ops = {
	.dev_configure		= zstd_raw_pmd_config,
	.dev_start		= zstd_raw_pmd_start,
	.dev_stop		= zstd_raw_pmd_stop,
	.dev_close		= zstd_raw_pmd_close,
	.stats_get		= zstd_raw_pmd_stats_get,
	.stats_reset		= zstd_raw_pmd_stats_reset,
	.dev_infos_get		= zstd_raw_pmd_info_get,
	.queue_pair_setup	= zstd_raw_pmd_qp_setup,
	.queue_pair_release	= zstd_raw_pmd_qp_release,
	.private_xform_create	= zstd_raw_pmd_private_xform_create,
	.private_xform_free	= zstd_raw_pmd_private_xform_free,
	.stream_create		= zstd_raw_pmd_stream_create,
	.stream_free		= zstd_raw_pmd_stream_free,
};

struct rte_compressdev_ops *rte_zstd_raw_pmd_ops = &zstd_raw_pmd_ops;
