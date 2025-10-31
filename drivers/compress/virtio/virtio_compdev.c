/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>
#include <rte_eal.h>

#include "virtio_compdev.h"
#include "rte_comp.h"
#include "virtqueue.h"
#include "virtio_comp_algs.h"
#include "virtio_comp_capabilities.h"

static int virtio_comp_dev_configure(struct rte_compressdev *dev,
		struct rte_compressdev_config *config);
static int virtio_comp_dev_start(struct rte_compressdev *dev);
static void virtio_comp_dev_stop(struct rte_compressdev *dev);
static int virtio_comp_dev_close(struct rte_compressdev *dev);
static void virtio_comp_dev_info_get(struct rte_compressdev *dev,
		struct rte_compressdev_info *dev_info);
static void virtio_comp_dev_stats_get(struct rte_compressdev *dev,
		struct rte_compressdev_stats *stats);
static void virtio_comp_dev_stats_reset(struct rte_compressdev *dev);
static int virtio_comp_qp_setup(struct rte_compressdev *dev,
		uint16_t queue_pair_id,
		uint32_t max_inflight_ops,
		int socket_id);
static int virtio_comp_qp_release(struct rte_compressdev *dev,
		uint16_t queue_pair_id);
static void virtio_comp_dev_free_mbufs(struct rte_compressdev *dev);

static int virtio_comp_stream_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform, 
		void **stream);
static int virtio_comp_stream_free(struct rte_compressdev *dev,
		void *stream);
static int virtio_comp_private_xform_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform,
		void **private_xform);
static int virtio_comp_private_xform_free(struct rte_compressdev *dev,
		void *private_xform);

static int virtio_comp_set_priv_xform_parameters(struct virtio_comp_priv_xform *private_xform, const struct rte_comp_xform *xform);

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_virtio_comp_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_COMP_PCI_VENDORID,
				VIRTIO_COMP_PCI_DEVICEID) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct rte_compressdev_capabilities virtio_capabilities[] = {
	VIRTIO_COMP_DEFLATE_CAPABILITIES,
	RTE_COMP_END_OF_CAPABILITIES_LIST()
};

static struct rte_compressdev_ops virtio_comp_dev_ops;

void
virtio_comp_queue_release(struct virtqueue *vq)
{
	struct virtio_comp_hw *hw;

	PMD_INIT_FUNC_TRACE();

	if (vq) {
		hw = vq->hw;
		/* Select and deactivate the queue */
		VTPCI_OPS(hw)->del_queue(hw, vq);

		hw->vqs[vq->vq_queue_index] = NULL;
		rte_memzone_free(vq->mz);
		rte_mempool_free(vq->mpool);
		rte_free(vq);
	}
}

#define MPOOL_MAX_NAME_SZ 32

int
virtio_comp_queue_setup(struct rte_compressdev *dev,
		int queue_type,
		uint16_t vtpci_queue_idx,
		uint16_t nb_desc,
		int socket_id,
		struct virtqueue **pvq)
{
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	char mpool_name[MPOOL_MAX_NAME_SZ];
	unsigned int vq_size;
	struct virtio_comp_hw *hw = dev->data->dev_private;
	struct virtqueue *vq = NULL;
	uint32_t i = 0;
	uint32_t j;

	PMD_INIT_FUNC_TRACE();

	VIRTIO_CRYPTO_INIT_LOG_DBG("setting up queue: %u", vtpci_queue_idx);

	/*
	 * Read the virtqueue size from the Queue Size field
	 * Always power of 2 and if 0 virtqueue does not exist
	 */
	vq_size = VTPCI_OPS(hw)->get_queue_num(hw, vtpci_queue_idx);
	if (vq_size == 0) {
		VIRTIO_CRYPTO_INIT_LOG_ERR("virtqueue does not exist");
		return -EINVAL;
	}
	VIRTIO_CRYPTO_INIT_LOG_DBG("vq_size: %u", vq_size);

	if (!rte_is_power_of_2(vq_size)) {
		VIRTIO_CRYPTO_INIT_LOG_ERR("virtqueue size is not powerof 2");
		return -EINVAL;
	}

	switch (queue_type) {
		case VTCOMP_DATAQ:
			snprintf(vq_name, sizeof(vq_name), "dev%d_dataqueue%d",
				dev->data->dev_id, vtpci_queue_idx);
			snprintf(mpool_name, sizeof(mpool_name),
				"dev%d_dataqueue%d_mpool",
				dev->data->dev_id, vtpci_queue_idx);
			break;
		case VTCOMP_CTRLQ:
			snprintf(vq_name, sizeof(vq_name), "dev%d_controlqueue",
					dev->data->dev_id);
			snprintf(mpool_name, sizeof(mpool_name),
					"dev%d_controlqueue_mpool",
					dev->data->dev_id);
			break;
		default:
			VIRTIO_CRYPTO_INIT_LOG_ERR("Invalid queue type");
	}

	/*
	 * Using part of the vring entries is permitted, but the maximum
	 * is vq_size
	 */
	if (nb_desc == 0 || nb_desc > vq_size)
		nb_desc = vq_size;

	if (hw->vqs[vtpci_queue_idx])
		vq = hw->vqs[vtpci_queue_idx];
	else
		vq = virtcomp_queue_alloc(hw, vtpci_queue_idx, nb_desc,
				socket_id, vq_name);
	if (vq == NULL) {
		VIRTIO_CRYPTO_INIT_LOG_ERR("Can not allocate virtqueue");
		return -ENOMEM;
	}

	hw->vqs[vtpci_queue_idx] = vq;

	if (queue_type == VTCOMP_DATAQ) {
		/* pre-allocate a mempool and use it in the data plane to
		 * improve performance
		 */
		vq->mpool = rte_mempool_lookup(mpool_name);
		if (vq->mpool == NULL)
			vq->mpool = rte_mempool_create(mpool_name,
					nb_desc,
					sizeof(struct virtio_comp_op_cookie),
					RTE_CACHE_LINE_SIZE, 0,
					NULL, NULL, NULL, NULL, socket_id,
					0);
		if (!vq->mpool) {
			VIRTIO_CRYPTO_DRV_LOG_ERR("Virtio Comp PMD "
					"Cannot create mempool");
			goto mpool_create_err;
		}
		for (i = 0; i < nb_desc; i++) {
			vq->vq_descx[i].cookie =
				rte_zmalloc("comp PMD op cookie pointer",
					sizeof(struct virtio_comp_op_cookie),
					RTE_CACHE_LINE_SIZE);
			if (vq->vq_descx[i].cookie == NULL) {
				VIRTIO_CRYPTO_DRV_LOG_ERR("Failed to "
						"alloc mem for cookie");
				goto cookie_alloc_err;
			}
		}
	}

	*pvq = vq;

	return 0;

cookie_alloc_err:
	rte_mempool_free(vq->mpool);
	if (i != 0) {
		for (j = 0; j < i; j++)
			rte_free(vq->vq_descx[j].cookie);
	}
mpool_create_err:
	rte_free(vq);
	return -ENOMEM;
}

static void
virtio_comp_free_queues(struct rte_compressdev *dev)
{
	unsigned int i;
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	/* data queue release */
	for (i = 0; i < hw->max_dataqueues; i++) {
		virtio_comp_queue_release(dev->data->queue_pairs[i]);
		dev->data->queue_pairs[i] = NULL;
	}
}

static int
virtio_comp_dev_close(struct rte_compressdev *dev __rte_unused)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	/* control queue release */
	if (hw->cvq)
		virtio_comp_queue_release(virtcomp_cq_to_vq(hw->cvq));

	hw->cvq = NULL;
	return 0;
}

static int virtio_comp_stream_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform, 
		void **stream) {
	// TODO: not implement for stateful compress
}

static int virtio_comp_stream_free(struct rte_compressdev *dev,
		void *stream) {
	// TODO: not implement for stateful compress
}

static int virtio_comp_private_xform_create(struct rte_compressdev *dev,
		const struct rte_comp_xform *xform,
		void **private_xform) {
	int ret = 0;
	int dlen[2] = {0, 0};
	int dnum = 1;
	struct virtio_comp_hw *hw = dev->data->dev_private;
	struct virtio_comp_op_ctrl_req *ctrl_req;
	struct virtio_comp_session_input *input;
	struct virtio_pmd_ctrl *ctrl;
	struct virtio_comp_session *session = (struct virtio_comp_session *)private_xform;

	ctrl_req = &ctrl->hdr;
	ctrl_req->header.opcode = VIRTIO_COMP_STATELESS_CREATE_SESSION;
	ctrl_req->header.queue_id = 0;
	input = &ctrl->input;
	input->status = VIRTIO_COMP_ERR;
	input->session_id = ~0ULL;

	if (xform == NULL) {
		VIRTIO_CRYPTO_DRV_LOG_ERR("Invalid Xform struct");
		return -EINVAL;
	}

	if (rte_mempool_get(hw->xform_pool, private_xform)) {
		VIRTIO_CRYPTO_DRV_LOG_ERR(
			"Couldn't get object from private xform mempool");
		return -ENOMEM;
	}

	ret = virtio_comp_set_priv_xform_parameters(*private_xform, xform);
	if (ret != 0) {
		VIRTIO_CRYPTO_DRV_LOG_ERR(
			"Failed to configure private xform parameters");
		/* Return privatge xform to mempool */
		rte_mempool_put(hw->xform_pool, private_xform);
		return ret;
	}

	ret = virtio_comp_send_command(hw->cvq, ctrl, dlen, dnum);
	if (ret < 0) {
		VIRTIO_CRYPTO_SESSION_LOG_ERR("create session failed: %d", ret);
		goto error_out;
	}

	ctrl = hw->cvq->hdr_mz->addr;
	input = &ctrl->input;
	if (input->status != VIRTIO_COMP_OK) {
		VIRTIO_CRYPTO_SESSION_LOG_ERR("Something wrong on backend! "
				"status=%u, session_id=%" PRIu64 "",
				input->status, input->session_id);
		goto error_out;
	} else {
		session->session_id = input->session_id;
		VIRTIO_CRYPTO_SESSION_LOG_INFO("Create session successfully, "
				"session_id=%" PRIu64 "", input->session_id);
	}
	return 0;

error_out:
	return ret;
}

static int virtio_comp_private_xform_free(struct rte_compressdev *dev,
		void *private_xform) {
	struct virtio_comp_hw *hw = dev->data->dev_private;

	if (private_xform) {
		memset(private_xform, 0, sizeof(struct rte_comp_xform));
		rte_mempool_put(hw->xform_pool, private_xform);
	}
	return 0;
}



static void
virtio_comp_update_stats(struct rte_compressdev *dev,
		struct rte_compressdev_stats *stats)
{
	unsigned int i;
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	if (stats == NULL) {
		VIRTIO_CRYPTO_DRV_LOG_ERR("invalid pointer");
		return;
	}

	for (i = 0; i < hw->max_dataqueues; i++) {
		const struct virtqueue *data_queue
			= dev->data->queue_pairs[i];
		if (data_queue == NULL)
			continue;

		stats->enqueued_count += data_queue->packets_sent_total;
		stats->enqueue_err_count += data_queue->packets_sent_failed;

		stats->dequeued_count += data_queue->packets_received_total;
		stats->dequeue_err_count
			+= data_queue->packets_received_failed;
	}
}

static void
virtio_comp_dev_stats_get(struct rte_compressdev *dev,
		struct rte_compressdev_stats *stats)
{
	PMD_INIT_FUNC_TRACE();

	virtio_comp_update_stats(dev, stats);
}

static void
virtio_comp_dev_stats_reset(struct rte_compressdev *dev)
{
	unsigned int i;
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < hw->max_dataqueues; i++) {
		struct virtqueue *data_queue = dev->data->queue_pairs[i];
		if (data_queue == NULL)
			continue;

		data_queue->packets_sent_total = 0;
		data_queue->packets_sent_failed = 0;

		data_queue->packets_received_total = 0;
		data_queue->packets_received_failed = 0;
	}
}

static int
virtio_comp_qp_setup(struct rte_compressdev *dev, uint16_t qp_id,
		uint32_t max_inflight_ops, int socket_id)
{
	int ret;
	struct virtqueue *vq;

	PMD_INIT_FUNC_TRACE();

	/* if virtio dev is started, do not touch the virtqueues */
	if (dev->data->dev_started)
		return 0;

	ret = virtio_comp_queue_setup(dev, VTCOMP_DATAQ, qp_id,
			max_inflight_ops, socket_id, &vq);
	if (ret < 0) {
		VIRTIO_CRYPTO_INIT_LOG_ERR(
			"virtio comp data queue initialization failed");
		return ret;
	}

	dev->data->queue_pairs[qp_id] = vq;

	return 0;
}

static int
virtio_comp_qp_release(struct rte_compressdev *dev, uint16_t queue_pair_id)
{
	struct virtqueue *vq
		= (struct virtqueue *)dev->data->queue_pairs[queue_pair_id];

	PMD_INIT_FUNC_TRACE();

	if (vq == NULL) {
		VIRTIO_CRYPTO_DRV_LOG_DBG("vq already freed");
		return 0;
	}

	virtio_comp_queue_release(vq);
	dev->data->queue_pairs[queue_pair_id] = NULL;
	return 0;
}

static int
virtio_negotiate_features(struct virtio_comp_hw *hw, uint64_t req_features)
{
	uint64_t host_features;

	PMD_INIT_FUNC_TRACE();

	/* Prepare guest_features: feature that driver wants to support */
	VIRTIO_CRYPTO_INIT_LOG_DBG("guest_features before negotiate = %" PRIx64,
		req_features);

	/* Read device(host) feature bits */
	host_features = VTPCI_OPS(hw)->get_features(hw);
	VIRTIO_CRYPTO_INIT_LOG_DBG("host_features before negotiate = %" PRIx64,
		host_features);

	/*
	 * Negotiate features: Subset of device feature bits are written back
	 * guest feature bits.
	 */
	hw->guest_features = req_features;
	hw->guest_features = vtpci_compdev_negotiate_features(hw,
							host_features);
	VIRTIO_CRYPTO_INIT_LOG_DBG("features after negotiate = %" PRIx64,
		hw->guest_features);

	if (hw->modern) {
		if (!vtpci_with_feature(hw, VIRTIO_F_VERSION_1)) {
			VIRTIO_CRYPTO_INIT_LOG_ERR(
				"VIRTIO_F_VERSION_1 features is not enabled.");
			return -1;
		}
		vtpci_compdev_set_status(hw,
			VIRTIO_CONFIG_STATUS_FEATURES_OK);
		if (!(vtpci_compdev_get_status(hw) &
			VIRTIO_CONFIG_STATUS_FEATURES_OK)) {
			VIRTIO_CRYPTO_INIT_LOG_ERR("failed to set FEATURES_OK "
						"status!");
			return -1;
		}
	}

	hw->req_guest_features = req_features;

	return 0;
}

static void
virtio_control_queue_notify(struct virtqueue *vq, __rte_unused void *cookie)
{
	virtqueue_notify(vq);
}

static int
virtio_comp_init_queue(struct rte_compressdev *dev, uint16_t queue_idx)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;
	int queue_type = virtio_get_queue_type(hw, queue_idx);
	int numa_node = dev->device->numa_node;
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	unsigned int vq_size;
	struct virtqueue *vq;
	int ret;

	PMD_INIT_LOG(INFO, "setting up queue: %u on NUMA node %d",
			queue_idx, numa_node);

	/*
	 * Read the virtqueue size from the Queue Size field
	 * Always power of 2 and if 0 virtqueue does not exist
	 */
	vq_size = VTPCI_OPS(hw)->get_queue_num(hw, queue_idx);
	PMD_INIT_LOG(DEBUG, "vq_size: %u", vq_size);
	if (vq_size == 0) {
		PMD_INIT_LOG(ERR, "virtqueue does not exist");
		return -EINVAL;
	}

	if (!rte_is_power_of_2(vq_size)) {
		PMD_INIT_LOG(ERR, "split virtqueue size is not power of 2");
		return -EINVAL;
	}

	snprintf(vq_name, sizeof(vq_name), "dev%d_vq%d", dev->data->dev_id, queue_idx);

	vq = virtcomp_queue_alloc(hw, queue_idx, vq_size, numa_node, vq_name);
	if (!vq) {
		PMD_INIT_LOG(ERR, "virtqueue init failed");
		return -ENOMEM;
	}

	hw->vqs[queue_idx] = vq;

	if (queue_type == VTCOMP_CTRLQ) {
		hw->cvq = &vq->cq;
		vq->cq.notify_queue = &virtio_control_queue_notify;
	}

	if (VTPCI_OPS(hw)->setup_queue(hw, vq) < 0) {
		PMD_INIT_LOG(ERR, "setup_queue failed");
		ret = -EINVAL;
		goto clean_vq;
	}

	return 0;

clean_vq:
	if (queue_type == VTCOMP_CTRLQ)
		hw->cvq = NULL;
	virtcomp_queue_free(vq);
	hw->vqs[queue_idx] = NULL;

	return ret;
}

static int
virtio_comp_alloc_queues(struct rte_compressdev *dev)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = hw->max_dataqueues + 1;
	uint16_t i;
	int ret;

	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * nr_vq, 0);
	if (!hw->vqs) {
		PMD_INIT_LOG(ERR, "failed to allocate vqs");
		return -ENOMEM;
	}

	for (i = 0; i < nr_vq; i++) {
		ret = virtio_comp_init_queue(dev, i);
		if (ret < 0) {
			virtio_comp_free_queues(dev);
			return ret;
		}
	}

	return 0;
}

/* reset device and renegotiate features if needed */
static int
virtio_comp_init_device(struct rte_compressdev *compdev,
	uint64_t req_features)
{
	struct virtio_comp_hw *hw = compdev->data->dev_private;
	struct virtio_comp_config local_config;
	struct virtio_comp_config *config = &local_config;

	PMD_INIT_FUNC_TRACE();

	/* Reset the device although not necessary at startup */
	vtpci_compdev_reset(hw);

	/* Tell the host we've noticed this device. */
	vtpci_compdev_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);

	/* Tell the host we've known how to drive the device. */
	vtpci_compdev_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);
	if (virtio_negotiate_features(hw, req_features) < 0)
		return -1;

	/* Get status of the device */
	vtpci_read_compdev_config(hw,
		offsetof(struct virtio_comp_config, status),
		&config->status, sizeof(config->status));
	if (config->status != VIRTIO_COMP_S_HW_READY) {
		VIRTIO_CRYPTO_DRV_LOG_ERR("accelerator hardware is "
				"not ready");
		return -1;
	}

	/* Get number of data queues */
	vtpci_read_compdev_config(hw,
		offsetof(struct virtio_comp_config, max_dataqueues),
		&config->max_dataqueues,
		sizeof(config->max_dataqueues));
	hw->max_dataqueues = config->max_dataqueues;

	VIRTIO_CRYPTO_INIT_LOG_DBG("hw->max_dataqueues=%d",
		hw->max_dataqueues);

	return 0;
}

int
comp_virtio_dev_init(struct rte_compressdev *compdev, uint64_t features,
		struct rte_pci_device *pci_dev)
{
	struct virtio_comp_hw *hw;

	compdev->dev_ops = &virtio_comp_dev_ops;

	compdev->enqueue_burst = virtio_comp_pkt_tx_burst;
	compdev->dequeue_burst = virtio_comp_pkt_rx_burst;

	/* BUG: cassius guessed about the supported feature flags here */
	compdev->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED | 
		RTE_COMPDEV_FF_CPU_SSE |
		RTE_COMPDEV_FF_CPU_AVX |
		RTE_COMPDEV_FF_CPU_AVX2 |
		RTE_COMPDEV_FF_CPU_AVX512 |
		RTE_COMPDEV_FF_CPU_NEON |
		RTE_COMPDEV_FF_OP_DONE_IN_DEQUEUE;

	hw = compdev->data->dev_private;
	hw->dev_id = compdev->data->dev_id;
	hw->virtio_dev_capabilities = virtio_capabilities;

	if (pci_dev) {
		/* pci device init */
		VIRTIO_CRYPTO_INIT_LOG_DBG("dev %d vendorID=0x%x deviceID=0x%x",
			compdev->data->dev_id, pci_dev->id.vendor_id,
			pci_dev->id.device_id);

		if (vtpci_compdev_init(pci_dev, hw))
			return -1;
	}

	if (virtio_comp_init_device(compdev, features) < 0)
		return -1;

	return 0;
}

/*
 * This function is based on probe() function
 * It returns 0 on success.
 */
static int
comp_virtio_create(const char *name, struct rte_pci_device *pci_dev,
		struct rte_compressdev_pmd_init_params *init_params)
{
	struct rte_compressdev *compdev;

	PMD_INIT_FUNC_TRACE();

	compdev = rte_compressdev_pmd_create(name, &pci_dev->device,
		sizeof(struct virtio_comp_private),	 /* BUG: cassius add this struct here to be passed in */
		init_params);
	if (compdev == NULL)
		return -ENODEV;

	if (comp_virtio_dev_init(compdev, VIRTIO_COMP_PMD_GUEST_FEATURES,
			pci_dev) < 0)
		return -1;

	return 0;
}

static int
virtio_comp_dev_uninit(struct rte_compressdev *compdev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return -EPERM;

	if (compdev->data->dev_started) {
		virtio_comp_dev_stop(compdev);
		virtio_comp_dev_close(compdev);
	}

	compdev->dev_ops = NULL;
	compdev->enqueue_burst = NULL;
	compdev->dequeue_burst = NULL;

	rte_compressdev_pmd_release_device(compdev);

	VIRTIO_CRYPTO_DRV_LOG_INFO("dev_uninit completed");

	return 0;
}

static int
virtio_comp_dev_configure(struct rte_compressdev *compdev,
	struct rte_compressdev_config *config __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	if (virtio_comp_init_device(compdev,
			VIRTIO_COMP_PMD_GUEST_FEATURES) < 0)
		return -1;

	/* setup control queue
	 * [0, 1, ... ,(config->max_dataqueues - 1)] are data queues
	 * config->max_dataqueues is the control queue
	 */
	if (virtio_comp_alloc_queues(compdev) < 0) {
		VIRTIO_CRYPTO_DRV_LOG_ERR("failed to create virtqueues");
		return -1;
	}

	virtio_comp_ctrlq_start(compdev);

	return 0;
}

static void
virtio_comp_dev_stop(struct rte_compressdev *dev)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();
	VIRTIO_CRYPTO_DRV_LOG_DBG("virtio_dev_stop");

	vtpci_compdev_reset(hw);

	virtio_comp_dev_free_mbufs(dev);
	virtio_comp_free_queues(dev);

	dev->data->dev_started = 0;
}

static int
virtio_comp_dev_start(struct rte_compressdev *dev)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;

	if (dev->data->dev_started)
		return 0;

	/* Do final configuration before queue engine starts */
	virtio_comp_dataq_start(dev);
	vtpci_compdev_reinit_complete(hw);

	dev->data->dev_started = 1;

	return 0;
}

static void
virtio_comp_dev_free_mbufs(struct rte_compressdev *dev)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		VIRTIO_CRYPTO_INIT_LOG_DBG("Before freeing dataq[%d] used "
			"and unused buf", i);
		VIRTQUEUE_DUMP((struct virtqueue *)
			dev->data->queue_pairs[i]);

		VIRTIO_CRYPTO_INIT_LOG_DBG("queue_pairs[%d]=%p",
				i, dev->data->queue_pairs[i]);

		virtqueue_detatch_unused(dev->data->queue_pairs[i]);

		VIRTIO_CRYPTO_INIT_LOG_DBG("After freeing dataq[%d] used and "
					"unused buf", i);
		VIRTQUEUE_DUMP(
			(struct virtqueue *)dev->data->queue_pairs[i]);
	}
}

static void
virtio_comp_dev_info_get(struct rte_compressdev *dev,
		struct rte_compressdev_info *info)
{
	struct virtio_comp_hw *hw = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	if (info != NULL) {
		info->feature_flags = dev->feature_flags;
		info->max_nb_queue_pairs = hw->max_dataqueues;
		/* No limit of number of queue pairs */
		info->max_nb_queue_pairs = 0;
		info->capabilities = hw->virtio_dev_capabilities;
	}
}

static int
comp_virtio_pci_probe(
	struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	struct rte_compressdev_pmd_init_params init_params = {
		.name = "",
		.socket_id = pci_dev->device.numa_node,
	};
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];

	VIRTIO_CRYPTO_DRV_LOG_DBG("Found Crypto device at %02x:%02x.%x",
			pci_dev->addr.bus,
			pci_dev->addr.devid,
			pci_dev->addr.function);

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	return comp_virtio_create(name, pci_dev, &init_params);
}

static int
comp_virtio_pci_remove(
	struct rte_pci_device *pci_dev __rte_unused)
{
	struct rte_compressdev *compdev;
	char compdev_name[RTE_COMPRESSDEV_NAME_MAX_LEN];

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, compdev_name,
			sizeof(compdev_name));

	compdev = rte_compressdev_pmd_get_named_dev(compdev_name);
	if (compdev == NULL)
		return -ENODEV;

	return virtio_comp_dev_uninit(compdev);
}

static int 
virtio_comp_set_priv_xform_parameters(
		struct virtio_comp_priv_xform *private_xform, 
		const struct rte_comp_xform *xform) 
{
	if (xform == NULL) 
		return -EINVAL;
	
	int strategy, level, window_size;
	/* set compression private xform variables */
	switch (xform->type) {
		case RTE_COMP_COMPRESS:
			/* set private xform type - COMPRESS/DECOMPRESS */
			private_xform = RTE_COMP_COMPRESS;

			/* set private xform algorithm */
			switch (xform->compress.algo) {
				case RTE_COMP_ALGO_DEFLATE:
					private_xform->compress.algo = RTE_COMP_ALGO_DEFLATE;
					break;
				case RTE_COMP_ALGO_LZ4:
					private_xform->compress.algo = RTE_COMP_ALGO_LZ4;
					break;
				case RTE_COMP_ALGO_ZSTD:
					private_xform->compress.algo = RTE_COMP_ALGO_ZSTD;
					break;
				default:
					VIRTIO_CRYPTO_DRV_LOG_ERR("algorithm not supported!");
					return -ENOTSUP;
			}

			break;
		case RTE_COMP_DECOMPRESS:
			
			break;
		default:
			VIRTIO_CRYPTO_DRV_LOG_ERR("xform type not supported!");
			return -ENOTSUP;
	}
	
}


/*
 * dev_ops for virtio, bare necessities for basic operation
 */
static struct rte_compressdev_ops virtio_comp_dev_ops = {
	/* Device related operations */
	.dev_configure			 = virtio_comp_dev_configure,
	.dev_start			 = virtio_comp_dev_start,
	.dev_stop			 = virtio_comp_dev_stop,
	.dev_close			 = virtio_comp_dev_close,
	.dev_infos_get			 = virtio_comp_dev_info_get,

	.stats_get			 = virtio_comp_dev_stats_get,
	.stats_reset			 = virtio_comp_dev_stats_reset,

	.queue_pair_setup                = virtio_comp_qp_setup,
	.queue_pair_release              = virtio_comp_qp_release,

	/* Compress related operations */
	.stream_create		 			= virtio_comp_stream_create,
	.stream_free		 			= virtio_comp_stream_free,
	.private_xform_create			= virtio_comp_private_xform_create,	
	.private_xform_free			= virtio_comp_private_xform_free,
};

static struct rte_pci_driver rte_virtio_comp_driver = {
	.id_table = pci_id_virtio_comp_map,
	.drv_flags = 0,
	.probe = comp_virtio_pci_probe,
	.remove = comp_virtio_pci_remove
};

// BUG: there is no similar struct in `rte_compressdev_pmd.h`
// static struct cryptodev_driver virtio_crypto_drv;

RTE_PMD_REGISTER_PCI(COMPDEV_NAME_VIRTIO_PMD, rte_virtio_comp_driver);


RTE_LOG_REGISTER_SUFFIX(virtio_comp_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(virtio_comp_logtype_session, session, NOTICE);
RTE_LOG_REGISTER_SUFFIX(virtio_comp_logtype_rx, rx, NOTICE);
RTE_LOG_REGISTER_SUFFIX(virtio_comp_logtype_tx, tx, NOTICE);
RTE_LOG_REGISTER_SUFFIX(virtio_comp_logtype_driver, driver, NOTICE);
