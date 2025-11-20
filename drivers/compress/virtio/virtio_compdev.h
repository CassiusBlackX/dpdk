/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_COMPDEV_H_
#define _VIRTIO_COMPDEV_H_

#include "virtio_comp.h"
#include "virtio_pci.h"
#include "virtio_ring.h"

/* Features desired/implemented by this driver. */
#define VIRTIO_COMP_PMD_GUEST_FEATURES (1ULL << VIRTIO_F_VERSION_1 | \
	1ULL << VIRTIO_F_IN_ORDER                | \
	1ULL << VIRTIO_F_RING_PACKED             | \
	1ULL << VIRTIO_F_NOTIFICATION_DATA       | \
	1ULL << VIRTIO_RING_F_INDIRECT_DESC      | \
	1ULL << VIRTIO_F_ORDER_PLATFORM)

#define COMPDEV_NAME_VIRTIO_PMD comp_virtio

#define NUM_ENTRY_VIRTIO_COMP_OP 7

#define VIRTIO_COMP_MAX_MSG_SIZE 512
#define VIRTIO_COMP_MAX_SIGN_SIZE 1024

#define VIRTIO_COMP_MAX_KEY_SIZE 256

#define VIRTIO_COMP_MAX_CTRL_DATA 4096

/* TODO: determine what is needed in op_cookie */
struct virtio_comp_op_cookie {
	struct virtio_comp_op_data_req data_req;
	struct virtio_comp_inhdr inhdr;
	struct vring_desc desc[NUM_ENTRY_VIRTIO_COMP_OP];
};

/*
 * Control queue function prototype
 */
void virtio_comp_ctrlq_start(struct rte_compressdev *dev);

/*
 * Data queue function prototype
 */
void virtio_comp_dataq_start(struct rte_compressdev *dev);

int virtio_comp_queue_setup(struct rte_compressdev *dev,
		int queue_type,
		uint16_t vtpci_queue_idx,
		uint16_t nb_desc,
		int socket_id,
		struct virtqueue **pvq);

void virtio_comp_queue_release(struct virtqueue *vq);

uint16_t virtio_comp_pkt_tx_burst(void *tx_queue,
		struct rte_comp_op **tx_pkts,
		uint16_t nb_pkts);

uint16_t virtio_comp_pkt_rx_burst(void *tx_queue,
		struct rte_comp_op **tx_pkts,
		uint16_t nb_pkts);

int comp_virtio_dev_init(struct rte_compressdev *compdev, uint64_t features,
		struct rte_pci_device *pci_dev);

/* TODO: all the followings are added by zal
*/

struct virtio_comp_priv_xform {
	enum rte_comp_xform_type type;
	union {
		struct rte_comp_compress_xform compress;
		struct rte_comp_decompress_xform decompress;
	};
	uint32_t level;
};

// enum virtio_comp_cmd_id {
// 	// TODO: sync with backend
// 	VIRTIO_COMP_CMD_STATELESS_CREATE_SESSION = 0,
// };

// struct virtio_comp_private {
// 	struct rte_compressdev *cdev;
// 	struct rte_mempool *xform_pool;
// };

#endif /* _VIRTIO_COMPDEV_H_ */
