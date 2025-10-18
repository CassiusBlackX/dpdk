/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_CRYPTODEV_H_
#define _VIRTIO_CRYPTODEV_H_

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

#define COMPRESSDEV_NAME_VIRTIO_PMD comp_virtio

#define NUM_ENTRY_VIRTIO_CRYPTO_OP 7

#define VIRTIO_CRYPTO_MAX_MSG_SIZE 512
#define VIRTIO_CRYPTO_MAX_SIGN_SIZE 1024

#define VIRTIO_CRYPTO_MAX_KEY_SIZE 256

#define VIRTIO_CRYPTO_MAX_CTRL_DATA 4096

/* TODO: determine what is needed in op_cookie */
struct virtio_comp_op_cookie {
	struct virtio_comp_op_data_req data_req;
	struct virtio_comp_inhdr inhdr;
	struct vring_desc desc[NUM_ENTRY_VIRTIO_CRYPTO_OP];
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

/* FIXME: copied from zlib_pmd_ops.c*/
struct virtio_comp_qp {
	struct rte_ring *processed_pkts;
	/**< Ring for placing process packets */
	struct rte_compressdev_stats qp_stats;
	/**< Queue pair statistics */
	uint16_t id;
	/**< Queue Pair Identifier */
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
	/**< Unique Queue Pair Name */
};

/* TODO: all the followings are copied from isal
*/
struct virtio_comp_private {
	struct rte_mempool *mp;
};

struct virtio_comp_priv_xform {
	enum rte_comp_xform_type type;
	union {
		struct rte_comp_compress_xform compress;
		struct rte_comp_decompress_xform decompress;
	};
	uint32_t level;
};


#endif /* _VIRTIO_CRYPTODEV_H_ */
