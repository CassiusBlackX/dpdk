/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */

#ifndef _VHOST_COMP_H_
#define _VHOST_COMP_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* pre-declare structs to avoid including full headers */
struct rte_mempool;
struct rte_comp_op;

#define VHOST_COMP_MBUF_POOL_SIZE		(8192)
#define VHOST_COMP_MAX_BURST_SIZE		(64)
#define VHOST_COMP_MAX_DATA_SIZE		(4096)
#define VHOST_COMP_SESSION_MAP_ENTRIES	(1024) /**< Max nb sessions */
/** max nb virtual queues in a burst for finalizing*/
#define VIRTIO_COMP_MAX_NUM_BURST_VQS		(64)
#define VHOST_COMP_MAX_IV_LEN			(32)
#define VHOST_COMP_MAX_N_DESC			(32)

enum rte_vhost_comp_zero_copy {
	RTE_VHOST_COMP_ZERO_COPY_DISABLE = 0,
	RTE_VHOST_COMP_ZERO_COPY_ENABLE = 1,
	RTE_VHOST_COMP_MAX_ZERO_COPY_OPTIONS
};

/**
 * Start vhost compress driver
 *
 * @param path
 *  The vhost-user socket file path
 * @return
 *  0 on success, -1 on failure
 */
int
rte_vhost_comp_driver_start(const char *path);

/**
 *  Create Vhost-compress instance
 *
 * @param vid
 *  The identifier of the vhost device.
 * @param compressdev_id
 *  The identifier of DPDK Compressdev, the same compressdev_id can be assigned to
 *  multiple Vhost-compress devices.
 * @param socket_id
 *  NUMA Socket ID to allocate resources on. *
 * @return
 *  0 if the Vhost Compress Instance is created successfully.
 *  Negative integer if otherwise
 */
int
rte_vhost_comp_create(int vid, uint8_t compressdev_id,
		int socket_id);

/**
 *  Free the Vhost-compress instance
 *
 * @param vid
 *  The identifier of the vhost device.
 * @return
 *  0 if the Vhost Compress Instance is created successfully.
 *  Negative integer if otherwise.
 */
int
rte_vhost_comp_free(int vid);

/**
 *  Enable or disable zero copy feature
 *
 * @param vid
 *  The identifier of the vhost device.
 * @param option
 *  Flag of zero copy feature.
 * @return
 *  0 if completed successfully.
 *  Negative integer if otherwise.
 */
int
rte_vhost_comp_set_zero_copy(int vid, enum rte_vhost_comp_zero_copy option);

/**
 * Fetch a number of vring descriptors from virt-queue and translate to DPDK
 * compress operations. After this function is executed, the user can enqueue
 * the processed ops to the target compressdev.
 *
 * @param vid
 *  The identifier of the vhost device.
 * @param qid
 *  Virtio queue index.
 * @param ops
 *  The address of an array of pointers to *rte_comp_op* structures that must
 *  be large enough to store *nb_ops* pointers in it.
 * @param nb_ops
 *  The maximum number of operations to be fetched and translated.
 * @return
 *  The number of fetched and processed vhost compress request operations.
 */
uint16_t
rte_vhost_comp_fetch_requests(int vid, uint32_t qid,
		struct rte_comp_op **ops, uint16_t nb_ops);
/**
 * Finalize the dequeued compress ops. After the translated compress ops are
 * dequeued from the compressdev, this function shall be called to write the
 * processed data back to the vring descriptor (if no-copy is turned off).
 *
 * @param ops
 *  The address of an array of *rte_comp_op* structure that was dequeued
 *  from compressdev.
 * @param nb_ops
 *  The number of operations contained in the array.
 * @callfds
 *  The callfd number(s) contained in this burst, this shall be an array with
 *  no less than VIRTIO_COMP_MAX_NUM_BURST_VQS elements.
 * @nb_callfds
 *  The number of call_fd numbers exist in the callfds.
 * @return
 *  The number of ops processed.
 */
uint16_t
rte_vhost_comp_finalize_requests(struct rte_comp_op **ops,
		uint16_t nb_ops, int *callfds, uint16_t *nb_callfds);

#ifdef __cplusplus
}
#endif

#endif /**< _VHOST_COMP_H_ */
