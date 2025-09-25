/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_CRYPTO_ALGS_H_
#define _VIRTIO_CRYPTO_ALGS_H_

#include <rte_memory.h>

#include "virtio_comp.h"

/* FIXME: cassius designed virtio_comp_session, 
not copied, possibly not right 
*/
struct virtio_comp_session {
	uint64_t session_id;
	enum rte_comp_algorithm algo;
	uint8_t level;
	uint8_t window_size;
	uint32_t checksum_type;
	/*
	TODO:
	stateful compress may require ```
	struct {
		phys_addr_t dict_phys_addr;
		uint32_t dict_size;
		uint32_t total_in;
	} state; 
	```
	or other similar fields to store state
	*/
	struct virtio_pmd_ctrl ctrl;
};

#endif /* _VIRTIO_CRYPTO_ALGS_H_ */
