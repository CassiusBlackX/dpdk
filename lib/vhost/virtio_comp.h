/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_COMP_H
#define _VIRTIO_COMP_H

#include <stdint.h>
#define VIRTIO_COMP_SERVICE_STATEFUL 0
#define VIRTIO_COMP_SERVICE_STATELESS 1

#define VIRTIO_COMP_OPCODE(service, op)   (((service) << 8) | (op))

struct virtio_comp_ctrl_header {
#define VIRTIO_COMP_STATEFUL_CREATE_SESSION \
	   VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATEFUL, 0x02)
#define VIRTIO_COMP_STATEFUL_DESTROY_SESSION \
	   VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATEFUL, 0x03)
#define VIRTIO_COMP_STATELESS_CREATE_SESSION \
	   VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATELESS, 0x04)
#define VIRTIO_COMP_STATELESS_DESTROY_SESSION \
	   VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATELESS, 0x05)
	uint32_t opcode;
	uint32_t algo;
	uint32_t flag;
	/* data virtqueue id */
	uint32_t queue_id;
};

struct virtio_comp_deflate_session_para {
	uint32_t huffman;
};

struct virtio_comp_session_para {
#define	VIRTIO_COMP_ALGO_UNSPECIFIED 0
#define	VIRTIO_COMP_ALGO_NONE 1
#define	VIRTIO_COMP_ALGO_DEFLATE 2
#define	VIRTIO_COMP_ALGO_LZS 3
#define	VIRTIO_COMP_ALGO_LZ4 4
	uint32_t algo;
#define VIRTIO_COMP_OP_COMPRESS  1
#define VIRTIO_COMP_OP_DECOMPRESS  2
	/* compress or decompress */
	uint32_t op;

	int level;
	uint8_t window_size;
	uint32_t chksum;
	uint32_t hash_algo;
	union {
		struct virtio_comp_deflate_session_para deflate;
	} u;
};

struct virtio_comp_session_input {
	/* Device-writable part */
	uint64_t session_id;
	uint32_t status;
	uint32_t padding;
};

struct virtio_comp_session_req {
	struct virtio_comp_session_para para;
	uint8_t padding[32];
};

struct virtio_comp_stateless_create_session_req {
	struct virtio_comp_session_req req;
};

struct virtio_comp_stateful_create_session_req {
	struct virtio_comp_session_req req;
};

struct virtio_comp_destroy_session_req {
	/* Device-readable part */
	uint64_t session_id;
	uint8_t padding[48];
};

/* The request of the control virtqueue's packet */
struct virtio_comp_op_ctrl_req {
	struct virtio_comp_ctrl_header header;

	union {
		struct virtio_comp_stateful_create_session_req
			stateful_create_session;
		struct virtio_comp_stateless_create_session_req
			stateless_create_session;
		struct virtio_comp_destroy_session_req
			destroy_session;
	} u;
};

struct virtio_comp_op_header {
#define VIRTIO_COMP_STATEFUL_COMPRESS \
	VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATEFUL, 0x00)
#define VIRTIO_COMP_STATEFUL_DECOMPRESS \
	VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATEFUL, 0x01)
#define VIRTIO_COMP_STATELESS_COMPRESS \
	VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATELESS, 0x00)
#define VIRTIO_COMP_STATELESS_DECOMPRESS \
	VIRTIO_COMP_OPCODE(VIRTIO_COMP_SERVICE_STATELESS, 0x01)
	uint32_t opcode;
	/* algo should be service-specific algorithms */
	uint32_t algo;
	/* session_id should be service-specific algorithms */
	uint64_t session_id;
	/* control flag to control the request */
	uint32_t flag;
	uint32_t padding;
};

struct virtio_comp_data_para {
	/* length of source data */
	uint32_t src_data_len;
	/* length of dst data */
	uint32_t dst_data_len;
	uint32_t padding;
};

struct virtio_comp_stateful_data_req {
	struct virtio_comp_data_para para;
};

struct virtio_comp_decompress_para {
	uint32_t src_data_len;
	uint32_t dst_data_len;
};

struct virtio_comp_stateless_data_req {
	struct virtio_comp_data_para para;
};

/* The request of the data virtqueue's packet */
struct virtio_comp_op_data_req {
	struct virtio_comp_op_header header;

	union {
		struct virtio_comp_stateful_data_req  stateful_req;
		struct virtio_comp_stateless_data_req stateless_req;
	} u;
};

#define VIRTIO_COMP_OK        0
#define VIRTIO_COMP_ERR       1
#define VIRTIO_COMP_BADMSG    2
#define VIRTIO_COMP_NOTSUPP   3
#define VIRTIO_COMP_INVSESS   4 /* Invalid session id */
#define VIRTIO_COMP_NOSPC     5 /* no free session ID */
#define VIRTIO_COMP_KEY_REJECTED 6 /* Signature verification failed */

/* The accelerator hardware is ready */
#define VIRTIO_COMP_S_HW_READY  (1 << 0)

struct virtio_comp_config {
	/* See VIRTIO_COMP_OP_* above */
	uint32_t  status;

	/*
	 * Maximum number of data queue
	 */
	uint32_t  max_dataqueues;

	/*
	 * Specifies the services mask which the device support,
	 * see VIRTIO_COMP_SERVICE_* above
	 */
	uint32_t compress_services;

	/* Detailed algorithms mask */
	uint32_t cipher_algo_l;
	uint32_t cipher_algo_h;
	uint32_t hash_algo;
	uint32_t mac_algo_l;
	uint32_t mac_algo_h;
	uint32_t aead_algo;
	/* Maximum length of cipher key */
	uint32_t max_key_len;
	/* Maximum length of authenticated key */
	uint32_t max_auth_key_len;
	uint32_t akcipher_algo;
	/* Maximum size of each compress request's content */
	uint64_t max_size;
};

struct virtio_comp_inhdr {
	/* See VIRTIO_COMP_* above */
	uint8_t status;

	uint32_t consumed;
	uint32_t produced;
};
#endif /* _VIRTIO_COMP_H */
