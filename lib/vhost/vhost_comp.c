#include <eal_export.h>
#include <rte_comp.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_compressdev.h>

#include "iotlb.h"
#include "rte_vhost_comp.h"
#include "vhost.h"
#include "vhost_user.h"
#include "virtio_comp.h"

#define INHDR_LEN		(sizeof(struct virtio_comp_inhdr))
#define IV_OFFSET		(sizeof(struct rte_comp_op) + \
				sizeof(struct rte_compress_compress_op))

RTE_LOG_REGISTER_SUFFIX(vhost_comp_logtype, compress, INFO);
#define RTE_LOGTYPE_VHOST_COMP	vhost_comp_logtype

#define VC_LOG_ERR(...)	\
	RTE_LOG_LINE_PREFIX(ERR, VHOST_COMP, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#define VC_LOG_INFO(...) \
	RTE_LOG_LINE_PREFIX(INFO, VHOST_COMP, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#ifdef RTE_LIBRTE_VHOST_DEBUG
#define VC_LOG_DBG(...)	\
	RTE_LOG_LINE_PREFIX(DEBUG, VHOST_COMP, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)
#else
#define VC_LOG_DBG(...)
#endif

#define VIRTIO_COMP_FEATURES ((1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |	\
		(1ULL << VIRTIO_RING_F_INDIRECT_DESC) |			\
		(1ULL << VIRTIO_RING_F_EVENT_IDX) |			\
		(1ULL << VIRTIO_NET_F_CTRL_VQ) |			\
		(1ULL << VIRTIO_F_VERSION_1) |				\
		(1ULL << VHOST_USER_F_PROTOCOL_FEATURES))

#define IOVA_TO_VVA(t, dev, vq, a, l, p)				\
	((t)(uintptr_t)vhost_iova_to_vva(dev, vq, a, l, p))

/*
 * vhost_comp_desc is used to copy original vring_desc to the local buffer
 * before processing (except the next index). The copy result will be an
 * array of vhost_comp_desc elements that follows the sequence of original
 * vring_desc.next is arranged.
 */
#define vhost_comp_desc vring_desc

struct vhost_comp_session {
	union {
		void *private_xform;
		void *stream;
	};
	enum rte_comp_op_type type;
	enum rte_comp_xform_type xform_type;
};

static int
compress_algo_deflate_transform_stateless(VhostUserCompSessionParam *param, struct rte_comp_xform *xform)
{
	if (xform->type == RTE_COMP_COMPRESS) {
		xform->compress.algo = RTE_COMP_ALGO_DEFLATE;
		xform->compress.deflate.huffman = param->u.stateless.u.deflate.huffman;
	} else {
		xform->decompress.algo = RTE_COMP_ALGO_DEFLATE;
	}

	return 1;
}

static int
compress_algo_transform_stateless(VhostUserCompSessionParam *param, 
	struct rte_comp_xform *xform)
{
	int ret = 0;


	switch (param->u.stateless.algo) {
	case VIRTIO_COMP_ALGO_DEFLATE:
		ret = compress_algo_deflate_transform_stateless(param, xform);
		break;
	case VIRTIO_COMP_ALGO_LZS:
		break;
	// case VIRTIO_COMP_ALGO_LZ4:
	// 	*algo = RTE_COMP_ALGO_LZ4;
	// 	break;
	default:
		VC_LOG_ERR("unsupported compress algo");
		return -VIRTIO_COMP_BADMSG;
		break;
	}

	return ret;
}

/**
 * vhost_comp struct is used to maintain a number of virtio_compresss and
 * one DPDK compress device that deals with all compress workloads. It is declared
 * here and defined in vhost_comp.c
 */
struct __rte_cache_aligned vhost_comp {
	/** Used to lookup DPDK Compressdev Session based on VIRTIO compress
	 *  session ID.
	 */
	struct rte_hash *session_map;
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *sess_pool;
	struct rte_mempool *wb_pool;

	/** DPDK compressdev ID */
	uint8_t cid;
	uint16_t nb_qps;

	uint64_t last_session_id;

	uint64_t cache_stateless_session_id;
	void *cache_private_xform;
	uint64_t cache_stateful_session_id;
	void *cache_stream;
	/** socket id for the device */
	int socket_id;

	struct virtio_net *dev;

	uint8_t option;
};

struct vhost_comp_writeback_data {
	uint8_t *src;
	uint8_t *dst;
	uint64_t len;
	struct vhost_comp_writeback_data *next;
};

struct vhost_comp_data_req {
	struct vring_desc *head;
	struct virtio_net *dev;
	struct virtio_comp_inhdr *inhdr;
	struct vhost_virtqueue *vq;
	struct vhost_comp_writeback_data *wb;
	struct rte_mempool *wb_pool;
	uint16_t desc_idx;
	uint16_t len;
	uint16_t zero_copy;
};

static int
transform_comp_stateless_param(struct rte_comp_xform *xform,
		VhostUserCompSessionParam *param)
{
	int ret;

	// 1. compress or decompress
	if (param->u.stateless.dir == VIRTIO_COMP_OP_COMPRESS)
		xform->type = RTE_COMP_COMPRESS;
	else if (param->u.stateless.dir == VIRTIO_COMP_OP_DECOMPRESS)
		xform->type = RTE_COMP_DECOMPRESS;
	else {
		VC_LOG_ERR("Bad operation type");
		return -VIRTIO_COMP_BADMSG;
	}

	// 2. common params
	if (xform->type == RTE_COMP_COMPRESS) {
		xform->compress.chksum = param->u.stateless.chksum;
		xform->compress.level = param->u.stateless.level;
		xform->compress.hash_algo = param->u.stateless.hash_algo;
		xform->compress.window_size = param->u.stateless.window_size;
	} else if (xform->type == RTE_COMP_DECOMPRESS) {
		xform->decompress.chksum = param->u.stateless.chksum;
		xform->decompress.hash_algo = param->u.stateless.hash_algo;
		xform->decompress.window_size = param->u.stateless.window_size;
	}

	// 3. algo-related params
	ret = compress_algo_transform_stateless(param, xform);
	if (unlikely(ret < 0))
		return ret;

	return 0;
}

static void
vhost_comp_create_private_xform(struct vhost_comp *vcompress,
		VhostUserCompSessionParam *param)
{
	struct rte_comp_xform xform1 = {0};
	struct vhost_comp_session *vhost_session;
	void *private_xform;
	int ret;

	ret = transform_comp_stateless_param(&xform1, param);
	if (unlikely(ret)) {
		VC_LOG_ERR("Error transform session msg (%i)", ret);
		param->session_id = ret;
		return;
	}

	ret = rte_compressdev_private_xform_create(vcompress->cid,
		 &xform1, &private_xform);
	if (ret != 0) {
		VC_LOG_ERR("Failed to create session");
		param->session_id = -VIRTIO_COMP_ERR;
		return;
	}

	vhost_session = rte_zmalloc(NULL, sizeof(*vhost_session), 0);
	if (vhost_session == NULL) {
		VC_LOG_ERR("Failed to alloc session memory");
		goto error_exit;
	}

	vhost_session->type = RTE_COMP_OP_STATELESS;
	vhost_session->xform_type = RTE_COMP_COMPRESS;
	vhost_session->private_xform = private_xform;

	/* insert session to map */
	if ((rte_hash_add_key_data(vcompress->session_map,
		&vcompress->last_session_id, vhost_session) < 0)) {
		VC_LOG_ERR("Failed to insert session to hash table");
		goto error_exit;
	}

	VC_LOG_INFO("Session %"PRIu64" created for vdev %i.", vcompress->last_session_id, vcompress->dev->vid);
	VC_LOG_ERR("features %p %lu", vcompress->dev, vcompress->dev->features);

	param->session_id = vcompress->last_session_id;
	vcompress->last_session_id++;
	return;

error_exit:
	if (rte_compressdev_private_xform_free(vcompress->cid, private_xform) < 0)
		VC_LOG_ERR("Failed to free session");

	param->session_id = -VIRTIO_COMP_ERR;
	rte_free(vhost_session);
}

// static void
// vhost_comp_create_stream(struct vhost_comp *vcompress,
// 		VhostUserCompSessionParam *sess_param)
// {
	
// }

static void
vhost_comp_create_sess(struct vhost_comp *vcompress,
		VhostUserCompSessionParam *sess_param)
{
	if (sess_param->op_code == VIRTIO_COMP_STATELESS_CREATE_SESSION)
		vhost_comp_create_private_xform(vcompress, sess_param);
	// else
	// 	vhost_comp_create_compress_sess(vcompress, sess_param);
}

static int
vhost_comp_close_sess(struct vhost_comp *vcompress, uint64_t session_id)
{
	struct vhost_comp_session *vhost_session = NULL;
	uint64_t sess_id = session_id;
	int ret;

	ret = rte_hash_lookup_data(vcompress->session_map, &sess_id,
				(void **)&vhost_session);
	if (unlikely(ret < 0)) {
		VC_LOG_ERR("Failed to find session for id %"PRIu64".", session_id);
		return -VIRTIO_COMP_INVSESS;
	}

	if (vhost_session->type == RTE_COMP_OP_STATELESS) {
		if (rte_compressdev_private_xform_free(vcompress->cid,
			vhost_session->private_xform) < 0) {
			VC_LOG_DBG("Failed to free session");
			return -VIRTIO_COMP_ERR;
		}
	} 
	// else if (vhost_session->type == RTE_COMP_OP_STATEFUL) {
		// if (rte_compressdev_decompress_session_free(vcompress->cid,
		// 	vhost_session->decompress) < 0) {
		// 	VC_LOG_DBG("Failed to free session");
		// }
			// return -VIRTIO_COMP_ERR;
	// } 
	else {
		VC_LOG_ERR("Invalid session for id %"PRIu64".", session_id);
		return -VIRTIO_COMP_INVSESS;
	}

	if (rte_hash_del_key(vcompress->session_map, &sess_id) < 0) {
		VC_LOG_DBG("Failed to delete session from hash table.");
		return -VIRTIO_COMP_ERR;
	}

	// VC_LOG_INFO("Session %"PRIu64" deleted for vdev %i.", sess_id, vcompress->dev->vid);

	rte_free(vhost_session);
	return 0;
}

static enum rte_vhost_msg_result
vhost_comp_msg_post_handler(int vid, void *msg)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_comp *vcompress;
	struct vhu_msg_context *ctx = msg;
	enum rte_vhost_msg_result ret = RTE_VHOST_MSG_RESULT_OK;

	if (dev == NULL) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return RTE_VHOST_MSG_RESULT_ERR;
	}

	vcompress = dev->extern_data;
	if (vcompress == NULL) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return RTE_VHOST_MSG_RESULT_ERR;
	}

	vcompress->dev = dev;

	VC_LOG_ERR("request frontend %d", ctx->msg.request.frontend);
	switch (ctx->msg.request.frontend) {
	case VHOST_USER_COMPRESS_CREATE_SESS:
		vhost_comp_create_sess(vcompress,
				&ctx->msg.payload.comp_session);
		ctx->fd_num = 0;
		ret = RTE_VHOST_MSG_RESULT_REPLY;
		break;
	case VHOST_USER_COMPRESS_CLOSE_SESS:
		if (vhost_comp_close_sess(vcompress, ctx->msg.payload.u64))
			ret = RTE_VHOST_MSG_RESULT_ERR;
		break;
	default:
		ret = RTE_VHOST_MSG_RESULT_NOT_HANDLED;
		break;
	}

	return ret;
}

static __rte_always_inline struct vhost_comp_desc *
find_write_desc(struct vhost_comp_desc *head, struct vhost_comp_desc *desc,
		uint32_t max_n_descs)
{
	if (desc < head)
		return NULL;

	while (desc - head < (int)max_n_descs) {
		if (desc->flags & VRING_DESC_F_WRITE)
			return desc;
		desc++;
	}

	return NULL;
}

static __rte_always_inline struct virtio_comp_inhdr *
reach_inhdr(struct virtio_net *dev, struct vhost_virtqueue *vq,
		struct vhost_comp_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct virtio_comp_inhdr *inhdr;
	struct vhost_comp_desc *last = head + (max_n_descs - 1);
	uint64_t dlen = last->len;

	if (unlikely(dlen != sizeof(*inhdr)))
		return NULL;

	inhdr = IOVA_TO_VVA(struct virtio_comp_inhdr *, dev, vq,
			last->addr, &dlen, VHOST_ACCESS_WO);
	if (unlikely(!inhdr || dlen != last->len))
		return NULL;

	return inhdr;
}

static __rte_always_inline int
move_desc(struct vhost_comp_desc *head,
		struct vhost_comp_desc **cur_desc,
		uint32_t size, uint32_t max_n_descs)
{
	struct vhost_comp_desc *desc = *cur_desc;
	int left = size - desc->len;

	while (desc->flags & VRING_DESC_F_NEXT && left > 0 &&
			desc >= head &&
			desc - head < (int)max_n_descs) {
		desc++;
		left -= desc->len;
	}

	if (unlikely(left > 0))
		return -1;

	if (unlikely(head - desc == (int)max_n_descs))
		*cur_desc = NULL;
	else
		*cur_desc = desc + 1;

	return 0;
}

static __rte_always_inline void *
get_data_ptr(struct vhost_virtqueue *vq, struct vhost_comp_data_req *vc_req,
		struct vhost_comp_desc *cur_desc,
		uint8_t perm)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	void *data;
	uint64_t dlen = cur_desc->len;

	data = IOVA_TO_VVA(void *, vc_req->dev, vq,
			cur_desc->addr, &dlen, perm);
	if (unlikely(!data || dlen != cur_desc->len)) {
		VC_LOG_ERR("Failed to map object");
		return NULL;
	}

	return data;
}

static __rte_always_inline uint32_t
copy_data_from_desc(void *dst, struct virtio_net *dev,
	struct vhost_virtqueue *vq, struct vhost_comp_desc *desc, uint32_t size)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	uint64_t remain;
	uint64_t addr;

	remain = RTE_MIN(desc->len, size);
	addr = desc->addr;
	do {
		uint64_t len;
		void *src;

		len = remain;
		src = IOVA_TO_VVA(void *, dev, vq,
				addr, &len, VHOST_ACCESS_RO);
		if (unlikely(src == NULL || len == 0))
			return 0;

		rte_memcpy(dst, src, len);
		remain -= len;
		/* cast is needed for 32-bit architecture */
		dst = RTE_PTR_ADD(dst, (size_t)len);
		addr += len;
	} while (unlikely(remain != 0));

	return RTE_MIN(desc->len, size);
}


static __rte_always_inline int
copy_data(void *data, struct virtio_net *dev, struct vhost_virtqueue *vq,
	struct vhost_comp_desc *head, struct vhost_comp_desc **cur_desc,
	uint32_t size, uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_comp_desc *desc = *cur_desc;
	uint32_t left = size;

	do {
		uint32_t copied;

		copied = copy_data_from_desc(data, dev, vq, desc, left);
		if (copied == 0)
			return -1;
		left -= copied;
		data = RTE_PTR_ADD(data, copied);
	} while (left != 0 && ++desc < head + max_n_descs);

	if (unlikely(left != 0))
		return -1;

	if (unlikely(desc == head + max_n_descs))
		*cur_desc = NULL;
	else
		*cur_desc = desc + 1;

	return 0;
}

static void
write_back_data(struct vhost_comp_data_req *vc_req)
{
	struct vhost_comp_writeback_data *wb_data = vc_req->wb, *wb_last;

	while (wb_data) {
		rte_memcpy(wb_data->dst, wb_data->src, wb_data->len);
		memset(wb_data->src, 0, wb_data->len);
		wb_last = wb_data;
		wb_data = wb_data->next;
		rte_mempool_put(vc_req->wb_pool, wb_last);
	}
}

static void
free_wb_data(struct vhost_comp_writeback_data *wb_data,
		struct rte_mempool *mp)
{
	while (wb_data->next != NULL)
		free_wb_data(wb_data->next, mp);

	rte_mempool_put(mp, wb_data);
}

/**
 * The function will allocate a vhost_comp_writeback_data linked list
 * containing the source and destination data pointers for the write back
 * operation after dequeued from Compressdev PMD queues.
 *
 * @param vc_req
 *   The vhost compress data request pointer
 * @param cur_desc
 *   The pointer of the current in use descriptor pointer. The content of
 *   cur_desc is expected to be updated after the function execution.
 * @param end_wb_data
 *   The last write back data element to be returned. It is used only in compress
 *   and hash chain operations.
 * @param src
 *   The source data pointer
 * @param offset
 *   The offset to both source and destination data. For source data the offset
 *   is the number of bytes between src and start point of compress operation. For
 *   destination data the offset is the number of bytes from *cur_desc->addr
 *   to the point where the src will be written to.
 * @param write_back_len
 *   The size of the write back length.
 * @return
 *   The pointer to the start of the write back data linked list.
 */
static __rte_always_inline struct vhost_comp_writeback_data *
prepare_write_back_data(struct vhost_virtqueue *vq,
		struct vhost_comp_data_req *vc_req,
		struct vhost_comp_desc *head_desc,
		struct vhost_comp_desc **cur_desc,
		struct vhost_comp_writeback_data **end_wb_data,
		uint8_t *src,
		uint32_t offset,
		uint64_t write_back_len,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_comp_writeback_data *wb_data, *head;
	struct vhost_comp_desc *desc = *cur_desc;
	uint64_t dlen;
	uint8_t *dst;
	int ret;

	ret = rte_mempool_get(vc_req->wb_pool, (void **)&head);
	if (unlikely(ret < 0)) {
		VC_LOG_ERR("no memory");
		goto error_exit;
	}

	wb_data = head;

	if (likely(desc->len > offset)) {
		wb_data->src = src + offset;
		dlen = desc->len;
		dst = IOVA_TO_VVA(uint8_t *, vc_req->dev, vq,
			desc->addr, &dlen, VHOST_ACCESS_RW);
		if (unlikely(!dst || dlen != desc->len)) {
			VC_LOG_ERR("Failed to map descriptor");
			goto error_exit;
		}

		wb_data->dst = dst + offset;
		wb_data->len = RTE_MIN(dlen - offset, write_back_len);
		write_back_len -= wb_data->len;
		src += offset + wb_data->len;
		offset = 0;

		if (unlikely(write_back_len)) {
			ret = rte_mempool_get(vc_req->wb_pool,
					(void **)&(wb_data->next));
			if (unlikely(ret < 0)) {
				VC_LOG_ERR("no memory");
				goto error_exit;
			}

			wb_data = wb_data->next;
		} else
			wb_data->next = NULL;
	} else
		offset -= desc->len;

	while (write_back_len &&
			desc >= head_desc &&
			desc - head_desc < (int)max_n_descs) {
		desc++;
		if (unlikely(!(desc->flags & VRING_DESC_F_WRITE))) {
			VC_LOG_ERR("incorrect descriptor");
			goto error_exit;
		}

		if (desc->len <= offset) {
			offset -= desc->len;
			continue;
		}

		dlen = desc->len;
		dst = IOVA_TO_VVA(uint8_t *, vc_req->dev, vq,
				desc->addr, &dlen, VHOST_ACCESS_RW) + offset;
		if (unlikely(dst == NULL || dlen != desc->len)) {
			VC_LOG_ERR("Failed to map descriptor");
			goto error_exit;
		}

		wb_data->src = src + offset;
		wb_data->dst = dst;
		wb_data->len = RTE_MIN(desc->len - offset, write_back_len);
		write_back_len -= wb_data->len;
		src += wb_data->len;
		offset = 0;

		if (write_back_len) {
			ret = rte_mempool_get(vc_req->wb_pool,
					(void **)&(wb_data->next));
			if (unlikely(ret < 0)) {
				VC_LOG_ERR("no memory");
				goto error_exit;
			}

			wb_data = wb_data->next;
		} else
			wb_data->next = NULL;
	}

	if (unlikely(desc - head_desc == (int)max_n_descs))
		*cur_desc = NULL;
	else
		*cur_desc = desc + 1;

	*end_wb_data = wb_data;

	return head;

error_exit:
	if (head)
		free_wb_data(head, vc_req->wb_pool);

	return NULL;
}

static __rte_always_inline uint8_t
vhost_comp_check_stateless_request(struct virtio_comp_stateless_data_req *req)
{
	if (likely((req->para.src_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE)))
		return VIRTIO_COMP_OK;
	return VIRTIO_COMP_BADMSG;
}

static __rte_always_inline uint8_t
prepare_stateless_comp_op(struct vhost_comp *vcomp, struct rte_comp_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_comp_data_req *vc_req,
		struct virtio_comp_stateless_data_req *comp,
		struct vhost_comp_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_comp_desc *desc = head;
	struct vhost_comp_writeback_data *ewb = NULL;
	struct rte_mbuf *m_src = op->m_src, *m_dst = op->m_dst;
	uint8_t ret = vhost_comp_check_stateless_request(comp);

	if (unlikely(ret != VIRTIO_COMP_OK))
		goto error_exit;

	/* prepare */

	switch (vcomp->option) {
	case RTE_VHOST_COMP_ZERO_COPY_ENABLE:
	case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
		m_src->data_len = comp->para.src_data_len;
		rte_mbuf_iova_set(m_src,
				  gpa_to_hpa(vcomp->dev, desc->addr, comp->para.src_data_len));
		m_src->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
		if (unlikely(rte_mbuf_iova_get(m_src) == 0 || m_src->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMP_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, comp->para.src_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMP_ERR;
			goto error_exit;
		}

		break;
	// case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
	// 	vc_req->wb_pool = vcomp->wb_pool;
	// 	m_src->data_len = comp->para.src_data_len;
	// 	if (unlikely(copy_data(rte_pktmbuf_mtod(m_src, uint8_t *),
	// 			vcomp->dev, vq, head, &desc,
	// 			comp->para.src_data_len, max_n_descs) < 0)) {
	// 		VC_LOG_ERR("Incorrect virtio descriptor");
	// 		ret = VIRTIO_COMP_BADMSG;
	// 		goto error_exit;
	// 	}
	// 	break;
	default:
		ret = VIRTIO_COMP_BADMSG;
		goto error_exit;
	}

	/* dst */
	desc = find_write_desc(head, desc, max_n_descs);
	if (unlikely(!desc)) {
		VC_LOG_ERR("Cannot find write location");
		ret = VIRTIO_COMP_BADMSG;
		goto error_exit;
	}


	switch (vcomp->option) {
	case RTE_VHOST_COMP_ZERO_COPY_ENABLE:
	case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
		rte_mbuf_iova_set(m_dst,
				  gpa_to_hpa(vcomp->dev, desc->addr, comp->para.dst_data_len));
		m_dst->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(rte_mbuf_iova_get(m_dst) == 0 || m_dst->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMP_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, comp->para.dst_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMP_ERR;
			goto error_exit;
		}

		m_dst->data_len = comp->para.dst_data_len;
		break;
	// case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
	// 	vc_req->wb = prepare_write_back_data(vq, vc_req, head, &desc, &ewb,
	// 			rte_pktmbuf_mtod(m_src, uint8_t *), 0,
	// 			comp->para.dst_data_len, max_n_descs);
	// 	if (unlikely(vc_req->wb == NULL)) {
	// 		ret = VIRTIO_COMP_ERR;
	// 		goto error_exit;
	// 	}

		// break;
	default:
		ret = VIRTIO_COMP_BADMSG;
		goto error_exit;
	}

	/* src data */
	op->op_type = RTE_COMP_OP_STATELESS;
	op->src.offset = 0;
	op->src.length = comp->para.src_data_len;

	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_COMP_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_COMP_OK;
	vc_req->len = comp->para.dst_data_len + INHDR_LEN;

	//TODO: flush type 
	op->flush_flag = RTE_COMP_FLUSH_FINAL;

	return 0;

error_exit:
	if (vc_req->wb)
		free_wb_data(vc_req->wb, vc_req->wb_pool);

	vc_req->len = INHDR_LEN;
	return ret;
}
// static __rte_always_inline uint8_t
// prepare_stateful_comp_op(struct vhost_comp *vcompress, struct rte_comp_op *op,
// 		struct vhost_virtqueue *vq,
// 		struct vhost_comp_data_req *vc_req,
// 		struct virtio_comp_op_data_req *req,
// 		struct vhost_comp_desc *head,
// 		uint32_t max_n_descs)
// 	__rte_requires_shared_capability(&vq->iotlb_lock)
// {
// 	return 0;
// }

/**
 * Process on descriptor
 */
static __rte_always_inline int
vhost_comp_process_one_req(struct vhost_comp *vcompress,
		struct vhost_virtqueue *vq, struct rte_comp_op *op,
		struct vring_desc *head, struct vhost_comp_desc *descs,
		uint16_t desc_idx)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_comp_data_req *vc_req, *vc_req_out;
	void *private_xform;
	void *stream;
	struct vhost_comp_data_req data_req = {0};
	struct vhost_comp_session *vhost_session;
	struct vhost_comp_desc *desc = descs;
	uint32_t nb_descs = 0, max_n_descs, i;
	struct virtio_comp_op_data_req req;
	struct virtio_comp_inhdr *inhdr;
	struct vring_desc *src_desc;
	uint64_t session_id;
	uint64_t dlen;
	int err;

	vc_req = &data_req;
	vc_req->desc_idx = desc_idx;
	vc_req->dev = vcompress->dev;
	vc_req->vq = vq;

	if (unlikely((head->flags & VRING_DESC_F_INDIRECT) == 0)) {
		VC_LOG_ERR("Invalid descriptor");
		return -1;
	}

	dlen = head->len;
	src_desc = IOVA_TO_VVA(struct vring_desc *, vc_req->dev, vq,
			head->addr, &dlen, VHOST_ACCESS_RO);
	if (unlikely(!src_desc || dlen != head->len)) {
		VC_LOG_ERR("Invalid descriptor");
		return -1;
	}
	head = src_desc;

	nb_descs = max_n_descs = dlen / sizeof(struct vring_desc);
	if (unlikely(nb_descs > VHOST_COMP_MAX_N_DESC || nb_descs == 0)) {
		err = VIRTIO_COMP_ERR;
		VC_LOG_ERR("Cannot process num of descriptors %u", nb_descs);
		if (nb_descs > 0) {
			struct vring_desc *inhdr_desc = head;
			while (inhdr_desc->flags & VRING_DESC_F_NEXT) {
				if (inhdr_desc->next >= max_n_descs)
					return -1;
				inhdr_desc = &head[inhdr_desc->next];
			}
			if (inhdr_desc->len != sizeof(*inhdr))
				return -1;
			inhdr = IOVA_TO_VVA(struct virtio_comp_inhdr *, vc_req->dev,
					vq, inhdr_desc->addr, &dlen,
					VHOST_ACCESS_WO);
			if (unlikely(!inhdr || dlen != inhdr_desc->len))
				return -1;
			inhdr->status = VIRTIO_COMP_ERR;
			return -1;
		}
	}

	/* copy descriptors to local variable */
	for (i = 0; i < max_n_descs; i++) {
		desc->addr = src_desc->addr;
		desc->len = src_desc->len;
		desc->flags = src_desc->flags;
		desc++;
		if (unlikely((src_desc->flags & VRING_DESC_F_NEXT) == 0))
			break;
		if (unlikely(src_desc->next >= max_n_descs)) {
			err = VIRTIO_COMP_BADMSG;
			VC_LOG_ERR("Invalid descriptor");
			goto error_exit;
		}
		src_desc = &head[src_desc->next];
	}

	vc_req->head = head;
	vc_req->zero_copy = vcompress->option;

	nb_descs = desc - descs;
	desc = descs;

	if (unlikely(desc->len < sizeof(req))) {
		err = VIRTIO_COMP_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	if (unlikely(copy_data(&req, vcompress->dev, vq, descs, &desc, sizeof(req),
			max_n_descs) < 0)) {
		err = VIRTIO_COMP_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	/* desc is advanced by 1 now */
	max_n_descs -= 1;

	switch (req.header.opcode) {
	case VIRTIO_COMP_STATELESS_COMPRESS:
	case VIRTIO_COMP_STATELESS_DECOMPRESS:
		vc_req_out = rte_mbuf_to_priv(op->m_src);
		memcpy(vc_req_out, vc_req, sizeof(struct vhost_comp_data_req));
		session_id = req.header.session_id;

		/* one branch to avoid unnecessary table lookup */
		if (vcompress->cache_stateless_session_id != session_id) {
			err = rte_hash_lookup_data(vcompress->session_map,
					&session_id, (void **)&vhost_session);
			if (unlikely(err < 0)) {
				err = VIRTIO_COMP_ERR;
				VC_LOG_ERR("Failed to find session %"PRIu64, session_id);
				goto error_exit;
			}

			vcompress->cache_private_xform = vhost_session->private_xform;
			vcompress->cache_stateless_session_id = session_id;
		}

		private_xform = vcompress->cache_private_xform;
		op->op_type = RTE_COMP_OP_STATELESS;
		op->private_xform = private_xform;

		err = prepare_stateless_comp_op(vcompress, op, vq, vc_req_out,
				&req.u.stateless_req, desc,
				max_n_descs);

		if (unlikely(err != 0)) {
			VC_LOG_ERR("Failed to process stateless request");
			goto error_exit;
		}
		break;
	default:
		err = VIRTIO_COMP_ERR;
		VC_LOG_ERR("Unsupported symmetric compress request type %u", req.header.opcode);
		goto error_exit;
	}

	return 0;

error_exit:

	inhdr = reach_inhdr(vc_req->dev, vq, descs, max_n_descs);
	if (likely(inhdr != NULL))
		inhdr->status = (uint8_t)err;

	return -1;
}

static __rte_always_inline struct vhost_virtqueue *
vhost_comp_finalize_one_request(struct rte_comp_op *op,
		struct vhost_virtqueue *old_vq)
{
	struct rte_mbuf *m_src = NULL, *m_dst = NULL;
	struct vhost_comp_data_req *vc_req;
	struct vhost_virtqueue *vq;
	uint16_t used_idx, desc_idx;

	if (op->op_type == RTE_COMP_OP_STATELESS) {
		m_src = op->m_src;
		m_dst = op->m_dst;
		vc_req = rte_mbuf_to_priv(m_src);
	}
	// else if (op->type == RTE_COMP_OP_STATEFUL) {
	// 	vc_req = rte_compressdev_decompress_session_get_user_data(op->asym->session);
	// }
	else {
		VC_LOG_ERR("Invalid compress op type");
		return NULL;
	}

	if (unlikely(!vc_req)) {
		VC_LOG_ERR("Failed to retrieve vc_req");
		return NULL;
	}
	vq = vc_req->vq;
	used_idx = vc_req->desc_idx;

	if (old_vq && (vq != old_vq))
		return vq;

	if (unlikely(op->status != RTE_COMP_OP_STATUS_SUCCESS))
		vc_req->inhdr->status = VIRTIO_COMP_ERR;
	else {
		if (vc_req->zero_copy == 0)
			write_back_data(vc_req);
	}

	vc_req->inhdr->consumed = op->consumed;
	vc_req->inhdr->produced = op->produced;

	desc_idx = vq->avail->ring[used_idx];
	vq->used->ring[desc_idx].id = vq->avail->ring[desc_idx];
	vq->used->ring[desc_idx].len = vc_req->len;

	if (op->op_type == RTE_COMP_OP_STATELESS) {
		rte_mempool_put(m_src->pool, (void *)m_src);
		if (m_dst)
			rte_mempool_put(m_dst->pool, (void *)m_dst);
	}

	return vq;
}

static __rte_always_inline uint16_t
vhost_comp_complete_one_vm_requests(struct rte_comp_op **ops,
		uint16_t nb_ops, int *callfd)
{
	uint16_t processed = 1;
	struct vhost_virtqueue *vq, *tmp_vq;

	if (unlikely(nb_ops == 0))
		return 0;

	vq = vhost_comp_finalize_one_request(ops[0], NULL);
	if (unlikely(vq == NULL))
		return 0;
	tmp_vq = vq;

	while ((processed < nb_ops)) {
		tmp_vq = vhost_comp_finalize_one_request(ops[processed],
				tmp_vq);

		if (unlikely(vq != tmp_vq))
			break;

		processed++;
	}

	*callfd = vq->callfd;

	*(volatile uint16_t *)&vq->used->idx += processed;

	return processed;
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_driver_start)
int
rte_vhost_comp_driver_start(const char *path)
{
	uint64_t protocol_features;
	int ret;

	ret = rte_vhost_driver_set_features(path, VIRTIO_COMP_FEATURES);
	if (ret)
		return -1;

	ret = rte_vhost_driver_get_protocol_features(path, &protocol_features);
	if (ret)
		return -1;
	protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_CONFIG);
	ret = rte_vhost_driver_set_protocol_features(path, protocol_features);
	if (ret)
		return -1;

	return rte_vhost_driver_start(path);
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_create)
int
rte_vhost_comp_create(int vid, uint8_t compressdev_id,
		int socket_id)
{
	struct virtio_net *dev = get_device(vid);
	struct rte_hash_parameters params = {0};
	struct vhost_comp *vcompress;
	char name[128];
	int ret;

	if (!dev) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	vcompress = rte_zmalloc_socket(NULL, sizeof(*vcompress),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!vcompress) {
		VC_LOG_ERR("Insufficient memory");
		return -ENOMEM;
	}

	// vcompress->sess_pool = sess_pool;
	vcompress->cid = compressdev_id;
	vcompress->cache_stateful_session_id = UINT64_MAX;
	vcompress->cache_stateless_session_id = UINT64_MAX;
	vcompress->last_session_id = 1;
	vcompress->dev = dev;
	vcompress->option = RTE_VHOST_COMP_ZERO_COPY_DISABLE;

	snprintf(name, 127, "HASH_VHOST_CRYPT_%u", (uint32_t)vid);
	params.name = name;
	params.entries = VHOST_COMP_SESSION_MAP_ENTRIES;
	params.hash_func = rte_jhash;
	params.key_len = sizeof(uint64_t);
	params.socket_id = socket_id;
	vcompress->session_map = rte_hash_create(&params);
	if (!vcompress->session_map) {
		VC_LOG_ERR("Failed to create session map");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "MBUF_POOL_VM_%u", (uint32_t)vid);
	vcompress->mbuf_pool = rte_pktmbuf_pool_create(name,
			VHOST_COMP_MBUF_POOL_SIZE, 512,
			sizeof(struct vhost_comp_data_req),
			VHOST_COMP_MAX_DATA_SIZE + RTE_PKTMBUF_HEADROOM,
			rte_socket_id());
	if (!vcompress->mbuf_pool) {
		VC_LOG_ERR("Failed to create mbuf pool");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
	vcompress->wb_pool = rte_mempool_create(name,
			VHOST_COMP_MBUF_POOL_SIZE,
			sizeof(struct vhost_comp_writeback_data),
			128, 0, NULL, NULL, NULL, NULL,
			rte_socket_id(), 0);
	if (!vcompress->wb_pool) {
		VC_LOG_ERR("Failed to create mempool");
		ret = -ENOMEM;
		goto error_exit;
	}

	dev->extern_data = vcompress;
	dev->extern_ops.pre_msg_handle = NULL;
	dev->extern_ops.post_msg_handle = vhost_comp_msg_post_handler;

	return 0;

error_exit:
	rte_hash_free(vcompress->session_map);
	rte_mempool_free(vcompress->mbuf_pool);

	rte_free(vcompress);

	return ret;
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_free)
int
rte_vhost_comp_free(int vid)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_comp *vcompress;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	vcompress = dev->extern_data;
	if (unlikely(vcompress == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return -ENOENT;
	}

	rte_hash_free(vcompress->session_map);
	rte_mempool_free(vcompress->mbuf_pool);
	rte_mempool_free(vcompress->wb_pool);
	rte_free(vcompress);

	dev->extern_data = NULL;
	dev->extern_ops.pre_msg_handle = NULL;
	dev->extern_ops.post_msg_handle = NULL;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_set_zero_copy)
int
rte_vhost_comp_set_zero_copy(int vid, enum rte_vhost_comp_zero_copy option)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_comp *vcompress;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	if (unlikely((uint32_t)option >=
				RTE_VHOST_COMP_MAX_ZERO_COPY_OPTIONS)) {
		VC_LOG_ERR("Invalid option %i", option);
		return -EINVAL;
	}

	vcompress = (struct vhost_comp *)dev->extern_data;
	if (unlikely(vcompress == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return -ENOENT;
	}

	if (vcompress->option == (uint8_t)option)
		return 0;

	if (!(rte_mempool_full(vcompress->mbuf_pool)) ||
			!(rte_mempool_full(vcompress->wb_pool))) {
		VC_LOG_ERR("Cannot update zero copy as mempool is not full");
		return -EINVAL;
	}

	if (option == RTE_VHOST_COMP_ZERO_COPY_DISABLE) {
		char name[128];

		snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
		vcompress->wb_pool = rte_mempool_create(name,
				VHOST_COMP_MBUF_POOL_SIZE,
				sizeof(struct vhost_comp_writeback_data),
				128, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), 0);
		if (!vcompress->wb_pool) {
			VC_LOG_ERR("Failed to create mbuf pool");
			return -ENOMEM;
		}
	} else {
		rte_mempool_free(vcompress->wb_pool);
		vcompress->wb_pool = NULL;
	}

	vcompress->option = (uint8_t)option;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_fetch_requests)
uint16_t
rte_vhost_comp_fetch_requests(int vid, uint32_t qid,
		struct rte_comp_op **ops, uint16_t nb_ops)
{
	struct rte_mbuf *mbufs[VHOST_COMP_MAX_BURST_SIZE * 2];
	struct vhost_comp_desc descs[VHOST_COMP_MAX_N_DESC];
	struct virtio_net *dev = get_device(vid);
	struct vhost_comp *vcompress;
	struct vhost_virtqueue *vq;
	uint16_t avail_idx;
	uint16_t start_idx;
	uint16_t count;
	uint16_t i = 0;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return 0;
	}

	if (unlikely(qid >= VHOST_MAX_QUEUE_PAIRS)) {
		VC_LOG_ERR("Invalid qid %u", qid);
		return 0;
	}

	vcompress = (struct vhost_comp *)dev->extern_data;
	if (unlikely(vcompress == NULL)) {
		// VC_LOG_ERR("Cannot find required data, is it initialized?");
		return 0;
	}

	vq = dev->virtqueue[qid];

	if (unlikely(vq == NULL)) {
		// VC_LOG_ERR("Invalid virtqueue %u", qid);
		return 0;
	}

	if (unlikely(rte_rwlock_read_trylock(&vq->access_lock) != 0))
		return 0;

	vhost_user_iotlb_rd_lock(vq);
	if (unlikely(!vq->access_ok)) {
		VC_LOG_DBG("Virtqueue %u vrings not yet initialized", qid);
		goto out_unlock;
	}

	avail_idx = *((volatile uint16_t *)&vq->avail->idx);
	start_idx = vq->last_used_idx;
	count = avail_idx - start_idx;
	count = RTE_MIN(count, VHOST_COMP_MAX_BURST_SIZE);
	count = RTE_MIN(count, nb_ops);

	if (unlikely(count == 0))
		goto out_unlock;

	/* for zero copy, we need 2 empty mbufs for src and dst, otherwise
	 * we need only 1 mbuf as src and dst
	 */
	switch (vcompress->option) {
	case RTE_VHOST_COMP_ZERO_COPY_ENABLE:
	case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
		if (unlikely(rte_mempool_get_bulk(vcompress->mbuf_pool,
				(void **)mbufs, count * 2) < 0)) {
			VC_LOG_ERR("Insufficient memory");
			goto out_unlock;
		}

		for (i = 0; i < count; i++) {
			uint16_t used_idx = (start_idx + i) & (vq->size - 1);
			uint16_t desc_idx = vq->avail->ring[used_idx];
			struct vring_desc *head = &vq->desc[desc_idx];
			struct rte_comp_op *op = ops[i];

			op->m_src = mbufs[i * 2];
			op->m_dst = mbufs[i * 2 + 1];
			op->m_src->data_off = 0;
			op->m_dst->data_off = 0;

			if (unlikely(vhost_comp_process_one_req(vcompress, vq,
					op, head, descs, used_idx) < 0))
				break;
		}
		if (unlikely(i < count))
			rte_mempool_put_bulk(vcompress->mbuf_pool,
					(void **)&mbufs[i * 2],
					(count - i) * 2);

		break;

	// case RTE_VHOST_COMP_ZERO_COPY_DISABLE:
	// 	if (unlikely(rte_mempool_get_bulk(vcompress->mbuf_pool,
	// 			(void **)mbufs, count) < 0)) {
	// 		VC_LOG_ERR("Insufficient memory");
	// 		goto out_unlock;
	// 	}

	// 	for (i = 0; i < count; i++) {
	// 		uint16_t used_idx = (start_idx + i) & (vq->size - 1);
	// 		uint16_t desc_idx = vq->avail->ring[used_idx];
	// 		struct vring_desc *head = &vq->desc[desc_idx];
	// 		struct rte_comp_op *op = ops[i];

	// 		op->m_src = mbufs[i];
	// 		op->m_dst = NULL;
	// 		op->m_src->data_off = 0;

	// 		if (unlikely(vhost_comp_process_one_req(vcompress, vq,
	// 				op, head, descs, desc_idx) < 0))
	// 			break;
	// 	}

	// 	if (unlikely(i < count))
	// 		rte_mempool_put_bulk(vcompress->mbuf_pool,
	// 				(void **)&mbufs[i],
	// 				count - i);

	// 	break;

	}

	vq->last_used_idx += i;

out_unlock:
	vhost_user_iotlb_rd_unlock(vq);
	rte_rwlock_read_unlock(&vq->access_lock);

	return i;
}

RTE_EXPORT_SYMBOL(rte_vhost_comp_finalize_requests)
uint16_t
rte_vhost_comp_finalize_requests(struct rte_comp_op **ops,
		uint16_t nb_ops, int *callfds, uint16_t *nb_callfds)
{
	struct rte_comp_op **tmp_ops = ops;
	uint16_t count = 0, left = nb_ops;
	int callfd;
	uint16_t idx = 0;

	while (left) {
		count = vhost_comp_complete_one_vm_requests(tmp_ops, left,
				&callfd);
		if (unlikely(count == 0))
			break;

		tmp_ops = &tmp_ops[count];
		left -= count;

		callfds[idx++] = callfd;

		if (unlikely(idx >= VIRTIO_COMP_MAX_NUM_BURST_VQS)) {
			VC_LOG_ERR("Too many vqs");
			break;
		}
	}

	*nb_callfds = idx;

	return nb_ops - left;
}
