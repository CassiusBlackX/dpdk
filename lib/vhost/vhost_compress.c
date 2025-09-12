#include <eal_export.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_compressdev.h>

#include "iotlb.h"
#include "rte_vhost_compress.h"
#include "vhost.h"
#include "vhost_user.h"
#include "virtio_compress.h"

#define INHDR_LEN		(sizeof(struct virtio_compress_inhdr))
#define IV_OFFSET		(sizeof(struct rte_compress_op) + \
				sizeof(struct rte_compress_sym_op))

RTE_LOG_REGISTER_SUFFIX(vhost_compress_logtype, compress, INFO);
#define RTE_LOGTYPE_VHOST_COMPRESS	vhost_compress_logtype

#define VC_LOG_ERR(...)	\
	RTE_LOG_LINE_PREFIX(ERR, VHOST_COMPRESS, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#define VC_LOG_INFO(...) \
	RTE_LOG_LINE_PREFIX(INFO, VHOST_COMPRESS, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#ifdef RTE_LIBRTE_VHOST_DEBUG
#define VC_LOG_DBG(...)	\
	RTE_LOG_LINE_PREFIX(DEBUG, VHOST_COMPRESS, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)
#else
#define VC_LOG_DBG(...)
#endif

#define VIRTIO_COMPRESS_FEATURES ((1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |	\
		(1ULL << VIRTIO_RING_F_INDIRECT_DESC) |			\
		(1ULL << VIRTIO_RING_F_EVENT_IDX) |			\
		(1ULL << VIRTIO_NET_F_CTRL_VQ) |			\
		(1ULL << VIRTIO_F_VERSION_1) |				\
		(1ULL << VHOST_USER_F_PROTOCOL_FEATURES))

#define IOVA_TO_VVA(t, dev, vq, a, l, p)				\
	((t)(uintptr_t)vhost_iova_to_vva(dev, vq, a, l, p))

/*
 * vhost_compress_desc is used to copy original vring_desc to the local buffer
 * before processing (except the next index). The copy result will be an
 * array of vhost_compress_desc elements that follows the sequence of original
 * vring_desc.next is arranged.
 */
#define vhost_compress_desc vring_desc

struct vhost_compress_session {
	union {
		struct rte_compressdev_asym_session *asym;
		struct rte_compressdev_sym_session *sym;
	};
	enum rte_compress_op_type type;
};

static int
cipher_algo_transform(uint32_t virtio_cipher_algo,
		enum rte_compress_cipher_algorithm *algo)
{
	switch (virtio_cipher_algo) {
	case VIRTIO_COMPRESS_CIPHER_AES_CBC:
		*algo = RTE_COMPRESS_CIPHER_AES_CBC;
		break;
	case VIRTIO_COMPRESS_CIPHER_AES_CTR:
		*algo = RTE_COMPRESS_CIPHER_AES_CTR;
		break;
	case VIRTIO_COMPRESS_CIPHER_DES_ECB:
		*algo = -VIRTIO_COMPRESS_NOTSUPP;
		break;
	case VIRTIO_COMPRESS_CIPHER_DES_CBC:
		*algo = RTE_COMPRESS_CIPHER_DES_CBC;
		break;
	case VIRTIO_COMPRESS_CIPHER_3DES_ECB:
		*algo = RTE_COMPRESS_CIPHER_3DES_ECB;
		break;
	case VIRTIO_COMPRESS_CIPHER_3DES_CBC:
		*algo = RTE_COMPRESS_CIPHER_3DES_CBC;
		break;
	case VIRTIO_COMPRESS_CIPHER_3DES_CTR:
		*algo = RTE_COMPRESS_CIPHER_3DES_CTR;
		break;
	case VIRTIO_COMPRESS_CIPHER_KASUMI_F8:
		*algo = RTE_COMPRESS_CIPHER_KASUMI_F8;
		break;
	case VIRTIO_COMPRESS_CIPHER_SNOW3G_UEA2:
		*algo = RTE_COMPRESS_CIPHER_SNOW3G_UEA2;
		break;
	case VIRTIO_COMPRESS_CIPHER_AES_F8:
		*algo = RTE_COMPRESS_CIPHER_AES_F8;
		break;
	case VIRTIO_COMPRESS_CIPHER_AES_XTS:
		*algo = RTE_COMPRESS_CIPHER_AES_XTS;
		break;
	case VIRTIO_COMPRESS_CIPHER_ZUC_EEA3:
		*algo = RTE_COMPRESS_CIPHER_ZUC_EEA3;
		break;
	default:
		return -VIRTIO_COMPRESS_BADMSG;
		break;
	}

	return 0;
}

static int
auth_algo_transform(uint32_t virtio_auth_algo,
		enum rte_compress_auth_algorithm *algo)
{
	switch (virtio_auth_algo) {
	case VIRTIO_COMPRESS_NO_MAC:
		*algo = RTE_COMPRESS_AUTH_NULL;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_MD5:
		*algo = RTE_COMPRESS_AUTH_MD5_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_SHA1:
		*algo = RTE_COMPRESS_AUTH_SHA1_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_SHA_224:
		*algo = RTE_COMPRESS_AUTH_SHA224_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_SHA_256:
		*algo = RTE_COMPRESS_AUTH_SHA256_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_SHA_384:
		*algo = RTE_COMPRESS_AUTH_SHA384_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_HMAC_SHA_512:
		*algo = RTE_COMPRESS_AUTH_SHA512_HMAC;
		break;
	case VIRTIO_COMPRESS_MAC_CMAC_AES:
		*algo = RTE_COMPRESS_AUTH_AES_CMAC;
		break;
	case VIRTIO_COMPRESS_MAC_KASUMI_F9:
		*algo = RTE_COMPRESS_AUTH_KASUMI_F9;
		break;
	case VIRTIO_COMPRESS_MAC_SNOW3G_UIA2:
		*algo = RTE_COMPRESS_AUTH_SNOW3G_UIA2;
		break;
	case VIRTIO_COMPRESS_MAC_GMAC_AES:
		*algo = RTE_COMPRESS_AUTH_AES_GMAC;
		break;
	case VIRTIO_COMPRESS_MAC_CBCMAC_AES:
		*algo = RTE_COMPRESS_AUTH_AES_CBC_MAC;
		break;
	case VIRTIO_COMPRESS_MAC_XCBC_AES:
		*algo = RTE_COMPRESS_AUTH_AES_XCBC_MAC;
		break;
	case VIRTIO_COMPRESS_MAC_CMAC_3DES:
	case VIRTIO_COMPRESS_MAC_GMAC_TWOFISH:
	case VIRTIO_COMPRESS_MAC_CBCMAC_KASUMI_F9:
		return -VIRTIO_COMPRESS_NOTSUPP;
	default:
		return -VIRTIO_COMPRESS_BADMSG;
	}

	return 0;
}

static int get_iv_len(enum rte_compress_cipher_algorithm algo)
{
	int len;

	switch (algo) {
	case RTE_COMPRESS_CIPHER_3DES_CBC:
		len = 8;
		break;
	case RTE_COMPRESS_CIPHER_3DES_CTR:
		len = 8;
		break;
	case RTE_COMPRESS_CIPHER_3DES_ECB:
		len = 8;
		break;
	case RTE_COMPRESS_CIPHER_AES_CBC:
		len = 16;
		break;

	/* TODO: add common algos */

	default:
		len = -1;
		break;
	}

	return len;
}

/**
 * vhost_compress struct is used to maintain a number of virtio_compresss and
 * one DPDK compress device that deals with all compress workloads. It is declared
 * here and defined in vhost_compress.c
 */
struct __rte_cache_aligned vhost_compress {
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

	uint64_t cache_sym_session_id;
	struct rte_compressdev_sym_session *cache_sym_session;
	uint64_t cache_asym_session_id;
	struct rte_compressdev_asym_session *cache_asym_session;
	/** socket id for the device */
	int socket_id;

	struct virtio_net *dev;

	uint8_t option;
};

struct vhost_compress_writeback_data {
	uint8_t *src;
	uint8_t *dst;
	uint64_t len;
	struct vhost_compress_writeback_data *next;
};

struct vhost_compress_data_req {
	struct vring_desc *head;
	struct virtio_net *dev;
	struct virtio_compress_inhdr *inhdr;
	struct vhost_virtqueue *vq;
	struct vhost_compress_writeback_data *wb;
	struct rte_mempool *wb_pool;
	uint16_t desc_idx;
	uint16_t len;
	uint16_t zero_copy;
};

static int
transform_cipher_param(struct rte_compress_sym_xform *xform,
		VhostUserCompressSymSessionParam *param)
{
	int ret;

	ret = cipher_algo_transform(param->cipher_algo, &xform->cipher.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->cipher_key_len > VHOST_USER_COMPRESS_MAX_CIPHER_KEY_LENGTH) {
		VC_LOG_DBG("Invalid cipher key length");
		return -VIRTIO_COMPRESS_BADMSG;
	}

	xform->type = RTE_COMPRESS_SYM_XFORM_CIPHER;
	xform->cipher.key.length = param->cipher_key_len;
	if (xform->cipher.key.length > 0)
		xform->cipher.key.data = param->cipher_key_buf;
	if (param->dir == VIRTIO_COMPRESS_OP_ENCRYPT)
		xform->cipher.op = RTE_COMPRESS_CIPHER_OP_ENCRYPT;
	else if (param->dir == VIRTIO_COMPRESS_OP_DECRYPT)
		xform->cipher.op = RTE_COMPRESS_CIPHER_OP_DECRYPT;
	else {
		VC_LOG_DBG("Bad operation type");
		return -VIRTIO_COMPRESS_BADMSG;
	}

	ret = get_iv_len(xform->cipher.algo);
	if (unlikely(ret < 0))
		return ret;
	xform->cipher.iv.length = (uint16_t)ret;
	xform->cipher.iv.offset = IV_OFFSET;
	return 0;
}

static int
transform_chain_param(struct rte_compress_sym_xform *xforms,
		VhostUserCompressSymSessionParam *param)
{
	struct rte_compress_sym_xform *xform_cipher, *xform_auth;
	int ret;

	switch (param->chaining_dir) {
	case VIRTIO_COMPRESS_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER:
		xform_auth = xforms;
		xform_cipher = xforms->next;
		xform_cipher->cipher.op = RTE_COMPRESS_CIPHER_OP_DECRYPT;
		xform_auth->auth.op = RTE_COMPRESS_AUTH_OP_VERIFY;
		break;
	case VIRTIO_COMPRESS_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH:
		xform_cipher = xforms;
		xform_auth = xforms->next;
		xform_cipher->cipher.op = RTE_COMPRESS_CIPHER_OP_ENCRYPT;
		xform_auth->auth.op = RTE_COMPRESS_AUTH_OP_GENERATE;
		break;
	default:
		return -VIRTIO_COMPRESS_BADMSG;
	}

	/* cipher */
	ret = cipher_algo_transform(param->cipher_algo,
			&xform_cipher->cipher.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->cipher_key_len > VHOST_USER_COMPRESS_MAX_CIPHER_KEY_LENGTH) {
		VC_LOG_DBG("Invalid cipher key length");
		return -VIRTIO_COMPRESS_BADMSG;
	}

	xform_cipher->type = RTE_COMPRESS_SYM_XFORM_CIPHER;
	xform_cipher->cipher.key.length = param->cipher_key_len;
	xform_cipher->cipher.key.data = param->cipher_key_buf;
	ret = get_iv_len(xform_cipher->cipher.algo);
	if (unlikely(ret < 0))
		return ret;
	xform_cipher->cipher.iv.length = (uint16_t)ret;
	xform_cipher->cipher.iv.offset = IV_OFFSET;

	/* auth */
	xform_auth->type = RTE_COMPRESS_SYM_XFORM_AUTH;
	ret = auth_algo_transform(param->hash_algo, &xform_auth->auth.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->auth_key_len > VHOST_USER_COMPRESS_MAX_HMAC_KEY_LENGTH) {
		VC_LOG_DBG("Invalid auth key length");
		return -VIRTIO_COMPRESS_BADMSG;
	}

	xform_auth->auth.digest_length = param->digest_len;
	xform_auth->auth.key.length = param->auth_key_len;
	xform_auth->auth.key.data = param->auth_key_buf;

	return 0;
}

static void
vhost_compress_create_sym_sess(struct vhost_compress *vcompress,
		VhostUserCompressSessionParam *sess_param)
{
	struct rte_compress_sym_xform xform1 = {0}, xform2 = {0};
	struct vhost_compress_session *vhost_session;
	struct rte_compressdev_sym_session *session;
	int ret;

	switch (sess_param->u.sym_sess.op_type) {
	case VIRTIO_COMPRESS_SYM_OP_NONE:
	case VIRTIO_COMPRESS_SYM_OP_CIPHER:
		ret = transform_cipher_param(&xform1, &sess_param->u.sym_sess);
		if (unlikely(ret)) {
			VC_LOG_ERR("Error transform session msg (%i)", ret);
			sess_param->session_id = ret;
			return;
		}
		break;
	case VIRTIO_COMPRESS_SYM_OP_ALGORITHM_CHAINING:
		if (unlikely(sess_param->u.sym_sess.hash_mode !=
				VIRTIO_COMPRESS_SYM_HASH_MODE_AUTH)) {
			sess_param->session_id = -VIRTIO_COMPRESS_NOTSUPP;
			VC_LOG_ERR("Error transform session message (%i)",
					-VIRTIO_COMPRESS_NOTSUPP);
			return;
		}

		xform1.next = &xform2;

		ret = transform_chain_param(&xform1, &sess_param->u.sym_sess);
		if (unlikely(ret)) {
			VC_LOG_ERR("Error transform session message (%i)", ret);
			sess_param->session_id = ret;
			return;
		}

		break;
	default:
		VC_LOG_ERR("Algorithm not yet supported");
		sess_param->session_id = -VIRTIO_COMPRESS_NOTSUPP;
		return;
	}

	session = rte_compressdev_sym_session_create(vcompress->cid, &xform1,
			vcompress->sess_pool);
	if (!session) {
		VC_LOG_ERR("Failed to create session");
		sess_param->session_id = -VIRTIO_COMPRESS_ERR;
		return;
	}

	vhost_session = rte_zmalloc(NULL, sizeof(*vhost_session), 0);
	if (vhost_session == NULL) {
		VC_LOG_ERR("Failed to alloc session memory");
		goto error_exit;
	}

	vhost_session->type = RTE_COMPRESS_OP_TYPE_SYMMETRIC;
	vhost_session->sym = session;

	/* insert session to map */
	if ((rte_hash_add_key_data(vcompress->session_map,
		&vcompress->last_session_id, vhost_session) < 0)) {
		VC_LOG_ERR("Failed to insert session to hash table");
		goto error_exit;
	}

	VC_LOG_INFO("Session %"PRIu64" created for vdev %i.",
			vcompress->last_session_id, vcompress->dev->vid);

	sess_param->session_id = vcompress->last_session_id;
	vcompress->last_session_id++;
	return;

error_exit:
	if (rte_compressdev_sym_session_free(vcompress->cid, session) < 0)
		VC_LOG_ERR("Failed to free session");

	sess_param->session_id = -VIRTIO_COMPRESS_ERR;
	rte_free(vhost_session);
}

static int
tlv_decode(uint8_t *tlv, uint8_t type, uint8_t **data, size_t *data_len)
{
	size_t tlen = -EINVAL, len;

	if (tlv[0] != type)
		return -EINVAL;

	if (tlv[1] == 0x82) {
		len = (tlv[2] << 8) | tlv[3];
		*data = &tlv[4];
		tlen = len + 4;
	} else if (tlv[1] == 0x81) {
		len = tlv[2];
		*data = &tlv[3];
		tlen = len + 3;
	} else {
		len = tlv[1];
		*data = &tlv[2];
		tlen = len + 2;
	}

	*data_len = len;
	return tlen;
}

static int
virtio_compress_asym_rsa_der_to_xform(uint8_t *der, size_t der_len,
		struct rte_compress_asym_xform *xform)
{
	uint8_t *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dp = NULL,
		*dq = NULL, *qinv = NULL, *v = NULL, *tlv;
	size_t nlen, elen, dlen, plen, qlen, dplen, dqlen, qinvlen, vlen;
	int len;

	RTE_SET_USED(der_len);

	if (der[0] != 0x30)
		return -EINVAL;

	if (der[1] == 0x82)
		tlv = &der[4];
	else if (der[1] == 0x81)
		tlv = &der[3];
	else
		return -EINVAL;

	len = tlv_decode(tlv, 0x02, &v, &vlen);
	if (len < 0 || v[0] != 0x0 || vlen != 1)
		return -EINVAL;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &n, &nlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &e, &elen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &d, &dlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &p, &plen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &q, &qlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &dp, &dplen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &dq, &dqlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &qinv, &qinvlen);
	if (len < 0)
		return len;

	xform->rsa.n.data = n;
	xform->rsa.n.length = nlen;
	xform->rsa.e.data = e;
	xform->rsa.e.length = elen;
	xform->rsa.d.data = d;
	xform->rsa.d.length = dlen;
	xform->rsa.qt.p.data = p;
	xform->rsa.qt.p.length = plen;
	xform->rsa.qt.q.data = q;
	xform->rsa.qt.q.length = qlen;
	xform->rsa.qt.dP.data = dp;
	xform->rsa.qt.dP.length = dplen;
	xform->rsa.qt.dQ.data = dq;
	xform->rsa.qt.dQ.length = dqlen;
	xform->rsa.qt.qInv.data = qinv;
	xform->rsa.qt.qInv.length = qinvlen;

	RTE_ASSERT(tlv + len == der + der_len);
	return 0;
}

static int
rsa_param_transform(struct rte_compress_asym_xform *xform,
		VhostUserCompressAsymSessionParam *param)
{
	int ret;

	ret = virtio_compress_asym_rsa_der_to_xform(param->key_buf, param->key_len, xform);
	if (ret < 0)
		return ret;

	switch (param->u.rsa.padding_algo) {
	case VIRTIO_COMPRESS_RSA_RAW_PADDING:
		xform->rsa.padding.type = RTE_COMPRESS_RSA_PADDING_NONE;
		break;
	case VIRTIO_COMPRESS_RSA_PKCS1_PADDING:
		xform->rsa.padding.type = RTE_COMPRESS_RSA_PADDING_PKCS1_5;
		break;
	default:
		VC_LOG_ERR("Unknown padding type");
		return -EINVAL;
	}

	xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;
	xform->xform_type = RTE_COMPRESS_ASYM_XFORM_RSA;
	return 0;
}

static void
vhost_compress_create_asym_sess(struct vhost_compress *vcompress,
		VhostUserCompressSessionParam *sess_param)
{
	struct rte_compressdev_asym_session *session = NULL;
	struct vhost_compress_session *vhost_session;
	struct rte_compress_asym_xform xform = {0};
	int ret;

	switch (sess_param->u.asym_sess.algo) {
	case VIRTIO_COMPRESS_AKCIPHER_RSA:
		ret = rsa_param_transform(&xform, &sess_param->u.asym_sess);
		if (unlikely(ret < 0)) {
			VC_LOG_ERR("Error transform session msg (%i)", ret);
			sess_param->session_id = ret;
			return;
		}
		break;
	default:
		VC_LOG_ERR("Invalid op algo");
		sess_param->session_id = -VIRTIO_COMPRESS_ERR;
		return;
	}

	ret = rte_compressdev_asym_session_create(vcompress->cid, &xform,
		vcompress->sess_pool, (void *)&session);
	if (session == NULL) {
		VC_LOG_ERR("Failed to create session");
		sess_param->session_id = -VIRTIO_COMPRESS_ERR;
		return;
	}

	vhost_session = rte_zmalloc(NULL, sizeof(*vhost_session), 0);
	if (vhost_session == NULL) {
		VC_LOG_ERR("Failed to alloc session memory");
		goto error_exit;
	}

	vhost_session->type = RTE_COMPRESS_OP_TYPE_ASYMMETRIC;
	vhost_session->asym = session;

	/* insert session to map */
	if ((rte_hash_add_key_data(vcompress->session_map,
			&vcompress->last_session_id, vhost_session) < 0)) {
		VC_LOG_ERR("Failed to insert session to hash table");
		goto error_exit;
	}

	VC_LOG_INFO("Session %"PRIu64" created for vdev %i.",
			vcompress->last_session_id, vcompress->dev->vid);

	sess_param->session_id = vcompress->last_session_id;
	vcompress->last_session_id++;
	return;

error_exit:
	if (rte_compressdev_asym_session_free(vcompress->cid, session) < 0)
		VC_LOG_ERR("Failed to free session");
	sess_param->session_id = -VIRTIO_COMPRESS_ERR;
	rte_free(vhost_session);
}

static void
vhost_compress_create_sess(struct vhost_compress *vcompress,
		VhostUserCompressSessionParam *sess_param)
{
	if (sess_param->op_code == VIRTIO_COMPRESS_AKCIPHER_CREATE_SESSION)
		vhost_compress_create_asym_sess(vcompress, sess_param);
	else
		vhost_compress_create_sym_sess(vcompress, sess_param);
}

static int
vhost_compress_close_sess(struct vhost_compress *vcompress, uint64_t session_id)
{
	struct vhost_compress_session *vhost_session = NULL;
	uint64_t sess_id = session_id;
	int ret;

	ret = rte_hash_lookup_data(vcompress->session_map, &sess_id,
				(void **)&vhost_session);
	if (unlikely(ret < 0)) {
		VC_LOG_ERR("Failed to find session for id %"PRIu64".", session_id);
		return -VIRTIO_COMPRESS_INVSESS;
	}

	if (vhost_session->type == RTE_COMPRESS_OP_TYPE_SYMMETRIC) {
		if (rte_compressdev_sym_session_free(vcompress->cid,
			vhost_session->sym) < 0) {
			VC_LOG_DBG("Failed to free session");
			return -VIRTIO_COMPRESS_ERR;
		}
	} else if (vhost_session->type == RTE_COMPRESS_OP_TYPE_ASYMMETRIC) {
		if (rte_compressdev_asym_session_free(vcompress->cid,
			vhost_session->asym) < 0) {
			VC_LOG_DBG("Failed to free session");
			return -VIRTIO_COMPRESS_ERR;
			}
	} else {
		VC_LOG_ERR("Invalid session for id %"PRIu64".", session_id);
		return -VIRTIO_COMPRESS_INVSESS;
	}

	if (rte_hash_del_key(vcompress->session_map, &sess_id) < 0) {
		VC_LOG_DBG("Failed to delete session from hash table.");
		return -VIRTIO_COMPRESS_ERR;
	}

	VC_LOG_INFO("Session %"PRIu64" deleted for vdev %i.", sess_id,
			vcompress->dev->vid);

	rte_free(vhost_session);
	return 0;
}

static enum rte_vhost_msg_result
vhost_compress_msg_post_handler(int vid, void *msg)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_compress *vcompress;
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

	switch (ctx->msg.request.frontend) {
	case VHOST_USER_COMPRESS_CREATE_SESS:
		vhost_compress_create_sess(vcompress,
				&ctx->msg.payload.compress_session);
		ctx->fd_num = 0;
		ret = RTE_VHOST_MSG_RESULT_REPLY;
		break;
	case VHOST_USER_COMPRESS_CLOSE_SESS:
		if (vhost_compress_close_sess(vcompress, ctx->msg.payload.u64))
			ret = RTE_VHOST_MSG_RESULT_ERR;
		break;
	default:
		ret = RTE_VHOST_MSG_RESULT_NOT_HANDLED;
		break;
	}

	return ret;
}

static __rte_always_inline struct vhost_compress_desc *
find_write_desc(struct vhost_compress_desc *head, struct vhost_compress_desc *desc,
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

static __rte_always_inline struct virtio_compress_inhdr *
reach_inhdr(struct virtio_net *dev, struct vhost_virtqueue *vq,
		struct vhost_compress_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct virtio_compress_inhdr *inhdr;
	struct vhost_compress_desc *last = head + (max_n_descs - 1);
	uint64_t dlen = last->len;

	if (unlikely(dlen != sizeof(*inhdr)))
		return NULL;

	inhdr = IOVA_TO_VVA(struct virtio_compress_inhdr *, dev, vq,
			last->addr, &dlen, VHOST_ACCESS_WO);
	if (unlikely(!inhdr || dlen != last->len))
		return NULL;

	return inhdr;
}

static __rte_always_inline int
move_desc(struct vhost_compress_desc *head,
		struct vhost_compress_desc **cur_desc,
		uint32_t size, uint32_t max_n_descs)
{
	struct vhost_compress_desc *desc = *cur_desc;
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
get_data_ptr(struct vhost_virtqueue *vq, struct vhost_compress_data_req *vc_req,
		struct vhost_compress_desc *cur_desc,
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
	struct vhost_virtqueue *vq, struct vhost_compress_desc *desc, uint32_t size)
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
	struct vhost_compress_desc *head, struct vhost_compress_desc **cur_desc,
	uint32_t size, uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_compress_desc *desc = *cur_desc;
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
write_back_data(struct vhost_compress_data_req *vc_req)
{
	struct vhost_compress_writeback_data *wb_data = vc_req->wb, *wb_last;

	while (wb_data) {
		rte_memcpy(wb_data->dst, wb_data->src, wb_data->len);
		memset(wb_data->src, 0, wb_data->len);
		wb_last = wb_data;
		wb_data = wb_data->next;
		rte_mempool_put(vc_req->wb_pool, wb_last);
	}
}

static void
free_wb_data(struct vhost_compress_writeback_data *wb_data,
		struct rte_mempool *mp)
{
	while (wb_data->next != NULL)
		free_wb_data(wb_data->next, mp);

	rte_mempool_put(mp, wb_data);
}

/**
 * The function will allocate a vhost_compress_writeback_data linked list
 * containing the source and destination data pointers for the write back
 * operation after dequeued from Compressdev PMD queues.
 *
 * @param vc_req
 *   The vhost compress data request pointer
 * @param cur_desc
 *   The pointer of the current in use descriptor pointer. The content of
 *   cur_desc is expected to be updated after the function execution.
 * @param end_wb_data
 *   The last write back data element to be returned. It is used only in cipher
 *   and hash chain operations.
 * @param src
 *   The source data pointer
 * @param offset
 *   The offset to both source and destination data. For source data the offset
 *   is the number of bytes between src and start point of cipher operation. For
 *   destination data the offset is the number of bytes from *cur_desc->addr
 *   to the point where the src will be written to.
 * @param write_back_len
 *   The size of the write back length.
 * @return
 *   The pointer to the start of the write back data linked list.
 */
static __rte_always_inline struct vhost_compress_writeback_data *
prepare_write_back_data(struct vhost_virtqueue *vq,
		struct vhost_compress_data_req *vc_req,
		struct vhost_compress_desc *head_desc,
		struct vhost_compress_desc **cur_desc,
		struct vhost_compress_writeback_data **end_wb_data,
		uint8_t *src,
		uint32_t offset,
		uint64_t write_back_len,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_compress_writeback_data *wb_data, *head;
	struct vhost_compress_desc *desc = *cur_desc;
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
vhost_compress_check_cipher_request(struct virtio_compress_cipher_data_req *req)
{
	if (likely((req->para.iv_len <= VHOST_COMPRESS_MAX_IV_LEN) &&
		(req->para.src_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE)))
		return VIRTIO_COMPRESS_OK;
	return VIRTIO_COMPRESS_BADMSG;
}

static __rte_always_inline uint8_t
prepare_sym_cipher_op(struct vhost_compress *vcompress, struct rte_compress_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_compress_data_req *vc_req,
		struct virtio_compress_cipher_data_req *cipher,
		struct vhost_compress_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_compress_desc *desc = head;
	struct vhost_compress_writeback_data *ewb = NULL;
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst = op->sym->m_dst;
	uint8_t *iv_data = rte_compress_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	uint8_t ret = vhost_compress_check_cipher_request(cipher);

	if (unlikely(ret != VIRTIO_COMPRESS_OK))
		goto error_exit;

	/* prepare */
	/* iv */
	if (unlikely(copy_data(iv_data, vcompress->dev, vq, head, &desc,
			cipher->para.iv_len, max_n_descs))) {
		VC_LOG_ERR("Incorrect virtio descriptor");
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
		m_src->data_len = cipher->para.src_data_len;
		rte_mbuf_iova_set(m_src,
				  gpa_to_hpa(vcompress->dev, desc->addr, cipher->para.src_data_len));
		m_src->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
		if (unlikely(rte_mbuf_iova_get(m_src) == 0 || m_src->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, cipher->para.src_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		break;
	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcompress->wb_pool;
		m_src->data_len = cipher->para.src_data_len;
		if (unlikely(copy_data(rte_pktmbuf_mtod(m_src, uint8_t *),
				vcompress->dev, vq, head, &desc,
				cipher->para.src_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_COMPRESS_BADMSG;
			goto error_exit;
		}
		break;
	default:
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	/* dst */
	desc = find_write_desc(head, desc, max_n_descs);
	if (unlikely(!desc)) {
		VC_LOG_ERR("Cannot find write location");
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
		rte_mbuf_iova_set(m_dst,
				  gpa_to_hpa(vcompress->dev, desc->addr, cipher->para.dst_data_len));
		m_dst->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(rte_mbuf_iova_get(m_dst) == 0 || m_dst->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, cipher->para.dst_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		m_dst->data_len = cipher->para.dst_data_len;
		break;
	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		vc_req->wb = prepare_write_back_data(vq, vc_req, head, &desc, &ewb,
				rte_pktmbuf_mtod(m_src, uint8_t *), 0,
				cipher->para.dst_data_len, max_n_descs);
		if (unlikely(vc_req->wb == NULL)) {
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		break;
	default:
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	/* src data */
	op->type = RTE_COMPRESS_OP_TYPE_SYMMETRIC;
	op->sess_type = RTE_COMPRESS_OP_WITH_SESSION;

	op->sym->cipher.data.offset = 0;
	op->sym->cipher.data.length = cipher->para.src_data_len;

	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_COMPRESS_OK;
	vc_req->len = cipher->para.dst_data_len + INHDR_LEN;

	return 0;

error_exit:
	if (vc_req->wb)
		free_wb_data(vc_req->wb, vc_req->wb_pool);

	vc_req->len = INHDR_LEN;
	return ret;
}

static __rte_always_inline uint8_t
vhost_compress_check_chain_request(struct virtio_compress_alg_chain_data_req *req)
{
	if (likely((req->para.iv_len <= VHOST_COMPRESS_MAX_IV_LEN) &&
		(req->para.src_data_len <= VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.cipher_start_src_offset <
			VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.len_to_cipher <= VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.hash_start_src_offset <
			VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.len_to_hash <= VHOST_COMPRESS_MAX_DATA_SIZE) &&
		(req->para.cipher_start_src_offset + req->para.len_to_cipher <=
			req->para.src_data_len) &&
		(req->para.hash_start_src_offset + req->para.len_to_hash <=
			req->para.src_data_len) &&
		(req->para.dst_data_len + req->para.hash_result_len <=
			VHOST_COMPRESS_MAX_DATA_SIZE)))
		return VIRTIO_COMPRESS_OK;
	return VIRTIO_COMPRESS_BADMSG;
}

static __rte_always_inline uint8_t
prepare_sym_chain_op(struct vhost_compress *vcompress, struct rte_compress_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_compress_data_req *vc_req,
		struct virtio_compress_alg_chain_data_req *chain,
		struct vhost_compress_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_compress_desc *desc = head, *digest_desc;
	struct vhost_compress_writeback_data *ewb = NULL, *ewb2 = NULL;
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst = op->sym->m_dst;
	uint8_t *iv_data = rte_compress_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	uint32_t digest_offset;
	void *digest_addr;
	uint8_t ret = vhost_compress_check_chain_request(chain);

	if (unlikely(ret != VIRTIO_COMPRESS_OK))
		goto error_exit;

	/* prepare */
	/* iv */
	if (unlikely(copy_data(iv_data, vcompress->dev, vq, head, &desc,
			chain->para.iv_len, max_n_descs) < 0)) {
		VC_LOG_ERR("Incorrect virtio descriptor");
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
		m_src->data_len = chain->para.src_data_len;
		m_dst->data_len = chain->para.dst_data_len;

		rte_mbuf_iova_set(m_src,
				  gpa_to_hpa(vcompress->dev, desc->addr, chain->para.src_data_len));
		m_src->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
		if (unlikely(rte_mbuf_iova_get(m_src) == 0 || m_src->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, chain->para.src_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}
		break;
	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcompress->wb_pool;
		m_src->data_len = chain->para.src_data_len;
		if (unlikely(copy_data(rte_pktmbuf_mtod(m_src, uint8_t *),
				vcompress->dev, vq, head, &desc,
				chain->para.src_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_COMPRESS_BADMSG;
			goto error_exit;
		}

		break;
	default:
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	/* dst */
	desc = find_write_desc(head, desc, max_n_descs);
	if (unlikely(!desc)) {
		VC_LOG_ERR("Cannot find write location");
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
		rte_mbuf_iova_set(m_dst,
				  gpa_to_hpa(vcompress->dev, desc->addr, chain->para.dst_data_len));
		m_dst->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(rte_mbuf_iova_get(m_dst) == 0 || m_dst->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(vc_req->head, &desc,
				chain->para.dst_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		op->sym->auth.digest.phys_addr = gpa_to_hpa(vcompress->dev,
				desc->addr, chain->para.hash_result_len);
		op->sym->auth.digest.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(op->sym->auth.digest.phys_addr == 0)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc,
				chain->para.hash_result_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		break;
	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		vc_req->wb = prepare_write_back_data(vq, vc_req, head, &desc, &ewb,
				rte_pktmbuf_mtod(m_src, uint8_t *),
				chain->para.cipher_start_src_offset,
				chain->para.dst_data_len -
					chain->para.cipher_start_src_offset,
				max_n_descs);
		if (unlikely(vc_req->wb == NULL)) {
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		digest_desc = desc;
		digest_offset = m_src->data_len;
		digest_addr = rte_pktmbuf_mtod_offset(m_src, void *,
				digest_offset);

		/** create a wb_data for digest */
		ewb->next = prepare_write_back_data(vq, vc_req, head, &desc,
				&ewb2, digest_addr, 0,
				chain->para.hash_result_len, max_n_descs);
		if (unlikely(ewb->next == NULL)) {
			ret = VIRTIO_COMPRESS_ERR;
			goto error_exit;
		}

		if (unlikely(copy_data(digest_addr, vcompress->dev, vq, head,
				&digest_desc, chain->para.hash_result_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_COMPRESS_BADMSG;
			goto error_exit;
		}

		op->sym->auth.digest.data = digest_addr;
		op->sym->auth.digest.phys_addr = rte_pktmbuf_iova_offset(m_src,
				digest_offset);
		break;
	default:
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	/* record inhdr */
	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_COMPRESS_OK;

	op->type = RTE_COMPRESS_OP_TYPE_SYMMETRIC;
	op->sess_type = RTE_COMPRESS_OP_WITH_SESSION;

	op->sym->cipher.data.offset = chain->para.cipher_start_src_offset;
	op->sym->cipher.data.length = chain->para.len_to_cipher;

	op->sym->auth.data.offset = chain->para.hash_start_src_offset;
	op->sym->auth.data.length = chain->para.len_to_hash;

	vc_req->len = chain->para.dst_data_len + chain->para.hash_result_len +
			INHDR_LEN;
	return 0;

error_exit:
	if (vc_req->wb)
		free_wb_data(vc_req->wb, vc_req->wb_pool);
	vc_req->len = INHDR_LEN;
	return ret;
}

static __rte_always_inline uint8_t
prepare_asym_rsa_op(struct vhost_compress *vcompress, struct rte_compress_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_compress_data_req *vc_req,
		struct virtio_compress_op_data_req *req,
		struct vhost_compress_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct rte_compress_rsa_op_param *rsa = &op->asym->rsa;
	struct vhost_compress_desc *desc = head;
	uint8_t ret = VIRTIO_COMPRESS_ERR;
	uint16_t wlen = 0;

	/* prepare */
	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcompress->wb_pool;
		if (req->header.opcode == VIRTIO_COMPRESS_AKCIPHER_SIGN) {
			rsa->op_type = RTE_COMPRESS_ASYM_OP_SIGN;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.src_data_len;
			rsa->sign.length = req->u.akcipher_req.para.dst_data_len;
			wlen = rsa->sign.length;
			desc = find_write_desc(head, desc, max_n_descs);
			if (unlikely(!desc)) {
				VC_LOG_ERR("Cannot find write location");
				ret = VIRTIO_COMPRESS_BADMSG;
				goto error_exit;
			}

			rsa->sign.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
			if (unlikely(rsa->sign.data == NULL)) {
				ret = VIRTIO_COMPRESS_ERR;
				goto error_exit;
			}

			desc += 1;
		} else if (req->header.opcode == VIRTIO_COMPRESS_AKCIPHER_VERIFY) {
			rsa->op_type = RTE_COMPRESS_ASYM_OP_VERIFY;
			rsa->sign.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->sign.length = req->u.akcipher_req.para.src_data_len;
			desc += 1;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.dst_data_len;
			desc += 1;
		} else if (req->header.opcode == VIRTIO_COMPRESS_AKCIPHER_ENCRYPT) {
			rsa->op_type = RTE_COMPRESS_ASYM_OP_ENCRYPT;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.src_data_len;
			rsa->cipher.length = req->u.akcipher_req.para.dst_data_len;
			wlen = rsa->cipher.length;
			desc = find_write_desc(head, desc, max_n_descs);
			if (unlikely(!desc)) {
				VC_LOG_ERR("Cannot find write location");
				ret = VIRTIO_COMPRESS_BADMSG;
				goto error_exit;
			}

			rsa->cipher.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
			if (unlikely(rsa->cipher.data == NULL)) {
				ret = VIRTIO_COMPRESS_ERR;
				goto error_exit;
			}

			desc += 1;
		} else if (req->header.opcode == VIRTIO_COMPRESS_AKCIPHER_DECRYPT) {
			rsa->op_type = RTE_COMPRESS_ASYM_OP_DECRYPT;
			rsa->cipher.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->cipher.length = req->u.akcipher_req.para.src_data_len;
			desc += 1;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.dst_data_len;
			desc += 1;
		} else {
			goto error_exit;
		}
		break;
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
	default:
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	op->type = RTE_COMPRESS_OP_TYPE_ASYMMETRIC;
	op->sess_type = RTE_COMPRESS_OP_WITH_SESSION;

	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_COMPRESS_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_COMPRESS_OK;
	vc_req->len = wlen + INHDR_LEN;
	return 0;
error_exit:
	if (vc_req->wb)
		free_wb_data(vc_req->wb, vc_req->wb_pool);

	vc_req->len = INHDR_LEN;
	return ret;
}

/**
 * Process on descriptor
 */
static __rte_always_inline int
vhost_compress_process_one_req(struct vhost_compress *vcompress,
		struct vhost_virtqueue *vq, struct rte_compress_op *op,
		struct vring_desc *head, struct vhost_compress_desc *descs,
		uint16_t desc_idx)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_compress_data_req *vc_req, *vc_req_out;
	struct rte_compressdev_asym_session *asym_session;
	struct rte_compressdev_sym_session *sym_session;
	struct vhost_compress_data_req data_req = {0};
	struct vhost_compress_session *vhost_session;
	struct vhost_compress_desc *desc = descs;
	uint32_t nb_descs = 0, max_n_descs, i;
	struct virtio_compress_op_data_req req;
	struct virtio_compress_inhdr *inhdr;
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
	if (unlikely(nb_descs > VHOST_COMPRESS_MAX_N_DESC || nb_descs == 0)) {
		err = VIRTIO_COMPRESS_ERR;
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
			inhdr = IOVA_TO_VVA(struct virtio_compress_inhdr *, vc_req->dev,
					vq, inhdr_desc->addr, &dlen,
					VHOST_ACCESS_WO);
			if (unlikely(!inhdr || dlen != inhdr_desc->len))
				return -1;
			inhdr->status = VIRTIO_COMPRESS_ERR;
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
			err = VIRTIO_COMPRESS_BADMSG;
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
		err = VIRTIO_COMPRESS_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	if (unlikely(copy_data(&req, vcompress->dev, vq, descs, &desc, sizeof(req),
			max_n_descs) < 0)) {
		err = VIRTIO_COMPRESS_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	/* desc is advanced by 1 now */
	max_n_descs -= 1;

	switch (req.header.opcode) {
	case VIRTIO_COMPRESS_CIPHER_ENCRYPT:
	case VIRTIO_COMPRESS_CIPHER_DECRYPT:
		vc_req_out = rte_mbuf_to_priv(op->sym->m_src);
		memcpy(vc_req_out, vc_req, sizeof(struct vhost_compress_data_req));
		session_id = req.header.session_id;

		/* one branch to avoid unnecessary table lookup */
		if (vcompress->cache_sym_session_id != session_id) {
			err = rte_hash_lookup_data(vcompress->session_map,
					&session_id, (void **)&vhost_session);
			if (unlikely(err < 0)) {
				err = VIRTIO_COMPRESS_ERR;
				VC_LOG_ERR("Failed to find session %"PRIu64,
						session_id);
				goto error_exit;
			}

			vcompress->cache_sym_session = vhost_session->sym;
			vcompress->cache_sym_session_id = session_id;
		}

		sym_session = vcompress->cache_sym_session;
		op->type = RTE_COMPRESS_OP_TYPE_SYMMETRIC;

		err = rte_compress_op_attach_sym_session(op, sym_session);
		if (unlikely(err < 0)) {
			err = VIRTIO_COMPRESS_ERR;
			VC_LOG_ERR("Failed to attach session to op");
			goto error_exit;
		}

		switch (req.u.sym_req.op_type) {
		case VIRTIO_COMPRESS_SYM_OP_NONE:
			err = VIRTIO_COMPRESS_NOTSUPP;
			break;
		case VIRTIO_COMPRESS_SYM_OP_CIPHER:
			err = prepare_sym_cipher_op(vcompress, op, vq, vc_req_out,
					&req.u.sym_req.u.cipher, desc,
					max_n_descs);
			break;
		case VIRTIO_COMPRESS_SYM_OP_ALGORITHM_CHAINING:
			err = prepare_sym_chain_op(vcompress, op, vq, vc_req_out,
					&req.u.sym_req.u.chain, desc,
					max_n_descs);
			break;
		}
		if (unlikely(err != 0)) {
			VC_LOG_ERR("Failed to process sym request");
			goto error_exit;
		}
		break;
	case VIRTIO_COMPRESS_AKCIPHER_SIGN:
	case VIRTIO_COMPRESS_AKCIPHER_VERIFY:
	case VIRTIO_COMPRESS_AKCIPHER_ENCRYPT:
	case VIRTIO_COMPRESS_AKCIPHER_DECRYPT:
		session_id = req.header.session_id;

		/* one branch to avoid unnecessary table lookup */
		if (vcompress->cache_asym_session_id != session_id) {
			err = rte_hash_lookup_data(vcompress->session_map,
					&session_id, (void **)&vhost_session);
			if (unlikely(err < 0)) {
				err = VIRTIO_COMPRESS_ERR;
				VC_LOG_ERR("Failed to find asym session %"PRIu64,
						   session_id);
				goto error_exit;
			}

			vcompress->cache_asym_session = vhost_session->asym;
			vcompress->cache_asym_session_id = session_id;
		}

		asym_session = vcompress->cache_asym_session;
		op->type = RTE_COMPRESS_OP_TYPE_ASYMMETRIC;

		err = rte_compress_op_attach_asym_session(op, asym_session);
		if (unlikely(err < 0)) {
			err = VIRTIO_COMPRESS_ERR;
			VC_LOG_ERR("Failed to attach asym session to op");
			goto error_exit;
		}

		vc_req_out = rte_compressdev_asym_session_get_user_data(asym_session);
		rte_memcpy(vc_req_out, vc_req, sizeof(struct vhost_compress_data_req));
		vc_req_out->wb = NULL;

		switch (req.header.algo) {
		case VIRTIO_COMPRESS_AKCIPHER_RSA:
			err = prepare_asym_rsa_op(vcompress, op, vq, vc_req_out,
					&req, desc, max_n_descs);
			break;
		}
		if (unlikely(err != 0)) {
			VC_LOG_ERR("Failed to process asym request");
			goto error_exit;
		}

		break;
	default:
		err = VIRTIO_COMPRESS_ERR;
		VC_LOG_ERR("Unsupported symmetric compress request type %u",
				req.header.opcode);
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
vhost_compress_finalize_one_request(struct rte_compress_op *op,
		struct vhost_virtqueue *old_vq)
{
	struct rte_mbuf *m_src = NULL, *m_dst = NULL;
	struct vhost_compress_data_req *vc_req;
	struct vhost_virtqueue *vq;
	uint16_t used_idx, desc_idx;

	if (op->type == RTE_COMPRESS_OP_TYPE_SYMMETRIC) {
		m_src = op->sym->m_src;
		m_dst = op->sym->m_dst;
		vc_req = rte_mbuf_to_priv(m_src);
	} else if (op->type == RTE_COMPRESS_OP_TYPE_ASYMMETRIC) {
		vc_req = rte_compressdev_asym_session_get_user_data(op->asym->session);
	} else {
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

	if (unlikely(op->status != RTE_COMPRESS_OP_STATUS_SUCCESS))
		vc_req->inhdr->status = VIRTIO_COMPRESS_ERR;
	else {
		if (vc_req->zero_copy == 0)
			write_back_data(vc_req);
	}

	desc_idx = vq->avail->ring[used_idx];
	vq->used->ring[desc_idx].id = vq->avail->ring[desc_idx];
	vq->used->ring[desc_idx].len = vc_req->len;

	if (op->type == RTE_COMPRESS_OP_TYPE_SYMMETRIC) {
		rte_mempool_put(m_src->pool, (void *)m_src);
		if (m_dst)
			rte_mempool_put(m_dst->pool, (void *)m_dst);
	}

	return vq;
}

static __rte_always_inline uint16_t
vhost_compress_complete_one_vm_requests(struct rte_compress_op **ops,
		uint16_t nb_ops, int *callfd)
{
	uint16_t processed = 1;
	struct vhost_virtqueue *vq, *tmp_vq;

	if (unlikely(nb_ops == 0))
		return 0;

	vq = vhost_compress_finalize_one_request(ops[0], NULL);
	if (unlikely(vq == NULL))
		return 0;
	tmp_vq = vq;

	while ((processed < nb_ops)) {
		tmp_vq = vhost_compress_finalize_one_request(ops[processed],
				tmp_vq);

		if (unlikely(vq != tmp_vq))
			break;

		processed++;
	}

	*callfd = vq->callfd;

	*(volatile uint16_t *)&vq->used->idx += processed;

	return processed;
}

RTE_EXPORT_SYMBOL(rte_vhost_compress_driver_start)
int
rte_vhost_compress_driver_start(const char *path)
{
	uint64_t protocol_features;
	int ret;

	ret = rte_vhost_driver_set_features(path, VIRTIO_COMPRESS_FEATURES);
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

RTE_EXPORT_SYMBOL(rte_vhost_compress_create)
int
rte_vhost_compress_create(int vid, uint8_t compressdev_id,
		struct rte_mempool *sess_pool,
		int socket_id)
{
	struct virtio_net *dev = get_device(vid);
	struct rte_hash_parameters params = {0};
	struct vhost_compress *vcompress;
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

	vcompress->sess_pool = sess_pool;
	vcompress->cid = compressdev_id;
	vcompress->cache_sym_session_id = UINT64_MAX;
	vcompress->cache_asym_session_id = UINT64_MAX;
	vcompress->last_session_id = 1;
	vcompress->dev = dev;
	vcompress->option = RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE;

	snprintf(name, 127, "HASH_VHOST_CRYPT_%u", (uint32_t)vid);
	params.name = name;
	params.entries = VHOST_COMPRESS_SESSION_MAP_ENTRIES;
	params.hash_func = rte_jhash;
	params.key_len = sizeof(uint64_t);
	params.socket_id = socket_id;
	vcompress->session_map = rte_hash_create(&params);
	if (!vcompress->session_map) {
		VC_LOG_ERR("Failed to creath session map");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "MBUF_POOL_VM_%u", (uint32_t)vid);
	vcompress->mbuf_pool = rte_pktmbuf_pool_create(name,
			VHOST_COMPRESS_MBUF_POOL_SIZE, 512,
			sizeof(struct vhost_compress_data_req),
			VHOST_COMPRESS_MAX_DATA_SIZE + RTE_PKTMBUF_HEADROOM,
			rte_socket_id());
	if (!vcompress->mbuf_pool) {
		VC_LOG_ERR("Failed to creath mbuf pool");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
	vcompress->wb_pool = rte_mempool_create(name,
			VHOST_COMPRESS_MBUF_POOL_SIZE,
			sizeof(struct vhost_compress_writeback_data),
			128, 0, NULL, NULL, NULL, NULL,
			rte_socket_id(), 0);
	if (!vcompress->wb_pool) {
		VC_LOG_ERR("Failed to creath mempool");
		ret = -ENOMEM;
		goto error_exit;
	}

	dev->extern_data = vcompress;
	dev->extern_ops.pre_msg_handle = NULL;
	dev->extern_ops.post_msg_handle = vhost_compress_msg_post_handler;

	return 0;

error_exit:
	rte_hash_free(vcompress->session_map);
	rte_mempool_free(vcompress->mbuf_pool);

	rte_free(vcompress);

	return ret;
}

RTE_EXPORT_SYMBOL(rte_vhost_compress_free)
int
rte_vhost_compress_free(int vid)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_compress *vcompress;

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

RTE_EXPORT_SYMBOL(rte_vhost_compress_set_zero_copy)
int
rte_vhost_compress_set_zero_copy(int vid, enum rte_vhost_compress_zero_copy option)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_compress *vcompress;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	if (unlikely((uint32_t)option >=
				RTE_VHOST_COMPRESS_MAX_ZERO_COPY_OPTIONS)) {
		VC_LOG_ERR("Invalid option %i", option);
		return -EINVAL;
	}

	vcompress = (struct vhost_compress *)dev->extern_data;
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

	if (option == RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE) {
		char name[128];

		snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
		vcompress->wb_pool = rte_mempool_create(name,
				VHOST_COMPRESS_MBUF_POOL_SIZE,
				sizeof(struct vhost_compress_writeback_data),
				128, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), 0);
		if (!vcompress->wb_pool) {
			VC_LOG_ERR("Failed to creath mbuf pool");
			return -ENOMEM;
		}
	} else {
		rte_mempool_free(vcompress->wb_pool);
		vcompress->wb_pool = NULL;
	}

	vcompress->option = (uint8_t)option;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vhost_compress_fetch_requests)
uint16_t
rte_vhost_compress_fetch_requests(int vid, uint32_t qid,
		struct rte_compress_op **ops, uint16_t nb_ops)
{
	struct rte_mbuf *mbufs[VHOST_COMPRESS_MAX_BURST_SIZE * 2];
	struct vhost_compress_desc descs[VHOST_COMPRESS_MAX_N_DESC];
	struct virtio_net *dev = get_device(vid);
	struct vhost_compress *vcompress;
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

	vcompress = (struct vhost_compress *)dev->extern_data;
	if (unlikely(vcompress == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return 0;
	}

	vq = dev->virtqueue[qid];

	if (unlikely(vq == NULL)) {
		VC_LOG_ERR("Invalid virtqueue %u", qid);
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
	count = RTE_MIN(count, VHOST_COMPRESS_MAX_BURST_SIZE);
	count = RTE_MIN(count, nb_ops);

	if (unlikely(count == 0))
		goto out_unlock;

	/* for zero copy, we need 2 empty mbufs for src and dst, otherwise
	 * we need only 1 mbuf as src and dst
	 */
	switch (vcompress->option) {
	case RTE_VHOST_COMPRESS_ZERO_COPY_ENABLE:
		if (unlikely(rte_mempool_get_bulk(vcompress->mbuf_pool,
				(void **)mbufs, count * 2) < 0)) {
			VC_LOG_ERR("Insufficient memory");
			goto out_unlock;
		}

		for (i = 0; i < count; i++) {
			uint16_t used_idx = (start_idx + i) & (vq->size - 1);
			uint16_t desc_idx = vq->avail->ring[used_idx];
			struct vring_desc *head = &vq->desc[desc_idx];
			struct rte_compress_op *op = ops[i];

			op->sym->m_src = mbufs[i * 2];
			op->sym->m_dst = mbufs[i * 2 + 1];
			op->sym->m_src->data_off = 0;
			op->sym->m_dst->data_off = 0;

			if (unlikely(vhost_compress_process_one_req(vcompress, vq,
					op, head, descs, used_idx) < 0))
				break;
		}

		if (unlikely(i < count))
			rte_mempool_put_bulk(vcompress->mbuf_pool,
					(void **)&mbufs[i * 2],
					(count - i) * 2);

		break;

	case RTE_VHOST_COMPRESS_ZERO_COPY_DISABLE:
		if (unlikely(rte_mempool_get_bulk(vcompress->mbuf_pool,
				(void **)mbufs, count) < 0)) {
			VC_LOG_ERR("Insufficient memory");
			goto out_unlock;
		}

		for (i = 0; i < count; i++) {
			uint16_t used_idx = (start_idx + i) & (vq->size - 1);
			uint16_t desc_idx = vq->avail->ring[used_idx];
			struct vring_desc *head = &vq->desc[desc_idx];
			struct rte_compress_op *op = ops[i];

			op->sym->m_src = mbufs[i];
			op->sym->m_dst = NULL;
			op->sym->m_src->data_off = 0;

			if (unlikely(vhost_compress_process_one_req(vcompress, vq,
					op, head, descs, desc_idx) < 0))
				break;
		}

		if (unlikely(i < count))
			rte_mempool_put_bulk(vcompress->mbuf_pool,
					(void **)&mbufs[i],
					count - i);

		break;

	}

	vq->last_used_idx += i;

out_unlock:
	vhost_user_iotlb_rd_unlock(vq);
	rte_rwlock_read_unlock(&vq->access_lock);

	return i;
}

RTE_EXPORT_SYMBOL(rte_vhost_compress_finalize_requests)
uint16_t
rte_vhost_compress_finalize_requests(struct rte_comp_op **ops,
		uint16_t nb_ops, int *callfds, uint16_t *nb_callfds)
{
	struct rte_compress_op **tmp_ops = ops;
	uint16_t count = 0, left = nb_ops;
	int callfd;
	uint16_t idx = 0;

	while (left) {
		count = vhost_compress_complete_one_vm_requests(tmp_ops, left,
				&callfd);
		if (unlikely(count == 0))
			break;

		tmp_ops = &tmp_ops[count];
		left -= count;

		callfds[idx++] = callfd;

		if (unlikely(idx >= VIRTIO_COMPRESS_MAX_NUM_BURST_VQS)) {
			VC_LOG_ERR("Too many vqs");
			break;
		}
	}

	*nb_callfds = idx;

	return nb_ops - left;
}
