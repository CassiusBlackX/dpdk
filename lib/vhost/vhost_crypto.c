/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */
#include <eal_export.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>

#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>

#include "iotlb.h"
#include "rte_vhost_crypto.h"
#include "vhost.h"
#include "vhost_user.h"
#include "virtio_crypto.h"
#include "vhost_crypto_migration.h"
#include <rte_hash_crc.h>
#include "vhost_crypto_snapshot.h"

#include <rte_errno.h>
#include <fcntl.h>    // for O_CREAT, O_WRONLY, O_TRUNC
#include <unistd.h>   // for close()
#include <rte_cycles.h>

static inline uint64_t vc_ts_ms(void)
{
    uint64_t hz = rte_get_timer_hz();
    uint64_t cyc = rte_get_timer_cycles();
    return hz ? (cyc * 1000 / hz) : 0;
}

#define VCLOG(level, fmt, ...) \
    RTE_LOG(level, USER1, "[VC][%llu ms] " fmt "\n", \
            (unsigned long long)vc_ts_ms(), ##__VA_ARGS__)


static inline uint16_t TOLE16(uint16_t x){ return rte_cpu_to_le_16(x); }
static inline uint32_t TOLE32(uint32_t x){ return rte_cpu_to_le_32(x); }
static inline uint64_t TOLE64(uint64_t x){ return rte_cpu_to_le_64(x); }
static inline uint16_t FROMLE16(uint16_t x){ return rte_le_to_cpu_16(x); }
static inline uint32_t FROMLE32(uint32_t x){ return rte_le_to_cpu_32(x); }
static inline uint64_t FROMLE64(uint64_t x){ return rte_le_to_cpu_64(x); }

uint32_t vc_crc32(const void *data, uint32_t len) {
    return rte_hash_crc(data, len, 0);
}

#define VHOST_USER_CRYPTO_TEST 55

#define INHDR_LEN		(sizeof(struct virtio_crypto_inhdr))
#define IV_OFFSET		(sizeof(struct rte_crypto_op) + \
				sizeof(struct rte_crypto_sym_op))

RTE_LOG_REGISTER_SUFFIX(vhost_crypto_logtype, crypto, INFO);
#define RTE_LOGTYPE_VHOST_CRYPTO	vhost_crypto_logtype

#define VC_LOG_ERR(...)	\
	RTE_LOG_LINE_PREFIX(ERR, VHOST_CRYPTO, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#define VC_LOG_INFO(...) \
	RTE_LOG_LINE_PREFIX(INFO, VHOST_CRYPTO, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#ifdef RTE_LIBRTE_VHOST_DEBUG
#define VC_LOG_DBG(...)	\
	RTE_LOG_LINE_PREFIX(DEBUG, VHOST_CRYPTO, "%s() line %u: ", \
		__func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)
#else
#define VC_LOG_DBG(...)
#endif

static void test_save_load_blob(int vid);

#define VIRTIO_CRYPTO_FEATURES ((1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |	\
		(1ULL << VIRTIO_RING_F_INDIRECT_DESC) |			\
		(1ULL << VIRTIO_RING_F_EVENT_IDX) |			\
		(1ULL << VIRTIO_NET_F_CTRL_VQ) |			\
		(1ULL << VIRTIO_F_VERSION_1) |				\
		(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
		(1ULL << VHOST_F_LOG_ALL)) 

#define IOVA_TO_VVA(t, dev, vq, a, l, p)				\
	((t)(uintptr_t)vhost_iova_to_vva(dev, vq, a, l, p))

/*
 * vhost_crypto_desc is used to copy original vring_desc to the local buffer
 * before processing (except the next index). The copy result will be an
 * array of vhost_crypto_desc elements that follows the sequence of original
 * vring_desc.next is arranged.
 */
#define vhost_crypto_desc vring_desc

static inline void explicit_bzero_fallback(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
}
#ifndef explicit_bzero
#define explicit_bzero explicit_bzero_fallback
#endif






/* duplicate bytes into DPDK heap (zero-inited) */
static inline uint8_t *
dup_bytes_dpdk(const void *src, size_t len)
{
    if (!src || len == 0)
        return NULL;

    uint8_t *p = rte_zmalloc(NULL, len, 0);  /* zero-init for safety */
    if (p == NULL)
        return NULL;

    rte_memcpy(p, src, len);
    return p;
}

/* secure zero + free (best effort) */
static inline void secure_free(void *p, size_t len) {
    if (!p) return;
    /* try to wipe; avoid being optimized out */
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
    rte_free(p);
}

struct vc_session_meta_blob {
    void    *blob;      // 连续缓冲：key|auth_key|iv_seed|…
    uint32_t blob_len;
};

struct vc_session_meta {
    bool     valid;
    uint64_t session_id;
    enum vc_sess_kind kind; // 来自 snapshot.h
    union {
        struct { struct vc_sym_meta_v1  desc; struct vc_session_meta_blob b; } sym;
        struct { struct vc_asym_meta_v1 desc; struct vc_session_meta_blob b; } asym;
    };
};

struct vhost_crypto_session {
	union {
		struct rte_cryptodev_asym_session *asym;
		struct rte_cryptodev_sym_session *sym;
	};
	enum rte_crypto_op_type type;
	struct vc_session_meta meta;
};
struct virtio_net;
extern struct virtio_net *get_device(int vid);

/* 从 vhost 设备拿到你自己的 vhost_crypto 实例 */
static inline struct vhost_crypto *vc_lookup(int vid) {
    struct virtio_net *dev = get_device(vid);
    if (!dev || !dev->extern_data) return NULL;
    return (struct vhost_crypto *)dev->extern_data;
}

static int
cipher_algo_transform(uint32_t virtio_cipher_algo,
		enum rte_crypto_cipher_algorithm *algo)
{
	switch (virtio_cipher_algo) {
	case VIRTIO_CRYPTO_CIPHER_AES_CBC:
		*algo = RTE_CRYPTO_CIPHER_AES_CBC;
		break;
	case VIRTIO_CRYPTO_CIPHER_AES_CTR:
		*algo = RTE_CRYPTO_CIPHER_AES_CTR;
		break;
	case VIRTIO_CRYPTO_CIPHER_DES_ECB:
		*algo = -VIRTIO_CRYPTO_NOTSUPP;
		break;
	case VIRTIO_CRYPTO_CIPHER_DES_CBC:
		*algo = RTE_CRYPTO_CIPHER_DES_CBC;
		break;
	case VIRTIO_CRYPTO_CIPHER_3DES_ECB:
		*algo = RTE_CRYPTO_CIPHER_3DES_ECB;
		break;
	case VIRTIO_CRYPTO_CIPHER_3DES_CBC:
		*algo = RTE_CRYPTO_CIPHER_3DES_CBC;
		break;
	case VIRTIO_CRYPTO_CIPHER_3DES_CTR:
		*algo = RTE_CRYPTO_CIPHER_3DES_CTR;
		break;
	case VIRTIO_CRYPTO_CIPHER_KASUMI_F8:
		*algo = RTE_CRYPTO_CIPHER_KASUMI_F8;
		break;
	case VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2:
		*algo = RTE_CRYPTO_CIPHER_SNOW3G_UEA2;
		break;
	case VIRTIO_CRYPTO_CIPHER_AES_F8:
		*algo = RTE_CRYPTO_CIPHER_AES_F8;
		break;
	case VIRTIO_CRYPTO_CIPHER_AES_XTS:
		*algo = RTE_CRYPTO_CIPHER_AES_XTS;
		break;
	case VIRTIO_CRYPTO_CIPHER_ZUC_EEA3:
		*algo = RTE_CRYPTO_CIPHER_ZUC_EEA3;
		break;
	default:
		return -VIRTIO_CRYPTO_BADMSG;
		break;
	}

	return 0;
}

static int
auth_algo_transform(uint32_t virtio_auth_algo,
		enum rte_crypto_auth_algorithm *algo)
{
	switch (virtio_auth_algo) {
	case VIRTIO_CRYPTO_NO_MAC:
		*algo = RTE_CRYPTO_AUTH_NULL;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_MD5:
		*algo = RTE_CRYPTO_AUTH_MD5_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_SHA1:
		*algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_SHA_224:
		*algo = RTE_CRYPTO_AUTH_SHA224_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_SHA_256:
		*algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_SHA_384:
		*algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_HMAC_SHA_512:
		*algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
		break;
	case VIRTIO_CRYPTO_MAC_CMAC_AES:
		*algo = RTE_CRYPTO_AUTH_AES_CMAC;
		break;
	case VIRTIO_CRYPTO_MAC_KASUMI_F9:
		*algo = RTE_CRYPTO_AUTH_KASUMI_F9;
		break;
	case VIRTIO_CRYPTO_MAC_SNOW3G_UIA2:
		*algo = RTE_CRYPTO_AUTH_SNOW3G_UIA2;
		break;
	case VIRTIO_CRYPTO_MAC_GMAC_AES:
		*algo = RTE_CRYPTO_AUTH_AES_GMAC;
		break;
	case VIRTIO_CRYPTO_MAC_CBCMAC_AES:
		*algo = RTE_CRYPTO_AUTH_AES_CBC_MAC;
		break;
	case VIRTIO_CRYPTO_MAC_XCBC_AES:
		*algo = RTE_CRYPTO_AUTH_AES_XCBC_MAC;
		break;
	case VIRTIO_CRYPTO_MAC_CMAC_3DES:
	case VIRTIO_CRYPTO_MAC_GMAC_TWOFISH:
	case VIRTIO_CRYPTO_MAC_CBCMAC_KASUMI_F9:
		return -VIRTIO_CRYPTO_NOTSUPP;
	default:
		return -VIRTIO_CRYPTO_BADMSG;
	}

	return 0;
}

static int get_iv_len(enum rte_crypto_cipher_algorithm algo)
{
	int len;

	switch (algo) {
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		len = 8;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CTR:
		len = 8;
		break;
	case RTE_CRYPTO_CIPHER_3DES_ECB:
		len = 8;
		break;
	case RTE_CRYPTO_CIPHER_AES_CBC:
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
 * vhost_crypto struct is used to maintain a number of virtio_cryptos and
 * one DPDK crypto device that deals with all crypto workloads. It is declared
 * here and defined in vhost_crypto.c
 */
struct __rte_cache_aligned vhost_crypto {
	/** Used to lookup DPDK Cryptodev Session based on VIRTIO crypto
	 *  session ID.
	 */
	struct rte_hash *session_map;
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *sess_pool;
	struct rte_mempool *wb_pool;

	/** DPDK cryptodev ID */
	uint8_t cid;
	uint16_t nb_qps;

	uint64_t last_session_id;

	uint64_t cache_sym_session_id;
	struct rte_cryptodev_sym_session *cache_sym_session;
	uint64_t cache_asym_session_id;
	struct rte_cryptodev_asym_session *cache_asym_session;
	/** socket id for the device */
	int socket_id;

	struct virtio_net *dev;

	uint8_t option;
	_Atomic unsigned int inflight;  /* ++ on submit, -- on completion */
	_Atomic unsigned int inflight_corrupt;
    volatile int frozen;            /* 1 => reject new submissions */

	rte_spinlock_t pending_lock;
    uint8_t *pending_load_buf;
    size_t pending_load_len;
    uint8_t pending_load_valid;
};

struct vhost_crypto_writeback_data {
	uint8_t *src;
	uint8_t *dst;
	uint64_t len;
	struct vhost_crypto_writeback_data *next;
};

struct vhost_crypto_data_req {
	struct vring_desc *head;
	struct virtio_net *dev;
	struct virtio_crypto_inhdr *inhdr;
	struct vhost_virtqueue *vq;
	struct vhost_crypto_writeback_data *wb;
	struct rte_mempool *wb_pool;
	uint16_t desc_idx;
	uint16_t len;
	uint16_t zero_copy;
	struct vhost_crypto *vcrypto;           /* 新增：设备回指，收尾/计数用 */

};

static int
transform_cipher_param(struct rte_crypto_sym_xform *xform,
		VhostUserCryptoSymSessionParam *param)
{
	int ret;

	ret = cipher_algo_transform(param->cipher_algo, &xform->cipher.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->cipher_key_len > VHOST_USER_CRYPTO_MAX_CIPHER_KEY_LENGTH) {
		VC_LOG_DBG("Invalid cipher key length");
		return -VIRTIO_CRYPTO_BADMSG;
	}

	xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform->cipher.key.length = param->cipher_key_len;
	if (xform->cipher.key.length > 0)
		xform->cipher.key.data = param->cipher_key_buf;
	if (param->dir == VIRTIO_CRYPTO_OP_ENCRYPT)
		xform->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	else if (param->dir == VIRTIO_CRYPTO_OP_DECRYPT)
		xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	else {
		VC_LOG_DBG("Bad operation type");
		return -VIRTIO_CRYPTO_BADMSG;
	}

	ret = get_iv_len(xform->cipher.algo);
	if (unlikely(ret < 0))
		return ret;
	xform->cipher.iv.length = (uint16_t)ret;
	xform->cipher.iv.offset = IV_OFFSET;
	return 0;
}

static int
transform_chain_param(struct rte_crypto_sym_xform *xforms,
		VhostUserCryptoSymSessionParam *param)
{
	struct rte_crypto_sym_xform *xform_cipher, *xform_auth;
	int ret;

	switch (param->chaining_dir) {
	case VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER:
		xform_auth = xforms;
		xform_cipher = xforms->next;
		xform_cipher->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		xform_auth->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
		break;
	case VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH:
		xform_cipher = xforms;
		xform_auth = xforms->next;
		xform_cipher->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		xform_auth->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
		break;
	default:
		return -VIRTIO_CRYPTO_BADMSG;
	}

	/* cipher */
	ret = cipher_algo_transform(param->cipher_algo,
			&xform_cipher->cipher.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->cipher_key_len > VHOST_USER_CRYPTO_MAX_CIPHER_KEY_LENGTH) {
		VC_LOG_DBG("Invalid cipher key length");
		return -VIRTIO_CRYPTO_BADMSG;
	}

	xform_cipher->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform_cipher->cipher.key.length = param->cipher_key_len;
	xform_cipher->cipher.key.data = param->cipher_key_buf;
	ret = get_iv_len(xform_cipher->cipher.algo);
	if (unlikely(ret < 0))
		return ret;
	xform_cipher->cipher.iv.length = (uint16_t)ret;
	xform_cipher->cipher.iv.offset = IV_OFFSET;

	/* auth */
	xform_auth->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	ret = auth_algo_transform(param->hash_algo, &xform_auth->auth.algo);
	if (unlikely(ret < 0))
		return ret;

	if (param->auth_key_len > VHOST_USER_CRYPTO_MAX_HMAC_KEY_LENGTH) {
		VC_LOG_DBG("Invalid auth key length");
		return -VIRTIO_CRYPTO_BADMSG;
	}

	xform_auth->auth.digest_length = param->digest_len;
	xform_auth->auth.key.length = param->auth_key_len;
	xform_auth->auth.key.data = param->auth_key_buf;

	return 0;
}

static void
vhost_crypto_create_sym_sess(struct vhost_crypto *vcrypto,
                             VhostUserCryptoSessionParam *sess_param)
{
    struct rte_crypto_sym_xform xform1 = {0}, xform2 = {0};
    struct vhost_crypto_session *vhost_session = NULL;
    struct rte_cryptodev_sym_session *session = NULL;
    int ret;

    switch (sess_param->u.sym_sess.op_type) {
    case VIRTIO_CRYPTO_SYM_OP_NONE:
    case VIRTIO_CRYPTO_SYM_OP_CIPHER:
        ret = transform_cipher_param(&xform1, &sess_param->u.sym_sess);
        if (unlikely(ret)) {
            VC_LOG_ERR("Error transform session msg (%i)", ret);
            sess_param->session_id = ret;
            return;
        }
        break;
    case VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING:
        if (unlikely(sess_param->u.sym_sess.hash_mode !=
                     VIRTIO_CRYPTO_SYM_HASH_MODE_AUTH)) {
            sess_param->session_id = -VIRTIO_CRYPTO_NOTSUPP;
            VC_LOG_ERR("Error transform session message (%i)",
                       -VIRTIO_CRYPTO_NOTSUPP);
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
        sess_param->session_id = -VIRTIO_CRYPTO_NOTSUPP;
        return;
    }

    session = rte_cryptodev_sym_session_create(vcrypto->cid, &xform1,
                                               vcrypto->sess_pool);
    if (!session) {
        VC_LOG_ERR("Failed to create session");
        sess_param->session_id = -VIRTIO_CRYPTO_ERR;
        return;
    }

    vhost_session = rte_zmalloc(NULL, sizeof(*vhost_session), 0);
    if (vhost_session == NULL) {
        VC_LOG_ERR("Failed to alloc session memory");
        goto error_exit;
    }

    vhost_session->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
    vhost_session->sym  = session;

    /* === 缓存“原始会话参数 + 密钥”用于迁移重建 === */
    vhost_session->meta.valid       = true;
    vhost_session->meta.session_id  = vcrypto->last_session_id;
    vhost_session->meta.kind        = VC_SESS_SYM;

    /* 1) 固定描述字段：来自 guest 的 sess_param */
    struct vc_sym_meta_v1 *D = &vhost_session->meta.sym.desc;
    memset(D, 0, sizeof(*D));
    D->algo_cipher = (uint16_t)sess_param->u.sym_sess.cipher_algo;
    D->algo_auth   = (uint16_t)sess_param->u.sym_sess.hash_algo;   /* 无 auth 可为 0 */
    D->algo_aead   = 0;        /* 目前不走 AEAD，保留 */
    D->chain_mode  = (uint16_t)sess_param->u.sym_sess.chaining_dir;
    D->key_len     = (uint16_t)sess_param->u.sym_sess.cipher_key_len;
    D->aad_len     = 0;        /* 非 AEAD */
    D->tag_len     = (uint16_t)sess_param->u.sym_sess.digest_len;  /* 链式/HMAC 才用 */
    D->iv_gen_mode = 0;

    /* iv_len 与 transform 一致：优先取 cipher xform 的 iv.length */
    do {
        const struct rte_crypto_sym_xform *cxf = NULL;
        if (xform1.type == RTE_CRYPTO_SYM_XFORM_CIPHER) cxf = &xform1;
        else if (xform2.type == RTE_CRYPTO_SYM_XFORM_CIPHER) cxf = &xform2;
        D->iv_len = (uint16_t)(cxf ? cxf->cipher.iv.length : 0);
    } while (0);

    /* 2) 变长 blob 约定顺序：cipher_key | auth_key | iv_seed(可选) */
    uint32_t key_len      = sess_param->u.sym_sess.cipher_key_len;
    uint32_t auth_key_len = sess_param->u.sym_sess.auth_key_len; /* 仅链式/HMAC有 */
    uint32_t iv_seed_len  = 0;  /* 通常每 op 提供 IV，默认不保存模板 */
    uint32_t blob_len     = key_len + auth_key_len + iv_seed_len;

    void *blob = (blob_len ? rte_zmalloc(NULL, blob_len, 0) : NULL);
    if (blob_len && !blob) {
        VC_LOG_ERR("No mem for sym meta blob");
        goto error_exit;
    }
    uint8_t *w = (uint8_t*)blob;
    if (key_len) {
        rte_memcpy(w, sess_param->u.sym_sess.cipher_key_buf, key_len);
        w += key_len;
    }
    if (auth_key_len) {
        rte_memcpy(w, sess_param->u.sym_sess.auth_key_buf, auth_key_len);
        w += auth_key_len;
    }
    if (iv_seed_len) {
        /* 若未来需要固定 IV 模板，在此 memcpy 对应来源；当前置零占位 */
        memset(w, 0, iv_seed_len);
        w += iv_seed_len;
    }
    vhost_session->meta.sym.b.blob     = blob;
    vhost_session->meta.sym.b.blob_len = blob_len;

    /* === 插入到会话映射 === */
    if (rte_hash_add_key_data(vcrypto->session_map,
                              &vcrypto->last_session_id, vhost_session) < 0) {
        VC_LOG_ERR("Failed to insert session to hash table");
        goto error_exit;
    }

    VC_LOG_INFO("Session %"PRIu64" created for vdev %i.",
                vcrypto->last_session_id, vcrypto->dev->vid);

    sess_param->session_id = vcrypto->last_session_id;
    vcrypto->last_session_id++;
    return;

error_exit:
    if (vhost_session && vhost_session->meta.valid &&
        vhost_session->meta.kind == VC_SESS_SYM &&
        vhost_session->meta.sym.b.blob) {
        explicit_bzero(vhost_session->meta.sym.b.blob,
                       vhost_session->meta.sym.b.blob_len);
        rte_free(vhost_session->meta.sym.b.blob);
        vhost_session->meta.sym.b.blob = NULL;
        vhost_session->meta.sym.b.blob_len = 0;
    }
    if (session) {
        if (rte_cryptodev_sym_session_free(vcrypto->cid, session) < 0)
            VC_LOG_ERR("Failed to free session");
    }
    sess_param->session_id = -VIRTIO_CRYPTO_ERR;
    rte_free(vhost_session);
}


static int
tlv_decode(uint8_t *tlv, uint8_t type, uint8_t **data, size_t *data_len)
{
    int tlen = -EINVAL;           // <-- 用 int
    size_t len;

    if (tlv[0] != type)
        return -EINVAL;

    if (tlv[1] == 0x82) {
        len = (tlv[2] << 8) | tlv[3];
        *data = &tlv[4];
        tlen = (int)len + 4;
    } else if (tlv[1] == 0x81) {
        len = tlv[2];
        *data = &tlv[3];
        tlen = (int)len + 3;
    } else {
        len = tlv[1];
        *data = &tlv[2];
        tlen = (int)len + 2;
    }

    *data_len = len;
    return tlen;
}

static int
virtio_crypto_asym_rsa_public_der_to_xform(uint8_t *der, size_t der_len,
		struct rte_crypto_asym_xform *xform)
{
	uint8_t *n = NULL, *e = NULL, *tlv;
	size_t nlen, elen;
	int len;

	RTE_SET_USED(der_len);

	if (der[0] != 0x30)
		return -EINVAL;


	if (der[1] == 0x82)
		tlv = &der[4];
	else if (der[1] == 0x81)
		tlv = &der[3];
	else if (der[1] < 0x80)
		tlv = &der[2];
	else
		return -EINVAL;

	len = tlv_decode(tlv, 0x02, &n, &nlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &e, &elen);
	if (len < 0)
		return len;

	xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
	xform->rsa.key_type = RTE_RSA_KEY_TYPE_EXP;
	xform->rsa.n.data = n;
	xform->rsa.n.length = nlen;
	xform->rsa.e.data = e;
	xform->rsa.e.length = elen;

	xform->rsa.d.data = NULL;
	xform->rsa.d.length = 0;
	xform->rsa.qt.p.data = NULL;
	xform->rsa.qt.p.length = 0;
	xform->rsa.qt.q.data = NULL;
	xform->rsa.qt.q.length = 0;
	xform->rsa.qt.dP.data = NULL;
	xform->rsa.qt.dP.length = 0;
	xform->rsa.qt.dQ.data = NULL;
	xform->rsa.qt.dQ.length = 0;
	xform->rsa.qt.qInv.data = NULL;
	xform->rsa.qt.qInv.length = 0;

	RTE_ASSERT(tlv + len == der + der_len);
	return 0;
}


static int
virtio_crypto_asym_rsa_der_to_xform(uint8_t *der, size_t der_len,
		struct rte_crypto_asym_xform *xform)
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
rsa_param_transform(struct rte_crypto_asym_xform *xform,
		VhostUserCryptoAsymSessionParam *param)
{
	int ret;


	switch (param->key_type) {
	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC:
		xform->rsa.key_type = RTE_RSA_KEY_TYPE_EXP;
		ret = virtio_crypto_asym_rsa_public_der_to_xform(param->key_buf, param->key_len, xform);
	break;
	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE:
		xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;
		ret = virtio_crypto_asym_rsa_der_to_xform(param->key_buf, param->key_len, xform);
	break;
	default:
		VC_LOG_ERR("Unknown rsa key type");
		return -EINVAL;
	}

	if (ret < 0) {
		VC_LOG_ERR("failed to parse rsa der");
		return ret;
	}

	switch (param->u.rsa.padding_algo) {
	case VIRTIO_CRYPTO_RSA_RAW_PADDING:
		xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
		break;
	case VIRTIO_CRYPTO_RSA_PKCS1_PADDING:
		xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
		break;
	default:
		VC_LOG_ERR("Unknown padding type");
		return -EINVAL;
	}

	xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
	return 0;
}

static void
vhost_crypto_create_asym_sess(struct vhost_crypto *vcrypto,
                              VhostUserCryptoSessionParam *sess_param)
{
    struct rte_cryptodev_asym_session *session = NULL;
    struct vhost_crypto_session *vhost_session = NULL;
    struct rte_crypto_asym_xform xform = (struct rte_crypto_asym_xform){0};
    int ret;

    /* 1) 来宾参数 -> DPDK xform（沿用你已有的转换） */
    switch (sess_param->u.asym_sess.algo) {
    case VIRTIO_CRYPTO_AKCIPHER_RSA:
        ret = rsa_param_transform(&xform, &sess_param->u.asym_sess);
        if (unlikely(ret < 0)) {
            VC_LOG_ERR("Error transform session msg (%i)", ret);
            sess_param->session_id = ret;
            return;
        }
        break;
    default:
        VC_LOG_ERR("Invalid op algo");
        sess_param->session_id = -VIRTIO_CRYPTO_ERR;
        return;
    }

    /* 2) 创建 cryptodev 会话（保持你现有 API 形态） */
    ret = rte_cryptodev_asym_session_create(vcrypto->cid, &xform,
                                            vcrypto->sess_pool, (void *)&session);
    if (session == NULL) {
        VC_LOG_ERR("Failed to create session");
        sess_param->session_id = -VIRTIO_CRYPTO_ERR;
        return;
    }

    /* 3) 分配 vhost 会话对象 */
    vhost_session = rte_zmalloc(NULL, sizeof(*vhost_session), 0);
    if (vhost_session == NULL) {
        VC_LOG_ERR("Failed to alloc session memory");
        goto error_exit;
    }
    vhost_session->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
    vhost_session->asym = session;

    /* 4) 缓存“原始会话参数+密钥素材”，供迁移重建 */
    vhost_session->meta.valid      = true;
    vhost_session->meta.session_id = vcrypto->last_session_id;
    vhost_session->meta.kind       = VC_SESS_ASYM;

    struct vc_asym_meta_v1 *A = &vhost_session->meta.asym.desc;
    memset(A, 0, sizeof(*A));
    A->algo_asym = (uint16_t)sess_param->u.asym_sess.algo;


    /* 对于 RSA：把 padding 策略占到 hash_algo 字段（你也可定义独立枚举映射） */
    A->padding_algo = (uint16_t)sess_param->u.asym_sess.u.rsa.padding_algo;
    A->curve_id  = 0;

    /* 变长密钥 blob：保存 guest 传来的私钥 DER 原文即可 */
    uint32_t blob_len = sess_param->u.asym_sess.key_len;
    void *blob = (blob_len ? rte_zmalloc(NULL, blob_len, 0) : NULL);
    if (blob_len && !blob) {
        VC_LOG_ERR("No mem for asym meta blob");
        goto error_exit;
    }
    if (blob_len) {
        rte_memcpy(blob, sess_param->u.asym_sess.key_buf, blob_len);
    }
    vhost_session->meta.asym.b.blob     = blob;
    vhost_session->meta.asym.b.blob_len = blob_len;

    /* 5) 插入会话映射 */
    if (rte_hash_add_key_data(vcrypto->session_map,
                              &vcrypto->last_session_id, vhost_session) < 0) {
        VC_LOG_ERR("Failed to insert session to hash table");
        goto error_exit;
    }

    VC_LOG_INFO("Asym session %"PRIu64" created for vdev %i.",
                vcrypto->last_session_id, vcrypto->dev->vid);

    sess_param->session_id = vcrypto->last_session_id;
    vcrypto->last_session_id++;
    return;

error_exit:
    if (vhost_session && vhost_session->meta.valid &&
        vhost_session->meta.kind == VC_SESS_ASYM &&
        vhost_session->meta.asym.b.blob) {
        explicit_bzero(vhost_session->meta.asym.b.blob,
                       vhost_session->meta.asym.b.blob_len);
        rte_free(vhost_session->meta.asym.b.blob);
        vhost_session->meta.asym.b.blob = NULL;
        vhost_session->meta.asym.b.blob_len = 0;
    }
    if (session) {
        if (rte_cryptodev_asym_session_free(vcrypto->cid, session) < 0)
            VC_LOG_ERR("Failed to free asym session");
    }
    sess_param->session_id = -VIRTIO_CRYPTO_ERR;
    rte_free(vhost_session);
}



static void
vhost_crypto_create_sess(struct vhost_crypto *vcrypto,
		VhostUserCryptoSessionParam *sess_param)
{
	if (sess_param->op_code == VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION)
		vhost_crypto_create_asym_sess(vcrypto, sess_param);
	else
		vhost_crypto_create_sym_sess(vcrypto, sess_param);
}

static int
vhost_crypto_close_sess(struct vhost_crypto *vcrypto, uint64_t session_id)
{
    struct vhost_crypto_session *vhost_session = NULL;
    uint64_t sid = session_id;
    int rc = 0;

    /* 1) 从会话表取指针（当前分支的既有用法） */
    if (rte_hash_lookup_data(vcrypto->session_map, &sid,
                             (void **)&vhost_session) < 0 || !vhost_session) {
        return -VIRTIO_CRYPTO_ERR;
    }

    /* 2) 先从哈希表移除，避免并发路径再拿到它 */
    if (rte_hash_del_key(vcrypto->session_map, &sid) < 0) {
        VC_LOG_DBG("Failed to delete session %" PRIu64 " from hash.", sid);
        rc = -VIRTIO_CRYPTO_ERR; /* 记录但继续做清理，避免泄漏 */
    }

    /* 3) 释放 DPDK 会话对象（对称/非对称分支） */
    if (vhost_session->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
        if (vhost_session->sym) {
            if (rte_cryptodev_sym_session_free(vcrypto->cid,
                                               vhost_session->sym) < 0) {
                VC_LOG_ERR("Failed to free sym session");
                rc = -VIRTIO_CRYPTO_ERR;
            }
            vhost_session->sym = NULL;
        }
    } else {
        if (vhost_session->asym) {
            if (rte_cryptodev_asym_session_free(vcrypto->cid,
                                                vhost_session->asym) < 0) {
                VC_LOG_ERR("Failed to free asym session");
                rc = -VIRTIO_CRYPTO_ERR;
            }
            vhost_session->asym = NULL;
        }
    }

    /* 4) 显式清零并释放缓存的密钥/DER blob（避免残留敏感信息） */
    if (vhost_session->meta.valid) {
        if (vhost_session->meta.kind == VC_SESS_SYM &&
            vhost_session->meta.sym.b.blob) {
            explicit_bzero(vhost_session->meta.sym.b.blob,
                           vhost_session->meta.sym.b.blob_len);
            rte_free(vhost_session->meta.sym.b.blob);
            vhost_session->meta.sym.b.blob = NULL;
            vhost_session->meta.sym.b.blob_len = 0;
        } else if (vhost_session->meta.kind == VC_SESS_ASYM &&
                   vhost_session->meta.asym.b.blob) {
            explicit_bzero(vhost_session->meta.asym.b.blob,
                           vhost_session->meta.asym.b.blob_len);
            rte_free(vhost_session->meta.asym.b.blob);
            vhost_session->meta.asym.b.blob = NULL;
            vhost_session->meta.asym.b.blob_len = 0;
        }
        vhost_session->meta.valid = false;
        memset(&vhost_session->meta, 0, sizeof(vhost_session->meta));
    }

    VC_LOG_INFO("Session %" PRIu64 " closed for vdev %i.",
                session_id, vcrypto->dev->vid);

    /* 5) 释放会话结构本身 */
    rte_free(vhost_session);

    return rc ? rc : 0;
}

static enum rte_vhost_msg_result
vhost_crypto_msg_pre_handler(int vid, void *msg)
{

    return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}


static int
read_all_from_fd(int fd, uint8_t **out_buf, size_t *out_len)
{
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf)
        return -ENOMEM;

    for (;;) {
        ssize_t n = read(fd, buf + len, cap - len);
        if (n > 0) {
            len += (size_t)n;
            if (len == cap) {
                cap *= 2;
                uint8_t *nb = realloc(buf, cap);
                if (!nb) {
                    free(buf);
                    return -ENOMEM;
                }
                buf = nb;
            }
            continue;
        }
        if (n == 0)
            break; /* EOF */
        if (errno == EINTR)
            continue;
        free(buf);
        return -errno;
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}
static inline int vhost_crypto_device_ready(struct virtio_net *dev);
static int vhost_crypto_load_state_fd(int vid, int fd);

static void
vhost_crypto_try_apply_pending_load(int vid, struct virtio_net *dev,
                                    struct vhost_crypto *vcrypto,
                                    const char *why)
{
    void *buf = NULL;
    size_t len = 0;

    if (!vcrypto)
        return;

    /* 先快速检查：没有 pending 直接返回 */
    rte_spinlock_lock(&vcrypto->pending_lock);
    if (!vcrypto->pending_load_valid) {
        rte_spinlock_unlock(&vcrypto->pending_lock);
        return;
    }
    rte_spinlock_unlock(&vcrypto->pending_lock);

    /* 设备未 ready：不动 pending，留待后续触发点再试 */
    if (!vhost_crypto_device_ready(dev)) {
        VC_LOG_INFO("pending LOAD, but device not ready yet (vid=%d why=%s)", vid, why);
        return;
    }

    /* ready 了：原子地“取走 pending 并清掉标志” */
    rte_spinlock_lock(&vcrypto->pending_lock);
    if (!vcrypto->pending_load_valid) { /* 期间可能被别的线程抢先 apply 了 */
        rte_spinlock_unlock(&vcrypto->pending_lock);
        return;
    }

    buf = vcrypto->pending_load_buf;
    len = vcrypto->pending_load_len;
    vcrypto->pending_load_buf = NULL;
    vcrypto->pending_load_len = 0;
    vcrypto->pending_load_valid = 0;
    rte_spinlock_unlock(&vcrypto->pending_lock);

    VC_LOG_INFO("Applying deferred CRYPTO_LOAD now (vid=%d why=%s len=%zu)", vid, why, len);

    int rc = vhost_crypto_load_state(vid, buf, len);

    rte_free(buf);

    if (rc == 0) {
        VC_LOG_INFO("Deferred LOAD OK (vid=%d)", vid);
        /* 这里是否自动 thaw 取决于你的策略；你现在在 SET_STATUS DRIVER_OK 里 thaw 也可以 */
    } else {
        VC_LOG_ERR("Deferred LOAD failed (vid=%d rc=%d)", vid, rc);
    }
}


static enum rte_vhost_msg_result
vhost_crypto_msg_post_handler(int vid, void *msg)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_crypto *vcrypto;
	struct vhu_msg_context *ctx = msg;
	VC_LOG_INFO("TAG_CTRL_POST vid=%d req=%u fd_num=%u",
            vid, ctx->msg.request.frontend, ctx->fd_num);
	enum rte_vhost_msg_result ret = RTE_VHOST_MSG_RESULT_OK;

	if (dev == NULL) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return RTE_VHOST_MSG_RESULT_ERR;
	}

	vcrypto = dev->extern_data;
	if (vcrypto == NULL) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return RTE_VHOST_MSG_RESULT_ERR;
	}
	vcrypto->dev = dev;

	switch (ctx->msg.request.frontend) {
	case VHOST_USER_CRYPTO_CREATE_SESS:
		vhost_crypto_create_sess(vcrypto, &ctx->msg.payload.crypto_session);
		ctx->fd_num = 0;
		ret = RTE_VHOST_MSG_RESULT_REPLY;
		break;

	case VHOST_USER_CRYPTO_CLOSE_SESS:
		if (vhost_crypto_close_sess(vcrypto, ctx->msg.payload.u64))
			ret = RTE_VHOST_MSG_RESULT_ERR;
		break;
	
	case VHOST_USER_SET_STATUS: 
		uint8_t st = (uint8_t)ctx->msg.payload.u64;
		/* DRIVER_OK 置位：允许数据面开始工作；迁移恢复后也会走到这里 */
		if (st & VIRTIO_DEVICE_STATUS_DRIVER_OK) {
			(void)vhost_crypto_thaw(vid);
		}
		ret = RTE_VHOST_MSG_RESULT_NOT_HANDLED; /* 让原生 handler 继续处理 */
		break;
	
	/* ---- migration extensions ---- */
	case VHOST_USER_CRYPTO_TEST:
    test_save_load_blob(vid);
    break;

	case VHOST_USER_CRYPTO_FREEZE:
		ret = (vhost_crypto_freeze(vid) == 0) ? RTE_VHOST_MSG_RESULT_OK
											: RTE_VHOST_MSG_RESULT_ERR;
		break;

	case VHOST_USER_CRYPTO_SAVE: {
		int fd = (ctx->fd_num > 0) ? ctx->fds[0] : -1;
		ctx->fds[0] = -1;
		ctx->fd_num = 0;

		if (fd < 0) {
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		/* 关键：SAVE 必须在 freeze 之后进行，否则导出状态不一致 */
		struct virtio_net *dev = get_device(vid);
		struct vhost_crypto *vcrypto = dev ? dev->extern_data : NULL;
		if (!dev || !vcrypto) {
			close(fd);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		/* Freeze only when we are actually snapshotting backend state */
		int fr = vhost_crypto_freeze(vid);
		while (fr == -EBUSY) {
			rte_delay_us_block(100);
			fr = vhost_crypto_freeze(vid);
		}
		if (fr < 0) {
			VC_LOG_ERR("SAVE: freeze failed (vid=%d ret=%d)", vid, fr);
			close(fd);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		/* 保险：哪怕 freeze 已经做过，也再确认一下 quiescent */
		if (__atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE) != 0) {
			VC_LOG_ERR("SAVE while inflight!=0 (vid=%d inflight=%u)",
					vid, __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE));
			close(fd);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		int rc = vhost_crypto_save_state(vid, fd);

		/* 建议：写完后 flush 一下，减少目的端读到半截的概率 */
		if (rc == 0) {
			(void)fsync(fd);
		}

		close(fd);
		ret = (rc == 0) ? RTE_VHOST_MSG_RESULT_OK : RTE_VHOST_MSG_RESULT_ERR;
		break;
	}


	case VHOST_USER_CRYPTO_LOAD: {
		int fd = (ctx->fd_num > 0) ? ctx->fds[0] : -1;
		ctx->fds[0] = -1;
		ctx->fd_num = 0;

		if (fd < 0) {
			VC_LOG_ERR("CRYPTO_LOAD missing fd (vid=%d)", vid);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		uint8_t *tmp = NULL;
		size_t len = 0;
		int rr = read_all_from_fd(fd, &tmp, &len);
		close(fd);

		if (rr < 0) {
			VC_LOG_ERR("CRYPTO_LOAD read fd failed (vid=%d rr=%d)", vid, rr);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}

		/* 把 malloc 的临时 buf 拷贝进 rte_malloc，后面统一 rte_free */
		void *buf = rte_malloc(NULL, len, 0);
		if (!buf) {
			free(tmp);
			ret = RTE_VHOST_MSG_RESULT_ERR;
			break;
		}
		memcpy(buf, tmp, len);
		free(tmp);

		/* 覆盖旧的 pending + 写入新 pending：必须加锁，避免 try_apply 撕裂/重复释放 */
		rte_spinlock_lock(&vcrypto->pending_lock);

		if (vcrypto->pending_load_valid && vcrypto->pending_load_buf) {
			rte_free(vcrypto->pending_load_buf);
		}

		vcrypto->pending_load_buf = buf;
		vcrypto->pending_load_len = len;
		vcrypto->pending_load_valid = 1;

		rte_spinlock_unlock(&vcrypto->pending_lock);

		ret = RTE_VHOST_MSG_RESULT_OK;
		break;
	}



	case VHOST_USER_CRYPTO_THAW:
		ret = (vhost_crypto_thaw(vid) == 0) ? RTE_VHOST_MSG_RESULT_OK
											: RTE_VHOST_MSG_RESULT_ERR;
		break;

	/* 可选：仅在宏存在时编译，避免报未定义 */
	#ifdef VHOST_USER_SUSPEND
	case VHOST_USER_SUSPEND:
		ret = (vhost_crypto_freeze(vid) == 0) ? RTE_VHOST_MSG_RESULT_OK
											: RTE_VHOST_MSG_RESULT_ERR;
		break;
	#endif

	#ifdef VHOST_USER_RESUME
	case VHOST_USER_RESUME:
		ret = (vhost_crypto_thaw(vid) == 0) ? RTE_VHOST_MSG_RESULT_OK
											: RTE_VHOST_MSG_RESULT_ERR;
		break;
	#endif

	case VHOST_USER_SET_MEM_TABLE:
	case VHOST_USER_SET_VRING_ADDR:
	case VHOST_USER_SET_VRING_NUM:
	case VHOST_USER_SET_VRING_BASE:
	case VHOST_USER_SET_VRING_KICK:
		/* 这些必须让 vhost core 去真正配置队列/内存，我们这里只做“配置后尝试 apply pending” */
		ret = RTE_VHOST_MSG_RESULT_NOT_HANDLED;

		vhost_crypto_try_apply_pending_load(vid, dev, vcrypto, "cfg-msg-post");
		break;
	default:
		ret = RTE_VHOST_MSG_RESULT_NOT_HANDLED;
		break;
	}


	return ret;
}

static __rte_always_inline struct vhost_crypto_desc *
find_write_desc(struct vhost_crypto_desc *head, struct vhost_crypto_desc *desc,
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

static __rte_always_inline struct virtio_crypto_inhdr *
reach_inhdr(struct virtio_net *dev, struct vhost_virtqueue *vq,
		struct vhost_crypto_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct virtio_crypto_inhdr *inhdr;
	struct vhost_crypto_desc *last = head + (max_n_descs - 1);
	uint64_t dlen = last->len;

	if (unlikely(dlen != sizeof(*inhdr)))
		return NULL;

	inhdr = IOVA_TO_VVA(struct virtio_crypto_inhdr *, dev, vq,
			last->addr, &dlen, VHOST_ACCESS_WO);
	if (unlikely(!inhdr || dlen != last->len))
		return NULL;

	return inhdr;
}

static __rte_always_inline int
move_desc(struct vhost_crypto_desc *head,
		struct vhost_crypto_desc **cur_desc,
		uint32_t size, uint32_t max_n_descs)
{
	struct vhost_crypto_desc *desc = *cur_desc;
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
get_data_ptr(struct vhost_virtqueue *vq, struct vhost_crypto_data_req *vc_req,
		struct vhost_crypto_desc *cur_desc,
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
	struct vhost_virtqueue *vq, struct vhost_crypto_desc *desc, uint32_t size)
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
	struct vhost_crypto_desc *head, struct vhost_crypto_desc **cur_desc,
	uint32_t size, uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_crypto_desc *desc = *cur_desc;
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
write_back_data(struct vhost_crypto_data_req *vc_req)
{
	struct vhost_crypto_writeback_data *wb_data = vc_req->wb, *wb_last;

	while (wb_data) {
		rte_memcpy(wb_data->dst, wb_data->src, wb_data->len);
		memset(wb_data->src, 0, wb_data->len);
		wb_last = wb_data;
		wb_data = wb_data->next;
		rte_mempool_put(vc_req->wb_pool, wb_last);
	}
}

static void
free_wb_data(struct vhost_crypto_writeback_data *wb_data,
		struct rte_mempool *mp)
{
	while (wb_data->next != NULL)
		free_wb_data(wb_data->next, mp);

	rte_mempool_put(mp, wb_data);
}

/**
 * The function will allocate a vhost_crypto_writeback_data linked list
 * containing the source and destination data pointers for the write back
 * operation after dequeued from Cryptodev PMD queues.
 *
 * @param vc_req
 *   The vhost crypto data request pointer
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
static __rte_always_inline struct vhost_crypto_writeback_data *
prepare_write_back_data(struct vhost_virtqueue *vq,
		struct vhost_crypto_data_req *vc_req,
		struct vhost_crypto_desc *head_desc,
		struct vhost_crypto_desc **cur_desc,
		struct vhost_crypto_writeback_data **end_wb_data,
		uint8_t *src,
		uint32_t offset,
		uint64_t write_back_len,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_crypto_writeback_data *wb_data, *head;
	struct vhost_crypto_desc *desc = *cur_desc;
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
vhost_crypto_check_cipher_request(struct virtio_crypto_cipher_data_req *req)
{
	if (likely((req->para.iv_len <= VHOST_CRYPTO_MAX_IV_LEN) &&
		(req->para.src_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= RTE_MBUF_DEFAULT_BUF_SIZE)))
		return VIRTIO_CRYPTO_OK;

	if (likely((req->para.iv_len <= VHOST_CRYPTO_MAX_IV_LEN) &&
		(req->para.src_data_len <= 32768) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= 32768)))
		return VIRTIO_CRYPTO_OK;
	return VIRTIO_CRYPTO_BADMSG;
}

static __rte_always_inline uint8_t
prepare_sym_cipher_op(struct vhost_crypto *vcrypto, struct rte_crypto_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_crypto_data_req *vc_req,
		struct virtio_crypto_cipher_data_req *cipher,
		struct vhost_crypto_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_crypto_desc *desc = head;
	struct vhost_crypto_writeback_data *ewb = NULL;
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst = op->sym->m_dst;
	uint8_t *iv_data = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	uint8_t ret = vhost_crypto_check_cipher_request(cipher);

	if (unlikely(ret != VIRTIO_CRYPTO_OK))
		goto error_exit;

	/* prepare */
	/* iv */
	if (unlikely(copy_data(iv_data, vcrypto->dev, vq, head, &desc,
			cipher->para.iv_len, max_n_descs))) {
		VC_LOG_ERR("Incorrect virtio descriptor");
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
		m_src->data_len = cipher->para.src_data_len;
		rte_mbuf_iova_set(m_src,
				  gpa_to_hpa(vcrypto->dev, desc->addr, cipher->para.src_data_len));
		m_src->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
		if (unlikely(rte_mbuf_iova_get(m_src) == 0 || m_src->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, cipher->para.src_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		break;
	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcrypto->wb_pool;
		m_src->data_len = cipher->para.src_data_len;
		if (unlikely(copy_data(rte_pktmbuf_mtod(m_src, uint8_t *),
				vcrypto->dev, vq, head, &desc,
				cipher->para.src_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_CRYPTO_BADMSG;
			goto error_exit;
		}
		break;
	default:
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	/* dst */
	desc = find_write_desc(head, desc, max_n_descs);
	if (unlikely(!desc)) {
		VC_LOG_ERR("Cannot find write location");
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
		rte_mbuf_iova_set(m_dst,
				  gpa_to_hpa(vcrypto->dev, desc->addr, cipher->para.dst_data_len));
		m_dst->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(rte_mbuf_iova_get(m_dst) == 0 || m_dst->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, cipher->para.dst_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		m_dst->data_len = cipher->para.dst_data_len;
		break;
	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		vc_req->wb = prepare_write_back_data(vq, vc_req, head, &desc, &ewb,
				rte_pktmbuf_mtod(m_src, uint8_t *), 0,
				cipher->para.dst_data_len, max_n_descs);
		if (unlikely(vc_req->wb == NULL)) {
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		break;
	default:
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	/* src data */
	op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;

	op->sym->cipher.data.offset = 0;
	op->sym->cipher.data.length = cipher->para.src_data_len;

	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_CRYPTO_OK;
	vc_req->len = cipher->para.dst_data_len + INHDR_LEN;

	return 0;

error_exit:
	if (vc_req->wb)
		free_wb_data(vc_req->wb, vc_req->wb_pool);

	vc_req->len = INHDR_LEN;
	return ret;
}

static __rte_always_inline uint8_t
vhost_crypto_check_chain_request(struct virtio_crypto_alg_chain_data_req *req)
{
	if (likely((req->para.iv_len <= VHOST_CRYPTO_MAX_IV_LEN) &&
		(req->para.src_data_len <= VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.dst_data_len >= req->para.src_data_len) &&
		(req->para.dst_data_len <= VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.cipher_start_src_offset <
			VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.len_to_cipher <= VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.hash_start_src_offset <
			VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.len_to_hash <= VHOST_CRYPTO_MAX_DATA_SIZE) &&
		(req->para.cipher_start_src_offset + req->para.len_to_cipher <=
			req->para.src_data_len) &&
		(req->para.hash_start_src_offset + req->para.len_to_hash <=
			req->para.src_data_len) &&
		(req->para.dst_data_len + req->para.hash_result_len <=
			VHOST_CRYPTO_MAX_DATA_SIZE)))
		return VIRTIO_CRYPTO_OK;
	return VIRTIO_CRYPTO_BADMSG;
}

static __rte_always_inline uint8_t
prepare_sym_chain_op(struct vhost_crypto *vcrypto, struct rte_crypto_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_crypto_data_req *vc_req,
		struct virtio_crypto_alg_chain_data_req *chain,
		struct vhost_crypto_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_crypto_desc *desc = head, *digest_desc;
	struct vhost_crypto_writeback_data *ewb = NULL, *ewb2 = NULL;
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst = op->sym->m_dst;
	uint8_t *iv_data = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	uint32_t digest_offset;
	void *digest_addr;
	uint8_t ret = vhost_crypto_check_chain_request(chain);

	if (unlikely(ret != VIRTIO_CRYPTO_OK))
		goto error_exit;

	/* prepare */
	/* iv */
	if (unlikely(copy_data(iv_data, vcrypto->dev, vq, head, &desc,
			chain->para.iv_len, max_n_descs) < 0)) {
		VC_LOG_ERR("Incorrect virtio descriptor");
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
		m_src->data_len = chain->para.src_data_len;
		m_dst->data_len = chain->para.dst_data_len;

		rte_mbuf_iova_set(m_src,
				  gpa_to_hpa(vcrypto->dev, desc->addr, chain->para.src_data_len));
		m_src->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
		if (unlikely(rte_mbuf_iova_get(m_src) == 0 || m_src->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc, chain->para.src_data_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}
		break;
	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcrypto->wb_pool;
		m_src->data_len = chain->para.src_data_len;
		if (unlikely(copy_data(rte_pktmbuf_mtod(m_src, uint8_t *),
				vcrypto->dev, vq, head, &desc,
				chain->para.src_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_CRYPTO_BADMSG;
			goto error_exit;
		}

		break;
	default:
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	/* dst */
	desc = find_write_desc(head, desc, max_n_descs);
	if (unlikely(!desc)) {
		VC_LOG_ERR("Cannot find write location");
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
		rte_mbuf_iova_set(m_dst,
				  gpa_to_hpa(vcrypto->dev, desc->addr, chain->para.dst_data_len));
		m_dst->buf_addr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(rte_mbuf_iova_get(m_dst) == 0 || m_dst->buf_addr == NULL)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(vc_req->head, &desc,
				chain->para.dst_data_len, max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		op->sym->auth.digest.phys_addr = gpa_to_hpa(vcrypto->dev,
				desc->addr, chain->para.hash_result_len);
		op->sym->auth.digest.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
		if (unlikely(op->sym->auth.digest.phys_addr == 0)) {
			VC_LOG_ERR("zero_copy may fail due to cross page data");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(move_desc(head, &desc,
				chain->para.hash_result_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect descriptor");
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		break;
	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		vc_req->wb = prepare_write_back_data(vq, vc_req, head, &desc, &ewb,
				rte_pktmbuf_mtod(m_src, uint8_t *),
				chain->para.cipher_start_src_offset,
				chain->para.dst_data_len -
					chain->para.cipher_start_src_offset,
				max_n_descs);
		if (unlikely(vc_req->wb == NULL)) {
			ret = VIRTIO_CRYPTO_ERR;
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
			ret = VIRTIO_CRYPTO_ERR;
			goto error_exit;
		}

		if (unlikely(copy_data(digest_addr, vcrypto->dev, vq, head,
				&digest_desc, chain->para.hash_result_len,
				max_n_descs) < 0)) {
			VC_LOG_ERR("Incorrect virtio descriptor");
			ret = VIRTIO_CRYPTO_BADMSG;
			goto error_exit;
		}

		op->sym->auth.digest.data = digest_addr;
		op->sym->auth.digest.phys_addr = rte_pktmbuf_iova_offset(m_src,
				digest_offset);
		break;
	default:
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	/* record inhdr */
	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_CRYPTO_OK;

	op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;

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
prepare_asym_rsa_op(struct vhost_crypto *vcrypto, struct rte_crypto_op *op,
		struct vhost_virtqueue *vq,
		struct vhost_crypto_data_req *vc_req,
		struct virtio_crypto_op_data_req *req,
		struct vhost_crypto_desc *head,
		uint32_t max_n_descs)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct rte_crypto_rsa_op_param *rsa = &op->asym->rsa;
	struct vhost_crypto_desc *desc = head;
	uint8_t ret = VIRTIO_CRYPTO_ERR;
	uint16_t wlen = 0;
	/* prepare */
	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		vc_req->wb_pool = vcrypto->wb_pool;
		if (req->header.opcode == VIRTIO_CRYPTO_AKCIPHER_SIGN) {
			rsa->op_type = RTE_CRYPTO_ASYM_OP_SIGN;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.src_data_len;
			rsa->sign.length = req->u.akcipher_req.para.dst_data_len;
			wlen = rsa->sign.length;
			desc = find_write_desc(head, desc, max_n_descs);
			if (unlikely(!desc)) {
				VC_LOG_ERR("Cannot find write location");
				ret = VIRTIO_CRYPTO_BADMSG;
				goto error_exit;
			}

			rsa->sign.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
			if (unlikely(rsa->sign.data == NULL)) {
				ret = VIRTIO_CRYPTO_ERR;
				goto error_exit;
			}

			desc += 1;
		} else if (req->header.opcode == VIRTIO_CRYPTO_AKCIPHER_VERIFY) {
			rsa->op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
			rsa->sign.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->sign.length = req->u.akcipher_req.para.src_data_len;
			desc += 1;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.dst_data_len;
			desc += 1;
		} else if (req->header.opcode == VIRTIO_CRYPTO_AKCIPHER_ENCRYPT) {
			rsa->op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;
			rsa->message.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RO);
			rsa->message.length = req->u.akcipher_req.para.src_data_len;
			rsa->cipher.length = req->u.akcipher_req.para.dst_data_len;
			wlen = rsa->cipher.length;
			desc = find_write_desc(head, desc, max_n_descs);
			if (unlikely(!desc)) {
				VC_LOG_ERR("Cannot find write location");
				ret = VIRTIO_CRYPTO_BADMSG;
				goto error_exit;
			}

			rsa->cipher.data = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_RW);
			if (unlikely(rsa->cipher.data == NULL)) {
				ret = VIRTIO_CRYPTO_ERR;
				goto error_exit;
			}

			desc += 1;
		} else if (req->header.opcode == VIRTIO_CRYPTO_AKCIPHER_DECRYPT) {
			rsa->op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;
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
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
	default:
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	op->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
	op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;

	vc_req->inhdr = get_data_ptr(vq, vc_req, desc, VHOST_ACCESS_WO);
	if (unlikely(vc_req->inhdr == NULL)) {
		ret = VIRTIO_CRYPTO_BADMSG;
		goto error_exit;
	}

	vc_req->inhdr->status = VIRTIO_CRYPTO_OK;
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
vhost_crypto_process_one_req(struct vhost_crypto *vcrypto,
		struct vhost_virtqueue *vq, struct rte_crypto_op *op,
		struct vring_desc *head, struct vhost_crypto_desc *descs,
		uint16_t desc_idx)
	__rte_requires_shared_capability(&vq->iotlb_lock)
{
	struct vhost_crypto_data_req *vc_req, *vc_req_out;
	struct rte_cryptodev_asym_session *asym_session;
	struct rte_cryptodev_sym_session *sym_session;
	struct vhost_crypto_data_req data_req = {0};
	struct vhost_crypto_session *vhost_session;
	struct vhost_crypto_desc *desc = descs;
	uint32_t nb_descs = 0, max_n_descs = 0, i;
	struct virtio_crypto_op_data_req req;
	struct virtio_crypto_inhdr *inhdr;
	struct vring_desc *src_desc;
	uint64_t session_id;
	uint64_t dlen;
	int err;

	vc_req = &data_req;
	vc_req->desc_idx = desc_idx;
	vc_req->dev = vcrypto->dev;          /* IOVA_TO_VVA 等还会用到 */
    vc_req->vq  = vq;
	vc_req->vcrypto = vcrypto;           /* 新增：用于 completion 时做 inflight-- */


	if (unlikely((head->flags & VRING_DESC_F_INDIRECT) == 0)) {
        VC_LOG_ERR("Invalid descriptor");
        err = VIRTIO_CRYPTO_BADMSG;
        goto error_exit;
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
	if (unlikely(nb_descs > VHOST_CRYPTO_MAX_N_DESC || nb_descs == 0)) {
		err = VIRTIO_CRYPTO_ERR;
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
			inhdr = IOVA_TO_VVA(struct virtio_crypto_inhdr *, vc_req->dev,
					vq, inhdr_desc->addr, &dlen,
					VHOST_ACCESS_WO);
			if (unlikely(!inhdr || dlen != inhdr_desc->len))
				return -1;
			inhdr->status = VIRTIO_CRYPTO_ERR;
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
			err = VIRTIO_CRYPTO_BADMSG;
			VC_LOG_ERR("Invalid descriptor");
			goto error_exit;
		}
		src_desc = &head[src_desc->next];
	}

	vc_req->head = head;
	vc_req->zero_copy = vcrypto->option;

	nb_descs = desc - descs;
	desc = descs;

	if (unlikely(desc->len < sizeof(req))) {
		err = VIRTIO_CRYPTO_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	if (unlikely(copy_data(&req, vcrypto->dev, vq, descs, &desc, sizeof(req),
			max_n_descs) < 0)) {
		err = VIRTIO_CRYPTO_BADMSG;
		VC_LOG_ERR("Invalid descriptor");
		goto error_exit;
	}

	/* desc is advanced by 1 now */
	max_n_descs -= 1;

	switch (req.header.opcode) {
	case VIRTIO_CRYPTO_CIPHER_ENCRYPT:
	case VIRTIO_CRYPTO_CIPHER_DECRYPT:
		vc_req_out = rte_mbuf_to_priv(op->sym->m_src);
		memcpy(vc_req_out, vc_req, sizeof(struct vhost_crypto_data_req));
		session_id = req.header.session_id;

		/* one branch to avoid unnecessary table lookup */
		if (vcrypto->cache_sym_session_id != session_id) {
			err = rte_hash_lookup_data(vcrypto->session_map,
					&session_id, (void **)&vhost_session);
			if (unlikely(err < 0)) {
				err = VIRTIO_CRYPTO_ERR;
				VC_LOG_ERR("Failed to find session %"PRIu64,
						session_id);
				goto error_exit;
			}

			vcrypto->cache_sym_session = vhost_session->sym;
			vcrypto->cache_sym_session_id = session_id;
		}

		sym_session = vcrypto->cache_sym_session;
		op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;

		err = rte_crypto_op_attach_sym_session(op, sym_session);
		if (unlikely(err < 0)) {
			err = VIRTIO_CRYPTO_ERR;
			VC_LOG_ERR("Failed to attach session to op");
			goto error_exit;
		}

		switch (req.u.sym_req.op_type) {
		case VIRTIO_CRYPTO_SYM_OP_NONE:
			err = VIRTIO_CRYPTO_NOTSUPP;
			break;
		case VIRTIO_CRYPTO_SYM_OP_CIPHER:
			err = prepare_sym_cipher_op(vcrypto, op, vq, vc_req_out,
					&req.u.sym_req.u.cipher, desc,
					max_n_descs);
			break;
		case VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING:
			err = prepare_sym_chain_op(vcrypto, op, vq, vc_req_out,
					&req.u.sym_req.u.chain, desc,
					max_n_descs);
			break;
		}
		if (unlikely(err != 0)) {
			VC_LOG_ERR("Failed to process sym request");
			goto error_exit;
		}
		break;
	case VIRTIO_CRYPTO_AKCIPHER_SIGN:
	case VIRTIO_CRYPTO_AKCIPHER_VERIFY:
	case VIRTIO_CRYPTO_AKCIPHER_ENCRYPT:
	case VIRTIO_CRYPTO_AKCIPHER_DECRYPT:
		session_id = req.header.session_id;

		/* one branch to avoid unnecessary table lookup */
		if (vcrypto->cache_asym_session_id != session_id) {
			err = rte_hash_lookup_data(vcrypto->session_map,
					&session_id, (void **)&vhost_session);
			if (unlikely(err < 0)) {
				err = VIRTIO_CRYPTO_ERR;
				VC_LOG_ERR("Failed to find asym session %"PRIu64,
						   session_id);
				goto error_exit;
			}

			vcrypto->cache_asym_session = vhost_session->asym;
			vcrypto->cache_asym_session_id = session_id;
		}

		asym_session = vcrypto->cache_asym_session;
		op->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;

		err = rte_crypto_op_attach_asym_session(op, asym_session);
		if (unlikely(err < 0)) {
			err = VIRTIO_CRYPTO_ERR;
			VC_LOG_ERR("Failed to attach asym session to op");
			goto error_exit;
		}

		// vc_req_out = rte_cryptodev_asym_session_get_user_data(asym_session);
		vc_req_out = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET + VHOST_CRYPTO_MAX_IV_LEN);
		rte_memcpy(vc_req_out, vc_req, sizeof(struct vhost_crypto_data_req));
		vc_req_out->wb = NULL;

		switch (req.header.algo) {
		case VIRTIO_CRYPTO_AKCIPHER_RSA:
			err = prepare_asym_rsa_op(vcrypto, op, vq, vc_req_out,
					&req, desc, max_n_descs);
			break;
		}
		if (unlikely(err != 0)) {
			VC_LOG_ERR("Failed to process asym request");
			goto error_exit;
		}

		break;
	default:
		err = VIRTIO_CRYPTO_ERR;
		VC_LOG_ERR("Unsupported symmetric crypto request type %u",
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
vhost_crypto_finalize_one_request(struct rte_crypto_op *op,
		struct vhost_virtqueue *old_vq)
{
	struct rte_mbuf *m_src = NULL, *m_dst = NULL;
	struct vhost_crypto_data_req *vc_req;
	struct vhost_virtqueue *vq;
	uint16_t used_idx, desc_idx;

	if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
		m_src = op->sym->m_src;
		m_dst = op->sym->m_dst;
		vc_req = rte_mbuf_to_priv(m_src);
	} else if (op->type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC) {
		// vc_req = rte_cryptodev_asym_session_get_user_data(op->asym->session);
		vc_req = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET + VHOST_CRYPTO_MAX_IV_LEN);
	} else {
		VC_LOG_ERR("Invalid crypto op type");
		return NULL;
	}

	if (unlikely(!vc_req)) {
		VC_LOG_ERR("Failed to retrieve vc_req");
		return NULL;
	}
	vq = vc_req->vq;
	used_idx = vc_req->desc_idx;

	/* vring pointers may be temporarily invalid during migration/reconnect */
	if (unlikely(vq == NULL || vq->avail == NULL || vq->used == NULL ||
			used_idx >= vq->size || rte_rwlock_read_trylock(&vq->access_lock) != 0)) {
		/* Cannot safely write back to vring: mark request failed but avoid deref */
		vc_req->inhdr->status = VIRTIO_CRYPTO_ERR;
		goto out_recycle;
	}

	vhost_user_iotlb_rd_lock(vq);
	if (unlikely(!vq->access_ok)) {
		vhost_user_iotlb_rd_unlock(vq);
		rte_rwlock_read_unlock(&vq->access_lock);
		vc_req->inhdr->status = VIRTIO_CRYPTO_ERR;
		goto out_recycle;
	}
	vhost_user_iotlb_rd_unlock(vq);

	if (old_vq && (vq != old_vq)) {
		rte_rwlock_read_unlock(&vq->access_lock);
		return vq;
	}

	if (unlikely(op->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
		vc_req->inhdr->status = VIRTIO_CRYPTO_ERR;
	else {
		if (vc_req->zero_copy == 0)
			write_back_data(vc_req);
	}

	desc_idx = vq->avail->ring[used_idx];
	vq->used->ring[desc_idx].id = vq->avail->ring[desc_idx];
	vq->used->ring[desc_idx].len = vc_req->len;
	
	rte_rwlock_read_unlock(&vq->access_lock);

	if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
		rte_mempool_put(m_src->pool, (void *)m_src);
		if (m_dst)
			rte_mempool_put(m_dst->pool, (void *)m_dst);
	}

	return vq;

out_recycle:
	if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
		rte_mempool_put(m_src->pool, (void *)m_src);
		if (m_dst)
			rte_mempool_put(m_dst->pool, (void *)m_dst);
	}
	return NULL;
}

static __rte_always_inline uint16_t
vhost_crypto_complete_one_vm_requests(struct rte_crypto_op **ops,
		uint16_t nb_ops, int *callfd)
{
	uint16_t processed = 1;
	struct vhost_virtqueue *vq, *tmp_vq;

	if (unlikely(nb_ops == 0))
		return 0;

	vq = vhost_crypto_finalize_one_request(ops[0], NULL);
	if (unlikely(vq == NULL))
		return 0;
	tmp_vq = vq;

	while ((processed < nb_ops)) {
		tmp_vq = vhost_crypto_finalize_one_request(ops[processed],
				tmp_vq);

		if (unlikely(vq != tmp_vq))
			break;

		processed++;
	}

	*callfd = vq->callfd;

	*(volatile uint16_t *)&vq->used->idx += processed;
	vq->last_used_idx += processed;
	/* inflight accounting: only decrement AFTER used->idx is updated */
	if (likely(processed != 0)) {
		struct rte_mbuf *m_src = ops[0]->sym ? ops[0]->sym->m_src : NULL;
		struct vhost_crypto_data_req *vc_req = m_src ? rte_mbuf_to_priv(m_src) : NULL;
		struct vhost_crypto *vcrypto = vc_req ? vc_req->vcrypto : NULL;

		if (likely(vcrypto)) {
			uint32_t cur = __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE);
			if (unlikely(cur < processed)) {
				VC_LOG_ERR("inflight underflow cur=%u sub=%u (BUG)", cur, processed);
				__atomic_store_n(&vcrypto->inflight_corrupt, 1, __ATOMIC_RELEASE);
				__atomic_store_n(&vcrypto->inflight, 0, __ATOMIC_RELEASE);
			} else {
				__atomic_fetch_sub(&vcrypto->inflight, processed, __ATOMIC_ACQ_REL);
			}
		} else {
			VC_LOG_ERR("inflight sub skipped: missing vcrypto in op priv (BUG)");
		}
	}

	return processed;
}

RTE_EXPORT_SYMBOL(rte_vhost_crypto_driver_start)
int
rte_vhost_crypto_driver_start(const char *path)
{
	uint64_t protocol_features;
	int ret;

	ret = rte_vhost_driver_set_features(path, VIRTIO_CRYPTO_FEATURES);
	if (ret)
		return -1;

	ret = rte_vhost_driver_get_protocol_features(path, &protocol_features);
	if (ret)
		return -1;
	//protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_CONFIG);
	ret = rte_vhost_driver_set_protocol_features(path, protocol_features);
	if (ret)
		return -1;

	return rte_vhost_driver_start(path);
}

RTE_EXPORT_SYMBOL(rte_vhost_crypto_create)
int
rte_vhost_crypto_create(int vid, uint8_t cryptodev_id,
		struct rte_mempool *sess_pool,
		int socket_id)
{
	struct virtio_net *dev = get_device(vid);
	struct rte_hash_parameters params = {0};
	struct vhost_crypto *vcrypto;
	char name[128];
	int ret;

	if (!dev) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	vcrypto = rte_zmalloc_socket(NULL, sizeof(*vcrypto),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!vcrypto) {
		VC_LOG_ERR("Insufficient memory");
		return -ENOMEM;
	}

	vcrypto->sess_pool = sess_pool;
	vcrypto->cid = cryptodev_id;
	vcrypto->cache_sym_session_id = UINT64_MAX;
	vcrypto->cache_asym_session_id = UINT64_MAX;
	vcrypto->last_session_id = 1;
	vcrypto->dev = dev;
	vcrypto->option = RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE;

	/* pending-load init (for deferred CRYPTO_LOAD) */
	rte_spinlock_init(&vcrypto->pending_lock);
	vcrypto->pending_load_buf = NULL;
	vcrypto->pending_load_len = 0;
	vcrypto->pending_load_valid = 0;

	snprintf(name, 127, "HASH_VHOST_CRYPT_%u", (uint32_t)vid);
	params.name = name;
	params.entries = VHOST_CRYPTO_SESSION_MAP_ENTRIES;
	params.hash_func = rte_jhash;
	params.key_len = sizeof(uint64_t);
	params.socket_id = socket_id;
	vcrypto->session_map = rte_hash_create(&params);
	if (!vcrypto->session_map) {
		VC_LOG_ERR("Failed to create session map");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "MBUF_POOL_VM_%u", (uint32_t)vid);
	vcrypto->mbuf_pool = rte_pktmbuf_pool_create(name,
			VHOST_CRYPTO_MBUF_POOL_SIZE, 512,
			sizeof(struct vhost_crypto_data_req),
			VHOST_CRYPTO_MAX_DATA_SIZE + RTE_PKTMBUF_HEADROOM,
			rte_socket_id());
	if (!vcrypto->mbuf_pool) {
		VC_LOG_ERR("Failed to create mbuf pool");
		ret = -ENOMEM;
		goto error_exit;
	}

	snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
	vcrypto->wb_pool = rte_mempool_create(name,
			VHOST_CRYPTO_MBUF_POOL_SIZE,
			sizeof(struct vhost_crypto_writeback_data),
			128, 0, NULL, NULL, NULL, NULL,
			rte_socket_id(), 0);
	if (!vcrypto->wb_pool) {
		VC_LOG_ERR("Failed to create mempool");
		ret = -ENOMEM;
		goto error_exit;
	}

	dev->extern_data = vcrypto;
	dev->extern_ops.pre_msg_handle = vhost_crypto_msg_pre_handler;;
	dev->extern_ops.post_msg_handle = vhost_crypto_msg_post_handler;

	return 0;

error_exit:
	/* pending buffer cleanup */
	rte_spinlock_lock(&vcrypto->pending_lock);
	if (vcrypto->pending_load_valid && vcrypto->pending_load_buf) {
		rte_free(vcrypto->pending_load_buf);
		vcrypto->pending_load_buf = NULL;
		vcrypto->pending_load_len = 0;
		vcrypto->pending_load_valid = 0;
	}
	rte_spinlock_unlock(&vcrypto->pending_lock);

	if (vcrypto->session_map)
		rte_hash_free(vcrypto->session_map);
	if (vcrypto->mbuf_pool)
		rte_mempool_free(vcrypto->mbuf_pool);
	if (vcrypto->wb_pool)
		rte_mempool_free(vcrypto->wb_pool);

	rte_free(vcrypto);

	return ret;
}

RTE_EXPORT_SYMBOL(rte_vhost_crypto_free)
int
rte_vhost_crypto_free(int vid)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_crypto *vcrypto;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	vcrypto = dev->extern_data;
	if (unlikely(vcrypto == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return -ENOENT;
	}

	/* free pending load buffer if any */
	rte_spinlock_lock(&vcrypto->pending_lock);
	if (vcrypto->pending_load_valid && vcrypto->pending_load_buf) {
		rte_free(vcrypto->pending_load_buf);
		vcrypto->pending_load_buf = NULL;
		vcrypto->pending_load_len = 0;
		vcrypto->pending_load_valid = 0;
	}
	rte_spinlock_unlock(&vcrypto->pending_lock);

	rte_hash_free(vcrypto->session_map);
	rte_mempool_free(vcrypto->mbuf_pool);
	rte_mempool_free(vcrypto->wb_pool);
	rte_free(vcrypto);

	dev->extern_data = NULL;
	dev->extern_ops.pre_msg_handle = NULL;
	dev->extern_ops.post_msg_handle = NULL;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vhost_crypto_set_zero_copy)
int
rte_vhost_crypto_set_zero_copy(int vid, enum rte_vhost_crypto_zero_copy option)
{
	struct virtio_net *dev = get_device(vid);
	struct vhost_crypto *vcrypto;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return -EINVAL;
	}

	if (unlikely((uint32_t)option >=
				RTE_VHOST_CRYPTO_MAX_ZERO_COPY_OPTIONS)) {
		VC_LOG_ERR("Invalid option %i", option);
		return -EINVAL;
	}

	vcrypto = (struct vhost_crypto *)dev->extern_data;
	if (unlikely(vcrypto == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return -ENOENT;
	}

	if (vcrypto->option == (uint8_t)option)
		return 0;

	if (!(rte_mempool_full(vcrypto->mbuf_pool)) ||
			!(rte_mempool_full(vcrypto->wb_pool))) {
		VC_LOG_ERR("Cannot update zero copy as mempool is not full");
		return -EINVAL;
	}

	if (option == RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE) {
		char name[128];

		snprintf(name, 127, "WB_POOL_VM_%u", (uint32_t)vid);
		vcrypto->wb_pool = rte_mempool_create(name,
				VHOST_CRYPTO_MBUF_POOL_SIZE,
				sizeof(struct vhost_crypto_writeback_data),
				128, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), 0);
		if (!vcrypto->wb_pool) {
			VC_LOG_ERR("Failed to create mbuf pool");
			return -ENOMEM;
		}
	} else {
		rte_mempool_free(vcrypto->wb_pool);
		vcrypto->wb_pool = NULL;
	}

	vcrypto->option = (uint8_t)option;

	return 0;
}

static inline void
vhost_crypto_dump_ready(struct virtio_net *dev, uint32_t qid)
{
    struct vhost_virtqueue *vq = (dev && qid < dev->nr_vring) ? dev->virtqueue[qid] : NULL;

    VC_LOG_INFO("READYCHK: mem=%p nreg=%u vq=%p size=%u desc=%p avail=%p used=%p kick=%d call=%d ready=%d access_ok=%d",
        dev ? dev->mem : NULL,
        (dev && dev->mem) ? dev->mem->nregions : 0,
        vq,
        vq ? vq->size : 0,
        vq ? vq->desc : NULL,
        vq ? vq->avail : NULL,
        vq ? vq->used : NULL,
        vq ? vq->kickfd : -1,
        vq ? vq->callfd : -1,
        vq ? vq->ready : 0,
        vq ? vq->access_ok : 0);
}

static inline int
vhost_crypto_device_ready(struct virtio_net *dev)
{
    if (!dev || !dev->mem || dev->mem->nregions == 0)
        return 0;

    if (dev->nr_vring == 0)
        return 0;

    struct vhost_virtqueue *vq = dev->virtqueue[0];
    if (!vq)
        return 0;

    /* SET_VRING_NUM */
    if (vq->size == 0)
        return 0;

    /* split ring 必须要有这三个 */
    if (!vq->desc || !vq->avail || !vq->used)
        return 0;

    /* mem translation + access */
    if (!vq->ready || !vq->access_ok)
        return 0;

    return 1;
}


RTE_EXPORT_SYMBOL(rte_vhost_crypto_fetch_requests)
uint16_t
rte_vhost_crypto_fetch_requests(int vid, uint32_t qid,
		struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct rte_mbuf *mbufs[VHOST_CRYPTO_MAX_BURST_SIZE * 2];
	struct vhost_crypto_desc descs[VHOST_CRYPTO_MAX_N_DESC];
	struct virtio_net *dev = get_device(vid);
	struct vhost_crypto *vcrypto;
	struct vhost_virtqueue *vq;
	uint16_t avail_idx;
	uint16_t start_idx;
	uint16_t count;
	uint16_t i = 0;

	if (unlikely(dev == NULL)) {
		VC_LOG_ERR("Invalid vid %i", vid);
		return 0;
	}
	

	vq = dev->virtqueue[qid];
	if (unlikely(vq == NULL))
		return 0;

	/* vring 未 ready/access_ok，不允许抓取 */
	if (unlikely(!vq->ready || !vq->access_ok))
		return 0;

	if (unlikely(qid >= VHOST_MAX_QUEUE_PAIRS)) {
		VC_LOG_ERR("Invalid qid %u", qid);
		return 0;
	}

	vcrypto = (struct vhost_crypto *)dev->extern_data;
	if (unlikely(vcrypto == NULL)) {
		VC_LOG_ERR("Cannot find required data, is it initialized?");
		return 0;
	}
	/* ✅ FREEZE 语义：冻结时不抓取新 descriptor（纯 backpressure，不改 vring 索引） */
	if (unlikely(__atomic_load_n(&vcrypto->frozen, __ATOMIC_ACQUIRE))) {
		return 0;
	}

	vq = dev->virtqueue[qid];

	if (unlikely(vq == NULL)) {
		VC_LOG_ERR("TAG_FETCH_INVALID_VQ vid=%d qid=%u flags=0x%x dev=%p vq=%p",
           vid, qid, dev->flags, dev, vq);
		   VC_LOG_ERR("TAG_FETCH_INVALID_VQ_MORE vid=%d qid=%u extern=%p frozen=%d inflight=%u",
           vid, qid, dev->extern_data,
           dev->extern_data ? ((struct vhost_crypto*)dev->extern_data)->frozen : -1,
           dev->extern_data ? __atomic_load_n(&((struct vhost_crypto*)dev->extern_data)->inflight, __ATOMIC_ACQUIRE) : 0);
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
	start_idx = vq->last_avail_idx;
	count = avail_idx - start_idx;
	count = RTE_MIN(count, VHOST_CRYPTO_MAX_BURST_SIZE);
	count = RTE_MIN(count, nb_ops);

	if (unlikely(count == 0))
		goto out_unlock;

	/* for zero copy, we need 2 empty mbufs for src and dst, otherwise
	 * we need only 1 mbuf as src and dst
	 */
	switch (vcrypto->option) {
	case RTE_VHOST_CRYPTO_ZERO_COPY_ENABLE:
		if (unlikely(rte_mempool_get_bulk(vcrypto->mbuf_pool,
				(void **)mbufs, count * 2) < 0)) {
			VC_LOG_ERR("Insufficient memory");
			goto out_unlock;
		}

		for (i = 0; i < count; i++) {
			uint16_t used_idx = (start_idx + i) & (vq->size - 1);
			uint16_t desc_idx = vq->avail->ring[used_idx];
			struct vring_desc *head = &vq->desc[desc_idx];
			struct rte_crypto_op *op = ops[i];

			op->sym->m_src = mbufs[i * 2];
			op->sym->m_dst = mbufs[i * 2 + 1];
			op->sym->m_src->data_off = 0;
			op->sym->m_dst->data_off = 0;

			if (unlikely(vhost_crypto_process_one_req(vcrypto, vq,
					op, head, descs, used_idx) < 0))
				break;
		}

		if (unlikely(i < count))
			rte_mempool_put_bulk(vcrypto->mbuf_pool,
					(void **)&mbufs[i * 2],
					(count - i) * 2);

		break;

	case RTE_VHOST_CRYPTO_ZERO_COPY_DISABLE:
		if (unlikely(rte_mempool_get_bulk(vcrypto->mbuf_pool,
				(void **)mbufs, count) < 0)) {
			VC_LOG_ERR("Insufficient memory");
			goto out_unlock;
		}

		for (i = 0; i < count; i++) {
			uint16_t used_idx = (start_idx + i) & (vq->size - 1);
			uint16_t desc_idx = vq->avail->ring[used_idx];
			struct vring_desc *head = &vq->desc[desc_idx];
			struct rte_crypto_op *op = ops[i];

			op->sym->m_src = mbufs[i];
			op->sym->m_dst = NULL;
			op->sym->m_src->data_off = 0;

			if (unlikely(vhost_crypto_process_one_req(vcrypto, vq,
					op, head, descs, used_idx) < 0))
				break;
		}

		if (unlikely(i < count))
			rte_mempool_put_bulk(vcrypto->mbuf_pool,
					(void **)&mbufs[i],
					count - i);

		break;
	default:
		VC_LOG_ERR("Unknown zero-copy option %d", vcrypto->option);
		goto out_unlock;

	}

	vq->last_avail_idx += i;
	/* inflight accounting: ops fetched => now owned by backend until completion */
	if (likely(i != 0)) {
		__atomic_fetch_add(&vcrypto->inflight, i, __ATOMIC_ACQ_REL);
	}
out_unlock:
	vhost_user_iotlb_rd_unlock(vq);
	rte_rwlock_read_unlock(&vq->access_lock);

	return i;
}

RTE_EXPORT_SYMBOL(rte_vhost_crypto_finalize_requests)
uint16_t
rte_vhost_crypto_finalize_requests(struct rte_crypto_op **ops,
		uint16_t nb_ops, int *callfds, uint16_t *nb_callfds)
{
	struct rte_crypto_op **tmp_ops = ops;
	uint16_t count = 0, left = nb_ops;
	int callfd;
	uint16_t idx = 0;

	while (left) {
		count = vhost_crypto_complete_one_vm_requests(tmp_ops, left,
				&callfd);
		if (unlikely(count == 0)) {
			VC_LOG_ERR("TAG_FINALIZE_STUCK nb_ops=%u left=%u (likely vring not ready / stopped)",
					nb_ops, left);
			break;
		}
			break;

		tmp_ops = &tmp_ops[count];
		left -= count;

		callfds[idx++] = callfd;

		if (unlikely(idx >= VIRTIO_CRYPTO_MAX_NUM_BURST_VQS)) {
			VC_LOG_ERR("Too many vqs");
			break;
		}
	}

	*nb_callfds = idx;

	return nb_ops - left;
}

/* --- inflight accounting helpers (called by the worker) --- */
void vhost_crypto_inflight_add(int vid, uint32_t n)
{
    if (n == 0) {
        return;
    }

    struct virtio_net *dev = get_device(vid);
    if (!dev || !dev->extern_data) {
        return;
    }

    struct vhost_crypto *vcrypto = dev->extern_data;
    __atomic_fetch_add(&vcrypto->inflight, n, __ATOMIC_ACQ_REL);
}

void vhost_crypto_inflight_sub(int vid, uint32_t n)
{
    if (n == 0) {
        return;
    }

    struct virtio_net *dev = get_device(vid);
    if (!dev || !dev->extern_data) {
        return;
    }

    struct vhost_crypto *vcrypto = dev->extern_data;

    uint32_t cur = __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE);
    while (1) {
        if (unlikely(cur < n)) {
            VC_LOG_ERR("inflight underflow vid=%d cur=%u sub=%u (BUG)", vid, cur, n);
            __atomic_store_n(&vcrypto->inflight_corrupt, 1, __ATOMIC_RELEASE);
            /* Avoid wrap-around; keep system running but mark state as unsafe */
            if (__atomic_compare_exchange_n(&vcrypto->inflight, &cur, 0,
                                            false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                break;
            }
            continue;
        }

        uint32_t next = cur - n;
        if (__atomic_compare_exchange_n(&vcrypto->inflight, &cur, next,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            break;
        }
		/* cur updated on failure */
    }
}


int vhost_crypto_freeze(int vid) {
    struct virtio_net *dev = get_device(vid);
    if (!dev || !dev->extern_data)
        return -ENOENT;
    struct vhost_crypto *vcrypto = dev->extern_data;

    if (unlikely(__atomic_load_n(&vcrypto->inflight_corrupt, __ATOMIC_ACQUIRE))) {
        VC_LOG_ERR("FREEZE refused: inflight accounting corrupt (vid=%d)", vid);
        return -EIO;
    }	
    /* Step 1: 设置冻结位，阻断新请求进入 */
    __atomic_store_n(&vcrypto->frozen, 1, __ATOMIC_RELEASE);
	VC_LOG_INFO("FREEZE_BEGIN vid=%d ts_ms=%llu",
            vid, (unsigned long long)(rte_get_timer_cycles() * 1000ULL / rte_get_timer_hz()));
	VC_LOG_INFO("TAG_FREEZE_STATE vid=%d frozen=%d inflight=%u",
            vid, vcrypto->frozen,
            __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE));
    /* Step 2: 等待所有 inflight 请求完成（有界等待） */
    const uint64_t hz = rte_get_timer_hz();
    const uint64_t start = rte_get_timer_cycles();
    const uint64_t deadline = start + 3 * hz;  // 最多等 3 秒
    uint32_t last_inflight = UINT32_MAX;

    while (1) {
        uint32_t cur = __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE);
        if (cur == 0) {
            VC_LOG_INFO("FREEZE_OK vid=%d ts_ms=%llu",
            vid, (unsigned long long)(rte_get_timer_cycles() * 1000ULL / rte_get_timer_hz()));
		    break; /* quiescent state reached */
        }

        /* 打印进度日志（只在 inflight 变化时输出） */
        if (cur != last_inflight) {
            VC_LOG_INFO("FREEZE_DRAIN vid=%d inflight=%u ts_ms=%llu",
            vid, cur, (unsigned long long)(rte_get_timer_cycles() * 1000ULL / rte_get_timer_hz()));
            last_inflight = cur;
        }

        /* 超时退出 */
        if (rte_get_timer_cycles() > deadline) {
			VC_LOG_ERR("FREEZE timeout; inflight still=%u", cur);
			__atomic_store_n(&vcrypto->frozen, 0, __ATOMIC_RELEASE); /* 回滚服务 */
			return -EBUSY;
		}

        /* 小延迟防止忙等 */
        rte_delay_us_block(10);
    }

	return 0;
}

static void dump_hex(const void *buf, size_t len) {
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) fprintf(stderr, "%04zx: ", i);
        fprintf(stderr, "%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) fprintf(stderr, "\n");
    }
}

/* 把 vcrypto 的状态序列化到 buf；成功返回写入字节数，失败返回负错码 */
static int
vhost_crypto_save_state_mem(struct vhost_crypto *vcrypto, void *buf, size_t buf_len)
{
    uint8_t *p = buf, *end = (uint8_t*)buf + buf_len;
    if (buf_len < sizeof(struct vc_snap_hdr)) return -ENOSPC;

    struct vc_snap_hdr *hdr = (struct vc_snap_hdr *)p;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic   = TOLE32(VC_SNAP_MAGIC);
    hdr->version = TOLE16(1);
    hdr->hdr_len = TOLE16(sizeof(*hdr));
    p += sizeof(*hdr);

    // ---- DEV_META ----
    struct vc_dev_meta_v1 meta = {
		.cid= vcrypto->cid,          /* for validation/debug */
        .last_session_id = vcrypto->last_session_id,
    };
    if (end - p < (ptrdiff_t)(sizeof(struct vc_tlv) + sizeof(meta))) return -ENOSPC;

    struct vc_tlv *tlv = (struct vc_tlv *)p;
    tlv->type = TOLE16(VC_TLV_DEV_META);
    tlv->rsvd = 0;
    tlv->len  = TOLE32((uint32_t)sizeof(meta));
    p += sizeof(*tlv);
    memcpy(p, &meta, sizeof(meta));
    p += sizeof(meta);

    fprintf(stderr, "[save_state] DEV_META: last_session_id=%lu\n", meta.last_session_id);

    // ---- SESSION TLVs ----
    uint32_t iter = 0;
    const void *k;
    void *d;
    while (rte_hash_iterate(vcrypto->session_map, &k, &d, &iter) >= 0) {
        struct vhost_crypto_session *s = (struct vhost_crypto_session *)d;
        if (!s || !s->meta.valid) continue;

        uint32_t desc_len, blob_len;
        if (s->meta.kind == VC_SESS_SYM) {
            desc_len = sizeof(s->meta.sym.desc);
            blob_len = s->meta.sym.b.blob_len;
        } else {
            desc_len = sizeof(s->meta.asym.desc);
            blob_len = s->meta.asym.b.blob_len;
        }

        struct vc_sess_head_v1 sh = {
            .session_id = TOLE64(s->meta.session_id),
            .kind       = s->meta.kind,
            .flags      = 0,
        };

        uint32_t vlen = (uint32_t)(sizeof(sh) + desc_len + blob_len);
        if (end - p < (ptrdiff_t)(sizeof(struct vc_tlv) + vlen)) return -ENOSPC;

        tlv = (struct vc_tlv *)p;
        tlv->type = TOLE16(VC_TLV_SESSION);
        tlv->rsvd = 0;
        tlv->len  = TOLE32(vlen);
        p += sizeof(*tlv);

        uint8_t *tlv_body_start = p;
        memcpy(p, &sh, sizeof(sh)); p += sizeof(sh);
        if (s->meta.kind == VC_SESS_SYM) {
            memcpy(p, &s->meta.sym.desc, desc_len); p += desc_len;
            if (blob_len) {
				memcpy(p, s->meta.sym.b.blob, blob_len);
			}
			p += blob_len;
        } else {
            memcpy(p, &s->meta.asym.desc, desc_len); p += desc_len;
            if (blob_len) {
				memcpy(p, s->meta.asym.b.blob, blob_len);
			}
			p += blob_len;
        }

        fprintf(stderr, "[save_state] SESSION: sid=%lu kind=%u desc_len=%u blob_len=%u total=%u\n",
                s->meta.session_id, s->meta.kind, desc_len, blob_len, vlen);
        dump_hex(tlv_body_start, vlen);
    }

    uint32_t pay = (uint32_t)((uintptr_t)p - (uintptr_t)buf - sizeof(*hdr));
    hdr->payload_len = TOLE32(pay);
    hdr->crc32 = TOLE32(vc_crc32((uint8_t*)buf + sizeof(*hdr), pay));

    fprintf(stderr, "[save_state] snapshot done. total=%td payload=%u\n",
            (uintptr_t)p - (uintptr_t)buf, pay);
    dump_hex(buf, (uintptr_t)p - (uintptr_t)buf);

    return (int)((uintptr_t)p - (uintptr_t)buf);
}

static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EIO;   /* EOF before we got enough */
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}


static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EIO;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int vhost_crypto_save_state(int vid, int fd)
{
    struct vhost_crypto *vcrypto = vc_lookup(vid);
    if (!vcrypto) return -ENOENT;

    size_t cap = 256 * 1024;
    const size_t cap_max = 32 * 1024 * 1024;
    void *buf = NULL;
    int nbytes = -1;

    for (;;) {
        if (buf) rte_free(buf);
        buf = rte_zmalloc(NULL, cap, 0);
        if (!buf) return -ENOMEM;

        nbytes = vhost_crypto_save_state_mem(vcrypto, buf, cap);
        if (nbytes == -ENOSPC) {
            if (cap >= cap_max) { rte_free(buf); return -ENOSPC; }
            cap <<= 1;
            continue;
        }
        break;
    }

    if (nbytes < 0) { rte_free(buf); return nbytes; }

    int rc = write_full(fd, buf, (size_t)nbytes);
    rte_free(buf);
    return rc;
}

static inline void
vc_session_destroy(struct vhost_crypto *vcrypto, struct vhost_crypto_session *vs)
{
    if (!vs) return;

    /* 1) free meta blob (wiping) */
    if (vs->meta.valid) {
        if (vs->meta.kind == VC_SESS_SYM) {
            secure_free(vs->meta.sym.b.blob, vs->meta.sym.b.blob_len);
            vs->meta.sym.b.blob = NULL;
            vs->meta.sym.b.blob_len = 0;
        } else if (vs->meta.kind == VC_SESS_ASYM) {
            secure_free(vs->meta.asym.b.blob, vs->meta.asym.b.blob_len);
            vs->meta.asym.b.blob = NULL;
            vs->meta.asym.b.blob_len = 0;
        }
        vs->meta.valid = false;
    }

    /* 2) free dpdk session */
    if (vs->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
        if (vs->sym) {
            rte_cryptodev_sym_session_free(vcrypto->cid, vs->sym);
            vs->sym = NULL;
        }
    } else if (vs->type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC) {
        if (vs->asym) {
            rte_cryptodev_asym_session_free(vcrypto->cid, vs->asym);
            vs->asym = NULL;
        }
    }

    /* 3) free container */
    rte_free(vs);
}


static struct vhost_crypto_session*
vc_session_create_sym(struct vhost_crypto *vcrypto, uint64_t sid,
                      const struct vc_sym_meta_v1 *D,
                      const void *blob, uint32_t blob_len)
{
    /* 0) 将 D(快照里的 meta) 解释为 DPDK 可用的 enum：禁止直接强转 */
    enum rte_crypto_cipher_algorithm dpdk_cipher_algo = 0;
    enum rte_crypto_auth_algorithm   dpdk_auth_algo   = 0;

    /* 你的工程里大概率已经有 virtio->dpdk 的映射函数；这里必须用它 */
    if (cipher_algo_transform(D->algo_cipher, &dpdk_cipher_algo) < 0) {
        VC_LOG_ERR("restore: unsupported cipher algo (virtio/id=%u) sid=%" PRIu64
                   " key_len=%u iv_len=%u",
                   (unsigned)D->algo_cipher, (uint64_t)sid,
                   (unsigned)D->key_len, (unsigned)D->iv_len);
        return NULL;
    }

    const bool need_auth = (D->algo_auth && D->tag_len);
    if (need_auth) {
        if (auth_algo_transform(D->algo_auth, &dpdk_auth_algo) < 0) {
            VC_LOG_ERR("restore: unsupported auth algo (virtio/id=%u) sid=%" PRIu64
                       " tag_len=%u",
                       (unsigned)D->algo_auth, (uint64_t)sid,
                       (unsigned)D->tag_len);
            return NULL;
        }
    }

    /* 1) 从 blob 切分 key | auth_key（当前不保存会话级 IV 模板） */
    const uint8_t *p = (const uint8_t *)blob;
    const uint8_t *key = NULL, *auth_key = NULL;
    uint16_t key_len = D->key_len, auth_key_len = 0;

    if (key_len) {
        if (blob_len < key_len) {
            VC_LOG_ERR("restore: blob too small for cipher key sid=%" PRIu64
                       " blob_len=%u key_len=%u",
                       (uint64_t)sid, (unsigned)blob_len, (unsigned)key_len);
            return NULL;
        }
        key = p;
        p += key_len;
    }

    if (blob_len > key_len) {
        auth_key_len = (uint16_t)(blob_len - key_len);
        auth_key = p;
    }

    /* 若 meta 表示需要 auth，但 blob 没带 auth_key，也直接判失败更清晰 */
    if (need_auth && auth_key_len == 0) {
        VC_LOG_ERR("restore: meta requires auth but no auth_key in blob sid=%" PRIu64
                   " algo_auth=%u tag_len=%u blob_len=%u key_len=%u",
                   (uint64_t)sid, (unsigned)D->algo_auth, (unsigned)D->tag_len,
                   (unsigned)blob_len, (unsigned)key_len);
        return NULL;
    }

    /* 2) 为 DPDK xform 准备“可写”密钥副本，避免 const-cast */
    uint8_t *cipher_key_copy = NULL;
    uint8_t *auth_key_copy   = NULL;

    if (key_len) {
        cipher_key_copy = dup_bytes_dpdk(key, key_len);
        if (!cipher_key_copy) {
            VC_LOG_ERR("restore: dup cipher key failed sid=%" PRIu64, (uint64_t)sid);
            return NULL;
        }
    }

    if (auth_key_len) {
        auth_key_copy = dup_bytes_dpdk(auth_key, auth_key_len);
        if (!auth_key_copy) {
            VC_LOG_ERR("restore: dup auth key failed sid=%" PRIu64, (uint64_t)sid);
            secure_free(cipher_key_copy, key_len);
            return NULL;
        }
    }

    /* 3) 构造 xform：若存在 auth，则 AUTH->CIPHER 链式，否则纯 CIPHER */
    struct rte_crypto_sym_xform xform1;
    struct rte_crypto_sym_xform xform2;
    memset(&xform1, 0, sizeof(xform1));
    memset(&xform2, 0, sizeof(xform2));
    struct rte_crypto_sym_xform *head = NULL;

    if (need_auth && auth_key_len) {
        xform2.type                 = RTE_CRYPTO_SYM_XFORM_AUTH;
        xform2.next                 = &xform1;

        /* 关键：使用映射后的 DPDK enum，而不是 (enum) 强转 */
        xform2.auth.algo            = dpdk_auth_algo;

        /*
         * 注意：这里仍然是你原来的默认方向。严格来说应该跟 D 的 op 对齐；
         * 先把 enum 映射修对，迁移先跑通；之后再补 op 的精确恢复。
         */
        xform2.auth.op              = RTE_CRYPTO_AUTH_OP_GENERATE;
        xform2.auth.digest_length   = D->tag_len;
        xform2.auth.key.data        = auth_key_copy;
        xform2.auth.key.length      = auth_key_len;
        head = &xform2;
    }

    xform1.type                    = RTE_CRYPTO_SYM_XFORM_CIPHER;
    xform1.next                    = NULL;

    /* 关键：使用映射后的 DPDK enum，而不是 (enum) 强转 */
    xform1.cipher.algo             = dpdk_cipher_algo;

    /*
     * 同上：严格应与 D 的 op 对齐（encrypt/decrypt）。先保留你原来的默认。
     */
    xform1.cipher.op               = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
    xform1.cipher.iv.length        = D->iv_len;
    xform1.cipher.key.data         = cipher_key_copy;
    xform1.cipher.key.length       = key_len;

    if (!head) {
        head = &xform1;
    }

    /* 4) 创建 cryptodev 会话 */
    struct rte_cryptodev_sym_session *sess =
        rte_cryptodev_sym_session_create(vcrypto->cid, head, vcrypto->sess_pool);

    if (!sess) {
        /* 打印 errno 会更好定位（不同 PMD 会给出不同错误） */
        VC_LOG_ERR("restore: rte_cryptodev_sym_session_create failed sid=%" PRIu64
                   " cipher(virtio=%u->dpdk=%d) auth(virtio=%u->dpdk=%d need_auth=%d)"
                   " key_len=%u iv_len=%u tag_len=%u auth_key_len=%u rte_errno=%d",
                   (uint64_t)sid,
                   (unsigned)D->algo_cipher, (int)dpdk_cipher_algo,
                   (unsigned)D->algo_auth,   (int)dpdk_auth_algo, (int)need_auth,
                   (unsigned)key_len, (unsigned)D->iv_len, (unsigned)D->tag_len,
                   (unsigned)auth_key_len, rte_errno);

        secure_free(cipher_key_copy, key_len);
        secure_free(auth_key_copy,   auth_key_len);
        return NULL;
    }

    /* 会话创建成功后，PMD 一般已拷贝/展开密钥至私有区，立刻擦除临时副本 */
    secure_free(cipher_key_copy, key_len);
    secure_free(auth_key_copy,   auth_key_len);

    /* 5) 分配 vhost 会话并回填 meta（供后续 save 复原） */
    struct vhost_crypto_session *vs = rte_zmalloc(NULL, sizeof(*vs), 0);
    if (!vs) {
        VC_LOG_ERR("restore: alloc vhost_crypto_session failed sid=%" PRIu64, (uint64_t)sid);
        rte_cryptodev_sym_session_free(vcrypto->cid, sess);
        return NULL;
    }

    vs->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
    vs->sym  = sess;

    vs->meta.valid       = true;
    vs->meta.session_id  = sid;
    vs->meta.kind        = VC_SESS_SYM;
    memcpy(&vs->meta.sym.desc, D, sizeof(*D));

    if (blob_len) {
        vs->meta.sym.b.blob = rte_zmalloc(NULL, blob_len, 0);
        if (!vs->meta.sym.b.blob) {
            VC_LOG_ERR("restore: alloc meta blob failed sid=%" PRIu64 " blob_len=%u",
                       (uint64_t)sid, (unsigned)blob_len);
            rte_cryptodev_sym_session_free(vcrypto->cid, sess);
            rte_free(vs);
            return NULL;
        }
        memcpy(vs->meta.sym.b.blob, blob, blob_len);
        vs->meta.sym.b.blob_len = blob_len;
    }

    return vs;
}

void test_save_load_blob(int vid)
{
    const char *path = "/tmp/snap.bin";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open for save");
        return;
    }

    if (vhost_crypto_save_state(vid, fd) < 0) {
        fprintf(stderr, "[test] save_state failed\n");
        close(fd);
        return;
    }
    close(fd);
    fprintf(stderr, "[test] save_state written to %s\n", path);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open for load");
        return;
    }

	uint8_t *tmp = NULL;
	size_t tlen = 0;

	if (read_all_from_fd(fd, &tmp, &tlen) < 0) {
		fprintf(stderr, "[test] read_all_from_fd failed\n");
		close(fd);
		return;
	}
	close(fd);

	if (vhost_crypto_load_state(vid, tmp, tlen) < 0) {
		fprintf(stderr, "[test] load_state failed\n");
		free(tmp);
		return;
	}
	free(tmp);

    close(fd);
    fprintf(stderr, "[test] load_state success\n");
}

static struct vhost_crypto_session*
vc_session_create_asym(struct vhost_crypto *vcrypto, uint64_t sid,
                       const struct vc_asym_meta_v1 *A,
                       const void *blob, uint32_t blob_len)
{
    if (!vcrypto || !A || !blob || !blob_len)
        return NULL;

    /* 目前只恢复 RSA，会话保存的是私钥 DER 原文 */
    if (A->algo_asym != VIRTIO_CRYPTO_AKCIPHER_RSA)
        return NULL;

    /* 1) 先把只读 DER 拷到一块可写内存，避免 const-cast */
    uint8_t *der_copy = dup_bytes_dpdk(blob, blob_len);
    if (!der_copy)
        return NULL;

    struct rte_crypto_asym_xform ax;
    memset(&ax, 0, sizeof(ax));

    /* 2) DER → xform（你工程的现成函数会解析 n/e/d/p/q... 写入 ax.rsa） */
    if (virtio_crypto_asym_rsa_der_to_xform(der_copy, blob_len, &ax) < 0) {
        secure_free(der_copy, blob_len);
        return NULL;
    }
    /* 拷贝已完成，立即擦除 DER 副本 */
    secure_free(der_copy, blob_len);

    /* 3) 固定 xform 类型与 key 类型（按你工程的用法） */
    ax.xform_type  = RTE_CRYPTO_ASYM_XFORM_RSA;
    ax.rsa.key_type = RTE_RSA_KEY_TYPE_QT;

    /* 4) 映射 virtio 的 padding 到 DPDK 的 padding type
          注意：padding 在 A->u.rsa.padding_algo */
    {
        uint16_t pad = A->padding_algo;  /* ← 关键：使用 u.rsa 成员 */

        switch (pad) {
        case VIRTIO_CRYPTO_RSA_RAW_PADDING:
            ax.rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
            break;
#ifdef VIRTIO_CRYPTO_RSA_PSS_PADDING
        case VIRTIO_CRYPTO_RSA_PSS_PADDING:
            ax.rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PSS;
            break;
#endif
        case VIRTIO_CRYPTO_RSA_PKCS1_PADDING:
        default:
            ax.rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
            break;
        }
    }

    /* 5) 创建 cryptodev 非对称会话（签名按你工程封装来）
          你给出的接口是：create(cid, &ax, pool, &out_sess) */
    struct rte_cryptodev_asym_session *sess = NULL;
    if (rte_cryptodev_asym_session_create(vcrypto->cid, &ax,
                                          vcrypto->sess_pool, (void *)&sess) < 0 || !sess) {
        return NULL;
    }

    /* 6) vhost 会话对象 + 回填 meta（保证再次 save 仍可复原） */
    struct vhost_crypto_session *vs = rte_zmalloc(NULL, sizeof(*vs), 0);
    if (!vs) {
        rte_cryptodev_asym_session_free(vcrypto->cid, sess);
        return NULL;
    }

    vs->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
    vs->asym = sess;

    vs->meta.valid       = true;
    vs->meta.session_id  = sid;
    vs->meta.kind        = VC_SESS_ASYM;

    memcpy(&vs->meta.asym.desc, A, sizeof(*A));

    if (blob_len) {
        vs->meta.asym.b.blob = rte_zmalloc(NULL, blob_len, 0);
        if (!vs->meta.asym.b.blob) {
            rte_cryptodev_asym_session_free(vcrypto->cid, sess);
            rte_free(vs);
            return NULL;
        }
        rte_memcpy(vs->meta.asym.b.blob, blob, blob_len);
        vs->meta.asym.b.blob_len = blob_len;
    }

    return vs;
}

int vhost_crypto_load_state(int vid, const void *buf, size_t len)
{
    int fd = -1;
#ifdef __linux__
    fd = memfd_create("vhost-crypto-snap", 0);
#endif
    if (fd < 0) {
        /* fallback: use tmpfile */
        FILE *fp = tmpfile();
        if (!fp)
            return -errno;
        fd = fileno(fp);
        /* fp will be closed when process exits; ok for test/debug */
    }

    if (write_full(fd, buf, len) != 0) {
        int e = -errno;
        close(fd);
        return e;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        int e = -errno;
        close(fd);
        return e;
    }

    int rc = vhost_crypto_load_state_fd(vid, fd);
    close(fd);
    return rc;
}


/* Load: read header + payload from fd and rebuild backend state */
static int vhost_crypto_load_state_fd(int vid, int fd)
{
    struct vhost_crypto *vcrypto = vc_lookup(vid);
    if (unlikely(!vcrypto)) {
        fprintf(stderr, "[load_state] vc_lookup(%d) failed\n", vid);
        return -ENOENT;
    }

    struct vc_snap_hdr hdr;
	int rc = read_full(fd, &hdr, sizeof(hdr));
	if (rc) {
		fprintf(stderr, "[load_state] failed to read header (%d)\n", rc);
		return rc;
	}

    /* Now interpret the header */
    if (FROMLE32(hdr.magic) != VC_SNAP_MAGIC) {
        fprintf(stderr, "[load_state] bad magic: 0x%x\n",
                FROMLE32(hdr.magic));
        return -EINVAL;
    }

    if (FROMLE16(hdr.version) != 1) {
        fprintf(stderr, "[load_state] unsupported version: %u\n",
                FROMLE16(hdr.version));
        return -EINVAL;
    }

    uint16_t hdr_len = FROMLE16(hdr.hdr_len);
    uint32_t pay_len = FROMLE32(hdr.payload_len);

    if (hdr_len < sizeof(hdr)) {
        fprintf(stderr, "[load_state] invalid hdr_len: %u\n", hdr_len);
        return -EINVAL;
    }

    /* rest = (header-extension) + payload(TLVs) */
    size_t rest = (size_t)hdr_len - sizeof(hdr) + (size_t)pay_len;
    
	/* size cap: must match/save-side cap_max (or choose your own) */
	const size_t rest_max = 32 * 1024 * 1024;  /* 32MB */
	if (rest == 0 || rest > rest_max) {
		fprintf(stderr, "[load_state] invalid rest size: %zu (hdr_len=%u pay_len=%u)\n",
				rest, hdr_len, pay_len);
		return -EINVAL;
	}
	
	uint8_t *buf = rte_zmalloc(NULL, rest, 0);
    if (!buf) {
        fprintf(stderr, "[load_state] malloc failed, size=%zu\n", rest);
        return -ENOMEM;
    }

    rc = read_full(fd, buf, rest);
	if (rc) {
		fprintf(stderr, "[load_state] failed to read payload (%d)\n", rc);
		rte_free(buf);
		return rc;
	}

    fprintf(stderr, "[load_state] full TLV region (hex), size=%zu:\n", rest);
    dump_hex(buf, rest);

    const uint8_t *tlv_base = buf + (hdr_len - sizeof(hdr));
    uint32_t crc = vc_crc32(tlv_base, pay_len);
    if (FROMLE32(hdr.crc32) != crc) {
        fprintf(stderr, "[load_state] crc mismatch: got 0x%x expected 0x%x\n",
                crc, FROMLE32(hdr.crc32));
        rte_free(buf);
        return -EINVAL;
    }

    const uint8_t *q    = tlv_base;
    const uint8_t *qend = tlv_base + pay_len;

    while (q + sizeof(struct vc_tlv) <= qend) {
        const struct vc_tlv *tlv = (const struct vc_tlv *)q;
        uint16_t t = FROMLE16(tlv->type);
        uint32_t L = FROMLE32(tlv->len);

        fprintf(stderr, "[load_state] TLV type=0x%x len=%u\n", t, L);

        q += sizeof(*tlv);
        if (q + L > qend) {
            fprintf(stderr, "[load_state] TLV length overrun: L=%u\n", L);
            rte_free(buf);
            return -EINVAL;
        }

        if (t == VC_TLV_DEV_META) {
            if (L < sizeof(struct vc_dev_meta_v1)) {
                fprintf(stderr,
                        "[load_state] DEV_META size too small: %u\n", L);
                rte_free(buf);
                return -EINVAL;
            }

            const struct vc_dev_meta_v1 *m = (const struct vc_dev_meta_v1 *)q;

			uint32_t snap_cid  = FROMLE32(m->cid);
			uint64_t snap_last = FROMLE64(m->last_session_id);

			if (snap_cid != vcrypto->cid) {
				fprintf(stderr,
						"[load_state] WARN: snapshot cid=%u != local cid=%u (keep local)\n",
						snap_cid, vcrypto->cid);
			}

			vcrypto->last_session_id = snap_last;

			fprintf(stderr,
					"[load_state] DEV_META: snapshot_cid=%u, local_cid=%u, last_sid=%lu\n",
					snap_cid, vcrypto->cid, (unsigned long)snap_last);

        } else if (t == VC_TLV_SESSION) {

            const uint8_t *s = q;
            if (L < sizeof(struct vc_sess_head_v1)) {
                fprintf(stderr,
                        "[load_state] SESSION head size too small: %u\n", L);
                rte_free(buf);
                return -EINVAL;
            }

            const struct vc_sess_head_v1 *sh =
                (const struct vc_sess_head_v1 *)s;
            uint64_t sid = FROMLE64(sh->session_id);
            uint8_t  kind = sh->kind;
            s += sizeof(*sh);

            fprintf(stderr,
                    "[load_state] SESSION TLV: sid=%lu kind=%u\n",
                    sid, kind);

            struct vhost_crypto_session *vs = NULL;

            if (kind == VC_SESS_SYM) {

                if (s + sizeof(struct vc_sym_meta_v1) > q + L) {
                    fprintf(stderr, "[load_state] SYM meta too long\n");
                    rte_free(buf);
                    return -EINVAL;
                }

                const struct vc_sym_meta_v1 *D =
                    (const struct vc_sym_meta_v1 *)s;
                s += sizeof(*D);
                const void *blob = s;
                uint32_t blen = (uint32_t)((q + L) - s);

                fprintf(stderr, "[load_state] SYM: blob_len=%u\n", blen);
                dump_hex(blob, blen);

                vs = vc_session_create_sym(vcrypto, sid, D, blob, blen);
                if (!vs) {
                    fprintf(stderr,
                            "[load_state] vc_session_create_sym failed\n");
                    rte_free(buf);
                    return -EIO;
                }

            } else if (kind == VC_SESS_ASYM) {

                if (s + sizeof(struct vc_asym_meta_v1) > q + L) {
                    fprintf(stderr, "[load_state] ASYM meta too long\n");
                    rte_free(buf);
                    return -EINVAL;
                }

                const struct vc_asym_meta_v1 *A =
                    (const struct vc_asym_meta_v1 *)s;
                s += sizeof(*A);
                const void *blob = s;
                uint32_t blen = (uint32_t)((q + L) - s);

                fprintf(stderr, "[load_state] ASYM: blob_len=%u\n", blen);
                dump_hex(blob, blen);

                vs = vc_session_create_asym(vcrypto, sid, A, blob, blen);
                if (!vs) {
                    fprintf(stderr,
                            "[load_state] vc_session_create_asym failed\n");
                    rte_free(buf);
                    return -EIO;
                }

            } else {
                fprintf(stderr,
                        "[load_state] unknown session kind: %u\n", kind);
                rte_free(buf);
                return -EINVAL;
            }

            int drc = rte_hash_del_key(vcrypto->session_map, &sid);
			if (drc < 0 && drc != -ENOENT) {
				fprintf(stderr,
						"[load_state] session_map del failed sid=%lu rc=%d\n",
						sid, drc);

				/* ✅ avoid leaking the just-created session */
				vc_session_destroy(vcrypto, vs);

				rte_free(buf);
				return drc; /* keep real errno */
			}

			int arc = rte_hash_add_key_data(vcrypto->session_map, &sid, vs);
			if (arc < 0) {
				fprintf(stderr,
						"[load_state] session_map add failed sid=%lu rc=%d\n",
						sid, arc);

				/* ✅ avoid leaking the just-created session */
				vc_session_destroy(vcrypto, vs);

				rte_free(buf);
				return arc; /* keep real errno */
			}

        } else {
            fprintf(stderr,
                    "[load_state] unknown TLV type: 0x%x, skipping\n", t);
        }

        q += L;
    }

    rte_free(buf);
    fprintf(stderr, "[load_state] done\n");
    return 0;
}


/* Thaw: resume processing */
int vhost_crypto_thaw(int vid)
{
    struct virtio_net *dev = get_device(vid);
    if (!dev || !dev->extern_data) {
        VC_LOG_ERR("THAW vid=%d failed: dev/extern_data missing", vid);
        return -ENOENT;
    }

    struct vhost_crypto *vcrypto = dev->extern_data;

    int old = __atomic_exchange_n(&vcrypto->frozen, 0, __ATOMIC_ACQ_REL);
    uint32_t inflight = __atomic_load_n(&vcrypto->inflight, __ATOMIC_ACQUIRE);

    VC_LOG_INFO("THAW vid=%d frozen:%d->0 inflight=%u", vid, old, inflight);
    return 0;
}


