// examples/vhost_crypto/vhost_crypto_snapshot.h
#ifndef VHOST_CRYPTO_SNAPSHOT_H
#define VHOST_CRYPTO_SNAPSHOT_H

#include <stdint.h>
#include <stdbool.h>

#if defined(__GNUC__)
#define VC_PACKED __attribute__((packed))
#else
#pragma pack(push, 1)
#define VC_PACKED
#endif

/* ---------- snapshot header ---------- */
struct VC_PACKED vc_snap_hdr {
    uint32_t magic;      // "VCRY"
    uint16_t version;    // from 1
    uint16_t hdr_len;    // bytes, including this header
    uint32_t payload_len;// TLV region length in bytes
    uint32_t crc32;      // optional CRC over TLV region
};

#define VC_SNAP_MAGIC 0x59524356u /* 'VCRY' */

/* ---------- TLV ---------- */
enum vc_tlv_type {
    VC_TLV_DEV_META = 1,
    VC_TLV_SESSION  = 2,
    VC_TLV_STATS    = 3,  /* optional */
    VC_TLV_FEATURES = 4,  /* optional */
};

struct VC_PACKED vc_tlv {
    uint16_t type;
    uint16_t rsvd;
    uint32_t len;     // value length in bytes (following immediately)
};

/* ---------- device meta payload ---------- */
struct VC_PACKED vc_dev_meta_v1 {
    uint8_t  cid;
    uint8_t  zero_copy;
    uint16_t rsvd;
    uint32_t qid;
    uint64_t last_session_id;
};

/* ---------- session payload (fixed head + variable blob) ---------- */
enum vc_sess_kind {
    VC_SESS_SYM  = 0,
    VC_SESS_ASYM = 1,
};

struct vc_sess_head_v1 {
    uint64_t session_id;   // 来宾视角的 id
    uint8_t  kind;         // 0: sym, 1: asym
    uint8_t  flags;        // 目前置 0
    uint16_t rsvd0;        // 置 0（这俩不是“预留字段”，只是对齐，不用就别读）
    uint32_t rsvd1;        // 置 0
} __attribute__((packed));

struct vc_sym_meta_v1 {
    uint16_t algo_cipher;
    uint16_t algo_auth;
    uint16_t algo_aead;
    uint16_t chain_mode;   /* virtio chaining_dir */

    uint16_t key_len;
    uint16_t iv_len;
    uint16_t aad_len;
    uint16_t tag_len;

    uint32_t iv_gen_mode;

    /* ---- added for precise restore (v2-in-desc, desc_len tells) ---- */
    uint8_t  op_type;      /* VIRTIO_CRYPTO_SYM_OP_* (from sym_sess.op_type) */
    uint8_t  dir;          /* sym_sess.dir: 1 encrypt, 0 decrypt (see transform_cipher_param) */
    uint8_t  hash_mode;    /* sym_sess.hash_mode */
    uint8_t  rsvd0;
};

/* asymmetric session fixed meta */
struct VC_PACKED vc_asym_meta_v1 {
    uint16_t algo_asym;    // RSA/ECDSA...
    uint16_t key_bits;
    uint16_t hash_algo;    // for sign/verify
    uint16_t curve_id;     // for ECDSA/ECDH
    uint16_t padding_algo;   /* virtio padding enum: RAW/PKCS1/PSS... */
    /* then variable blob: priv_key[...] or (n,d,p,q,...) as per your create API */
};

#if !defined(__GNUC__)
#pragma pack(pop)
#undef VC_PACKED
#else
#undef VC_PACKED
#endif

/* (可选) 简单的 CRC32 声明，便于 save/load 里调用 */
uint32_t vc_crc32(const void *data, uint32_t len);

#endif /* VHOST_CRYPTO_SNAPSHOT_H */
