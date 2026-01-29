
#include <rte_crypto_sym.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_malloc.h>

/* Config */
#define MBUF_POOL_NAME "MBUF_POOL"
#define MBUF_CACHE_SIZE 256
#define NUM_MBUFS 4096
#define MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

/* Use crypto device 0 and queue-pair 0 for minimal example */
#define CRYPTODEV_ID 0
#define QP_ID 0

/* AES block and key */
static const uint8_t aes_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};

static const uint8_t iv_init[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

int main(int argc, char **argv)
{
    int ret;
    unsigned nb_mbufs = NUM_MBUFS;
    struct rte_mempool *mbuf_pool = NULL;
    uint16_t dev_id = CRYPTODEV_ID;
    uint16_t qp_id = QP_ID;

    /* 1) Init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Failed to init EAL\n");
        return -1;
    }

    /* 2) Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create(MBUF_POOL_NAME,
                                        nb_mbufs,
                                        MBUF_CACHE_SIZE, 0,
                                        MBUF_DATA_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "Failed to create mbuf pool\n");
        return -1;
    }

    /* 3) Check crypto device exists */
    if (dev_id >= rte_cryptodev_count()) {
        fprintf(stderr, "No crypto device with id %u (count=%u)\n", dev_id, rte_cryptodev_count());
        return -1;
    }

    /* 4) Query device info (optional, but useful) */
    struct rte_cryptodev_info dev_info;
    rte_cryptodev_info_get(dev_id, &dev_info);

    /* 5) Configure crypto device */
    struct rte_cryptodev_config dev_conf = {
        .nb_queue_pairs = 1,
        .socket_id = rte_socket_id(),
    };
    ret = rte_cryptodev_configure(dev_id, &dev_conf);
    if (ret < 0) {
        fprintf(stderr, "rte_cryptodev_configure failed\n");
        return -1;
    }

    /* 6) Setup queue pair (use default crypto_qp_conf) */
    struct rte_cryptodev_qp_conf qp_conf = { .nb_descriptors = 256 };
    ret = rte_cryptodev_queue_pair_setup(dev_id, qp_id, &qp_conf, rte_socket_id());
    if (ret < 0) {
        fprintf(stderr, "rte_cryptodev_queue_pair_setup failed\n");
        return -1;
    }

    /* 7) Start device */
    ret = rte_cryptodev_start(dev_id);
    if (ret < 0) {
        fprintf(stderr, "rte_cryptodev_start failed\n");
        return -1;
    }

    printf("Crypto device %u started\n", dev_id);

    /* 8) Create crypto op pool (for allocating crypto ops) */
    struct rte_mempool *crypto_mp = rte_crypto_op_pool_create("CRYPTO_OP_POOL",
                                                              RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                                              2048, 0, 0,
                                                              rte_socket_id());
    if (!crypto_mp) {
        fprintf(stderr, "Failed to create crypto op pool\n");
        return -1;
    }

    /* --- Step: create cipher transform chain --- */
    struct rte_crypto_sym_xform cipher_xform;
    memset(&cipher_xform, 0, sizeof(cipher_xform));

    cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher_xform.next = NULL; /* only one transform in this example */
    cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
    cipher_xform.cipher.key.data = (uint8_t *)aes_key;
    cipher_xform.cipher.key.length = sizeof(aes_key);
    cipher_xform.cipher.iv.offset = 0;
    cipher_xform.cipher.iv.length = 16;

    struct rte_mempool *session_pool = rte_cryptodev_sym_session_pool_create(
        "session_pool", 1024, rte_cryptodev_sym_get_private_session_size(dev_id), 0, 0, rte_socket_id());
    if (!session_pool) {
        rte_exit(-1, "Session pool creation failed\n");
    }
    struct rte_cryptodev_sym_session *session = rte_cryptodev_sym_session_create(dev_id, &cipher_xform, session_pool);
    if (!session)
        rte_exit(-1, "Session creation failed\n");
    
    /* 10) Prepare a plaintext mbuf */
    // const char *plaintext = "Hello DPDK Crypto!012"; /* length 20 (not multiple of 16) */
    char plaintext[4097] = {0};
    memset(plaintext, 'a', 2048 - 1);
    size_t pt_len = strlen(plaintext);
    /* For AES-CBC block cipher we need padding or use exact multiple of 16 for simplicity.
      Here we round up to 16-byte multiple and zero-pad (not a secure padding, demo only). */
    size_t blk = 16;
    size_t padded_len = (pt_len + blk - 1) / blk * blk;

    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (!m) {
        fprintf(stderr, "Failed to alloc mbuf\n");
        return -1;
    }

    uint8_t *mbuf_data = rte_pktmbuf_append(m, padded_len);
    if (!mbuf_data) {
        fprintf(stderr, "Failed to append data to mbuf\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    memset(mbuf_data, 0, padded_len);
    memcpy(mbuf_data, plaintext, pt_len);

    //------------------//

    struct rte_mbuf *m1 = rte_pktmbuf_alloc(mbuf_pool);
    if (!m) {
        fprintf(stderr, "Failed to alloc mbuf\n");
        return -1;
    }

    uint8_t *mbuf_data1 = rte_pktmbuf_append(m1, padded_len);
    if (!mbuf_data1) {
        fprintf(stderr, "Failed to append data to mbuf\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    memset(mbuf_data1, 0, padded_len);

    /* 11) Allocate crypto_op and attach session */
    struct rte_crypto_op *op[1] = {0};
    for (int i = 0; i < 1; i++) {

    op[i] = rte_crypto_op_alloc(crypto_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (!op[i]) {
        fprintf(stderr, "Failed to alloc crypto op\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    
    /* attach mbuf */
    op[i]->sym->m_src = m;
    op[i]->sym->m_dst = m1; /* in-place (many PMDs support in-place) */
    
    /* set session (API name may vary as noted) */
    if (rte_crypto_op_attach_sym_session(op[i], session) != 0) {
        fprintf(stderr, "Failed to attach session to crypto op\n");
        rte_crypto_op_free(op[i]);
        rte_pktmbuf_free(m);
        return -1;
    }
    op[i]->sym->session = session;

    op[i]->sym->cipher.data.offset = 0;
    op[i]->sym->cipher.data.length = padded_len;

    }

    time_t time1 = time(NULL);
    for (int i = 0; i < 1000000; i++) {
      // fprintf(stderr, "%ld\n", 111);
    uint16_t enq = rte_cryptodev_enqueue_burst(dev_id, qp_id, op, 1);

    struct rte_crypto_op *dequeued[1];

    unsigned tries = 0;
    while (tries < 1000) {
        uint16_t deq = rte_cryptodev_dequeue_burst(dev_id, qp_id, dequeued, 256);
        if (deq != 0) {
            break;
        }
    }
  }
  time_t time2 = time(NULL);

  fprintf(stderr, "%ld\n", time2 - time1);
  /* 13) Dequeue completed ops (poll loop) */
    // unsigned tries = 0;
    // uint8_t *out = NULL;
    // while (tries < 1000) {
    //     uint16_t deq = rte_cryptodev_dequeue_burst(dev_id, qp_id, dequeued, 1);
    //     if (deq == 1) {
    //         struct rte_crypto_op *rop = dequeued[0];
    //         fprintf(stderr, ":::%p %p\n", 
    //             rop->sym->m_dst->buf_addr, (void*)rop->sym->m_dst->buf_iova);
    //         if (rop->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    //             fprintf(stderr, "Crypto op failed (status=%d)\n", rop->status);
    //         } else {
    //             /* result is in m (in-place) */
    //             uint8_t *out = rte_pktmbuf_mtod(rop->sym->m_dst, uint8_t *);
    //             printf("Encrypted (hex, %zu bytes):\n", padded_len);
    //             for (size_t i = 0; i < padded_len; ++i) {
    //                 printf("%02x", out[i]);
    //                 if ((i+1) % 16 == 0) printf("\n");
    //                 else if ((i+1) % 2 == 0) printf(" ");
    //             }
    //             printf("\n");
    //         }
    //         /* free resources */
    //         rte_crypto_op_free(rop);
    //         rte_pktmbuf_free(m);
    //         break;
    //     }
    //     tries++;
    //     rte_delay_us_block(100);
    // }
    // if (tries >= 1000) {
    //     fprintf(stderr, "Timeout waiting for crypto op completion\n");
    // }

        /* ------------------------ */
    /* Now DECRYPT the results  */
    /* ------------------------ */
    // fprintf(stderr, "%d\n", __LINE__);

    // /* 3) Create a crypto op for decrypt */
    // struct rte_crypto_op *dec_op =
    //     rte_crypto_op_alloc(crypto_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    // if (!dec_op) {
    //     fprintf(stderr, "Failed to alloc decrypt crypto op\n");
    //     return -1;
    // }
    // fprintf(stderr, "%d\n", __LINE__);
    // struct rte_crypto_sym_xform cipher_xform2;
    // memset(&cipher_xform2, 0, sizeof(cipher_xform2));

    // cipher_xform2.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    // cipher_xform2.next = NULL; /* only one transform in this example */
    // cipher_xform2.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
    // cipher_xform2.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    // cipher_xform2.cipher.key.data = (uint8_t *)aes_key;
    // cipher_xform2.cipher.key.length = sizeof(aes_key);
    // cipher_xform2.cipher.iv.offset = 0;
    // cipher_xform2.cipher.iv.length = 16;
    // struct rte_cryptodev_sym_session *session2 = rte_cryptodev_sym_session_create(dev_id, &cipher_xform2, session_pool);
    // fprintf(stderr, "%d\n", __LINE__);

    // /* 4) Use the same session (key+IV same). AES-CBC decrypt uses same session. */
    // dec_op->sym->session = session2;
    // dec_op->sym->m_src  = m1;
    // dec_op->sym->m_dst  = m;
    // uint8_t *tmp = rte_pktmbuf_mtod(m, uint8_t *);
    // memset(tmp, 0, padded_len);

    // dec_op->sym->cipher.data.offset = 0;
    // dec_op->sym->cipher.data.length = padded_len;
    // fprintf(stderr, "%d\n", __LINE__);

    // /* 5) enqueue decrypt op */
    // struct rte_crypto_op *dec_ops[1] = { dec_op };
    // uint16_t enq2 = rte_cryptodev_enqueue_burst(dev_id, qp_id, dec_ops, 1);
    // if (enq2 != 1) {
    //     fprintf(stderr, "Decrypt enqueue failed\n");
    //     rte_crypto_op_free(dec_op);
    //     return -1;
    // }
    // fprintf(stderr, "%d\n", __LINE__);

    // /* 6) dequeue decrypt result */
    // struct rte_crypto_op *decq[1];
    // tries = 0;
    // while (tries < 100) {
    //     uint16_t deq2 = rte_cryptodev_dequeue_burst(dev_id, qp_id, decq, 1);
    //     if (deq2 == 1) {
    //         struct rte_crypto_op *dop = decq[0];
    //         if (dop->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    //             fprintf(stderr, "Decrypt failed! status=%d\n", dop->status);
    //         } else {
    //             uint8_t *pt = rte_pktmbuf_mtod(dop->sym->m_dst, uint8_t *);
    //             printf("\nDecrypted plaintext:\n");
    //             for (size_t i = 0; i < padded_len; i++) {
    //                 printf("%c", pt[i] ? pt[i] : '.');  
    //             }
    //             printf("\n");
    //         }

    //         rte_crypto_op_free(dop);
    //         break;
    //     }
    //     tries++;
    //     rte_delay_us_block(100);
    // }
    // if (tries >= 100) {
    //     fprintf(stderr, "Timeout on decrypt\n");
    // }

    // /* ----- session + device cleanup (you already have) ----- */


    /* 14) cleanup */
    rte_cryptodev_sym_session_free(dev_id, session); /* may be version dependent */
    // rte_cryptodev_sym_session_free(dev_id, session2); /* may be version dependent */
    rte_cryptodev_stop(dev_id);
    rte_cryptodev_close(dev_id);

    printf("Done\n");
    return 0;
}
