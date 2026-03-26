#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_crypto_asym.h>

#define ASYM_SESS_POOL_NAME "asym_sess_pool"
#define ASYM_OP_POOL_NAME "asym_op_pool"
#define ASYM_OPS_PER_POOL 1024
#define ASYM_SESS_PER_POOL 1024
#define PMD_NAME "crypto_uadk"
#define RSA_KEY_SIZE_BYTES 256 /* 2048 bits */
#define PRIVATE_KEY_FILE "private.pem"
#define HEX_PRINT_LEN 16

static struct rte_mempool *asym_op_pool = NULL;
static struct rte_mempool *asym_sess_pool = NULL;
typedef struct {
    uint8_t n[RSA_KEY_SIZE_BYTES];
    uint8_t e[RSA_KEY_SIZE_BYTES];
    uint8_t d[RSA_KEY_SIZE_BYTES];
    uint8_t p[RSA_KEY_SIZE_BYTES/2];
    uint8_t q[RSA_KEY_SIZE_BYTES/2];
    uint8_t dmp1[RSA_KEY_SIZE_BYTES/2];
    uint8_t dmq1[RSA_KEY_SIZE_BYTES/2];
    uint8_t iqmp[RSA_KEY_SIZE_BYTES/2];
    size_t e_len;
} RsaKeyData;

static bool load_rsa_key_components(RsaKeyData* data) {
    bool ret = false;

    FILE* fp = fopen(PRIVATE_KEY_FILE, "r");
    if (!fp) {
        fprintf(stderr, "Error: failed to open rsa private key file\n");
        goto cleanup;
    }

    // 1. read private key
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (!pkey) {
        fprintf(stderr, "failed to read RSA private key from PEM\n");
        goto cleanup;
    }

    // 2. check if is RSA!
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "EVP_PKEY is not an RSA key\n");
        goto cleanup;
    }

    // 3. extract private key infos including CRT parameters
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    
    // 获取标准参数
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
        fprintf(stderr, "failed to extract modulus N\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        fprintf(stderr, "failed to extract public exponent E\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) != 1) {
        fprintf(stderr, "failed to extract private exponent D\n");
        goto cleanup;
    }
    
    // 获取CRT参数
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) != 1) {
        fprintf(stderr, "failed to extract CRT parameter p\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) != 1) {
        fprintf(stderr, "failed to extract CRT parameter q\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1) != 1) {
        fprintf(stderr, "failed to extract CRT parameter dmp1\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1) != 1) {
        fprintf(stderr, "failed to extract CRT parameter dmq1\n");
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp) != 1) {
        fprintf(stderr, "failed to extract CRT parameter iqmp\n");
        goto cleanup;
    }

    // 4. transform BIGNUM into Big Endian mode

    // Modulus (N)
    if (BN_bn2binpad(n, data->n, RSA_KEY_SIZE_BYTES) != RSA_KEY_SIZE_BYTES) {
        fprintf(stderr, "failed to convert N to binary\n");
        goto cleanup;
    }

    // Public Exponent (E)
    data->e_len = BN_bn2binpad(e, data->e, RSA_KEY_SIZE_BYTES);
    if (data->e_len <= 0) {
        fprintf(stderr, "failed to convert E to binary\n");
        goto cleanup;
    }

    // Private Exponent (D)
    if (BN_bn2binpad(d, data->d, RSA_KEY_SIZE_BYTES) != RSA_KEY_SIZE_BYTES) {
        fprintf(stderr, "failed to convert D to binary\n");
        goto cleanup;
    }

    // CRT parameters (注意：这些参数的大小通常是N的一半)
    size_t crt_size = RSA_KEY_SIZE_BYTES / 2;
    
    if (BN_bn2binpad(p, data->p, crt_size) != crt_size) {
        fprintf(stderr, "failed to convert p to binary\n");
        goto cleanup;
    }
    if (BN_bn2binpad(q, data->q, crt_size) != crt_size) {
        fprintf(stderr, "failed to convert q to binary\n");
        goto cleanup;
    }
    if (BN_bn2binpad(dmp1, data->dmp1, crt_size) != crt_size) {
        fprintf(stderr, "failed to convert dmp1 to binary\n");
        goto cleanup;
    }
    if (BN_bn2binpad(dmq1, data->dmq1, crt_size) != crt_size) {
        fprintf(stderr, "failed to convert dmq1 to binary\n");
        goto cleanup;
    }
    if (BN_bn2binpad(iqmp, data->iqmp, crt_size) != crt_size) {
        fprintf(stderr, "failed to convert iqmp to binary\n");
        goto cleanup;
    }

    ret = true;

cleanup:
    if (fp) fclose(fp);
    // 释放 BIGNUM 结构
    if (n) BN_free(n);
    if (e) BN_free(e);
    if (d) BN_free(d);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (dmp1) BN_free(dmp1);
    if (dmq1) BN_free(dmq1);
    if (iqmp) BN_free(iqmp);
    // 释放 EVP_PKEY
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}


static int setup_cryptodev() {
  // uint8_t cdev_ids[64] = {0};
  // int num_cdevs = rte_cryptodev_devices_get(PMD_NAME, cdev_ids, 64);
  // assert(num_cdevs > 0 && "no cdev" PMD_NAME "found");
  uint8_t cdev_id = 0;

  struct rte_cryptodev_config config = {
    .nb_queue_pairs = 1,
    .socket_id = SOCKET_ID_ANY,
  };
  if (rte_cryptodev_configure(cdev_id, &config) < 0) {
    fprintf(stderr, "failed to configure crypto dev: %u\n", cdev_id);
    return -1;
  }

  struct rte_cryptodev_qp_conf qp_conf = {
    .nb_descriptors = 256,
  };
  if (rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf, rte_socket_id()) < 0) {
    fprintf(stderr, "failed to setup queue pair 0 on crypto dev: %u\n", cdev_id);
    return -1;
  }

  if (rte_cryptodev_start(cdev_id) < 0) {
    fprintf(stderr, "failed to start crypto dev: %u\n", cdev_id);
    return -1;
  }

  return cdev_id;
}

static const char* rte_crypto_op_err_msg(const struct rte_crypto_op *op) {
  switch (op->status) {
    case RTE_CRYPTO_OP_STATUS_SUCCESS:
      return "success";
    case RTE_CRYPTO_OP_STATUS_NOT_PROCESSED:
      return "Not Processed";
    case RTE_CRYPTO_OP_STATUS_AUTH_FAILED:
      return "auth failed";
    case RTE_CRYPTO_OP_STATUS_INVALID_SESSION:
      return "invalid session";
    case RTE_CRYPTO_OP_STATUS_INVALID_ARGS:
      return "invalid args";
    case RTE_CRYPTO_OP_STATUS_ERROR:
      return "error";
    default:
      return "unknown error";
  }
}

static bool do_asym_op(uint8_t cdev_id, struct rte_crypto_op *op) {
  struct rte_crypto_op *ops_enq[] = {op};
  struct rte_crypto_op *ops_deq[1] = {NULL};
  int enqueued = 0, dequeued = 0;
  unsigned int retires = 0;


  // 1. enqueue
  enqueued = rte_cryptodev_enqueue_burst(cdev_id, 0, ops_enq, 1);
  if (enqueued != 1) {
    fprintf(stderr, "failed to enqueue op, retrying later\n");
    return false;
  }

  // 2. dequeue (poll for completion)
  while (dequeued == 0) {
    dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, ops_deq, 1);
    retires++;
  }
  if (dequeued != 1) {
    fprintf(stderr, "failed to dequeue crypto op\n");
    return false;
  }

  // 3. check result
  struct rte_crypto_op *completed_op = (struct rte_crypto_op*)ops_deq[0];
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    fprintf(stderr, "operation failed, status: %s\n", rte_crypto_op_err_msg(completed_op));
    return false;
  }

  return true;
}

static struct rte_cryptodev_asym_session *create_asym_session(uint8_t cdev_id, const RsaKeyData *key_data) {
  // xform for private key
  struct rte_crypto_rsa_xform rsa_xform = {
    .key_type = RTE_RSA_KEY_TYPE_QT,
    .n = {.data = (uint8_t *)key_data->n, .length = RSA_KEY_SIZE_BYTES},
    .e = {.data = (uint8_t *)key_data->e, .length = RSA_KEY_SIZE_BYTES},
    .d = {.data = (uint8_t *)key_data->d, .length = RSA_KEY_SIZE_BYTES},
    .qt.p = {.data = (uint8_t *)key_data->p, .length = RSA_KEY_SIZE_BYTES / 2},
    .qt.q = {.data = (uint8_t *)key_data->q, .length = RSA_KEY_SIZE_BYTES / 2},
    .qt.dP = {.data = (uint8_t *)key_data->dmp1, .length = RSA_KEY_SIZE_BYTES / 2},
    .qt.dQ = {.data = (uint8_t *)key_data->dmq1, .length = RSA_KEY_SIZE_BYTES / 2},
    .qt.qInv = {.data = (uint8_t *)key_data->iqmp, .length = RSA_KEY_SIZE_BYTES / 2},
    .padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5,
    // .padding.type = RTE_CRYPTO_RSA_PADDING_NONE,
  };
  struct rte_crypto_asym_xform asym_xform = {
    .next = NULL,
    .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
    .rsa = rsa_xform,
  };
  struct rte_cryptodev_asym_session *sess = NULL;
  int ret = rte_cryptodev_asym_session_create(cdev_id, &asym_xform, asym_sess_pool, (void**)&sess);
  if (ret != 0 || !sess) {
    fprintf(stderr, "failed to create asym_session\n");
    return NULL;
  }
  return sess;
}

static bool perform_rsa_sign_verify_test(uint8_t cdev_id, const RsaKeyData *key_data, struct rte_cryptodev_asym_session *sess) {
  // 1. param check
  if (!key_data || !sess) {
    fprintf(stderr, "nullptr input\n");
    return false;
  }
  bool ret = false;

  // 2. prepare plaintext
  const char *plaintext = "DPDK rsa sign test message";
  size_t plaintext_len = strlen(plaintext);

  uint8_t *plain_buf = rte_zmalloc("msg_buf", RSA_KEY_SIZE_BYTES, 0);
  uint8_t *sign_buf = rte_zmalloc("sign_buf", RSA_KEY_SIZE_BYTES, 0);
  if (!plain_buf || !sign_buf) {
    fprintf(stderr, "failed to alloc for buf\n");
    return false;
  }
  memcpy(plain_buf, plaintext, plaintext_len);
  memcpy(sign_buf, plaintext, plaintext_len);

  // 3. alloc crypto op
  struct rte_crypto_op *op = rte_crypto_op_alloc(asym_op_pool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    fprintf(stderr, "failed to alloc for crypto op");
    goto cleanup;
  }

  // 4. fill in op for sign
  rte_crypto_op_attach_asym_session(op, sess);
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
  op->asym->rsa.message.data = plain_buf;
  op->asym->rsa.message.length = RSA_KEY_SIZE_BYTES;
  op->asym->rsa.sign.data = sign_buf;
  op->asym->rsa.sign.length = RSA_KEY_SIZE_BYTES;

  // 5. sign
  if (!do_asym_op(cdev_id, op)) {
   fprintf(stderr, "rsa sign failed\n");
   goto cleanup;
  }
  printf("RSA sign success, signature generated\n");

  // 6. fill in op for verify
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
  op->asym->rsa.sign.data = sign_buf;
  op->asym->rsa.sign.length = RSA_KEY_SIZE_BYTES;
  op->asym->rsa.message.data = plain_buf;
  op->asym->rsa.message.length = RSA_KEY_SIZE_BYTES;

  // 7. verify
  if (!do_asym_op(cdev_id, op)) {
    fprintf(stderr, "RSA verify failed\n");
    goto cleanup;
  } else {
    printf("verify success\n");
    ret = true;
  }

  // 8. mallicious verify
  // signed data bytes reverted
  uint8_t *err_buf = rte_zmalloc("err_buf", RSA_KEY_SIZE_BYTES, 0);
  memcpy(err_buf, sign_buf, RSA_KEY_SIZE_BYTES);
  err_buf[0] ^= 0xff;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
  op->asym->rsa.sign.data = err_buf;
  op->asym->rsa.sign.length = RSA_KEY_SIZE_BYTES;
  op->asym->rsa.message.data = plain_buf;
  op->asym->rsa.message.length = RSA_KEY_SIZE_BYTES;
  bool err_res = do_asym_op(cdev_id, op);
  if (!err_res) {
    printf("mallicious verify FAILED as expected, status: %s\n", rte_crypto_op_err_msg(op));
  } else {
    fprintf(stderr, "mallicious check failed\n");
    ret = false;
    goto cleanup;
  }

cleanup:
  if (plain_buf) rte_free(plain_buf);
  if (sign_buf) rte_free(sign_buf);
  if (err_buf) rte_free(err_buf);
  if (op) rte_crypto_op_free(op);
  return ret;
}

int main(int argc, char** argv) {
  int ret = 1;
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  // 1. read rsa data
  RsaKeyData *key_data = malloc(sizeof(RsaKeyData));
  if (!load_rsa_key_components(key_data)) {
    fprintf(stderr, "failed to load rsa data\n");
    goto cleanup;
  }

  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  rte_eal_init(argc, argv);

  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  // 2. cryptodev setup
  uint8_t cdev_id = setup_cryptodev();
  if (cdev_id == (uint8_t)-1) {
    fprintf(stderr, "Error configure cryptodev\n");
    goto cleanup;
  }
  // 3. sess & crypto_op mempool alloc
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  asym_op_pool = rte_crypto_op_pool_create(
      ASYM_OP_POOL_NAME, RTE_CRYPTO_OP_TYPE_ASYMMETRIC, ASYM_OPS_PER_POOL, 0,
      sizeof(struct rte_crypto_asym_op), rte_socket_id());
  if (!asym_op_pool) {
    fprintf(stderr, "failed to alloc asym_op_pool\n");
    goto cleanup;
  }

  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  size_t priv_size = rte_cryptodev_asym_get_private_session_size(cdev_id);
  asym_sess_pool = rte_cryptodev_asym_session_pool_create(ASYM_SESS_POOL_NAME, ASYM_SESS_PER_POOL, 0, priv_size, rte_socket_id());
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  if (!asym_sess_pool) {
    fprintf(stderr, "failed to aloc asym_sess_pool\n");
    goto cleanup;
  }

  // 4. create sess
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  struct rte_cryptodev_asym_session *sess = create_asym_session(cdev_id, key_data);
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  if (!sess) {
    fprintf(stderr, "failed to create sess\n");
    goto cleanup;
  }

  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  // 5. perform test
  ret = perform_rsa_sign_verify_test(cdev_id, key_data, sess);
  fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);
  ret = ~ret;
  printf("test complete, cleaning resource...\n");

cleanup:
  if (sess) rte_cryptodev_asym_session_free(cdev_id, sess); /* may be version dependent */
  if (asym_op_pool) rte_mempool_free(asym_op_pool);
  if (asym_sess_pool) rte_mempool_free(asym_sess_pool);
  rte_cryptodev_stop(cdev_id);
  rte_eal_cleanup();
  return ret;
}