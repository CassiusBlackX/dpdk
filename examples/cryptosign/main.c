#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/types.h>

#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#define ASYM_SESS_POOL_NAME "asym_sess_pool"
#define ASYM_OP_POOL_NAME "asym_op_pool"
#define MBUF_POOL_NAME "data_mbuf_pool"
#define ASYM_OPS_PER_POOL 64
#define MBUFS_PER_POOL 64
#define ASYM_SESS_PER_POOL 64
#define RSA_KEY_SIZE_BITS 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE_BITS / 8)

#define PRIVATE_KEY_FILE "/home/cassius/nothing/private.pem"

typedef struct {
  uint8_t p[RSA_KEY_SIZE_BYTES / 2];    // prime p (1024 bits)
  uint8_t q[RSA_KEY_SIZE_BYTES / 2];    // prime q (1024 bits)
  uint8_t dp[RSA_KEY_SIZE_BYTES / 2];   // d mod (p-1)
  uint8_t dq[RSA_KEY_SIZE_BYTES / 2];   // d mod (q-1)
  uint8_t qinv[RSA_KEY_SIZE_BYTES / 2]; // q^{-1} mod p
  uint8_t n[RSA_KEY_SIZE_BYTES];        // modulus n (2048 bits)
  uint8_t e[RSA_KEY_SIZE_BYTES];        // public exponent
  size_t e_len;                         // exact length of e
} RsaKeyData;

bool load_rsa_key_components(RsaKeyData *data) {
  bool ret = false;
  FILE *fp = NULL;
  EVP_PKEY *pkey = NULL;
  BIGNUM *n = NULL, *e = NULL, *d = NULL;
  BIGNUM *p = NULL, *q = NULL, *dp_bn = NULL, *dq_bn = NULL, *qinv_bn = NULL;

  fp = fopen(PRIVATE_KEY_FILE, "r");
  if (!fp) {
    fprintf(stderr, "Error: failed to open rsa private key file\n");
    goto cleanup;
  }

  // 1. read private key
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
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

  // 3. extract RSA parameters
  // Modulus (N)
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
    fprintf(stderr, "failed to extract modulus N\n");
    goto cleanup;
  }
  // Public exponent (E)
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
    fprintf(stderr, "failed to extract public exponent E\n");
    goto cleanup;
  }
  // Private exponent (D) - needed for CRT calculation validation
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) != 1) {
    fprintf(stderr, "failed to extract private exponent D\n");
    goto cleanup;
  }
  // CRT parameters: p, q, dp, dq, qinv
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) != 1) {
    fprintf(stderr, "failed to extract factor p\n");
    goto cleanup;
  }
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) != 1) {
    fprintf(stderr, "failed to extract factor q\n");
    goto cleanup;
  }
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp_bn) != 1) {
    fprintf(stderr, "failed to extract exponent1 (dp)\n");
    goto cleanup;
  }
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq_bn) != 1) {
    fprintf(stderr, "failed to extract exponent2 (dq)\n");
    goto cleanup;
  }
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qinv_bn) !=
      1) {
    fprintf(stderr, "failed to extract coefficient (qinv)\n");
    goto cleanup;
  }

  // 4. convert BIGNUM to Big Endian format

  // Modulus (N) - 256 bytes for 2048-bit RSA
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

  // Prime P (1024 bits = 128 bytes)
  if (BN_bn2binpad(p, data->p, RSA_KEY_SIZE_BYTES / 2) !=
      RSA_KEY_SIZE_BYTES / 2) {
    fprintf(stderr, "failed to convert P to binary\n");
    goto cleanup;
  }

  // Prime Q (1024 bits = 128 bytes)
  if (BN_bn2binpad(q, data->q, RSA_KEY_SIZE_BYTES / 2) !=
      RSA_KEY_SIZE_BYTES / 2) {
    fprintf(stderr, "failed to convert Q to binary\n");
    goto cleanup;
  }

  // dp = d mod (p-1)
  if (BN_bn2binpad(dp_bn, data->dp, RSA_KEY_SIZE_BYTES / 2) !=
      RSA_KEY_SIZE_BYTES / 2) {
    fprintf(stderr, "failed to convert DP to binary\n");
    goto cleanup;
  }

  // dq = d mod (q-1)
  if (BN_bn2binpad(dq_bn, data->dq, RSA_KEY_SIZE_BYTES / 2) !=
      RSA_KEY_SIZE_BYTES / 2) {
    fprintf(stderr, "failed to convert DQ to binary\n");
    goto cleanup;
  }

  // qinv = q^{-1} mod p
  if (BN_bn2binpad(qinv_bn, data->qinv, RSA_KEY_SIZE_BYTES / 2) !=
      RSA_KEY_SIZE_BYTES / 2) {
    fprintf(stderr, "failed to convert QINV to binary\n");
    goto cleanup;
  }

  ret = true;

cleanup:
  if (fp)
    fclose(fp);
  if (n)
    BN_free(n);
  if (e)
    BN_free(e);
  if (d)
    BN_free(d);
  if (p)
    BN_free(p);
  if (q)
    BN_free(q);
  if (dp_bn)
    BN_free(dp_bn);
  if (dq_bn)
    BN_free(dq_bn);
  if (qinv_bn)
    BN_free(qinv_bn);
  if (pkey)
    EVP_PKEY_free(pkey);

  return ret;
}

static struct rte_mempool *asym_op_pool = NULL;
static struct rte_mempool *asym_sess_pool = NULL;
static struct rte_mempool *mbuf_pool = NULL;

static const char *rte_crypto_op_err_msg(const struct rte_crypto_op *op) {
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

static int setup_cryptodev() {
  uint8_t cdev_id = 0;

  struct rte_cryptodev_config config = {
      .nb_queue_pairs = 1,
      .socket_id = rte_socket_id(),
  };
  if (rte_cryptodev_configure(cdev_id, &config) < 0) {
    fprintf(stderr, "failed to configure crypto dev: %u\n", cdev_id);
    return -1;
  }

  struct rte_cryptodev_qp_conf qp_conf = {
      .nb_descriptors = 256,
  };
  if (rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf, rte_socket_id()) <
      0) {
    fprintf(stderr, "failed to setup queue pair 0 on crypto dev: %u\n",
            cdev_id);
    return -1;
  }

  if (rte_cryptodev_start(cdev_id) < 0) {
    fprintf(stderr, "failed to start crypto dev: %u\n", cdev_id);
    return -1;
  }

  return cdev_id;
}

static struct rte_cryptodev_asym_session *
create_sign_session(uint8_t cdev_id, const RsaKeyData *key_data) {
  // xform for signing (uses private key via QT format)
  struct rte_crypto_rsa_xform rsa_xform = {
      .key_type = RTE_RSA_KEY_TYPE_QT,
      .n = {.data = (uint8_t *)key_data->n, .length = RSA_KEY_SIZE_BYTES},
      .e = {.data = (uint8_t *)key_data->e, .length = key_data->e_len},
      // CRT parameters for private key operations
      .qt.p = {.data = (uint8_t *)key_data->p, .length = RSA_KEY_SIZE_BYTES / 2},
      .qt.q = {.data = (uint8_t *)key_data->q, .length = RSA_KEY_SIZE_BYTES / 2},
      .qt.dP = {.data = (uint8_t *)key_data->dp, .length = RSA_KEY_SIZE_BYTES / 2},
      .qt.dQ = {.data = (uint8_t *)key_data->dq, .length = RSA_KEY_SIZE_BYTES / 2},
      .qt.qInv = {.data = (uint8_t *)key_data->qinv,
               .length = RSA_KEY_SIZE_BYTES / 2},
      .padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5,
  };
  struct rte_crypto_asym_xform asym_xform = {
      .next = NULL,
      .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
      .rsa = rsa_xform,
  };
  struct rte_cryptodev_asym_session *sess = NULL;
  int ret = rte_cryptodev_asym_session_create(cdev_id, &asym_xform,
                                              asym_sess_pool, (void **)&sess);
  if (ret != 0 || !sess) {
    fprintf(stderr, "failed to create sign session\n");
    return NULL;
  }
  return sess;
}

static struct rte_cryptodev_asym_session *
create_verify_session(uint8_t cdev_id, const RsaKeyData *key_data) {
  // xform for verification (uses public key)
  struct rte_crypto_rsa_xform rsa_xform = {
      .key_type = RTE_RSA_KEY_TYPE_EXP,
      .n = {.data = (uint8_t *)key_data->n, .length = RSA_KEY_SIZE_BYTES},
      .e = {.data = (uint8_t *)key_data->e, .length = key_data->e_len},
      .padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5,
  };
  struct rte_crypto_asym_xform asym_xform = {
      .next = NULL,
      .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
      .rsa = rsa_xform,
  };
  struct rte_cryptodev_asym_session *sess = NULL;
  int ret = rte_cryptodev_asym_session_create(cdev_id, &asym_xform,
                                              asym_sess_pool, (void **)&sess);
  if (ret != 0 || !sess) {
    fprintf(stderr, "failed to create verify session\n");
    return NULL;
  }
  return sess;
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
  while (dequeued == 0 && retires < 10000) {
    dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, ops_deq, 1);
    retires++;
  }
  if (dequeued != 1) {
    fprintf(stderr, "failed to dequeue crypto op\n");
    return false;
  }

  // 3. check result
  struct rte_crypto_op *completed_op = ops_deq[0];
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    fprintf(stderr, "operation failed, status: %s\n",
            rte_crypto_op_err_msg(completed_op));
    return false;
  }

  return true;
}

bool perform_rsa_sign_verify_test(uint8_t cdev_id, const RsaKeyData *key_data,
                                   struct rte_cryptodev_asym_session *sign_sess,
                                   struct rte_cryptodev_asym_session *verify_sess) {
  bool ret = false;

  // 1. prepare message to sign
  const char *message = "DPDK RSA2048 test message for signing";
  size_t msg_len = strlen(message);

  // For PKCS#1 v1.5 padding, we need to hash the message first
  // The message length can be up to key size - padding overhead
  // For 2048-bit RSA with SHA256, we can sign the hash directly

  // Compute SHA256 hash of the message
  unsigned char hash[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    fprintf(stderr, "failed to create message digest context\n");
    goto cleanup;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(md_ctx, message, msg_len) != 1 ||
      EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    fprintf(stderr, "failed to compute SHA256 hash\n");
    EVP_MD_CTX_free(md_ctx);
    goto cleanup;
  }
  EVP_MD_CTX_free(md_ctx);

  printf("Original message: %s\n", message);
  printf("Message length: %zu bytes\n", msg_len);
  printf("SHA256 hash: ");
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  // 2. allocate buffers
  uint8_t *hash_buf = rte_zmalloc("hash_buf", SHA256_DIGEST_LENGTH, 0);
  if (!hash_buf) {
    fprintf(stderr, "failed to alloc for hash_buf\n");
    goto cleanup;
  }
  memcpy(hash_buf, hash, SHA256_DIGEST_LENGTH);

  uint8_t *signature_buf = rte_zmalloc("signature_buf", RSA_KEY_SIZE_BYTES, 0);
  if (!signature_buf) {
    fprintf(stderr, "failed to alloc for signature_buf\n");
    goto cleanup;
  }

  // 3. allocate crypto ops
  struct rte_crypto_op *op_sign =
      rte_crypto_op_alloc(asym_op_pool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op_sign) {
    fprintf(stderr, "failed to alloc for op_sign\n");
    goto cleanup;
  }

  struct rte_crypto_op *op_verify =
      rte_crypto_op_alloc(asym_op_pool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op_verify) {
    fprintf(stderr, "failed to alloc for op_verify\n");
    goto cleanup;
  }

  // 4. setup sign operation
  rte_crypto_op_attach_asym_session(op_sign, sign_sess);
  op_sign->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
  op_sign->asym->rsa.message.data = hash_buf;
  op_sign->asym->rsa.message.length = SHA256_DIGEST_LENGTH;
  op_sign->asym->rsa.sign.data = signature_buf;
  op_sign->asym->rsa.sign.length = RSA_KEY_SIZE_BYTES;

  // 5. perform sign operation
  printf("\nPerforming RSA sign operation...\n");
  if (!do_asym_op(cdev_id, op_sign)) {
    fprintf(stderr, "RSA signing failed\n");
    goto cleanup;
  }
  size_t sig_len = op_sign->asym->rsa.sign.length;
  printf("Signing successful, signature length: %zu bytes\n", sig_len);

  // Print first few bytes of signature for debugging
  printf("Signature (first 32 bytes): ");
  for (int i = 0; i < (sig_len > 32 ? 32 : sig_len); i++) {
    printf("%02x", signature_buf[i]);
  }
  printf("\n");

  // 6. setup verify operation
  rte_crypto_op_attach_asym_session(op_verify, verify_sess);
  op_verify->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
  op_verify->asym->rsa.sign.data = signature_buf;
  op_verify->asym->rsa.sign.length = sig_len;
  op_verify->asym->rsa.message.data = hash_buf;
  op_verify->asym->rsa.message.length = SHA256_DIGEST_LENGTH;

  // 7. perform verify operation
  printf("\nPerforming RSA verify operation...\n");
  if (!do_asym_op(cdev_id, op_verify)) {
    fprintf(stderr, "RSA verification failed\n");
    goto cleanup;
  }

  printf("Verification successful!\n");
  printf("The signature is valid.\n");

  ret = true;

cleanup:
  if (hash_buf)
    rte_free(hash_buf);
  if (signature_buf)
    rte_free(signature_buf);
  if (op_sign)
    rte_crypto_op_free(op_sign);
  if (op_verify)
    rte_crypto_op_free(op_verify);
  return ret;
}

int main(int argc, char **argv) {
  int ret = 0;
  uint8_t cdev_id = 0;
  bool cdev_started = false;
  RsaKeyData *key_data = NULL;
  struct rte_cryptodev_asym_session *sign_sess = NULL;
  struct rte_cryptodev_asym_session *verify_sess = NULL;

  // 1. read rsa data
  key_data = malloc(sizeof(RsaKeyData));
  if (!key_data) {
    fprintf(stderr, "failed to allocate key_data\n");
    ret = -1;
    goto cleanup;
  }

  if (!load_rsa_key_components(key_data)) {
    fprintf(stderr, "failed to load rsa data\n");
    ret = -1;
    goto cleanup;
  }

  // 2. initialize EAL
  if (rte_eal_init(argc, argv) < 0) {
    fprintf(stderr, "failed to init EAL\n");
    ret = -1;
    goto cleanup;
  }

  // 3. cryptodev setup
  cdev_id = setup_cryptodev();
  if (cdev_id == (uint8_t)-1) {
    fprintf(stderr, "Error configure cryptodev\n");
    ret = -1;
    goto cleanup;
  }
  cdev_started = true;

  // 4. mbuf & crypto_op mempool alloc
  asym_op_pool = rte_crypto_op_pool_create(
      ASYM_OP_POOL_NAME, RTE_CRYPTO_OP_TYPE_ASYMMETRIC, ASYM_OPS_PER_POOL, 0,
      sizeof(struct rte_crypto_asym_op), rte_socket_id());
  if (!asym_op_pool) {
    fprintf(stderr, "asym_op_pool alloc failed\n");
    ret = -1;
    goto cleanup;
  }

  mbuf_pool =
      rte_pktmbuf_pool_create(MBUF_POOL_NAME, MBUFS_PER_POOL, 0, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (!mbuf_pool) {
    fprintf(stderr, "mbuf_pool alloc failed\n");
    ret = -1;
    goto cleanup;
  }

  size_t priv_size = rte_cryptodev_asym_get_private_session_size(cdev_id);
  printf("got priv_size: %zu\n", priv_size);

  asym_sess_pool = rte_cryptodev_asym_session_pool_create(
      ASYM_SESS_POOL_NAME, ASYM_SESS_PER_POOL, 0, priv_size, rte_socket_id());
  if (!asym_sess_pool) {
    fprintf(stderr, "failed to alloc asym_sess_pool\n");
    ret = -1;
    goto cleanup;
  }

  // 5. create sessions
  sign_sess = create_sign_session(cdev_id, key_data);
  if (!sign_sess) {
    fprintf(stderr, "failed to create sign session\n");
    ret = -1;
    goto cleanup;
  }

  verify_sess = create_verify_session(cdev_id, key_data);
  if (!verify_sess) {
    fprintf(stderr, "failed to create verify session\n");
    ret = -1;
    goto cleanup;
  }

  // 6. perform sign and verify test
  if (!perform_rsa_sign_verify_test(cdev_id, key_data, sign_sess, verify_sess)) {
    fprintf(stderr, "RSA sign/verify test failed\n");
    ret = -1;
    goto cleanup;
  }

  printf("\ntest complete, cleaning resource...\n");

cleanup:
  if (sign_sess)
    rte_cryptodev_asym_session_free(cdev_id, sign_sess);
  if (verify_sess)
    rte_cryptodev_asym_session_free(cdev_id, verify_sess);
  if (mbuf_pool)
    rte_mempool_free(mbuf_pool);
  if (asym_op_pool)
    rte_mempool_free(asym_op_pool);
  if (asym_sess_pool)
    rte_mempool_free(asym_sess_pool);
  if (cdev_started)
    rte_cryptodev_stop(cdev_id);
  if (key_data)
    free(key_data);
  rte_eal_cleanup();

  return ret;
}

