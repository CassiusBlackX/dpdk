#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_comp.h>
#include <rte_compressdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define INPUT_SIZE_BYTES (512u * 1024u * 1024u)
#define CHUNK_SIZE_BYTES (32u * 1024u)
#define SRC_MBUF_DATA_ROOM (CHUNK_SIZE_BYTES + 2048)
#define DST_MBUF_DATA_ROOM (CHUNK_SIZE_BYTES + 4096)
#define MBUF_POOL_SIZE 4096
#define OP_POOL_SIZE 2048
#define MEMPOOL_CACHE_SIZE 128
#define QP_NB_DESCRIPTORS 1024
#define DECOMP_DST_CHAIN_BYTES (CHUNK_SIZE_BYTES * 64u)

static int copy_from_mbuf_chain(const struct rte_mbuf *mbuf, uint8_t *dst,
                                uint32_t len) {
  const struct rte_mbuf *seg = mbuf;
  uint32_t copied = 0;

  while (seg != NULL && copied < len) {
    uint32_t seg_len = rte_pktmbuf_data_len(seg);
    uint32_t to_copy = RTE_MIN(seg_len, len - copied);
    const uint8_t *src = rte_pktmbuf_mtod(seg, const uint8_t *);

    memcpy(dst + copied, src, to_copy);
    copied += to_copy;
    seg = seg->next;
  }

  return copied == len ? 0 : -EINVAL;
}

static struct rte_mbuf *alloc_dst_chain(struct rte_mempool *pool,
                                        uint32_t total_len) {
  uint32_t remaining = total_len;
  struct rte_mbuf *head, *seg;

  head = rte_pktmbuf_alloc(pool);
  if (head == NULL)
    return NULL;

  while (remaining > 0) {
    uint32_t seg_len = RTE_MIN(remaining, (uint32_t)DST_MBUF_DATA_ROOM);
    void *data;

    if (head->pkt_len == 0) {
      seg = head;
    } else {
      seg = rte_pktmbuf_alloc(pool);
      if (seg == NULL)
        goto fail;
      if (rte_pktmbuf_chain(head, seg) < 0) {
        rte_pktmbuf_free(seg);
        goto fail;
      }
    }

    data = rte_pktmbuf_append(seg, seg_len);
    if (data == NULL)
      goto fail;

    remaining -= seg_len;
  }

  return head;

fail:
  rte_pktmbuf_free(head);
  return NULL;
}

static int verify_decompressed_data(const uint8_t *decompressed,
                                    size_t decompressed_len,
                                    const uint8_t *expected,
                                    size_t expected_len) {
  if (decompressed_len != expected_len)
    return -EIO;

  if (memcmp(decompressed, expected, expected_len) != 0) {
    size_t i;

    for (i = 0; i < expected_len; i++) {
      if (decompressed[i] != expected[i]) {
        printf("Data mismatch at position %zu: got 0x%02x, expected 0x%02x\n",
               i, decompressed[i], expected[i]);
        break;
      }
    }
    return -EIO;
  }

  return 0;
}

int main(int argc, char **argv) {
  int ret = 1;
  int cdev_started = 0;
  uint16_t dev_id = 0;
  uint16_t nb_devs;
  struct rte_compressdev_config cdev_conf;
  struct rte_comp_xform compress_xform;
  struct rte_comp_xform decompress_xform;
  void *compress_stream = NULL;
  void *decompress_stream = NULL;
  struct rte_mempool *src_pool = NULL;
  struct rte_mempool *dst_pool = NULL;
  struct rte_mempool *op_pool = NULL;
  uint8_t *input = NULL;
  uint8_t *compressed = NULL;
  uint8_t *decompressed = NULL;
  uint32_t *compressed_chunk_lens = NULL;
  size_t compressed_cap;
  size_t compressed_len = 0;
  size_t decompressed_len = 0;
  size_t input_off = 0;
  size_t compressed_off = 0;
  uint64_t nb_input_chunks =
      (INPUT_SIZE_BYTES + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES;
  uint64_t chunk_idx = 0;
  uint64_t decomp_chunk_idx = 0;

  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "EAL init failed\n");

  nb_devs = rte_compressdev_count();
  if (nb_devs == 0)
    rte_exit(EXIT_FAILURE,
             "No compressdev found, run with --vdev compress_zlib\n");

  printf("Found %u compressdev(s), use dev_id=%u\n", nb_devs, dev_id);

  input = malloc(INPUT_SIZE_BYTES);
  if (input == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate input buffer\n");

  for (uint64_t i = 0; i < INPUT_SIZE_BYTES; i++)
    input[i] = (uint8_t)((i * 1315423911ULL + (i >> 7)) & 0xff);

  compressed_cap = INPUT_SIZE_BYTES + (INPUT_SIZE_BYTES / 8) +
                   (INPUT_SIZE_BYTES / CHUNK_SIZE_BYTES) * 32 + 4096;
  compressed = malloc(compressed_cap);
  if (compressed == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate compressed buffer\n");

  compressed_chunk_lens =
      calloc(nb_input_chunks, sizeof(*compressed_chunk_lens));
  if (compressed_chunk_lens == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate compressed chunk lens\n");

  decompressed = malloc(INPUT_SIZE_BYTES);
  if (decompressed == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate decompressed buffer\n");

  src_pool = rte_pktmbuf_pool_create(
      "stateful_src_pool", MBUF_POOL_SIZE, MEMPOOL_CACHE_SIZE, 0,
      SRC_MBUF_DATA_ROOM + RTE_PKTMBUF_HEADROOM, rte_socket_id());
  if (src_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create source mbuf pool\n");

  dst_pool = rte_pktmbuf_pool_create(
      "stateful_dst_pool", MBUF_POOL_SIZE, MEMPOOL_CACHE_SIZE, 0,
      DST_MBUF_DATA_ROOM + RTE_PKTMBUF_HEADROOM, rte_socket_id());
  if (dst_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create destination mbuf pool\n");

  op_pool = rte_comp_op_pool_create("stateful_op_pool", OP_POOL_SIZE,
                                    MEMPOOL_CACHE_SIZE, 0, rte_socket_id());
  if (op_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create comp op pool\n");

  memset(&cdev_conf, 0, sizeof(cdev_conf));
  cdev_conf.socket_id = rte_socket_id();
  cdev_conf.nb_queue_pairs = 1;
  cdev_conf.max_nb_priv_xforms = 2;
  cdev_conf.max_nb_streams = 2;

  if (rte_compressdev_configure(dev_id, &cdev_conf) < 0)
    rte_exit(EXIT_FAILURE, "rte_compressdev_configure failed\n");

  if (rte_compressdev_queue_pair_setup(dev_id, 0, QP_NB_DESCRIPTORS,
                                       rte_socket_id()) < 0)
    rte_exit(EXIT_FAILURE, "rte_compressdev_queue_pair_setup failed\n");

  if (rte_compressdev_start(dev_id) < 0)
    rte_exit(EXIT_FAILURE, "rte_compressdev_start failed\n");
  cdev_started = 1;

  memset(&compress_xform, 0, sizeof(compress_xform));
  compress_xform.type = RTE_COMP_COMPRESS;
  compress_xform.compress.algo = RTE_COMP_ALGO_DEFLATE;
  compress_xform.compress.deflate.huffman = RTE_COMP_HUFFMAN_DEFAULT;
  compress_xform.compress.level = RTE_COMP_LEVEL_PMD_DEFAULT;
  compress_xform.compress.chksum = RTE_COMP_CHECKSUM_NONE;
  compress_xform.compress.window_size = 15;

  memset(&decompress_xform, 0, sizeof(decompress_xform));
  decompress_xform.type = RTE_COMP_DECOMPRESS;
  decompress_xform.decompress.algo = RTE_COMP_ALGO_DEFLATE;
  decompress_xform.decompress.chksum = RTE_COMP_CHECKSUM_NONE;
  decompress_xform.decompress.window_size = 15;

  if (rte_compressdev_stream_create(dev_id, &compress_xform, &compress_stream) <
      0)
    rte_exit(EXIT_FAILURE,
             "rte_compressdev_stream_create failed for compression\n");

  printf("Starting stateful compression...\n");

  while (input_off < INPUT_SIZE_BYTES) {
    uint32_t chunk_len = (uint32_t)RTE_MIN((size_t)CHUNK_SIZE_BYTES,
                                           INPUT_SIZE_BYTES - input_off);
    struct rte_mbuf *src;
    struct rte_mbuf *dst;
    struct rte_comp_op *op;
    uint8_t *src_data;
    uint8_t *dst_data;
    enum rte_comp_flush_flag flush = (input_off + chunk_len == INPUT_SIZE_BYTES)
                                         ? RTE_COMP_FLUSH_FINAL
                                         : RTE_COMP_FLUSH_NONE;

    src = rte_pktmbuf_alloc(src_pool);
    dst = rte_pktmbuf_alloc(dst_pool);
    op = rte_comp_op_alloc(op_pool);
    if (!src || !dst || !op)
      rte_exit(EXIT_FAILURE, "mbuf/op alloc failed at chunk=%" PRIu64 "\n",
               chunk_idx);

    src_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(src, chunk_len);
    dst_data =
        (uint8_t *)(uintptr_t)rte_pktmbuf_append(dst, CHUNK_SIZE_BYTES + 1024);
    if (!src_data || !dst_data)
      rte_exit(EXIT_FAILURE, "rte_pktmbuf_append failed at chunk=%" PRIu64 "\n",
               chunk_idx);

    memcpy(src_data, input + input_off, chunk_len);

    op->m_src = src;
    op->m_dst = dst;
    op->src.offset = 0;
    op->src.length = chunk_len;
    op->dst.offset = 0;
    op->flush_flag = flush;
    op->op_type = RTE_COMP_OP_STATEFUL;
    op->stream = compress_stream;

    while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0)
      rte_pause();

    while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0)
      rte_pause();

    if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
      rte_exit(EXIT_FAILURE,
               "stateful compress failed at chunk=%" PRIu64 ", status=%u\n",
               chunk_idx, op->status);
    }

    if (compressed_len + op->produced > compressed_cap)
      rte_exit(EXIT_FAILURE, "compressed output buffer too small\n");

    memcpy(compressed + compressed_len, dst_data, op->produced);
    compressed_chunk_lens[chunk_idx] = op->produced;
    compressed_len += op->produced;

    rte_comp_op_free(op);
    rte_pktmbuf_free(src);
    rte_pktmbuf_free(dst);

    input_off += chunk_len;
    chunk_idx++;
  }

  printf("Stateful compressed 512MB input to %zu bytes (%" PRIu64 " chunks)\n",
         compressed_len, chunk_idx);

  printf("Starting stateful decompression...\n");

  if (rte_compressdev_stream_create(dev_id, &decompress_xform,
                                    &decompress_stream) < 0)
    rte_exit(EXIT_FAILURE,
             "rte_compressdev_stream_create failed for decompression\n");

  decompressed_len = 0;
  for (decomp_chunk_idx = 0; decomp_chunk_idx < chunk_idx; decomp_chunk_idx++) {
    uint32_t chunk_len = compressed_chunk_lens[decomp_chunk_idx];
    struct rte_mbuf *src;
    struct rte_mbuf *dst;
    struct rte_comp_op *op;
    uint8_t *src_data;
    enum rte_comp_flush_flag flush = (decomp_chunk_idx + 1 == chunk_idx)
                                         ? RTE_COMP_FLUSH_FINAL
                                         : RTE_COMP_FLUSH_NONE;

    if (chunk_len == 0)
      continue;

    src = rte_pktmbuf_alloc(src_pool);
    dst = alloc_dst_chain(dst_pool, DECOMP_DST_CHAIN_BYTES);
    op = rte_comp_op_alloc(op_pool);
    if (!src || !dst || !op)
      rte_exit(EXIT_FAILURE,
               "mbuf/op alloc failed at decomp chunk=%" PRIu64 "\n",
               decomp_chunk_idx);

    src_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(src, chunk_len);
    if (!src_data)
      rte_exit(EXIT_FAILURE,
               "rte_pktmbuf_append failed at decomp chunk=%" PRIu64 "\n",
               decomp_chunk_idx);

    memcpy(src_data, compressed + compressed_off, chunk_len);

    op->m_src = src;
    op->m_dst = dst;
    op->src.offset = 0;
    op->src.length = chunk_len;
    op->dst.offset = 0;
    op->flush_flag = flush;
    op->op_type = RTE_COMP_OP_STATEFUL;
    op->stream = decompress_stream;

    while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0)
      rte_pause();

    while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0)
      rte_pause();

    if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
      if (op->status == RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED) {
        rte_exit(EXIT_FAILURE,
                 "stateful decompress dst chain too small at chunk=%" PRIu64
                 ", produced=%u (status=%u)\n",
                 decomp_chunk_idx, op->produced, op->status);
      }
      rte_exit(EXIT_FAILURE,
               "stateful decompress failed at chunk=%" PRIu64 ", status=%u\n",
               decomp_chunk_idx, op->status);
    }

    if (decompressed_len + op->produced > INPUT_SIZE_BYTES) {
      rte_exit(
          EXIT_FAILURE,
          "decompressed output buffer too small: "
          "decompressed_len=%zu, produced=%u, total=%zu, buffer_size=%zu\n",
          decompressed_len, op->produced, decompressed_len + op->produced,
          (size_t)INPUT_SIZE_BYTES);
    }

    if (copy_from_mbuf_chain(dst, decompressed + decompressed_len,
                             op->produced) < 0) {
      rte_exit(EXIT_FAILURE,
               "copy_from_mbuf_chain failed at chunk=%" PRIu64 "\n",
               decomp_chunk_idx);
    }
    decompressed_len += op->produced;

    rte_comp_op_free(op);
    rte_pktmbuf_free(src);
    rte_pktmbuf_free(dst);

    compressed_off += chunk_len;
  }

  if (compressed_off != compressed_len)
    rte_exit(EXIT_FAILURE,
             "decompression consumed %zu compressed bytes, expected %zu\n",
             compressed_off, compressed_len);

  printf(
      "Stateful decompressed %zu bytes compressed data to %zu bytes (%" PRIu64
      " chunks)\n",
      compressed_len, decompressed_len, decomp_chunk_idx);

  ret = verify_decompressed_data(decompressed, decompressed_len, input,
                                 INPUT_SIZE_BYTES);
  if (ret == 0)
    printf("PASS: DPDK stateful decompression verify success\n");
  else
    printf("FAIL: DPDK stateful decompression verify failed (%d)\n", ret);

  ret = (ret == 0) ? 0 : 1;

  if (compress_stream)
    rte_compressdev_stream_free(dev_id, compress_stream);
  if (decompress_stream)
    rte_compressdev_stream_free(dev_id, decompress_stream);
  if (cdev_started)
    rte_compressdev_stop(dev_id);
  rte_compressdev_close(dev_id);

  free(input);
  free(compressed);
  free(decompressed);
  free(compressed_chunk_lens);

  return ret;
}
