/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co.,Ltd.
 */

/*
 * compress_uadk (WD_LZ77_ZSTD) produces literals + sequences in the dst mbuf.
 * This example wraps each chunk with libzstd ZSTD_compressSequences() into a
 * ZSTD frame, concatenates frames, and verifies via ZSTD_decompress().
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <rte_common.h>
#include <rte_compressdev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pause.h>

#define INPUT_DEFAULT (512u * 1024u * 1024u)
#define INPUT_QUICK (8u * 1024u * 1024u)
/*
 * Per-segment mbuf data is uint16_t-limited; use 32 KiB chunks (still within
 * UADK 128 KiB ZSTD_MAX_SIZE). Chain source mbufs if larger chunks are needed.
 */
#define CHUNK_MAX (32u * 1024u)
#define UADK_LIT_RSV 16u
#define UADK_FREQ_SZ 784u
#define UADK_SEQ_ROOM (8u * 1024u * 1024u)
#define DST_SEG_ROOM ((uint16_t)UINT16_MAX)

#define OP_POOL_SZ 512u
#define SRC_POOL_SZ 512u
/*
 * One ZSTD offload needs ~8MiB seq room + literals + freq. With ~64KiB per mbuf
 * segment, that is ceil(8.4MiB / ~63KiB) ≈ 130 mbufs — pool must be >= that.
 */
#define DST_SEG_PAYLOAD_ELTS (((uint32_t)DST_SEG_ROOM - RTE_PKTMBUF_HEADROOM))
#define UADK_DST_NEED_BYTES(in_len)                                            \
  ((in_len) + UADK_LIT_RSV + UADK_FREQ_SZ + UADK_SEQ_ROOM)
#define DST_MBUFS_PER_CHUNK_MAX                                                \
  ((UADK_DST_NEED_BYTES(CHUNK_MAX) + DST_SEG_PAYLOAD_ELTS - 1) /               \
   DST_SEG_PAYLOAD_ELTS)
#define DST_CHAIN_POOL (DST_MBUFS_PER_CHUNK_MAX + 64u)
#define QP_NB 1024u
/*
 * Per-lcore mempool cache flush threshold is (cache*3)/2 and must be <= n.
 * With DST_CHAIN_POOL small and many lcores, a non-zero cache breaks create.
 */
#define MP_CACHE_SRC 128u
#define MP_CACHE_DST 0u
#define MP_CACHE_OP 128u

typedef struct {
  uint32_t offset;
  uint16_t litLength;
  uint16_t matchLength;
} hw_seqdef;

static uint32_t dst_seg_payload(void) {
  return (uint32_t)DST_SEG_ROOM - RTE_PKTMBUF_HEADROOM;
}

static unsigned int dst_nb_segs_for(uint32_t need_bytes) {
  uint32_t per = dst_seg_payload();

  return (unsigned int)((need_bytes + per - 1) / per);
}

static uint32_t dst_need_bytes(uint32_t in_len) {
  return in_len + UADK_LIT_RSV + UADK_FREQ_SZ + UADK_SEQ_ROOM;
}

static struct rte_mbuf *alloc_dst_chain(struct rte_mempool *mp,
                                        uint32_t need_bytes) {
  unsigned int n = dst_nb_segs_for(need_bytes);
  uint32_t need = need_bytes;
  uint32_t per = dst_seg_payload();
  struct rte_mbuf **segs;
  struct rte_mbuf *head;
  unsigned int i;

  if (n == 0)
    return NULL;
  segs = malloc(n * sizeof(*segs));
  if (segs == NULL)
    return NULL;
  for (i = 0; i < n; i++) {
    segs[i] = rte_pktmbuf_alloc(mp);
    if (segs[i] == NULL) {
      while (i > 0)
        rte_pktmbuf_free(segs[--i]);
      free(segs);
      return NULL;
    }
  }
  for (i = 0; i < n; i++) {
    uint32_t chunk = RTE_MIN(per, need);
    unsigned int j;

    if (rte_pktmbuf_append(segs[i], (uint16_t)chunk) == NULL) {
      for (j = 0; j < n; j++)
        rte_pktmbuf_free(segs[j]);
      free(segs);
      return NULL;
    }
    need -= chunk;
  }
  if (need != 0) {
    for (i = 0; i < n; i++)
      rte_pktmbuf_free(segs[i]);
    free(segs);
    return NULL;
  }
  head = segs[0];
  for (i = 1; i < n; i++) {
    if (rte_pktmbuf_chain(head, segs[i]) != 0) {
      unsigned int j;

      rte_pktmbuf_free(head);
      for (j = i; j < n; j++)
        rte_pktmbuf_free(segs[j]);
      free(segs);
      return NULL;
    }
  }
  free(segs);
  return head;
}

static uint8_t find_zstd_lz77_compressdev(void) {
  uint8_t i;
  uint8_t n = (uint8_t)rte_compressdev_count();

  for (i = 0; i < n; i++) {
    struct rte_compressdev_info inf;

    rte_compressdev_info_get(i, &inf);
    if (inf.driver_name == NULL)
      continue;
    if (strcmp(inf.driver_name, "compress_uadk") == 0 ||
        strcmp(inf.driver_name, "compress_lz77_zstd") == 0)
      return i;
  }
  return UINT8_MAX;
}

static void enqueue_dequeue(uint16_t dev_id, struct rte_comp_op *op) {
  while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0)
    rte_pause();
  while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0)
    rte_pause();
}

static int hw_seqs_to_zstd(const uint8_t *raw, uint32_t seq_count,
                           ZSTD_Sequence *out) {
  uint32_t i;

  for (i = 0; i < seq_count; i++) {
    const hw_seqdef *h = (const hw_seqdef *)(raw + i * sizeof(hw_seqdef));

    out[i].offset = h->offset;
    out[i].litLength = h->litLength;
    out[i].matchLength = h->matchLength;
    out[i].rep = 0;
  }
  return 0;
}

static void *app_malloc(size_t sz) {
  void *p = NULL;

  if (sz == 0)
    return NULL;
  if (posix_memalign(&p, RTE_CACHE_LINE_SIZE, sz) != 0)
    return NULL;
  return p;
}

static void compressdev_shutdown(uint16_t dev_id, void **priv_xform,
                                 bool dev_started) {
  if (*priv_xform != NULL) {
    rte_compressdev_private_xform_free(dev_id, *priv_xform);
    *priv_xform = NULL;
  }
  if (dev_started) {
    rte_compressdev_stop(dev_id);
    rte_compressdev_close(dev_id);
  }
}

int main(int argc, char **argv) {
  uint8_t *input = NULL;
  size_t input_len = INPUT_DEFAULT;
  size_t comp_total_cap;
  uint8_t *comp_concat = NULL;
  size_t comp_off = 0;
  size_t *frame_sizes = NULL;
  size_t nframes = 0;
  size_t max_frames;
  struct rte_mempool *src_pool = NULL;
  struct rte_mempool *dst_pool = NULL;
  struct rte_mempool *op_pool = NULL;
  uint16_t dev_id;
  void *priv_xform = NULL;
  ZSTD_CCtx *zc = NULL;
  int ret;
  size_t in_off;
  bool dev_started = false;
  int exit_rc = EXIT_FAILURE;

  if (getenv("DPDK_UADK_ZSTD_QUICK") != NULL)
    input_len = INPUT_QUICK;

  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "EAL init failed\n");

  dev_id = find_zstd_lz77_compressdev();
  if (dev_id == UINT8_MAX)
    rte_exit(
        EXIT_FAILURE,
        "No compress_uadk or compress_lz77_zstd device "
        "(compressdev_count=%u). "
        "Use e.g. --vdev compress_uadk or --vdev compress_lz77_zstd "
        "(not compress_zstdraw: vdev matches compress_zstd prefix first); "
        "for static builds enable compress/uadk and/or compress/zstd_raw.\n",
        (unsigned int)rte_compressdev_count());

  {
    struct rte_compressdev_config cfg = {0};

    cfg.socket_id = rte_socket_id();
    cfg.nb_queue_pairs = 1;
    cfg.max_nb_priv_xforms = 8;
    cfg.max_nb_streams = 8;
    if (rte_compressdev_configure(dev_id, &cfg) != 0)
      rte_exit(EXIT_FAILURE, "compressdev configure failed\n");
  }
  if (rte_compressdev_queue_pair_setup(dev_id, 0, QP_NB, rte_socket_id()) != 0)
    rte_exit(EXIT_FAILURE, "queue pair setup failed\n");
  if (rte_compressdev_start(dev_id) != 0)
    rte_exit(EXIT_FAILURE, "compressdev start failed\n");
  dev_started = true;

  {
    struct rte_comp_xform xf = {0};

    xf.type = RTE_COMP_COMPRESS;
    xf.compress.algo = RTE_COMP_ALGO_ZSTD;
    xf.compress.level = RTE_COMP_LEVEL_PMD_DEFAULT;
    xf.compress.chksum = RTE_COMP_CHECKSUM_NONE;
    xf.compress.window_size = 15;
    if (rte_compressdev_private_xform_create(dev_id, &xf, &priv_xform) != 0) {
      fprintf(stderr, "private_xform_create ZSTD failed\n");
      goto fail;
    }
  }

  input = app_malloc(input_len);
  if (input == NULL) {
    fprintf(stderr,
            "alloc input (%zu MiB) failed (use system memory, not DPDK "
            "rte_malloc)\n",
            input_len / (1024 * 1024));
    goto fail;
  }
  for (size_t i = 0; i < input_len; i++)
    input[i] = (uint8_t)((i * 1315423911ULL + (i >> 7)) & 0xff);

  max_frames = (input_len + CHUNK_MAX - 1) / CHUNK_MAX + 8;
  frame_sizes = calloc(max_frames, sizeof(*frame_sizes));
  comp_total_cap = max_frames * ZSTD_compressBound(CHUNK_MAX) + 65536u;
  if (frame_sizes == NULL) {
    fprintf(stderr, "calloc frame_sizes failed\n");
    goto fail;
  }
  comp_concat = app_malloc(comp_total_cap);
  if (comp_concat == NULL) {
    fprintf(stderr, "alloc comp_concat failed (%zu bytes)\n", comp_total_cap);
    goto fail;
  }

  src_pool = rte_pktmbuf_pool_create("uz_src", SRC_POOL_SZ, MP_CACHE_SRC, 0,
                                     CHUNK_MAX + RTE_PKTMBUF_HEADROOM,
                                     rte_socket_id());
  dst_pool = rte_pktmbuf_pool_create("uz_dst", DST_CHAIN_POOL, MP_CACHE_DST, 0,
                                     DST_SEG_ROOM, rte_socket_id());
  op_pool = rte_comp_op_pool_create("uz_op", OP_POOL_SZ, MP_CACHE_OP, 0,
                                    rte_socket_id());
  if (src_pool == NULL || dst_pool == NULL || op_pool == NULL) {
    fprintf(stderr,
            "mempool create failed (errno=%d). "
            "For small dst pool use MP_CACHE_DST=0 (flush_thresh <= n).\n",
            rte_errno);
    goto fail;
  }

  zc = ZSTD_createCCtx();
  if (zc == NULL) {
    fprintf(stderr, "ZSTD_createCCtx failed\n");
    goto fail;
  }
  /*
   * ZSTD_CCtx_setParameter() returns 0 for many params but not all; success
   * must be checked with ZSTD_isError(), not (ret != 0).
   */
  {
    size_t zst;

    zst = ZSTD_CCtx_setParameter(zc, ZSTD_c_blockDelimiters,
                                 (int)ZSTD_sf_noBlockDelimiters);
    if (ZSTD_isError(zst)) {
      fprintf(stderr, "ZSTD_c_blockDelimiters: %s\n", ZSTD_getErrorName(zst));
      goto fail;
    }
    /*
     * UADK returns hardware tuple format (offBase/mlBase) which is
     * compatible for frame regeneration but not always accepted by
     * libzstd's strict external-sequence validator.
     */
    zst = ZSTD_CCtx_setParameter(zc, ZSTD_c_validateSequences, 0);
    if (ZSTD_isError(zst)) {
      fprintf(stderr, "ZSTD_c_validateSequences: %s\n", ZSTD_getErrorName(zst));
      goto fail;
    }
    zst = ZSTD_CCtx_setParameter(zc, ZSTD_c_minMatch, ZSTD_MINMATCH_MIN);
    if (ZSTD_isError(zst)) {
      fprintf(stderr, "ZSTD_c_minMatch: %s\n", ZSTD_getErrorName(zst));
      goto fail;
    }
    /* Match compressdev xform window_size (15). */
    zst = ZSTD_CCtx_setParameter(zc, ZSTD_c_windowLog, 15);
    if (ZSTD_isError(zst)) {
      fprintf(stderr, "ZSTD_c_windowLog: %s\n", ZSTD_getErrorName(zst));
      goto fail;
    }
  }

  in_off = 0;
  while (in_off < input_len) {
    uint32_t chunk = (uint32_t)RTE_MIN((size_t)CHUNK_MAX, input_len - in_off);
    uint32_t dst_need = dst_need_bytes(chunk);
    uint32_t seq_off = 0;
    struct rte_mbuf *src;
    struct rte_mbuf *dst;
    struct rte_comp_op *op;
    uint32_t lit_num;
    uint32_t seq_num;
    uint8_t *raw_seq;
    ZSTD_Sequence *zseq;
    size_t zsz;

    src = rte_pktmbuf_alloc(src_pool);
    if (src == NULL) {
      fprintf(stderr, "rte_pktmbuf_alloc(src_pool) failed\n");
      goto fail;
    }
    dst = alloc_dst_chain(dst_pool, dst_need);
    if (dst == NULL) {
      fprintf(stderr,
              "alloc_dst_chain failed: output_need=%u bytes (~%u mbuf segs), "
              "dst_pool_elts=%u (increase DST_CHAIN_POOL if too small)\n",
              dst_need, (unsigned int)dst_nb_segs_for(dst_need),
              (unsigned int)DST_CHAIN_POOL);
      rte_pktmbuf_free(src);
      goto fail;
    }
    op = rte_comp_op_alloc(op_pool);
    if (op == NULL) {
      fprintf(stderr, "rte_comp_op_alloc failed\n");
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }

    memcpy(rte_pktmbuf_append(src, chunk), input + in_off, chunk);
    op->op_type = RTE_COMP_OP_STATELESS;
    op->flush_flag = RTE_COMP_FLUSH_FINAL;
    op->m_src = src;
    op->m_dst = dst;
    op->src.offset = 0;
    op->src.length = chunk;
    op->dst.offset = 0;
    op->private_xform = priv_xform;

    enqueue_dequeue(dev_id, op);

    if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
      fprintf(stderr, "comp op failed status=%u debug_status=%" PRIu64 "\n",
              op->status, (uint64_t)op->debug_status);
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }

    lit_num = (uint32_t)(op->debug_status & 0xffffffffu);
    seq_num = (uint32_t)(op->debug_status >> 32);
    for (struct rte_mbuf *seg = dst;
         seg != NULL && seq_off < chunk + UADK_LIT_RSV; seg = seg->next) {
      seq_off += rte_pktmbuf_data_len(seg);
    }
    if (seq_off < chunk + UADK_LIT_RSV) {
      fprintf(stderr, "dst chain shorter than zstd literals area\n");
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }
    raw_seq = NULL;
    if (lit_num > seq_off) {
      fprintf(stderr, "invalid lit_num=%u for chunk=%u\n", lit_num, chunk);
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }
    zseq = malloc(RTE_MAX((size_t)seq_num, 1u) * sizeof(ZSTD_Sequence));
    if (zseq == NULL) {
      fprintf(stderr, "seq buffer alloc failed\n");
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }

    if (seq_num != 0) {
      raw_seq = malloc((size_t)seq_num * 8u);
      if (raw_seq == NULL) {
        fprintf(stderr, "raw_seq alloc failed\n");
        free(zseq);
        rte_comp_op_free(op);
        rte_pktmbuf_free(src);
        rte_pktmbuf_free(dst);
        goto fail;
      }
      if (rte_pktmbuf_read(dst, seq_off, seq_num * 8u, raw_seq) == NULL) {
        fprintf(stderr, "read sequences failed\n");
        free(raw_seq);
        free(zseq);
        rte_comp_op_free(op);
        rte_pktmbuf_free(src);
        rte_pktmbuf_free(dst);
        goto fail;
      }
      hw_seqs_to_zstd(raw_seq, seq_num, zseq);
    }

    if (comp_off + ZSTD_compressBound(chunk) > comp_total_cap) {
      fprintf(stderr, "comp_concat too small\n");
      free(zseq);
      if (raw_seq != NULL)
        free(raw_seq);
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }

    zsz = ZSTD_compressSequences(zc, comp_concat + comp_off,
                                 comp_total_cap - comp_off, zseq, seq_num,
                                 input + in_off, chunk);
    if (ZSTD_isError(zsz)) {
      fprintf(stderr, "ZSTD_compressSequences: %s\n", ZSTD_getErrorName(zsz));
      free(zseq);
      if (raw_seq != NULL)
        free(raw_seq);
      rte_comp_op_free(op);
      rte_pktmbuf_free(src);
      rte_pktmbuf_free(dst);
      goto fail;
    }

    frame_sizes[nframes++] = zsz;
    comp_off += zsz;

    free(zseq);
    if (raw_seq != NULL)
      free(raw_seq);
    rte_comp_op_free(op);
    rte_pktmbuf_free(src);
    rte_pktmbuf_free(dst);
    in_off += chunk;
  }

  {
    uint8_t *out = app_malloc(input_len);
    size_t out_sz = 0;
    size_t cin = 0;

    if (out == NULL) {
      fprintf(stderr, "out alloc failed\n");
      goto fail;
    }

    for (size_t f = 0; f < nframes; f++) {
      size_t fsz = frame_sizes[f];
      size_t dec;

      if (cin + fsz > comp_off) {
        fprintf(stderr, "frame size corrupt\n");
        free(out);
        goto fail;
      }
      dec = ZSTD_decompress(out + out_sz, input_len - out_sz, comp_concat + cin,
                            fsz);
      if (ZSTD_isError(dec)) {
        fprintf(stderr, "ZSTD_decompress failed\n");
        free(out);
        goto fail;
      }
      cin += fsz;
      out_sz += dec;
    }
    if (out_sz != input_len || memcmp(out, input, input_len) != 0) {
      fprintf(stderr, "VERIFY FAIL: data mismatch\n");
      free(out);
      goto fail;
    }
    printf("PASS: %" PRIu64 " MiB round-trip (uadk ZSTD + libzstd frames)\n",
           (uint64_t)input_len / (1024 * 1024));
    free(out);
  }

  exit_rc = EXIT_SUCCESS;

fail:
  ZSTD_freeCCtx(zc);
  /* Mempools are released on process exit; avoid mismatched-free warnings. */
  (void)src_pool;
  (void)dst_pool;
  (void)op_pool;
  compressdev_shutdown(dev_id, &priv_xform, dev_started);
  free(input);
  free(comp_concat);
  free(frame_sizes);
  return exit_rc;
}
