/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zstd.h>

#include <rte_common.h>
#include <rte_compressdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define INPUT_SIZE_BYTES_DEFAULT (512u * 1024u * 1024u)
#define INPUT_SIZE_BYTES_QUICK (8u * 1024u * 1024u)
#define CHUNK_SIZE_BYTES (32u * 1024u)
#define COMP_OP_POOL_SIZE 512
#define SRC_MBUF_POOL_SIZE 512
/*
 * Pool holds (ZC_DST_POOL_CHAINS * segments_per_max_chain) mbufs. Only one chain
 * is built at a time in this example; extra chains cover mempool caching.
 */
#define ZC_DST_POOL_CHAINS 8u
/*
 * rte_pktmbuf_pool_create data_room_size is uint16_t (max 65535). ZSTD
 * CStream/DStream need ~128 KiB; use max single-segment room and chain mbufs.
 */
#define ZC_DST_SEG_DATA_ROOM ((uint16_t)UINT16_MAX)
#define QP_NB_DESCRIPTORS 1024
#define MEMPOOL_CACHE_SIZE 128

static const uint32_t src_mbuf_room =
		CHUNK_SIZE_BYTES + 2048 + RTE_PKTMBUF_HEADROOM;
/*
 * ZSTD_decompressStream requires an output buffer >= ZSTD_DStreamOutSize()
 * (128 KiB) to flush a block; a smaller mbuf can stall the decoder forever.
 */
static inline uint32_t
zc_dst_need_stateful_decomp(uint32_t this_in, size_t out_remaining,
		size_t comp_remaining)
{
	uint32_t rem = out_remaining > (size_t)(UINT32_MAX - 8192u)
			? (UINT32_MAX - 8192u)
			: (uint32_t)out_remaining;
	uint64_t comp_left = comp_remaining;

	if (comp_left == 0)
		comp_left = 1;
	/* this_in <= comp_remaining always, so est <= out_remaining */
	uint64_t est =
			((uint64_t)this_in * (uint64_t)out_remaining) / comp_left;
	if (est > (uint64_t)(UINT32_MAX - 131072u))
		est = (uint64_t)(UINT32_MAX - 131072u);
	uint32_t tgt = (uint32_t)est + 65536u;
	uint32_t floor = (uint32_t)ZSTD_DStreamOutSize() + 4096u;

	if (tgt < floor)
		tgt = floor;
	if (tgt > rem)
		tgt = rem;
	return tgt;
}

static inline uint32_t
zc_dst_seg_payload(void)
{
	return (uint32_t)ZC_DST_SEG_DATA_ROOM - RTE_PKTMBUF_HEADROOM;
}

static inline unsigned int
zc_dst_nb_segs_for(uint32_t need_bytes)
{
	uint32_t per = zc_dst_seg_payload();

	return (unsigned int)((need_bytes + per - 1) / per);
}

static struct rte_mbuf *
zc_alloc_dst_chain(struct rte_mempool *mp, uint32_t need_bytes)
{
	unsigned int n = zc_dst_nb_segs_for(need_bytes);
	uint32_t need = need_bytes;
	uint32_t per = zc_dst_seg_payload();
	struct rte_mbuf **segs = NULL;
	struct rte_mbuf *head = NULL;
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
		fprintf(stderr,
			"zc_alloc_dst_chain: need left %u (n=%u per=%u)\n",
			need, n, per);
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

static void
zc_copy_dst_out(struct rte_mbuf *dst, uint32_t produced, uint8_t *to)
{
	const void *p;

	if (produced == 0)
		return;
	p = rte_pktmbuf_read(dst, 0, produced, to);
	if (p == NULL) {
		fprintf(stderr, "rte_pktmbuf_read dst failed produced=%u\n",
				produced);
		exit(1);
	}
	if (p != (const void *)to)
		memcpy(to, p, produced);
}

static void
enqueue_dequeue_sync(uint16_t dev_id, struct rte_comp_op *op)
{
	while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0)
		rte_pause();
	while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0)
		rte_pause();
}

/* One ZSTD frame per slice; matches DPDK stateless one-frame-per-chunk output. */
static int
zstd_decompress_per_frame(const uint8_t *src, size_t src_total,
		const size_t *frame_sizes, size_t nframes, uint8_t *dst,
		size_t dst_cap, size_t *out_len)
{
	size_t in_off = 0, out_off = 0;

	for (size_t i = 0; i < nframes; i++) {
		size_t fsz = frame_sizes[i];
		size_t rem = dst_cap - out_off;
		size_t dsz;

		if (fsz == 0 || in_off + fsz > src_total || rem == 0)
			return -EINVAL;
		dsz = ZSTD_decompress(dst + out_off, rem, src + in_off, fsz);
		if (ZSTD_isError(dsz))
			return -EINVAL;
		in_off += fsz;
		out_off += dsz;
	}
	*out_len = out_off;
	return 0;
}

static size_t
zstd_compress_chunks(const uint8_t *input, size_t input_len, uint8_t *out,
		size_t out_cap, size_t *frame_sizes, size_t *num_frames_out)
{
	size_t in_off = 0, out_off = 0, idx = 0;

	while (in_off < input_len) {
		size_t chunk = input_len - in_off > CHUNK_SIZE_BYTES
				? CHUNK_SIZE_BYTES
				: (input_len - in_off);
		size_t z = ZSTD_compress(out + out_off, out_cap - out_off,
				input + in_off, chunk, ZSTD_CLEVEL_DEFAULT);

		if (ZSTD_isError(z))
			return 0;
		frame_sizes[idx++] = z;
		out_off += z;
		in_off += chunk;
	}
	*num_frames_out = idx;
	return out_off;
}

static size_t input_total_bytes = INPUT_SIZE_BYTES_DEFAULT;

/*
 * Largest dst chain this example allocates. Stateful decompress may emit all
 * remaining plaintext in one op when this_in equals the rest of the bitstream.
 */
static uint32_t
zc_dst_pool_max_need(void)
{
	uint32_t c = (uint32_t)ZSTD_CStreamOutSize();
	uint32_t d = (uint32_t)ZSTD_DStreamOutSize();
	uint32_t cbound = (uint32_t)ZSTD_COMPRESSBOUND(CHUNK_SIZE_BYTES) + 4096;
	uint32_t base = RTE_MAX(cbound, CHUNK_SIZE_BYTES + 4096);
	uint32_t uncomp;

	base = RTE_MAX(base, RTE_MAX(c, d));
	if (input_total_bytes > (size_t)(UINT32_MAX - 131072u))
		uncomp = UINT32_MAX - 131072u;
	else
		uncomp = (uint32_t)input_total_bytes;
	base = RTE_MAX(base, uncomp);
	return base + 4096u;
}

static size_t
dpdk_compress_stateless(const uint8_t *input, size_t input_len,
		uint8_t *out_raw, size_t out_cap, size_t *raw_sizes,
		size_t *num_chunks_out,
		struct rte_mempool *src_pool, struct rte_mempool *dst_pool,
		struct rte_mempool *op_pool, uint16_t dev_id, void *priv_xform)
{
	size_t in_off = 0, raw_off = 0, chunk_idx = 0;

	while (in_off < input_len) {
		uint32_t this_chunk = (uint32_t)((input_len - in_off) >
				CHUNK_SIZE_BYTES
				? CHUNK_SIZE_BYTES
				: (input_len - in_off));
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		uint32_t dst_need = (uint32_t)ZSTD_COMPRESSBOUND(this_chunk) + 4096u;
		struct rte_mbuf *dst = zc_alloc_dst_chain(dst_pool, dst_need);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		uint8_t *src_data;

		if (!src || !dst || !op) {
			fprintf(stderr, "mbuf/op alloc failed chunk=%zu\n",
					chunk_idx);
			exit(1);
		}
		src_data = (uint8_t *)rte_pktmbuf_append(src, this_chunk);
		memcpy(src_data, input + in_off, this_chunk);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = this_chunk;
		op->dst.offset = 0;
		op->flush_flag = RTE_COMP_FLUSH_FINAL;
		op->op_type = RTE_COMP_OP_STATELESS;
		op->private_xform = priv_xform;
		enqueue_dequeue_sync(dev_id, op);
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			fprintf(stderr,
				"stateless compress failed chunk=%zu status=%u\n",
				chunk_idx, op->status);
			exit(1);
		}
		if (raw_off + op->produced > out_cap) {
			fprintf(stderr, "compress output overflow\n");
			exit(1);
		}
		zc_copy_dst_out(dst, op->produced, out_raw + raw_off);
		raw_sizes[chunk_idx] = op->produced;
		raw_off += op->produced;
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		in_off += this_chunk;
		chunk_idx++;
	}
	*num_chunks_out = chunk_idx;
	return raw_off;
}

static size_t
dpdk_decompress_stateless(const uint8_t *raw, size_t raw_len,
		const size_t *frame_sizes, size_t nframes, uint8_t *out,
		size_t out_cap, struct rte_mempool *src_pool,
		struct rte_mempool *dst_pool, struct rte_mempool *op_pool,
		uint16_t dev_id, void *priv_xform)
{
	size_t in_off = 0, out_off = 0, fi = 0;

	while (fi < nframes && in_off < raw_len) {
		size_t fsz = frame_sizes[fi];
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		uint32_t dst_need = CHUNK_SIZE_BYTES + 4096u;
		struct rte_mbuf *dst = zc_alloc_dst_chain(dst_pool, dst_need);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		uint8_t *src_data;

		if (!src || !dst || !op) {
			fprintf(stderr, "mbuf/op alloc decompress fi=%zu\n", fi);
			exit(1);
		}
		if (fsz == 0 || in_off + fsz > raw_len) {
			fprintf(stderr, "bad frame size fi=%zu\n", fi);
			exit(1);
		}
		src_data = (uint8_t *)rte_pktmbuf_append(src, (uint32_t)fsz);
		memcpy(src_data, raw + in_off, fsz);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = (uint32_t)fsz;
		op->dst.offset = 0;
		op->flush_flag = RTE_COMP_FLUSH_FINAL;
		op->op_type = RTE_COMP_OP_STATELESS;
		op->private_xform = priv_xform;
		enqueue_dequeue_sync(dev_id, op);
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			fprintf(stderr,
				"stateless decompress failed fi=%zu status=%u\n",
				fi, op->status);
			exit(1);
		}
		if (out_off + op->produced > out_cap) {
			fprintf(stderr, "decompress output overflow\n");
			exit(1);
		}
		zc_copy_dst_out(dst, op->produced, out + out_off);
		out_off += op->produced;
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		in_off += fsz;
		fi++;
	}
	return out_off;
}

static size_t
dpdk_compress_stateful_stream(const uint8_t *input, size_t input_len,
		uint8_t *out, size_t out_cap, void *stream,
		struct rte_mempool *src_pool, struct rte_mempool *dst_pool,
		struct rte_mempool *op_pool, uint16_t dev_id)
{
	size_t in_off = 0, comp_off = 0, chunk_idx = 0;

	while (in_off < input_len) {
		uint32_t this_chunk = (uint32_t)((input_len - in_off) >
				CHUNK_SIZE_BYTES
				? CHUNK_SIZE_BYTES
				: (input_len - in_off));
		int is_last = (in_off + this_chunk >= input_len);
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		uint32_t dst_need = (uint32_t)ZSTD_COMPRESSBOUND(this_chunk) + 4096u;
		struct rte_mbuf *dst = zc_alloc_dst_chain(dst_pool, dst_need);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		uint8_t *src_data;

		if (!src || !dst || !op) {
			fprintf(stderr, "stateful compress alloc failed\n");
			exit(1);
		}
		src_data = (uint8_t *)rte_pktmbuf_append(src, this_chunk);
		memcpy(src_data, input + in_off, this_chunk);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = this_chunk;
		op->dst.offset = 0;
		op->flush_flag = is_last ? RTE_COMP_FLUSH_FINAL
				: RTE_COMP_FLUSH_NONE;
		op->op_type = RTE_COMP_OP_STATEFUL;
		op->stream = stream;
		enqueue_dequeue_sync(dev_id, op);
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			fprintf(stderr,
				"stateful compress failed chunk=%zu status=%u\n",
				chunk_idx, op->status);
			exit(1);
		}
		if (comp_off + op->produced > out_cap) {
			fprintf(stderr, "stateful compress buffer full\n");
			exit(1);
		}
		zc_copy_dst_out(dst, op->produced, out + comp_off);
		comp_off += op->produced;
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		in_off += this_chunk;
		chunk_idx++;
	}
	return comp_off;
}

static size_t
dpdk_decompress_stateful_stream(const uint8_t *comp, size_t comp_len,
		uint32_t chunk_sz, uint8_t *out, size_t out_cap, void *stream,
		struct rte_mempool *src_pool, struct rte_mempool *dst_pool,
		struct rte_mempool *op_pool, uint16_t dev_id)
{
	size_t in_off = 0, out_off = 0, part = 0;

	while (in_off < comp_len) {
		uint32_t this_in = (uint32_t)((comp_len - in_off) > chunk_sz
				? chunk_sz
				: (comp_len - in_off));
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		uint32_t dst_need = zc_dst_need_stateful_decomp(this_in,
				out_cap - out_off, comp_len - in_off);
		struct rte_mbuf *dst = zc_alloc_dst_chain(dst_pool, dst_need);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		uint8_t *src_data;

		if (!src || !dst || !op) {
			fprintf(stderr, "stateful decompress alloc failed\n");
			exit(1);
		}
		src_data = (uint8_t *)rte_pktmbuf_append(src, this_in);
		memcpy(src_data, comp + in_off, this_in);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = this_in;
		op->dst.offset = 0;
		op->flush_flag = RTE_COMP_FLUSH_FINAL;
		op->op_type = RTE_COMP_OP_STATEFUL;
		op->stream = stream;
		enqueue_dequeue_sync(dev_id, op);
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			fprintf(stderr,
				"stateful decompress failed part=%zu status=%u\n",
				part, op->status);
			exit(1);
		}
		if (out_off + op->produced > out_cap) {
			fprintf(stderr, "stateful decompress overflow\n");
			exit(1);
		}
		zc_copy_dst_out(dst, op->produced, out + out_off);
		out_off += op->produced;
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		in_off += this_in;
		part++;
	}
	return out_off;
}

int
main(int argc, char **argv)
{
	size_t max_chunks;
	size_t comp_cap;
	uint8_t *input_buf;
	uint8_t *comp_a;
	uint8_t *comp_b;
	uint8_t *comp_c;
	uint8_t *out_a;
	uint8_t *out_b;
	uint8_t *out_c;
	uint8_t *out_d;
	uint8_t *out_e;
	size_t *sizes_a;
	size_t *sizes_lib;
	size_t zstd_lib_len;
	size_t decomp_len;
	size_t comp_dpdk_len;
	size_t num_dpdk_chunks = 0;
	size_t num_lib_frames = 0;
	size_t stateful_comp_len;
	int ret;
	uint16_t nb_devs;
	uint16_t dev_id = 0;
	struct rte_mempool *src_pool;
	struct rte_mempool *dst_pool;
	struct rte_mempool *op_pool;
	struct rte_compressdev_config cdev_config;
	struct rte_comp_xform xform_c;
	struct rte_comp_xform xform_d;
	void *priv_c;
	void *priv_d;
	void *stream_c;
	void *stream_d;
	void *stream_c2;
	void *stream_d2;

	if (getenv("DPDK_ZSTDCOMPRESS_QUICK") != NULL)
		input_total_bytes = INPUT_SIZE_BYTES_QUICK;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	printf("the EAL init success\n");

	argc -= ret;
	argv += ret;
	while (argc > 0 && strcmp(argv[0], "--") == 0) {
		argc--;
		argv++;
	}
	if (argc > 0 && strcmp(argv[0], "--quick") == 0)
		input_total_bytes = INPUT_SIZE_BYTES_QUICK;

	max_chunks = (input_total_bytes + CHUNK_SIZE_BYTES - 1) /
			CHUNK_SIZE_BYTES;
	comp_cap = input_total_bytes + (input_total_bytes / 4) + 65536;

	if (input_total_bytes == INPUT_SIZE_BYTES_QUICK)
		printf("Quick mode: %zu MiB input (set DPDK_ZSTDCOMPRESS_QUICK or pass -- after EAL args)\n",
				input_total_bytes / (1024 * 1024));

	nb_devs = rte_compressdev_count();
	if (nb_devs == 0)
		rte_exit(EXIT_FAILURE,
			"No compressdev; use e.g. --vdev compress_zstd\n");

	input_buf = malloc(input_total_bytes);
	comp_a = malloc(comp_cap);
	comp_b = malloc(comp_cap);
	comp_c = malloc(comp_cap);
	out_a = malloc(input_total_bytes);
	out_b = malloc(input_total_bytes);
	out_c = malloc(input_total_bytes);
	out_d = malloc(input_total_bytes);
	out_e = malloc(input_total_bytes);
	sizes_a = calloc(max_chunks, sizeof(size_t));
	sizes_lib = calloc(max_chunks, sizeof(size_t));
	if (!input_buf || !comp_a || !comp_b || !comp_c || !out_a || !out_b ||
			!out_c || !out_d || !out_e || !sizes_a || !sizes_lib)
		rte_exit(EXIT_FAILURE, "malloc failed\n");

	for (uint64_t i = 0; i < input_total_bytes; i++)
		input_buf[i] = (uint8_t)((i * 1315423911ULL + (i >> 7)) & 0xff);

	src_pool = rte_pktmbuf_pool_create("zc_src", SRC_MBUF_POOL_SIZE,
			MEMPOOL_CACHE_SIZE, 0, src_mbuf_room, rte_socket_id());
	dst_pool = rte_pktmbuf_pool_create("zc_dst",
			ZC_DST_POOL_CHAINS *
					zc_dst_nb_segs_for(zc_dst_pool_max_need()),
			MEMPOOL_CACHE_SIZE, 0,
			ZC_DST_SEG_DATA_ROOM, rte_socket_id());
	op_pool = rte_comp_op_pool_create("zc_op", COMP_OP_POOL_SIZE,
			MEMPOOL_CACHE_SIZE, 0, rte_socket_id());
	if (!src_pool || !dst_pool || !op_pool)
		rte_exit(EXIT_FAILURE, "mempool create failed\n");

	if (input_total_bytes == INPUT_SIZE_BYTES_DEFAULT) {
		unsigned int dst_nb = ZC_DST_POOL_CHAINS *
				zc_dst_nb_segs_for(zc_dst_pool_max_need());

		printf("512 MiB mode: use sufficient EAL memory (e.g. -m 12288) "
			"and huge pages; dst pool has %u mbufs (max ~%u KiB per chain).\n",
				dst_nb,
				(unsigned)(zc_dst_pool_max_need() / 1024u));
	}

	memset(&cdev_config, 0, sizeof(cdev_config));
	cdev_config.socket_id = rte_socket_id();
	cdev_config.nb_queue_pairs = 1;
	cdev_config.max_nb_priv_xforms = 4;
	cdev_config.max_nb_streams = 8;
	if (rte_compressdev_configure(dev_id, &cdev_config) < 0)
		rte_exit(EXIT_FAILURE, "compressdev configure failed\n");
	if (rte_compressdev_queue_pair_setup(dev_id, 0, QP_NB_DESCRIPTORS,
			rte_socket_id()) < 0)
		rte_exit(EXIT_FAILURE, "queue pair setup failed\n");
	if (rte_compressdev_start(dev_id) < 0)
		rte_exit(EXIT_FAILURE, "compressdev start failed\n");

	memset(&xform_c, 0, sizeof(xform_c));
	xform_c.type = RTE_COMP_COMPRESS;
	xform_c.compress.algo = RTE_COMP_ALGO_ZSTD;
	xform_c.compress.level = RTE_COMP_LEVEL_PMD_DEFAULT;
	xform_c.compress.chksum = RTE_COMP_CHECKSUM_NONE;
	xform_c.compress.hash_algo = RTE_COMP_HASH_ALGO_NONE;
	xform_c.compress.window_size = 0;

	memset(&xform_d, 0, sizeof(xform_d));
	xform_d.type = RTE_COMP_DECOMPRESS;
	xform_d.decompress.algo = RTE_COMP_ALGO_ZSTD;
	xform_d.decompress.chksum = RTE_COMP_CHECKSUM_NONE;
	xform_d.decompress.hash_algo = RTE_COMP_HASH_ALGO_NONE;
	xform_d.decompress.window_size = 0;

	if (rte_compressdev_private_xform_create(dev_id, &xform_c, &priv_c) <
			0)
		rte_exit(EXIT_FAILURE, "private_xform compress failed\n");
	if (rte_compressdev_private_xform_create(dev_id, &xform_d, &priv_d) <
			0)
		rte_exit(EXIT_FAILURE, "private_xform decompress failed\n");

	printf("compressdev ZSTD: %zu MiB, chunk=%u bytes\n",
			input_total_bytes / (1024 * 1024),
			(unsigned)CHUNK_SIZE_BYTES);

	/* --- Stateless --- */
	comp_dpdk_len = dpdk_compress_stateless(input_buf, input_total_bytes,
			comp_a, comp_cap, sizes_a, &num_dpdk_chunks, src_pool,
			dst_pool, op_pool, dev_id, priv_c);
	printf("[S1] DPDK stateless compress -> libzstd: %zu bytes compressed\n",
			comp_dpdk_len);
	if (zstd_decompress_per_frame(comp_a, comp_dpdk_len, sizes_a,
				num_dpdk_chunks, out_a, input_total_bytes,
				&decomp_len) != 0 ||
			decomp_len != input_total_bytes ||
			memcmp(input_buf, out_a, input_total_bytes) != 0)
		printf("[S1] FAIL\n");
	else
		printf("[S1] PASS\n");

	zstd_lib_len = zstd_compress_chunks(input_buf, input_total_bytes,
			comp_b, comp_cap, sizes_lib, &num_lib_frames);
	printf("[S2] libzstd chunk frames -> DPDK stateless: %zu bytes\n",
			zstd_lib_len);
	decomp_len = dpdk_decompress_stateless(comp_b, zstd_lib_len, sizes_lib,
			num_lib_frames, out_b, input_total_bytes, src_pool,
			dst_pool, op_pool, dev_id, priv_d);
	if (decomp_len != input_total_bytes ||
			memcmp(input_buf, out_b, input_total_bytes) != 0)
		printf("[S2] FAIL\n");
	else
		printf("[S2] PASS\n");

	decomp_len = dpdk_decompress_stateless(comp_a, comp_dpdk_len, sizes_a,
			num_dpdk_chunks, out_c, input_total_bytes, src_pool,
			dst_pool, op_pool, dev_id, priv_d);
	if (decomp_len != input_total_bytes ||
			memcmp(input_buf, out_c, input_total_bytes) != 0)
		printf("[S3] FAIL (DPDK stateless round-trip)\n");
	else
		printf("[S3] PASS (DPDK stateless round-trip)\n");

	/* --- Stateful --- */
	if (rte_compressdev_stream_create(dev_id, &xform_c, &stream_c) < 0)
		rte_exit(EXIT_FAILURE, "stream_create compress failed\n");

	stateful_comp_len = dpdk_compress_stateful_stream(input_buf,
			input_total_bytes, comp_c, comp_cap, stream_c, src_pool,
			dst_pool, op_pool, dev_id);
	printf("[T1] DPDK stateful compress (single frame) -> libzstd: %zu B\n",
			stateful_comp_len);
	{
		size_t zr = ZSTD_decompress(out_a, input_total_bytes, comp_c,
				stateful_comp_len);

		if (ZSTD_isError(zr))
			printf("[T1] FAIL (ZSTD_decompress)\n");
		else if (zr != input_total_bytes ||
				memcmp(input_buf, out_a, input_total_bytes) != 0)
			printf("[T1] FAIL (data)\n");
		else
			printf("[T1] PASS\n");
	}
	rte_compressdev_stream_free(dev_id, stream_c);

	zstd_lib_len = ZSTD_compress(comp_b, comp_cap, input_buf,
			input_total_bytes, ZSTD_CLEVEL_DEFAULT);
	if (ZSTD_isError(zstd_lib_len))
		rte_exit(EXIT_FAILURE, "ZSTD_compress full buffer failed\n");
	if (rte_compressdev_stream_create(dev_id, &xform_d, &stream_d) < 0)
		rte_exit(EXIT_FAILURE, "stream_create decompress failed\n");
	decomp_len = dpdk_decompress_stateful_stream(comp_b, zstd_lib_len,
			CHUNK_SIZE_BYTES / 2, out_d, input_total_bytes, stream_d,
			src_pool, dst_pool, op_pool, dev_id);
	printf("[T2] libzstd single frame -> DPDK stateful: out %zu B\n",
			decomp_len);
	if (decomp_len != input_total_bytes ||
			memcmp(input_buf, out_d, input_total_bytes) != 0)
		printf("[T2] FAIL\n");
	else
		printf("[T2] PASS\n");

	rte_compressdev_stream_free(dev_id, stream_d);

	if (rte_compressdev_stream_create(dev_id, &xform_c, &stream_c2) < 0)
		rte_exit(EXIT_FAILURE, "stream_create compress 2 failed\n");
	if (rte_compressdev_stream_create(dev_id, &xform_d, &stream_d2) < 0)
		rte_exit(EXIT_FAILURE, "stream_create decompress 2 failed\n");

	stateful_comp_len = dpdk_compress_stateful_stream(input_buf,
			input_total_bytes, comp_c, comp_cap, stream_c2, src_pool,
			dst_pool, op_pool, dev_id);
	decomp_len = dpdk_decompress_stateful_stream(comp_c, stateful_comp_len,
			CHUNK_SIZE_BYTES / 2, out_e, input_total_bytes, stream_d2,
			src_pool, dst_pool, op_pool, dev_id);
	printf("[T3] DPDK stateful round-trip: compressed %zu -> out %zu B\n",
			stateful_comp_len, decomp_len);
	if (decomp_len != input_total_bytes ||
			memcmp(input_buf, out_e, input_total_bytes) != 0)
		printf("[T3] FAIL\n");
	else
		printf("[T3] PASS\n");

	rte_compressdev_stream_free(dev_id, stream_c2);
	rte_compressdev_stream_free(dev_id, stream_d2);

	rte_compressdev_private_xform_free(dev_id, priv_c);
	rte_compressdev_private_xform_free(dev_id, priv_d);
	rte_compressdev_stop(dev_id);
	rte_compressdev_close(dev_id);

	free(input_buf);
	free(comp_a);
	free(comp_b);
	free(comp_c);
	free(out_a);
	free(out_b);
	free(out_c);
	free(out_d);
	free(out_e);
	free(sizes_a);
	free(sizes_lib);
	return 0;
}
