#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <rte_byteorder.h>
#include <rte_compressdev.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define INPUT_SIZE_BYTES (512u * 1024u * 1024u)
#define CHUNK_SIZE_BYTES (32u * 1024u)
#define COMP_OP_POOL_SIZE 2048
#define MBUF_POOL_SIZE 4096
#define QP_NB_DESCRIPTORS 1024
#define MEMPOOL_CACHE_SIZE 128
#define SRC_MBUF_DATA_ROOM (CHUNK_SIZE_BYTES + 2048)
#define DST_MBUF_DATA_ROOM (CHUNK_SIZE_BYTES + 4096)

static void write_adler32_be(uint8_t *dst, uint32_t val) {
	dst[0] = (uint8_t)((val >> 24) & 0xff);
	dst[1] = (uint8_t)((val >> 16) & 0xff);
	dst[2] = (uint8_t)((val >> 8) & 0xff);
	dst[3] = (uint8_t)(val & 0xff);
}

// 封装为zlib member
static int append_zlib_wrapped_chunk(uint8_t *dst, size_t dst_cap, size_t *dst_off,
	uint8_t *raw_deflate, uint32_t raw_len, uint32_t adler) {
	const uint8_t zlib_header[2] = {0x78, 0x9c};
	size_t needed = sizeof(zlib_header) + raw_len + 4;
	if (*dst_off + needed > dst_cap) return -ENOSPC;
	memcpy(dst + *dst_off, zlib_header, sizeof(zlib_header));
	*dst_off += sizeof(zlib_header);
	memcpy(dst + *dst_off, raw_deflate, raw_len);
	*dst_off += raw_len;
	write_adler32_be(dst + *dst_off, adler);
	*dst_off += 4;
	return 0;
}

static int zlib_decompress_concat(const uint8_t *input, size_t input_len,
	uint8_t *out, size_t out_cap, size_t *out_len) {
	z_stream stream;
	int ret;

	memset(&stream, 0, sizeof(stream));
	stream.next_in = (Bytef *)(uintptr_t)input;
	stream.avail_in = input_len;
	stream.next_out = out;
	stream.avail_out = out_cap;

	ret = inflateInit(&stream);
	if (ret != Z_OK)
		return -EINVAL;

	while (1) {
		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret == Z_STREAM_END) {
			if (stream.avail_in == 0)
				break;

			ret = inflateReset(&stream);
			if (ret != Z_OK) {
				inflateEnd(&stream);
				return -EINVAL;
			}
			continue;
		}

		if (ret == Z_BUF_ERROR && stream.avail_in == 0)
			break;

		if (ret != Z_OK) {
			inflateEnd(&stream);
			return -EINVAL;
		}

		if (stream.avail_out == 0 && stream.avail_in != 0) {
			inflateEnd(&stream);
			return -ENOSPC;
		}
	}

	*out_len = (size_t)(stream.next_out - out);
	inflateEnd(&stream);
	return 0;
}

// DPDK分片压缩，输出zlib member串流
static size_t dpdk_compress_stateless(uint8_t *input, size_t input_len,
	uint8_t *out_raw, size_t out_raw_cap, size_t *raw_sizes,
	uint8_t *out_zlib, size_t out_zlib_cap, size_t *zlib_sizes, size_t *zlib_len,
	struct rte_mempool *src_pool, struct rte_mempool *dst_pool, struct rte_mempool *op_pool,
	uint16_t dev_id, void *priv_xform) {
	size_t input_off = 0, raw_off = 0, zlib_off = 0, chunk_idx = 0;
	while (input_off < input_len) {
		uint32_t this_chunk = (uint32_t)((input_len - input_off) > CHUNK_SIZE_BYTES ? CHUNK_SIZE_BYTES : (input_len - input_off));
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		struct rte_mbuf *dst = rte_pktmbuf_alloc(dst_pool);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		if (!src || !dst || !op) {
			printf("mbuf/op alloc failed at chunk=%zu\n", chunk_idx);
			exit(1);
		}
		uint8_t *src_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(src, this_chunk);
		uint8_t *dst_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(dst, CHUNK_SIZE_BYTES + 1024);
		memcpy(src_data, input + input_off, this_chunk);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = this_chunk;
		op->dst.offset = 0;
		op->flush_flag = RTE_COMP_FLUSH_FINAL;
		op->op_type = RTE_COMP_OP_STATELESS;
		op->private_xform = priv_xform;
		while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0) rte_pause();
		while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0) rte_pause();
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			printf("compress op failed at chunk=%zu, status=%u\n", chunk_idx, op->status);
			exit(1);
		}
		if (raw_off + op->produced > out_raw_cap) {
			printf("raw deflate output buffer too small\n");
			exit(1);
		}
		memcpy(out_raw + raw_off, dst_data, op->produced);
		raw_sizes[chunk_idx] = op->produced;
		raw_off += op->produced;

		if (out_zlib && zlib_sizes) {
			uint32_t adler = adler32(1u, src_data, this_chunk);
			if (append_zlib_wrapped_chunk(out_zlib, out_zlib_cap, &zlib_off, dst_data, op->produced, adler) != 0) {
				printf("zlib output buffer too small\n");
				exit(1);
			}
			zlib_sizes[chunk_idx] = (size_t)(2 + op->produced + 4);
		}
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		input_off += this_chunk;
		chunk_idx++;
	}
	if (zlib_len)
		*zlib_len = zlib_off;
	return raw_off;
}

// DPDK分片解压，输入zlib member串流
static size_t dpdk_decompress_stateless(const uint8_t *raw_stream, size_t raw_len,
	const size_t *raw_sizes, size_t member_count,
	uint8_t *out, size_t out_cap,
	struct rte_mempool *src_pool, struct rte_mempool *dst_pool, struct rte_mempool *op_pool,
	uint16_t dev_id, void *priv_xform) {
	size_t in_off = 0, out_off = 0, chunk_idx = 0;
	while (chunk_idx < member_count && in_off < raw_len) {
		size_t chunk_sz = raw_sizes[chunk_idx];
		if (chunk_sz == 0 || in_off + chunk_sz > raw_len) {
			printf("invalid raw deflate size at chunk=%zu\n", chunk_idx);
			exit(1);
		}
		struct rte_mbuf *src = rte_pktmbuf_alloc(src_pool);
		struct rte_mbuf *dst = rte_pktmbuf_alloc(dst_pool);
		struct rte_comp_op *op = rte_comp_op_alloc(op_pool);
		if (!src || !dst || !op) {
			printf("mbuf/op alloc failed at chunk=%zu\n", chunk_idx);
			exit(1);
		}
		uint8_t *src_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(src, chunk_sz);
		uint8_t *dst_data = (uint8_t *)(uintptr_t)rte_pktmbuf_append(dst, CHUNK_SIZE_BYTES + 1024);
		memcpy(src_data, raw_stream + in_off, chunk_sz);
		op->m_src = src;
		op->m_dst = dst;
		op->src.offset = 0;
		op->src.length = chunk_sz;
		op->dst.offset = 0;
		op->flush_flag = RTE_COMP_FLUSH_FINAL;
		op->op_type = RTE_COMP_OP_STATELESS;
		op->private_xform = priv_xform;
		while (rte_compressdev_enqueue_burst(dev_id, 0, &op, 1) == 0) rte_pause();
		while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0) rte_pause();
		if (op->status != RTE_COMP_OP_STATUS_SUCCESS) {
			printf("decompress op failed at chunk=%zu, status=%u\n", chunk_idx, op->status);
			exit(1);
		}
		if (out_off + op->produced > out_cap) {
			printf("decompressed output buffer too small\n");
			exit(1);
		}
		memcpy(out + out_off, dst_data, op->produced);
		out_off += op->produced;
		rte_comp_op_free(op);
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
		in_off += chunk_sz;
		chunk_idx++;
	}
	return out_off;
}

static size_t zlib_compress_chunks_raw(const uint8_t *input, size_t input_len,
	uint8_t *out, size_t out_cap, size_t *raw_sizes) {
	size_t input_off = 0, out_off = 0, chunk_idx = 0;
	while (input_off < input_len) {
		uint32_t this_chunk = (uint32_t)((input_len - input_off) > CHUNK_SIZE_BYTES ? CHUNK_SIZE_BYTES : (input_len - input_off));
		z_stream stream;
		memset(&stream, 0, sizeof(stream));
		stream.next_in = (Bytef *)(uintptr_t)(input + input_off);
		stream.avail_in = this_chunk;
		stream.next_out = (Bytef *)(uintptr_t)(out + out_off);
		stream.avail_out = out_cap - out_off;
		int ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
		if (ret != Z_OK)
			return 0;
		ret = deflate(&stream, Z_FINISH);
		if (ret != Z_STREAM_END) {
			deflateEnd(&stream);
			return 0;
		}
		raw_sizes[chunk_idx] = stream.total_out;
		out_off += stream.total_out;
		deflateEnd(&stream);
		input_off += this_chunk;
		chunk_idx++;
	}
	return out_off;
}

int main(int argc, char **argv) {
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
	uint16_t nb_devs = rte_compressdev_count();
	if (nb_devs == 0) rte_exit(EXIT_FAILURE, "No compressdev found. Run with --vdev compress_zlib\n");
	uint16_t dev_id = 0;
	printf("Found %u compressdev(s), use dev_id=%u\n", nb_devs, dev_id);

	// 生成原始数据
	uint8_t *input_buf = malloc(INPUT_SIZE_BYTES);
	for (uint64_t i = 0; i < INPUT_SIZE_BYTES; i++)
		input_buf[i] = (uint8_t)((i * 1315423911ULL + (i >> 7)) & 0xff);

	// 预分配所有缓冲区
	size_t comp_cap = INPUT_SIZE_BYTES + (INPUT_SIZE_BYTES / 8) + (INPUT_SIZE_BYTES / CHUNK_SIZE_BYTES) * 16 + 4096;
	uint8_t *comp_dpdk = malloc(comp_cap);
	uint8_t *comp_zlib = malloc(comp_cap);
	uint8_t *decomp_zlib = malloc(INPUT_SIZE_BYTES);
	uint8_t *decomp_dpdk = malloc(INPUT_SIZE_BYTES);
	uint8_t *decomp_dpdk2 = malloc(INPUT_SIZE_BYTES);

	struct rte_mempool *src_pool = rte_pktmbuf_pool_create("bigc_src_mbuf_pool", MBUF_POOL_SIZE, MEMPOOL_CACHE_SIZE, 0, SRC_MBUF_DATA_ROOM + RTE_PKTMBUF_HEADROOM, rte_socket_id());
	struct rte_mempool *dst_pool = rte_pktmbuf_pool_create("bigc_dst_mbuf_pool", MBUF_POOL_SIZE, MEMPOOL_CACHE_SIZE, 0, DST_MBUF_DATA_ROOM + RTE_PKTMBUF_HEADROOM, rte_socket_id());
	struct rte_mempool *op_pool = rte_comp_op_pool_create("bigc_comp_op_pool", COMP_OP_POOL_SIZE, MEMPOOL_CACHE_SIZE, 0, rte_socket_id());
	if (!src_pool || !dst_pool || !op_pool) rte_exit(EXIT_FAILURE, "mempool alloc failed\n");

	struct rte_compressdev_config cdev_config = {0};
	cdev_config.socket_id = rte_socket_id();
	cdev_config.nb_queue_pairs = 1;
	cdev_config.max_nb_priv_xforms = 2;
	cdev_config.max_nb_streams = 0;
	if (rte_compressdev_configure(dev_id, &cdev_config) < 0)
		rte_exit(EXIT_FAILURE, "rte_compressdev_configure failed\n");
	if (rte_compressdev_queue_pair_setup(dev_id, 0, QP_NB_DESCRIPTORS, rte_socket_id()) < 0)
		rte_exit(EXIT_FAILURE, "rte_compressdev_queue_pair_setup failed\n");
	if (rte_compressdev_start(dev_id) < 0)
		rte_exit(EXIT_FAILURE, "rte_compressdev_start failed\n");

	struct rte_comp_xform xform_c = {0};
	xform_c.type = RTE_COMP_COMPRESS;
	xform_c.compress.algo = RTE_COMP_ALGO_DEFLATE;
	xform_c.compress.deflate.huffman = RTE_COMP_HUFFMAN_DEFAULT;
	xform_c.compress.level = RTE_COMP_LEVEL_PMD_DEFAULT;
	xform_c.compress.chksum = RTE_COMP_CHECKSUM_NONE;
	xform_c.compress.window_size = 15;
	void *priv_xform_c = NULL;
	if (rte_compressdev_private_xform_create(dev_id, &xform_c, &priv_xform_c) < 0)
		rte_exit(EXIT_FAILURE, "rte_compressdev_private_xform_create failed\n");

	struct rte_comp_xform xform_d = {0};
	xform_d.type = RTE_COMP_DECOMPRESS;
	xform_d.decompress.algo = RTE_COMP_ALGO_DEFLATE;
	xform_d.decompress.chksum = RTE_COMP_CHECKSUM_NONE;
	xform_d.decompress.window_size = 15;
	void *priv_xform_d = NULL;
	if (rte_compressdev_private_xform_create(dev_id, &xform_d, &priv_xform_d) < 0)
		rte_exit(EXIT_FAILURE, "rte_compressdev_private_xform_create failed\n");

	const size_t max_chunks = (INPUT_SIZE_BYTES + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES;
	size_t *dpdk_raw_sizes = calloc(max_chunks, sizeof(size_t));
	size_t *dpdk_zlib_sizes = calloc(max_chunks, sizeof(size_t));
	size_t *zlib_raw_sizes = calloc(max_chunks, sizeof(size_t));

	if (!dpdk_raw_sizes || !dpdk_zlib_sizes || !zlib_raw_sizes)
		rte_exit(EXIT_FAILURE, "size array alloc failed\n");

	// 1. DPDK分片压缩→zlib解压
	size_t comp_dpdk_zlib_len = 0;
	size_t comp_dpdk_raw_len = dpdk_compress_stateless(input_buf, INPUT_SIZE_BYTES,
		comp_dpdk, comp_cap, dpdk_raw_sizes,
		comp_zlib, comp_cap, dpdk_zlib_sizes, &comp_dpdk_zlib_len,
		src_pool, dst_pool, op_pool, dev_id, priv_xform_c);
	printf("[1] DPDK compress → zlib decompress: Compressed %zu bytes\n", comp_dpdk_raw_len);
	size_t decomp_zlib_len = 0;
	ret = zlib_decompress_concat(comp_zlib, comp_dpdk_zlib_len, decomp_zlib, INPUT_SIZE_BYTES, &decomp_zlib_len);
	if (ret == 0 && decomp_zlib_len == INPUT_SIZE_BYTES && memcmp(input_buf, decomp_zlib, INPUT_SIZE_BYTES) == 0)
		printf("[1] PASS: zlib解压后数据一致\n");
	else
		printf("[1] FAIL: zlib解压后数据不一致\n");

	// 2. zlib压缩→DPDK分片解压
	size_t comp_zlib_len = zlib_compress_chunks_raw(input_buf, INPUT_SIZE_BYTES, comp_zlib, comp_cap, zlib_raw_sizes);
	printf("[2] zlib compress → DPDK decompress: Compressed %zu bytes\n", comp_zlib_len);
	size_t decomp_dpdk_len = dpdk_decompress_stateless(comp_zlib, comp_zlib_len, zlib_raw_sizes, max_chunks, decomp_dpdk, INPUT_SIZE_BYTES, src_pool, dst_pool, op_pool, dev_id, priv_xform_d);
	if (decomp_dpdk_len == INPUT_SIZE_BYTES && memcmp(input_buf, decomp_dpdk, INPUT_SIZE_BYTES) == 0)
		printf("[2] PASS: DPDK解压后数据一致\n");
	else
		printf("[2] FAIL: DPDK解压后数据不一致\n");

	// 3. DPDK分片压缩→DPDK分片解压
	size_t decomp_dpdk2_len = dpdk_decompress_stateless(comp_dpdk, comp_dpdk_raw_len, dpdk_raw_sizes, max_chunks, decomp_dpdk2, INPUT_SIZE_BYTES, src_pool, dst_pool, op_pool, dev_id, priv_xform_d);
	if (decomp_dpdk2_len == INPUT_SIZE_BYTES && memcmp(input_buf, decomp_dpdk2, INPUT_SIZE_BYTES) == 0)
		printf("[3] PASS: DPDK压缩解压后数据一致\n");
	else
		printf("[3] FAIL: DPDK压缩解压后数据不一致\n");

	rte_compressdev_private_xform_free(dev_id, priv_xform_c);
	rte_compressdev_private_xform_free(dev_id, priv_xform_d);
	rte_compressdev_stop(dev_id);
	rte_compressdev_close(dev_id);
	free(input_buf); free(comp_dpdk); free(comp_zlib); free(decomp_zlib); free(decomp_dpdk); free(decomp_dpdk2);
	free(dpdk_raw_sizes); free(dpdk_zlib_sizes); free(zlib_raw_sizes);
	return 0;
}
