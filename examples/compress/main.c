#include <stdio.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_compressdev.h>

#define POOL_SIZE 8
#define SEG_SIZE  2048
#define EXIT_FAILURE -1

int main(int argc, char **argv)
{
    // 1. 初始化 DPDK 环境
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }

    // 2. 获取可用压缩设备数量
    uint16_t nb_devs = rte_compressdev_count();
    if (nb_devs == 0)
        rte_exit(EXIT_FAILURE, "No compressdev devices found\n");
    printf("111/n");

    printf("Found %u compressdev devices\n", nb_devs);
    // 3. 创建 mbuf 内存池
    struct rte_mempool *pool = rte_pktmbuf_pool_create("mbuf_pool",
        8, 0, 0, 1024, rte_socket_id());
    if (pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mempool\n");
    printf("111/n");

    // 4. 配置第一个压缩设备
    uint16_t dev_id = 0;
    struct rte_compressdev_config config = {
        .socket_id = rte_socket_id(),
        .nb_queue_pairs = 1,
        .max_nb_priv_xforms = 2,
        .max_nb_streams = 1,
    };
    if (rte_compressdev_configure(dev_id, &config) < 0)
        rte_exit(EXIT_FAILURE, "Device config failed\n");
    printf("Compressdev %u configured\n", dev_id);

    if (rte_compressdev_queue_pair_setup(dev_id, 0, 96, rte_socket_id()) < 0)
        rte_exit(EXIT_FAILURE, "Queue pair setup failed\n");
    printf("Compressdev %u qp setup\n", dev_id);
    // 5. 启动设备
    if (rte_compressdev_start(dev_id) < 0)
        rte_exit(EXIT_FAILURE, "Device start failed\n");

    printf("Compressdev %u started\n", dev_id);

    // 6. 创建压缩 transform
    struct rte_comp_xform xform = {
        .type = RTE_COMP_COMPRESS,
        .compress = {
            .algo = RTE_COMP_ALGO_DEFLATE,
            .deflate.huffman = RTE_COMP_HUFFMAN_FIXED,
            .level = RTE_COMP_LEVEL_PMD_DEFAULT,
            .window_size = 15,
            .chksum = RTE_COMP_CHECKSUM_NONE,
        }
    };
    printf("111 %d %p %u\n", __LINE__, &xform, xform.type);

    void *comp_xform = NULL;
    rte_compressdev_private_xform_create(dev_id, &xform, &comp_xform);
    if (!comp_xform)
        rte_exit(EXIT_FAILURE, "xform create failed\n");
    printf("111 %d \n", __LINE__);

    // 7. 分配输入输出 mbuf
    const char *input_str = "123123123123123123";
    printf("111 %d \n", __LINE__);
    uint32_t input_len = strlen(input_str) + 1;

    printf("111 %d \n", __LINE__);
    //------------------------//

    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    if (!m) {
        fprintf(stderr, "Failed to alloc mbuf\n");
        return -1;
    }

    uint8_t *mbuf_data = rte_pktmbuf_append(m, input_len);
    if (!mbuf_data) {
        fprintf(stderr, "Failed to append data to mbuf\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    memset(mbuf_data, 0, input_len);
    memcpy(mbuf_data, input_str, input_len);

    //------------------//

    struct rte_mbuf *m1 = rte_pktmbuf_alloc(pool);
    if (!m1) {
        fprintf(stderr, "Failed to alloc mbuf\n");
        return -1;
    }

    uint8_t *mbuf_data1 = rte_pktmbuf_append(m1, input_len);
    if (!mbuf_data1) {
        fprintf(stderr, "Failed to append data to mbuf\n");
        rte_pktmbuf_free(m1);
        return -1;
    }
    memset(mbuf_data1, 0, input_len);
    memcpy(mbuf_data1, input_str, input_len);
    mbuf_data1[0] = 'a';
    mbuf_data1[1] = 'a';
    //------------------//

    struct rte_mbuf *m2 = rte_pktmbuf_alloc(pool);
    if (!m2) {
        fprintf(stderr, "Failed to alloc mbuf\n");
        return -1;
    }

    uint8_t *mbuf_data2 = rte_pktmbuf_append(m2, input_len);
    if (!mbuf_data2) {
        fprintf(stderr, "Failed to append data to mbuf\n");
        rte_pktmbuf_free(m2);
        return -1;
    }
    memset(mbuf_data2, 0, input_len);
    // memcpy(mbuf_data2, input_str, input_len);
    printf("111 %d \n", __LINE__);
    if (!m || !m1 || !m2)
        rte_exit(EXIT_FAILURE, "mbuf alloc failed\n");
    printf("111 %d \n", __LINE__);

    m->data_len = input_len;
    m->pkt_len = input_len;

    m1->data_len = SEG_SIZE;
    m1->pkt_len = SEG_SIZE;
    m2->data_len = SEG_SIZE;
    m2->pkt_len = SEG_SIZE;
    printf("111 %d \n", __LINE__);

    // 8. 准备压缩操作
    struct rte_comp_op *op = rte_comp_op_alloc(pool);
    if (!op)
        rte_exit(EXIT_FAILURE, "op alloc failed\n");
    printf("111 %d \n", __LINE__);

    op->m_src = m;
    op->m_dst = m1;
    op->src.offset = 0;
    op->src.length = input_len;
    op->dst.offset = 0;
    op->private_xform = comp_xform;
    op->op_type = RTE_COMP_OP_STATELESS;
    op->flush_flag = RTE_COMP_FLUSH_FINAL;
    printf("111 %d \n", __LINE__);

    // 9. 执行压缩
    uint16_t enq = rte_compressdev_enqueue_burst(dev_id, 0, &op, 1);
    printf("send %u request to vhost backend.\n", enq);
    while (rte_compressdev_dequeue_burst(dev_id, 0, &op, 1) == 0)
        rte_pause();

    printf("Address: %p %p", m1->buf_addr, (void*)m1->buf_iova);
    printf("Compressed length: %u bytes\n", op->produced);
    for(unsigned int i = 0; i < op->produced; i++)
    {
        unsigned char *aaa = rte_pktmbuf_mtod(m1, unsigned char*);
        printf("%d", aaa[i]);
    }
    printf("111 %d \n", __LINE__);

    // 10. 解压操作
    struct rte_comp_xform decompress_xform = {
        .type = RTE_COMP_DECOMPRESS,
        .decompress = {
            .algo = RTE_COMP_ALGO_DEFLATE,
            .chksum = RTE_COMP_CHECKSUM_NONE,
            .window_size = 15
        }
    };
    void *decomp_xform = NULL;
    rte_compressdev_private_xform_create(dev_id, &decompress_xform, &decomp_xform);

    struct rte_mbuf *decomp_out = rte_pktmbuf_alloc(pool);
    memcpy(decomp_out, input_str, 2);
    struct rte_comp_op *decomp_op = rte_comp_op_alloc(pool);
    decomp_op->m_src = m1;
    decomp_op->m_dst = m2;
    decomp_op->src.offset = 0;
    decomp_op->src.length = op->produced;
    decomp_op->dst.offset = 0;
    decomp_op->private_xform = decomp_xform;
    decomp_op->op_type = RTE_COMP_OP_STATELESS;
    decomp_op->flush_flag = RTE_COMP_FLUSH_FINAL;

    rte_compressdev_enqueue_burst(dev_id, 0, &decomp_op, 1);
    while (rte_compressdev_dequeue_burst(dev_id, 0, &decomp_op, 1) == 0)
        rte_pause();

    printf("Decompressed length: %u bytes\n", decomp_op->produced);
    for(unsigned int i = 0; i < decomp_op->produced; i++)
    {
        unsigned char *aaa = rte_pktmbuf_mtod(m2, unsigned char*);
        printf("%c", aaa[i]);
    }

    // 12. 清理
    rte_compressdev_private_xform_free(dev_id, comp_xform);
    rte_pktmbuf_free(m);
    rte_pktmbuf_free(m1);
    rte_pktmbuf_free(m2);
    rte_compressdev_stop(dev_id);

    printf("Done.\n");
    return 0;
}
