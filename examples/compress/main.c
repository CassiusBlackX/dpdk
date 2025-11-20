#include <stdio.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_compressdev.h>

#define POOL_SIZE 8
#define SEG_SIZE  2048

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
        .max_nb_priv_xforms = 1,
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
    const char *input_str = "111111111111111111";
    printf("111 %d \n", __LINE__);
    uint32_t input_len = strlen(input_str) + 1;

    printf("111 %d \n", __LINE__);
    struct rte_mbuf *src = rte_pktmbuf_alloc(pool);
    printf("111 %d \n", __LINE__);
    struct rte_mbuf *dst = rte_pktmbuf_alloc(pool);
    if (!src || !dst)
        rte_exit(EXIT_FAILURE, "mbuf alloc failed\n");
    printf("111 %d \n", __LINE__);

    char *src_data = rte_pktmbuf_mtod(src, char *);
    memcpy(src_data, input_str, input_len);
    src->data_len = input_len;
    src->pkt_len = input_len;

    dst->data_len = SEG_SIZE;
    dst->pkt_len = SEG_SIZE;
    printf("111 %d \n", __LINE__);

    // 8. 准备压缩操作
    struct rte_comp_op *op = rte_comp_op_alloc(pool);
    if (!op)
        rte_exit(EXIT_FAILURE, "op alloc failed\n");
    printf("111 %d \n", __LINE__);

    op->m_src = src;
    op->m_dst = dst;
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

    printf("Compressed length: %u bytes\n", op->produced);
    printf("111 %d \n", __LINE__);

    // 12. 清理
    rte_compressdev_private_xform_free(dev_id, comp_xform);
    rte_pktmbuf_free(src);
    rte_pktmbuf_free(dst);
    rte_compressdev_stop(dev_id);

    printf("Done.\n");
    return 0;
}
