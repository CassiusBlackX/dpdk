#ifndef _VIRTIO_COMP_CAPABILITIES_H_
#define _VIRTIO_COMP_CAPABILITIES_H_

#define VIRTIO_COMP_DEFLATE_CAPABILITIES \
    { \
        .algo = RTE_COMP_ALGO_DEFLATE, \
        /* the current flag is copied from `drivers/compress/qat/dev/qat_comp_pmd_gen1.c`, `qat_gen1_comp_capabilities`  */ \
        .comp_feature_flags = RTE_COMP_FF_MULTI_PKT_CHECKSUM | \
                    RTE_COMP_FF_CRC32_CHECKSUM | \
                    RTE_COMP_FF_ADLER32_CHECKSUM | \
                    RTE_COMP_FF_CRC32_ADLER32_CHECKSUM | \
                    RTE_COMP_FF_SHAREABLE_PRIV_XFORM | \
                    RTE_COMP_FF_HUFFMAN_FIXED | \
                    RTE_COMP_FF_HUFFMAN_DYNAMIC | \
                    RTE_COMP_FF_OOP_SGL_IN_SGL_OUT | \
                    RTE_COMP_FF_OOP_SGL_IN_LB_OUT | \
                    RTE_COMP_FF_OOP_LB_IN_SGL_OUT | \
                    RTE_COMP_FF_STATEFUL_DECOMPRESSION, \
        .window_size = {.min = 15, .max = 15, .increment = 0} , \
    }

#endif /* _VIRTIO_COMP_CAPABILITIES_H_ */