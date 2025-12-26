sudo \
WD_RSA_CTX_NUM="sync:2@0,async:4@0" \
WD_DH_CTX_NUM="sync:2@0,async:4@0" \
WD_CIPHER_CTX_NUM="sync:2@2,async:4@2" \
WD_DIGEST_CTX_NUM="sync:2@2,async:4@2" \
WD_COMP_CTX_NUM="sync_comp:2@2,sync_decomp:2@2,async_comp:4@2,async_decomp:4@2" \
bash -c 'sudo ./build/examples/dpdk-compress --vdev compress_uadk'
