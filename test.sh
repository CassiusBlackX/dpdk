sudo \
WD_RSA_CTX_NUM="sync:2@0,async:4@0" \
WD_DH_CTX_NUM="sync:2@0,async:4@0" \
WD_CIPHER_CTX_NUM="sync:2@2,async:4@2" \
WD_DIGEST_CTX_NUM="sync:2@2,async:4@2" \
WD_COMP_CTX_NUM="sync-comp:2@2,sync-decomp:2@2,async-comp:4@2,async-decomp:4@2" \
bash -c './build/examples/dpdk-compress --vdev compress_uadk'
