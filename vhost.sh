sudo \
WD_RSA_CTX_NUM="sync:2@0,async:4@0" \
WD_DH_CTX_NUM="sync:2@0,async:4@0" \
WD_CIPHER_CTX_NUM="sync:2@2,async:4@2" \
WD_DIGEST_CTX_NUM="sync:2@2,async:4@2" \
WD_COMP_CTX_NUM="sync-comp:2@2,sync-decomp:2@2,async-comp:4@2,async-decomp:4@2" \
bash -c 'rm /tmp/vhost_compress.sock
./build/examples/dpdk-vhost_compress \
--socket-mem 1024,0 -n 4 --file-prefix=dpdk2 --vdev="compress_uadk" \
-- --socket-file 2,/tmp/vhost_compress.sock --config=0,0,0 --zero-copy'
