sudo \
WD_RSA_CTX_NUM="sync:2@0,async:4@0" \
WD_DH_CTX_NUM="sync:2@0,async:4@0" \
WD_CIPHER_CTX_NUM="sync:2@2,async:4@2" \
WD_DIGEST_CTX_NUM="sync:2@2,async:4@2" \
bash -c '
rm -f /tmp/vhost_crypto.sock
./build/examples/dpdk-vhost_crypto -l 1-3 -n 4 --vdev "crypto_uadk" -- --socket-file 2,/tmp/vhost_crypto.sock --zero-copy
'

