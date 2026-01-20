sudo \
WD_RSA_CTX_NUM="sync:2@0,async:4@0" \
WD_DH_CTX_NUM="sync:2@0,async:4@0" \
WD_CIPHER_CTX_NUM="sync:2@2,async:4@2" \
WD_DIGEST_CTX_NUM="sync:2@2,async:4@2" \
WD_COMP_CTX_NUM="sync-comp:2@2,sync-decomp:2@2,async-comp:4@2,async-decomp:4@2" \
bash -c './build/app/dpdk-test-crypto-perf -l 2-3 --vdev crypto_openssl -- --devtype crypto_openssl --cipher-algo aes-cbc --cipher-key-sz 32 --cipher-iv-sz 16 --cipher-op encrypt --optype cipher-only --silent --total-ops 5000000 --buffer-sz 1024
'
