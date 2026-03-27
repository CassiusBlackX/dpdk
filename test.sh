sudo \
WD_CIPHER_CTX_NUM="sync:2@0,async:2@0" \
WD_DIGEST_CTX_NUM="sync:2@0,async:2@0" \
bash -c './build/app/dpdk-test-crypto-perf --file-prefix=dpdk1 -l 5-6 --vdev crypto_uadk -- --devtype crypto_uadk --cipher-algo aes-cbc --cipher-key-sz 32 --cipher-iv-sz 16 --cipher-op encrypt --optype cipher-only --silent --total-ops 1000000 --buffer-sz 16 --burst-sz 256' &

sudo \
WD_CIPHER_CTX_NUM="sync:2@0,async:2@0" \
WD_DIGEST_CTX_NUM="sync:2@0,async:2@0" \
bash -c './build/app/dpdk-test-crypto-perf --file-prefix=dpdk2 -l 2-3 --vdev crypto_uadk -- --devtype crypto_uadk --cipher-algo aes-cbc --cipher-key-sz 32 --cipher-iv-sz 16 --cipher-op encrypt --optype cipher-only --silent --total-ops 1000000 --buffer-sz 16 --burst-sz 64' &

wait

# ./build/app/dpdk-test-crypto-perf -l 3-4 --vdev crypto_uadk -- \
# --devtype crypto_uadk --ptest throughput --optype rsa --asym-op sign \
# --rsa-modlen 2048 --rsa-priv-keytype qt --total-ops 100 

# ./build/app/dpdk-test-crypto-perf -l 3-4 --vdev crypto_uadk -- \
# --devtype crypto_uadk --ptest throughput --optype rsa --asym-op encrypt \
# --rsa-modlen 2048 --total-ops 100 