# sudo \
# WD_CIPHER_CTX_NUM="sync:2@0,async:2@0" \
# WD_DIGEST_CTX_NUM="sync:2@0,async:2@0" \
# bash -c './build/app/dpdk-test-crypto-perf --file-prefix=dpdk1 -l 5-6 --vdev crypto_uadk -- --devtype crypto_uadk --cipher-algo aes-cbc --cipher-key-sz 32 --cipher-iv-sz 16 --cipher-op encrypt --optype cipher-only --silent --total-ops 1000 --buffer-sz 2048 --burst-sz 32' 

# sudo \
# WD_CIPHER_CTX_NUM="sync:2@0,async:2@0" \
# WD_DIGEST_CTX_NUM="sync:2@0,async:2@0" \
# bash -c './build/app/dpdk-test-crypto-perf --file-prefix=dpdk2 -l 2-3 --vdev crypto_uadk -- --devtype crypto_uadk --cipher-algo aes-cbc --cipher-key-sz 32 --cipher-iv-sz 16 --cipher-op encrypt --optype cipher-only --silent --total-ops 2048 --buffer-sz 2048 --burst-sz 512' &

# wait
sudo \
WD_RSA_CTX_NUM="sync:2@0,async:2@0" \
./build/app/dpdk-test-crypto-perf --file-prefix=dpdk1 -l 3-4 --vdev crypto_uadk -- \
--devtype crypto_uadk --ptest throughput --optype rsa --asym-op sign \
--rsa-modlen 2048 --rsa-priv-keytype qt --total-ops 1000  --burst-sz 256 &
sudo \
WD_RSA_CTX_NUM="sync:2@1,async:2@1" \
./build/app/dpdk-test-crypto-perf --file-prefix=dpdk2 -l 5-6 --vdev crypto_uadk -- \
--devtype crypto_uadk --ptest throughput --optype rsa --asym-op sign \
--rsa-modlen 2048 --rsa-priv-keytype qt --total-ops 1000  --burst-sz 256 &
sudo \
WD_RSA_CTX_NUM="sync:2@2,async:2@2" \
./build/app/dpdk-test-crypto-perf --file-prefix=dpdk3 -l 7-8 --vdev crypto_uadk -- \
--devtype crypto_uadk --ptest throughput --optype rsa --asym-op sign \
--rsa-modlen 2048 --rsa-priv-keytype qt --total-ops 1000  --burst-sz 256 &
wait

# ./build/app/dpdk-test-crypto-perf -l 3-4 --vdev crypto_uadk -- \
# --devtype crypto_uadk --ptest throughput --optype rsa --asym-op encrypt \
# --rsa-modlen 2048 --total-ops 100 