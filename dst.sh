#!/bin/bash

sudo \
WD_RSA_CTX_NUM="sync:2@3,async:4@3" \
WD_DH_CTX_NUM="sync:2@3,async:4@3" \
WD_CIPHER_CTX_NUM="sync:2@3,async:4@3" \
WD_DIGEST_CTX_NUM="sync:2@3,async:4@3" \
bash -c '
set -e

SOCK=/tmp/vhost_crypto_dst.sock
rm -f "$SOCK"

./build/examples/dpdk-vhost_crypto \
  -l 240-247 \
  -n 4 \
  --file-prefix=dpdk3 \
  --socket-mem 0,0,0,1024 \
  --vdev "crypto_uadk" \
  -- \
  --socket-file 241,"$SOCK" \
  --zero-copy
'
