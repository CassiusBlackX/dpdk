sudo rm /tmp/vhost_crypto.sock
sudo ./build/examples/dpdk-vhost_crypto -l 1-3 -n 4 --vdev 'crypto_openssl' -- --socket-file 2,/tmp/vhost_crypto.sock
