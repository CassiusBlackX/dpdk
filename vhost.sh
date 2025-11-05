sudo rm /tmp/vhost_compress.sock
sudo ./build/examples/dpdk-vhost_compress -l 1-3 -n 4 --vdev 'compress_zlib' -- --socket-file 2,/tmp/vhost_compress.sock
