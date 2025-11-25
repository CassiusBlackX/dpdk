sudo rm /tmp/vhost_compress.sock
sudo ./build/examples/dpdk-vhost_compress \
--socket-mem 1024,0 -n 4 --vdev="compress_zlib" \
-- --socket-file 2,/tmp/vhost_compress.sock --config=0,0,0
