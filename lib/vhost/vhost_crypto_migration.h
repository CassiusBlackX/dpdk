/* dpdk/lib/vhost/vhost_crypto_migration.h */
#ifndef VHOST_CRYPTO_MIGRATION_H
#define VHOST_CRYPTO_MIGRATION_H

#include <stdint.h>
#include "vhost_crypto_snapshot.h" 

/* DPDK lib/vhost internal migration hooks for virtio-crypto backend.
 * vid: vhost device id managed by lib/vhost
 * fd : an already-opened writable/readable fd (memfd, pipe, temp file, etc.)
 */
struct vhost_crypto_dev;
int vhost_crypto_freeze(int vid);              /* stop enqueue + drain inflight */
int vhost_crypto_save_state(int vid, int fd);  /* serialize device/queues/sessions -> fd */
/* lib/vhost/vhost_crypto_migration.h */
int vhost_crypto_load_state(int vid, const void *buf, size_t len);

int vhost_crypto_thaw(int vid);                /* resume workers */

#endif /* VHOST_CRYPTO_MIGRATION_H */