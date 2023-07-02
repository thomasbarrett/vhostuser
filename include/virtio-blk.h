#ifndef VIRTIO_BLK_H
#define VIRTIO_BLK_H

#include <bdev.h>
#include <virtio-core.h>

#include <sys/uio.h>
#include <linux/virtio_blk.h>

void virtio_blk_outhdr_debug(struct virtio_blk_outhdr *hdr) ;

void virtio_blk_handle(bdev_queue_t *bdev_queue, struct virtio_blk_outhdr *hdr, struct iovec *iov, size_t iov_len, uint8_t *res, virtio_ctx_t *virtio_ctx);

#endif
