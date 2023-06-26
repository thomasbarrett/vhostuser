#ifndef VIRTIO_CORE_H
#define VIRTIO_CORE_H

#include <linux/virtio_ring.h>

typedef struct virtio_ctx {
    struct vring vring;
    __virtio32 id;
    __virtio32 len;
    int eventfd;
} virtio_ctx_t;

int virtio_done(virtio_ctx_t *ctx);

#endif
