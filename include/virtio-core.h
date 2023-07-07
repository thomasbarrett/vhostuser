#ifndef VIRTIO_CORE_H
#define VIRTIO_CORE_H

#include <linux/virtio_ring.h>

typedef struct desc_state {
    uint8_t inflight;
} desc_state_t;

typedef struct queue_state {
    __virtio16 last_avail_idx;
    desc_state_t desc[];
} queue_state_t;

typedef struct virtio_ctx {
    struct vring vring;
    desc_state_t *desc;
    __virtio32 id;
    __virtio32 len;
    int eventfd;
} virtio_ctx_t;

int virtio_done(virtio_ctx_t *ctx);

#endif
