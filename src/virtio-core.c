#include <virtio-core.h>

#include <stdatomic.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static void vring_used_push(struct vring vring, desc_state_t *desc, __virtio32 id, __virtio32 len) {
   vring.used->ring[vring.used->idx % vring.num] = (vring_used_elem_t) {
        .id = id,
        .len = 0,
    };
    atomic_thread_fence(memory_order_release);
    desc->inflight = 0;
    vring.used->idx++;
}

int virtio_done(virtio_ctx_t *ctx) {
    vring_used_push(ctx->vring, ctx->desc, ctx->id, ctx->len);
    if (write(ctx->eventfd, &(uint64_t){1}, sizeof(uint64_t)) < 0) {
        printf("ERROR: failed to write to eventfd\n");
    }
    free(ctx);
    return 0;
}
