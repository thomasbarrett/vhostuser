#include <virtio-blk.h>
#include <virtio-core.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct virtio_blk_io_ctx {
    uint8_t *res;
    virtio_ctx_t *virtio_ctx;
    size_t size;
} virtio_blk_io_ctx_t;

void virtio_blk_io_cb(void *ctx, ssize_t res) {
    virtio_blk_io_ctx_t *io_ctx = (virtio_blk_io_ctx_t*) ctx;
    if (res == io_ctx->size) {
        *(io_ctx->res) = VIRTIO_BLK_S_OK;
    } else {
        *(io_ctx->res) = VIRTIO_BLK_S_IOERR;
    }
    virtio_done(io_ctx->virtio_ctx);
    free(io_ctx);
}

static size_t get_iov_len(struct iovec *iov, size_t iov_len) {
    size_t res = 0;
    for (size_t i = 0; i < iov_len; i++) {
        res += iov[i].iov_len;
    }

    return res;
}

void virtio_blk_handle(io_queue_t *io_queue, struct virtio_blk_outhdr *hdr, struct iovec *iov, size_t iovcnt, uint8_t *res, virtio_ctx_t *virtio_ctx) {
    switch (hdr->type) {
    case VIRTIO_BLK_T_IN:
        {
            if (iovcnt == 1 && !io_queue->vtable.read) break;
            if (iovcnt > 1 && !io_queue->vtable.readv) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = get_iov_len(iov, iovcnt);
            if (iovcnt == 1) {
                io_queue->vtable.read(io_queue, iov[0].iov_base, iov[0].iov_len, hdr->sector, virtio_blk_io_cb, io_ctx);
            } else {
                io_queue->vtable.readv(io_queue, iov, iovcnt, hdr->sector, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_OUT:
        {
            if (iovcnt == 1 && !io_queue->vtable.write) break;
            if (iovcnt > 1 && !io_queue->vtable.writev) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = get_iov_len(iov, iovcnt);
            if (iovcnt == 1) {
                io_queue->vtable.write(io_queue, iov[0].iov_base, iov[0].iov_len, hdr->sector, virtio_blk_io_cb, io_ctx);
            } else {
                io_queue->vtable.writev(io_queue, iov, iovcnt, hdr->sector, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_FLUSH:
        {
            if (!io_queue->vtable.flush) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = 0;
            io_queue->vtable.flush(io_queue, virtio_blk_io_cb, io_ctx);
            return;
        }
    case VIRTIO_BLK_T_GET_ID:
        memcpy(iov[1].iov_base, "hello", strlen("hello"));
        *res = VIRTIO_BLK_S_OK;
        virtio_done(virtio_ctx);
        return;       
    }

    *res = VIRTIO_BLK_S_UNSUPP;
    virtio_done(virtio_ctx);
}

void virtio_blk_outhdr_debug(struct virtio_blk_outhdr *hdr) {
    printf("struct virtio_blk_outhdr { "
        "type: %u, "
        "ioprio: %u, "
        "sector: %llx, "
        "}\n",
        hdr->type,
        hdr->ioprio,
        hdr->sector
    );
}
