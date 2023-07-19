#include <virtio-blk.h>
#include <virtio-core.h>
#include <log.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/epoll.h>
#include <linux/virtio_blk.h>

device_queue_vtable_t virtio_blk_device_queue_vtable = {
    .epoll_register = virtio_blk_queue_epoll_register,
    .epoll_deregister = virtio_blk_queue_epoll_deregister,
    .handle = virtio_blk_queue_handle,
};

virtio_blk_queue_t* virtio_blk_queue_create(bdev_queue_t *bdev_queue) {
    virtio_blk_queue_t *queue = calloc(1, sizeof(virtio_blk_queue_t));
    if (queue == NULL) return NULL;
    queue->vtable = virtio_blk_device_queue_vtable,
    queue->bdev_queue = bdev_queue;
    queue->poll = (task_t) {
        .self = (void*) queue,
        .call = (int (*)(void*, int))(virtio_blk_queue_poll),
    };
    
    return queue;
}

void virtio_blk_queue_destroy(virtio_blk_queue_t *queue) {
    free(queue);
}

typedef struct virtio_blk_io_ctx {
    uint8_t *res;
    virtio_ctx_t *virtio_ctx;
    size_t size;
    size_t sector;
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

void virtio_blk_handle_req(bdev_queue_t *bdev_queue, struct virtio_blk_outhdr *hdr, struct iovec *iov, size_t iovcnt, uint8_t *res, virtio_ctx_t *virtio_ctx) {
    switch (hdr->type) {
    case VIRTIO_BLK_T_IN:
        {
            if (iovcnt == 1 && !bdev_queue->vtable.read) break;
            if (iovcnt > 1 && !bdev_queue->vtable.readv) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = get_iov_len(iov, iovcnt);
            io_ctx->sector = hdr->sector;
            if (iovcnt == 1) {
                bdev_queue_read(bdev_queue, iov[0].iov_base, iov[0].iov_len, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            } else {
                bdev_queue_readv(bdev_queue, iov, iovcnt, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_OUT:
        {
            if (iovcnt == 1 && !bdev_queue->vtable.write) break;
            if (iovcnt > 1 && !bdev_queue->vtable.writev) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = get_iov_len(iov, iovcnt);
            io_ctx->sector = hdr->sector;
            if (iovcnt == 1) {
                bdev_queue_write(bdev_queue, iov[0].iov_base, iov[0].iov_len, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            } else {
                bdev_queue_writev(bdev_queue, iov, iovcnt, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_FLUSH:
        {
            if (!bdev_queue->vtable.flush) break;
            virtio_blk_io_ctx_t *io_ctx = calloc(1, sizeof(virtio_blk_io_ctx_t));
            io_ctx->res = res;
            io_ctx->virtio_ctx = virtio_ctx;
            io_ctx->size = 0;
            io_ctx->sector = hdr->sector;
            bdev_queue_flush(bdev_queue, virtio_blk_io_cb, io_ctx);
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

int virtio_blk_queue_poll(virtio_blk_queue_t *queue, int _) {
    if (bdev_queue_poll(queue->bdev_queue) < 0) {
        error("Failed to poll bdev queue", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_epoll_register(struct device_queue *queue, int epollfd) {
    virtio_blk_queue_t *virtio_blk_queue = (virtio_blk_queue_t*) queue;

    struct epoll_event event = {0};
    int fd = bdev_queue_eventfd(virtio_blk_queue->bdev_queue);
    event.events = EPOLLIN;
    event.data.ptr = &virtio_blk_queue->poll;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
        error("Failed to add fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_epoll_deregister(struct device_queue *queue, int epollfd) {
    virtio_blk_queue_t *virtio_blk_queue = (virtio_blk_queue_t*) queue;

    int fd = bdev_queue_eventfd(virtio_blk_queue->bdev_queue);
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        error("Failed to remove fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_handle(device_queue_t *queue, struct iovec *iov, size_t iovcnt, virtio_ctx_t *virtio_ctx) {
    virtio_blk_queue_t *virtio_blk_queue = (virtio_blk_queue_t*) queue;
    /* All virtio-blk requests must include at least a header and a status byte. */
    if (iovcnt < 2) {
        error("Received virtio-blk message with unsupported framing: iovcnt=%d", iovcnt);
        return -1;
    }
    /* Check that the first segment is the correct length to be a header. */
    if (iov[0].iov_len != sizeof(struct virtio_blk_outhdr)) {
        error("Received virtio-blk message with unsupported framing: iov[0].iov_len=%d", iov[0].iov_len);
        return -1;
    }
    /* Check that the last segment is the correct length to be a status byte. */
    if (iov[iovcnt - 1].iov_len != 1) {
        error("Received virtio-blk message with unsupported framing: iov[iovcnt - 1].iov_len=%d", iov[iovcnt - 1].iov_len);
        return -1;
    }
    
    struct iovec *data_iov = NULL;
    size_t data_iovcnt = iovcnt - 2;
    if (data_iovcnt > 0) {
        data_iov = &iov[1];
    }

    struct virtio_blk_outhdr* hdr = (struct virtio_blk_outhdr*) iov[0].iov_base;
    virtio_blk_handle_req(virtio_blk_queue->bdev_queue, hdr, data_iov, data_iovcnt, (uint8_t*) iov[iovcnt - 1].iov_base, virtio_ctx); 
    
    return 0;   
}
