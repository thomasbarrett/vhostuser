#define _GNU_SOURCE

#include <bdev.h>
#include <log.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/eventfd.h>

#include <libaio.h>

struct aio_bdev_queue;

typedef struct aio_bdev {
    bdev_vtable_t vtable;
    struct aio_bdev_queue **queues;
    size_t queue_count;
    int fd;
    size_t queue_depth;
} aio_bdev_t;

typedef struct aio_bdev_queue {
    bdev_queue_vtable_t vtable;
    aio_bdev_t *bdev;
    int eventfd;
    io_context_t ctx;
    size_t inflight;
} aio_bdev_queue_t;

typedef struct aio_bdev_queue_callback {
    bdev_callback_t cb;
    void *ctx;
} aio_bdev_queue_callback_t;

int aio_bdev_queue_callback_init(struct iocb *io, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_callback_t *cb2 = malloc(sizeof(aio_bdev_queue_callback_t));
    if (cb2 == NULL) return -1;

    cb2->cb = cb;
    cb2->ctx = ctx;
    io->data = cb2;
    return 0;
}

void aio_bdev_queue_callback_deinit(aio_bdev_queue_t *queue, struct io_event *event) {
    aio_bdev_queue_callback_t *cb2 = event->data;
    cb2->cb(cb2->ctx, event->res);

    free(cb2);
}

void aio_bdev_queue_read(bdev_queue_t *q, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;

    struct iocb io = {0};
    io_prep_pread(&io, queue->bdev->fd, buf, count, offset);
    io_set_eventfd(&io, queue->eventfd);
    int res = aio_bdev_queue_callback_init(&io, cb, ctx);
    if (res < 0) goto error;

    struct iocb *ios[1] = {&io};
    res = io_submit(queue->ctx, 1, ios);
    if (res < 0) goto error;

    return;
error:
    cb(ctx, -1);
}

void aio_bdev_queue_write(bdev_queue_t *q, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;

    struct iocb io = {0};
    io_prep_pwrite(&io, queue->bdev->fd, buf, count, offset);
    io_set_eventfd(&io, queue->eventfd);
    int res = aio_bdev_queue_callback_init(&io, cb, ctx);
    if (res < 0) goto error;

    struct iocb *ios[1] = {&io};
    res = io_submit(queue->ctx, 1, ios);
    if (res < 0) goto error;

    return;
error:
    cb(ctx, -1);
}

void aio_bdev_queue_readv(bdev_queue_t *q, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;
    struct iocb io = {0};

    io_prep_preadv(&io, queue->bdev->fd, iov, iovcnt, offset);
    io_set_eventfd(&io, queue->eventfd);
    int res = aio_bdev_queue_callback_init(&io, cb, ctx);
    if (res < 0) goto error;

    struct iocb *ios[1] = {&io};
    res = io_submit(queue->ctx, 1, ios);
    if (res < 0) goto error;

    return;
error:
    cb(ctx, -1);
}

void aio_bdev_queue_writev(bdev_queue_t *q, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;

    struct iocb io = {0};
    io_prep_pwritev(&io, queue->bdev->fd, iov, iovcnt, offset);
    io_set_eventfd(&io, queue->eventfd);
    int res = aio_bdev_queue_callback_init(&io, cb, ctx);
    if (res < 0) goto error;

    struct iocb *ios[1] = {&io};
    res = io_submit(queue->ctx, 1, ios);
    if (res < 0) goto error;

    return;
error:
    cb(ctx, -1);
}

void aio_bdev_queue_flush(bdev_queue_t *q, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;

    struct iocb io = {0};
    io_prep_fsync(&io, queue->bdev->fd);
    io_set_eventfd(&io, queue->eventfd);
    int res = aio_bdev_queue_callback_init(&io, cb, ctx);
    if (res < 0) goto error;

    struct iocb *ios[1] = {&io};
    res = io_submit(queue->ctx, 1, ios);
    if (res < 0) goto error;

    return;
error:
    cb(ctx, -1);
}

int aio_bdev_queue_poll(bdev_queue_t *q) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;
    uint64_t nevents;
    read(queue->eventfd, &nevents, sizeof(nevents));
    struct io_event cqe[128];
    struct timespec timeout = (struct timespec) {
        .tv_sec = 0,
        .tv_nsec = 100000000
    };
    int res = io_getevents(queue->ctx, 1, 128, cqe, &timeout);
    if (res < 0) {
        errno = -res;
        return -1;
    }
    for (int j = 0; j < res; j++) {
        queue->inflight--;
        aio_bdev_queue_callback_deinit(queue, &cqe[j]);
    }

    return 0;
}

int aio_bdev_queue_eventfd(bdev_queue_t *q) {
    aio_bdev_queue_t *queue = (aio_bdev_queue_t*) q;

    return queue->eventfd;
}

bdev_queue_vtable_t aio_bdev_queue_vtable = {
    .read = aio_bdev_queue_read,
    .write = aio_bdev_queue_write,
    .readv = aio_bdev_queue_readv,
    .writev = aio_bdev_queue_writev,
    .flush = aio_bdev_queue_flush,
    .eventfd = aio_bdev_queue_eventfd,
    .poll = aio_bdev_queue_poll,
};

aio_bdev_queue_t* aio_bdev_queue_create(aio_bdev_t *bdev) {
    aio_bdev_queue_t *queue = calloc(1, sizeof(aio_bdev_queue_t));
    if (queue == NULL) return NULL;
    queue->vtable = aio_bdev_queue_vtable;
    queue->bdev = bdev;

    int res = io_setup(bdev->queue_depth, &queue->ctx);
    if (res < 0) {
        errno = -res;
        goto error0;
    }

    queue->eventfd = eventfd(0, EFD_NONBLOCK);
    if (queue->eventfd < 0) {
        goto error1;
    }

    return queue;

error1:
    io_destroy(queue->ctx);

error0:
    free(queue);
    return NULL;
}

void aio_bdev_queue_destroy(aio_bdev_queue_t *queue) {
    free(queue);
}

bdev_queue_t* aio_bdev_get_queue(bdev_t *bdev, size_t i) {
   aio_bdev_t *aio_bdev = (aio_bdev_t*) bdev;
   if (i >= aio_bdev->queue_count) return NULL;
   return (bdev_queue_t*) aio_bdev->queues[i];
}

bdev_vtable_t aio_bdev_vtable = {
    .get_queue = aio_bdev_get_queue,
};

bdev_t* aio_bdev_create(char *path, size_t queue_count, size_t queue_depth) {
    aio_bdev_t *bdev = calloc(1, sizeof(aio_bdev_t));
    if (bdev == NULL) return NULL;
    bdev->vtable = aio_bdev_vtable;

    int res = open(path, O_DIRECT | O_RDWR);
    if (res < 0) {
        goto error0;
    }
    bdev->fd = res;
    bdev->queue_depth = queue_depth;
    bdev->queues = calloc(queue_count, sizeof(aio_bdev_queue_t*));
    if (bdev->queues == NULL) goto error1;
    for (size_t i = 0; i < queue_count; i++) {
        bdev->queues[i] = aio_bdev_queue_create(bdev);
        if (bdev->queues[i] == NULL) goto error2;
        bdev->queue_count++;
    }
    return (bdev_t*) bdev;

error2:
    for (size_t i = 0; i < bdev->queue_count; i++) {
        aio_bdev_queue_destroy(bdev->queues[i]);
    }
    free(bdev->queues);

error1:
    close(bdev->fd);

error0:
    free(bdev);
    return NULL;
}

void aio_bdev_destroy(bdev_t *bdev) {
    aio_bdev_t *aio_bdev = (aio_bdev_t*) bdev;
    for (size_t i = 0; i < aio_bdev->queue_count; i++) {
        aio_bdev_queue_destroy(aio_bdev->queues[i]);
    }
    free(aio_bdev->queues);
    close(aio_bdev->fd);
    free(aio_bdev);
}

