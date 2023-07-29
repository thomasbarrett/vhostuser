#define _GNU_SOURCE

#include <bdev.h>
#include <log.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

#include <libaio.h>
#include <linux/fs.h>

typedef struct aio_bdev_io {
    bdev_callback_t cb;
    void *ctx;
    struct iocb iocb;
} aio_bdev_io_t;

typedef struct aio_bdev_queue_callback {
    bdev_callback_t cb;
    void *ctx;
} aio_bdev_queue_callback_t;

size_t aio_bdev_queue_nr_tags(aio_bdev_queue_t *queue) {
    return queue->nr_tags;
}

void aio_bdev_queue_read(void *self, uint16_t tag, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = self;

    queue->ios[tag].cb = cb;
    queue->ios[tag].ctx = ctx;
    queue->ios[tag].iocb = (struct iocb){0};

    struct iocb *iocb = &queue->ios[tag].iocb;
    io_prep_pread(iocb, queue->bdev->fd, buf, count, offset);
    io_set_eventfd(iocb, queue->eventfd);
    iocb->data = (void *) (uintptr_t) tag;

    struct iocb *ios[1] = {iocb};
    int res = io_submit(queue->ctx, 1, ios);
    if (res < 0) {
        error("Failed to submit io: %s", strerror(-res));
        goto error0;
    }

    return;
error0:
    cb(ctx, -1);
}

void aio_bdev_queue_write(void *self, uint16_t tag, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = self;

    queue->ios[tag].cb = cb;
    queue->ios[tag].ctx = ctx;
    queue->ios[tag].iocb = (struct iocb){0};

    struct iocb *iocb = &queue->ios[tag].iocb;
    io_prep_pwrite(iocb, queue->bdev->fd, buf, count, offset);
    io_set_eventfd(iocb, queue->eventfd);
    iocb->data = (void *) (uintptr_t) tag;

    struct iocb *ios[1] = {iocb};
    int res = io_submit(queue->ctx, 1, ios);
    if (res < 0) {
        error("Failed to submit io: %s", strerror(-res));
        goto error0;
    }

    return;
error0:
    cb(ctx, -1);
}

void aio_bdev_queue_readv(void *self, uint16_t tag, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = self;

    queue->ios[tag].cb = cb;
    queue->ios[tag].ctx = ctx;
    queue->ios[tag].iocb = (struct iocb){0};

    struct iocb *iocb = &queue->ios[tag].iocb;
    io_prep_preadv(iocb, queue->bdev->fd, iov, iovcnt, offset);
    io_set_eventfd(iocb, queue->eventfd);
    iocb->data = (void *) (uintptr_t) tag;

    struct iocb *ios[1] = {iocb};
    int res = io_submit(queue->ctx, 1, ios);
    if (res < 0) {
        error("Failed to submit io: %s", strerror(-res));
        goto error0;
    }

    return;
error0:
    cb(ctx, -1);
}

void aio_bdev_queue_writev(void *self, uint16_t tag, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = self;

    queue->ios[tag].cb = cb;
    queue->ios[tag].ctx = ctx;
    queue->ios[tag].iocb = (struct iocb){0};

    struct iocb *iocb = &queue->ios[tag].iocb;
    io_prep_pwritev(iocb, queue->bdev->fd, iov, iovcnt, offset);
    io_set_eventfd(iocb, queue->eventfd);
    iocb->data = (void *) (uintptr_t) tag;

    struct iocb *ios[1] = {iocb};
    int res = io_submit(queue->ctx, 1, ios);
    if (res < 0) {
        error("Failed to submit io: %s", strerror(-res));
        goto error0;
    }

    return;
error0:
    cb(ctx, -1);
}

void aio_bdev_queue_flush(void *self, uint16_t tag, bdev_callback_t cb, void *ctx) {
    aio_bdev_queue_t *queue = self;

    queue->ios[tag].cb = cb;
    queue->ios[tag].ctx = ctx;
    queue->ios[tag].iocb = (struct iocb){0};

    struct iocb *iocb = &queue->ios[tag].iocb;
    io_prep_fsync(iocb, queue->bdev->fd);
    io_set_eventfd(iocb, queue->eventfd);
    iocb->data = (void *) (uintptr_t) tag;

    struct iocb *ios[1] = {iocb};
    int res = io_submit(queue->ctx, 1, ios);
    if (res < 0) {
        error("Failed to submit io: %s", strerror(-res));
        goto error0;
    }

    return;
error0:
    cb(ctx, -1);
}

int aio_bdev_queue_poll(void *self) {
    aio_bdev_queue_t *queue = self;
    
    uint64_t nevents;
    read(queue->eventfd, &nevents, sizeof(nevents));

    // 10ms timeout.
    struct timespec timeout = (struct timespec) {
        .tv_sec = 0,
        .tv_nsec = 10000000
    };
    int res = io_getevents(queue->ctx, 1, queue->nr_tags, queue->events, &timeout);
    if (res < 0) {
        return -1;
    }
    if (res == 0) {
        return 0;
    }

    for (int j = 0; j < res; j++) {
        uint16_t tag = (uint16_t) (uintptr_t) queue->events[j].data;
        aio_bdev_io_t *io = &queue->ios[tag];
        io->cb(io->ctx, queue->events[j].res);
    }

    return 0;
}

int aio_bdev_queue_eventfd(void *self) {
    aio_bdev_queue_t *queue = self;

    return queue->eventfd;
}

bdev_queue_vtable_t aio_bdev_queue_vtable = {
    .nr_tags = (size_t (*)(void *)) aio_bdev_queue_nr_tags,
    .read = aio_bdev_queue_read,
    .write = aio_bdev_queue_write,
    .readv = aio_bdev_queue_readv,
    .writev = aio_bdev_queue_writev,
    .flush = aio_bdev_queue_flush,
    .eventfd = aio_bdev_queue_eventfd,
    .poll = aio_bdev_queue_poll,
};

int aio_bdev_queue_init(aio_bdev_queue_t *queue, aio_bdev_t *bdev, size_t nr_tags) {
    memset(queue, 0, sizeof(aio_bdev_t));
    queue->nr_tags = nr_tags;
    queue->ios = calloc(nr_tags, sizeof(aio_bdev_io_t));
    if (queue->ios == NULL) goto error0;

    queue->events = calloc(nr_tags, sizeof(struct io_event));
    if (queue->events == NULL) goto error1;

    queue->bdev = bdev;
    
    int res = io_setup(nr_tags, &queue->ctx);
    if (res < 0) goto error2;

    res = eventfd(0, EFD_NONBLOCK);
    if (res < 0) goto error3;
    queue->eventfd = res;

    return 0;

error3:
    io_destroy(queue->ctx);
error2:
    free(queue->events);
error1:
    free(queue->ios);
error0:
    return -1;
}

void aio_bdev_queue_deinit(aio_bdev_queue_t *queue) {
    close(queue->eventfd);
    io_destroy(queue->ctx);
    free(queue->events);
    free(queue->ios);
}

bdev_queue_t aio_bdev_queue(void *self, size_t i) {
    aio_bdev_t *aio_bdev = self;
    if (i >= aio_bdev->queue_count) {
        return (bdev_queue_t){0};
    }

    return (bdev_queue_t) {
        .self = &aio_bdev->queues[i],
        .vtable = &aio_bdev_queue_vtable,
    };
}


int aio_bdev_init(aio_bdev_t *bdev, char *path, size_t queue_count, size_t nr_tags) {
    memset(bdev, 0, sizeof(aio_bdev_t));
    int res = open(path, O_DIRECT | O_RDWR);
    if (res < 0) {
        goto error0;
    }
    bdev->fd = res;
    bdev->queues = calloc(queue_count, sizeof(aio_bdev_queue_t));
    if (bdev->queues == NULL) goto error1;
    for (size_t i = 0; i < queue_count; i++) {
        if (aio_bdev_queue_init(&bdev->queues[i], bdev, nr_tags) < 0) {
            goto error2;
        }
        bdev->queue_count++;
    }
    return 0;

error2:
    for (size_t i = 0; i < bdev->queue_count; i++) {
        aio_bdev_queue_deinit(&bdev->queues[i]);
    }
    free(bdev->queues);

error1:
    close(bdev->fd);

error0:
    return -1;
}

int aio_bdev_size(aio_bdev_t *bdev, uint64_t *size) {
    if (ioctl(bdev->fd, BLKGETSIZE64, size) != 0) {
        return -1;
    }

    return 0;
}

void aio_bdev_deinit(aio_bdev_t *bdev) {
    for (size_t i = 0; i < bdev->queue_count; i++) {
        aio_bdev_queue_deinit(&bdev->queues[i]);
    }
    free(bdev->queues);
    close(bdev->fd);
}

size_t aio_bdev_queue_count(aio_bdev_t *bdev) {
    return bdev->queue_count;
}

bdev_vtable_t aio_bdev_vtable = {
    .size = (int (*)(void*, uint64_t*)) aio_bdev_size,
    .queue_count = (size_t (*)(void*)) aio_bdev_queue_count,
    .queue = aio_bdev_queue,
};
