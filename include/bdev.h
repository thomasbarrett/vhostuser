#ifndef BDEV_H
#define BDEV_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef void (*bdev_callback_t)(void *ctx, ssize_t res);

struct bdev_queue;

typedef struct bdev_queue_vtable {
    void (*read)(struct bdev_queue *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*write)(struct bdev_queue *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*readv)(struct bdev_queue *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*writev)(struct bdev_queue *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*flush)(struct bdev_queue *self, bdev_callback_t cb, void *ctx);
    int (*eventfd)(struct bdev_queue *self);
    int (*poll)(struct bdev_queue *self);
} bdev_queue_vtable_t;

#define bdev_queue_read(queue, ...) (queue->vtable.read(queue, __VA_ARGS__))
#define bdev_queue_readv(queue, ...) (queue->vtable.readv(queue, __VA_ARGS__))
#define bdev_queue_write(queue, ...) (queue->vtable.write(queue, __VA_ARGS__))
#define bdev_queue_writev(queue, ...) (queue->vtable.writev(queue, __VA_ARGS__))
#define bdev_queue_flush(queue, ...) (queue->vtable.flush(queue, __VA_ARGS__))
#define bdev_queue_eventfd(queue) (queue->vtable.eventfd(queue))
#define bdev_queue_poll(queue) (queue->vtable.poll(queue))

typedef struct bdev_queue {
    bdev_queue_vtable_t vtable;
} bdev_queue_t;

struct bdev;

typedef struct bdev_vtable {
    bdev_queue_t* (*get_queue)(struct bdev *bdev, size_t i);
} bdev_vtable_t;

#define bdev_get_queue(bdev, ...) (bdev->vtable.get_queue(bdev, __VA_ARGS__))

typedef struct bdev {
    bdev_vtable_t vtable;
} bdev_t;

bdev_t* aio_bdev_create(char *path, size_t queue_count, size_t queue_depth);

void aio_bdev_destroy(bdev_t *bdev);

#endif
