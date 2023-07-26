#ifndef BDEV_H
#define BDEV_H

#include <queue.h>
#include <libaio.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef void (*bdev_callback_t)(void *ctx, ssize_t res);

typedef struct bdev_queue_vtable {
    void (*read)(void *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*write)(void *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*readv)(void *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*writev)(void *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*flush)(void *self, bdev_callback_t cb, void *ctx);
    int (*eventfd)(void *self);
    int (*poll)(void *self);
} bdev_queue_vtable_t;

typedef struct bdev_queue {
    void *self;
    bdev_queue_vtable_t *vtable;
} bdev_queue_t;

#define bdev_queue_read(queue, ...) (queue.vtable->read(queue.self, __VA_ARGS__))
#define bdev_queue_readv(queue, ...) (queue.vtable->readv(queue.self, __VA_ARGS__))
#define bdev_queue_write(queue, ...) (queue.vtable->write(queue.self, __VA_ARGS__))
#define bdev_queue_writev(queue, ...) (queue.vtable->writev(queue.self, __VA_ARGS__))
#define bdev_queue_flush(queue, ...) (queue.vtable->flush(queue.self, __VA_ARGS__))
#define bdev_queue_eventfd(queue) (queue.vtable->eventfd(queue.self))
#define bdev_queue_poll(queue) (queue.vtable->poll(queue.self))

typedef struct bdev_vtable {
    size_t (*queue_count)(void *self);
    size_t (*queue_depth)(void *self);
    bdev_queue_t (*get_queue)(void *bdev, size_t i);
} bdev_vtable_t;

typedef struct bdev {
    void *self;
    bdev_vtable_t *vtable;
} bdev_t;

#define bdev_queue_count(bdev) (bdev.vtable->queue_count(bdev.self))
#define bdev_queue_depth(bdev) (bdev.vtable->queue_depth(bdev.self))
#define bdev_get_queue(bdev, ...) (bdev.vtable->get_queue(bdev.self, __VA_ARGS__))

struct aio_bdev;
struct aio_bdev_io;

typedef struct aio_bdev_queue {
    struct aio_bdev *bdev;
    int eventfd;
    io_context_t ctx;
    struct aio_bdev_io *ios;
    queue_t tags; 
    struct io_event *events;
} aio_bdev_queue_t;

typedef struct aio_bdev {
    struct aio_bdev_queue *queues;
    size_t queue_count;
    int fd;
    size_t queue_depth;
} aio_bdev_t;

int aio_bdev_init(aio_bdev_t *self, char *path, size_t queue_count, size_t queue_depth);

void aio_bdev_deinit(aio_bdev_t *self);

extern bdev_vtable_t aio_bdev_vtable;

#endif
