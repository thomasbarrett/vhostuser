#ifndef BDEV_H
#define BDEV_H

#include <libaio.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>

typedef void (*bdev_callback_t)(void *ctx, ssize_t res);

typedef struct bdev_queue_vtable {
    size_t (*nr_tags)(void *self);
    void (*read)(void *self, uint16_t tag, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*write)(void *self, uint16_t tag, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    void (*readv)(void *self, uint16_t tag, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*writev)(void *self, uint16_t tag, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx);
    void (*flush)(void *self, uint16_t tag, bdev_callback_t cb, void *ctx);
    int (*eventfd)(void *self);
    int (*poll)(void *self);
} bdev_queue_vtable_t;

typedef struct bdev_queue {
    void *self;
    bdev_queue_vtable_t *vtable;
} bdev_queue_t;

#define bdev_queue_nr_tags(bdev) (bdev.vtable->nr_tags(bdev.self))
#define bdev_queue_read(queue, ...) (queue.vtable->read(queue.self, __VA_ARGS__))
#define bdev_queue_readv(queue, ...) (queue.vtable->readv(queue.self, __VA_ARGS__))
#define bdev_queue_write(queue, ...) (queue.vtable->write(queue.self, __VA_ARGS__))
#define bdev_queue_writev(queue, ...) (queue.vtable->writev(queue.self, __VA_ARGS__))
#define bdev_queue_flush(queue, ...) (queue.vtable->flush(queue.self, __VA_ARGS__))
#define bdev_queue_eventfd(queue) (queue.vtable->eventfd(queue.self))
#define bdev_queue_poll(queue) (queue.vtable->poll(queue.self))

typedef struct bdev_vtable {
    int (*size)(void *self, uint64_t *size);
    size_t (*queue_count)(void *self);
    bdev_queue_t (*queue)(void *self, size_t i);
} bdev_vtable_t;

typedef struct bdev {
    void *self;
    bdev_vtable_t *vtable;
} bdev_t;

#define bdev_size(bdev, ...) (bdev.vtable->size(bdev.self, __VA_ARGS__))
#define bdev_queue_count(bdev) (bdev.vtable->queue_count(bdev.self))
#define bdev_queue(bdev, ...) (bdev.vtable->queue(bdev.self, __VA_ARGS__))

struct aio_bdev;
struct aio_bdev_io;

typedef struct aio_bdev_queue {
    struct aio_bdev *bdev;
    int eventfd;
    io_context_t ctx;
    struct aio_bdev_io *ios;
    struct io_event *events;
    size_t nr_tags;
} aio_bdev_queue_t;

typedef struct aio_bdev {
    struct aio_bdev_queue *queues;
    size_t queue_count;
    int fd;
} aio_bdev_t;

/**
 * Initialize the aio block device.
 * 
 * \param self: the block device.
 * \param path: the block device path.
 * \param queue_count: the queue count.
 * \param nr_tags: the queue depth.
 */
int aio_bdev_init(aio_bdev_t *self, char *path, size_t queue_count, size_t nr_tags);

/**
 * Deinitialize the aio block device.
 * 
 * \param self: the block device.
 */
void aio_bdev_deinit(aio_bdev_t *self);

/**
 * Report the block device size in bytes.
 * 
 * \param bdev: the block device.
 * \param size: the result.
 * \return 0 on success and -1 on error. 
 */
int aio_bdev_size(aio_bdev_t *bdev, uint64_t *size);

extern bdev_vtable_t aio_bdev_vtable;

#endif
