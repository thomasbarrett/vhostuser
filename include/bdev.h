#ifndef BDEV_H
#define BDEV_H

#include <unistd.h>
#include <sys/types.h>

typedef void (*bdev_callback_t)(void *ctx, ssize_t res);

struct io_queue;

typedef struct io_queue_vtable {
    int (*read)(struct io_queue *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    int (*write)(struct io_queue *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx);
    int (*flush)(struct io_queue *self, bdev_callback_t cb, void *ctx);
} io_queue_vtable_t;

typedef struct io_queue {
    io_queue_vtable_t vtable;
} io_queue_t;

#define BDEV_MAX_ID_LEN 20

typedef struct bdev {
    char id[BDEV_MAX_ID_LEN];
} bdev_t;

io_queue_t* mock_io_queue_create();
void mock_io_queue_destroy(io_queue_t *queue);

#endif
