#include <bdev.h>
#include <log.h>

#include <string.h>
#include <stdlib.h>

// BEGIN: mock_io_queue_t

typedef struct mock_io_queue {
    io_queue_vtable_t vtable;
} mock_io_queue_t;

int mock_io_queue_read(io_queue_t *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    memset(buf, 0, count);
    info("bdev_read { count: 0x%zx, offset: 0x%lx }", count, offset);
    cb(ctx, count);
    return 0;
}

int mock_io_queue_write(io_queue_t *self, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    info("bdev_write { count: 0x%zx, offset: 0x%lx }", count, offset);
    cb(ctx, count);
    return 0;
}

static size_t get_iov_len(struct iovec *iov, size_t iov_len) {
    size_t res = 0;
    for (size_t i = 0; i < iov_len; i++) {
        res += iov[i].iov_len;
    }

    return res;
}

int mock_io_queue_readv(io_queue_t *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    size_t count = get_iov_len(iov, iovcnt);
    info("bdev_readv { count: 0x%zx, offset: 0x%lx }", count, offset);
    cb(ctx, count);
    return 0;
}

int mock_io_queue_writev(io_queue_t *self, struct iovec *iov, int iovcnt, off_t offset, bdev_callback_t cb, void *ctx) {
    size_t count = get_iov_len(iov, iovcnt);
    info("bdev_writev { count: 0x%zx, offset: 0x%lx }", count, offset);
    cb(ctx, count);
    return 0;
}

int mock_io_queue_flush(io_queue_t *self, bdev_callback_t cb, void *ctx) {
    info("bdev_flush {}");
    cb(ctx, 0);
    return 0;
}

io_queue_vtable_t mock_io_queue_vtable = {
    .read = mock_io_queue_read,
    .write = mock_io_queue_write,
    .readv = mock_io_queue_readv,
    .writev = mock_io_queue_writev,
    .flush = mock_io_queue_flush,
};

io_queue_t* mock_io_queue_create(void) {
    mock_io_queue_t *res = calloc(1, sizeof(mock_io_queue_t));
    if (res == NULL) return NULL;
    res->vtable = mock_io_queue_vtable;
    return (io_queue_t*) res;
}

void mock_io_queue_destroy(io_queue_t *queue) {
    free(queue);
}

// END mock_io_queue_t
