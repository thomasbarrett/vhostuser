// CFLAGS: -Wl,--wrap=epoll_ctl
#define _GNU_SOURCE
#include <src/virtio-blk.c>
#include <src/log.c>
#include <src/bitmap.c>

#include <assert.h>

#define MOCK_EPOLLFD 4
#define MOCK_BDEV_EVENTFD 5

int metric_client_register(metric_client_t *client, metric_t *metric) {
    return 0;
}

int metric_client_deregister(metric_client_t *client, metric_t *metric) {
    return 0;
}

int metric_counter_init(metric_counter_t *counter, const char *name, metric_label_t *labels, size_t label_count) {
    return 0;
}

void metric_counter_deinit(metric_counter_t *counter) {
    return;
}

void metric_counter_inc(metric_counter_t *counter, uint64_t count) {
    return;
}

int io_done_called = 0;
int io_done(void *ctx, int _) {
    io_done_called = 1;
    return 0;
}

typedef struct mock_bdev_queue {
    void *buf;
    size_t count;
    bdev_callback_t cb;
    void *ctx;
} mock_bdev_queue_t;

size_t mock_bdev_queue_nr_tags(void *self) {
    return 128;
}

void mock_bdev_queue_read(void *self, uint16_t tag, void *buf, size_t count, off_t offset, bdev_callback_t cb, void *ctx) {
    mock_bdev_queue_t *queue = self;
    assert(count == 4096);
    assert(offset == 4096);
    queue->buf = buf;
    queue->count = count;
    queue->cb = cb;
    queue->ctx = ctx;
}

int mock_bdev_queue_eventfd(void *self) {
    return MOCK_BDEV_EVENTFD;
}

int mock_bdev_queue_poll(void *self) {
    mock_bdev_queue_t *queue = (mock_bdev_queue_t*) self;
    memset(queue->buf, 1, queue->count);
    queue->cb(queue->ctx, queue->count);
    return 0;
}

int __wrap_epoll_ctl(int epollfd, int op, int fd, struct epoll_event *event) {
    assert(epollfd == MOCK_EPOLLFD);
    assert(fd == MOCK_BDEV_EVENTFD);
    return 0;
}

bdev_queue_vtable_t mock_bdev_queue_vtable = {
    .nr_tags = mock_bdev_queue_nr_tags,
    .read = mock_bdev_queue_read,
    .eventfd = mock_bdev_queue_eventfd,
    .poll = mock_bdev_queue_poll,
};


void test_virtio_blk() {
    mock_bdev_queue_t mock_bdev_queue = {0};
    virtio_blk_queue_t queue;
    assert(virtio_blk_queue_init(&queue, (bdev_queue_t) {
        .self = &mock_bdev_queue,
        .vtable = &mock_bdev_queue_vtable,
    }, NULL, 1) == 0);
    assert(virtio_blk_queue_epoll_register(&queue, MOCK_EPOLLFD) == 0);

    struct virtio_blk_outhdr hdr = {
        .type = VIRTIO_BLK_T_IN,
        .sector = 8,
    };
    uint8_t buf[4096] = {0};
    uint8_t res;
    struct iovec iov[3] = {
        {
            .iov_base = &hdr,
            .iov_len = sizeof(hdr),
        }, {
            .iov_base = buf,
            .iov_len = sizeof(buf),
        }, {
            .iov_base = &res,
            .iov_len = 1,
        }
    };

    assert(virtio_blk_queue_handle(&queue, iov, 3, (task_t){.self = NULL, .call = io_done}) == 0);
    assert(virtio_blk_queue_poll(&queue, MOCK_EPOLLFD) == 0);
    assert(io_done_called == 1);
    assert(res == VIRTIO_BLK_S_OK);
    for (size_t i = 0; i < 4096; i++) {
        assert(buf[i] == 1);
    }
    assert(virtio_blk_queue_epoll_deregister(&queue, MOCK_EPOLLFD) == 0);

    virtio_blk_queue_deinit(&queue);
}

int main(void) {
    test_virtio_blk();
    return 0;
}
