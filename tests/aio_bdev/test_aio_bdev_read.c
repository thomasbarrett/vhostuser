// CFLAGS: -Wl,--wrap=open -Wl,--wrap=close -Wl,--wrap=eventfd -Wl,--wrap=read
#include <src/bdev.c>
#include <src/queue.c>
#include <src/log.c>

#include <assert.h>

#define MOCK_BLKDEV_FD 4
#define MOCK_EVENT_FD 5

int __wrap_open(const char *path, int oflag, ...) {
    assert(strcmp(path, "/dev/hda") == 0);
    assert(oflag | O_DIRECT);
    assert(oflag | O_RDWR);

    return MOCK_BLKDEV_FD;
}

int blkdev_fd_closed = 0;
int event_fd_closed = 0;
int __wrap_close(int fd) {
    switch (fd) {
    case MOCK_BLKDEV_FD:
        blkdev_fd_closed = 1;
        break;
    case MOCK_EVENT_FD:
        event_fd_closed = 1;
        break;
    default:
        assert(0);
    }
    return 0;
}

int __wrap_eventfd(unsigned int count, int flags) {
    assert(count == 0);
    assert(flags | EFD_NONBLOCK);
    return MOCK_EVENT_FD;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbytes) {
    assert(fd == MOCK_EVENT_FD);
    assert(nbytes == sizeof(uint64_t));
    *((uint64_t*) buf) = 1;
    return sizeof(uint64_t);
}

struct iocb *iocb;
int io_submit(io_context_t ctx, long nr, struct iocb *ios[]) {
    assert(nr == 1);
    assert(iocb == NULL);
    iocb = ios[0];
    assert(iocb->aio_fildes == MOCK_BLKDEV_FD);
    assert(iocb->aio_lio_opcode == IO_CMD_PREAD);
    assert(iocb->aio_reqprio == 0);
    write(iocb->u.c.resfd, &(uint64_t){1}, sizeof(uint64_t));
    return 0;
}

int io_setup(int maxevents, io_context_t *ctxp) {
    return 0;
}

int io_getevents(io_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout) {
    assert(min_nr == 1);
    assert(nr == 256);
    events[0] = (struct io_event){
        .data = iocb->data,
        .obj = iocb,
        .res = 4096,
        .res2 = 0,
    };

    return 1;
}

int io_destroy_called = 0;
int io_destroy(io_context_t ctx) {
    io_destroy_called++;
    return 0;
}

int read_cb_called = 0;
void read_cb(void *ctx, ssize_t res) {
    assert(res == 4096);  
    read_cb_called++;  
}

int main(void) {
    aio_bdev_t aio_bdev = {0};
    assert(aio_bdev_init(&aio_bdev, "/dev/hda", 1, 256) == 0);
    bdev_t bdev = {
        .self = &aio_bdev,
        .vtable = &aio_bdev_vtable,
    };

    assert(bdev.self != NULL);
    bdev_queue_t queue = bdev_get_queue(bdev, 0);
    assert(queue.self != NULL);

    char buf[4096] = {0};
    bdev_queue_read(queue, buf, 4096, 8192, read_cb, NULL);
    assert(bdev_queue_poll(queue) == 0);
    assert(read_cb_called);

    aio_bdev_deinit(&aio_bdev);
    assert(io_destroy_called);
    assert(blkdev_fd_closed);
    assert(event_fd_closed);

    return 0;
}
