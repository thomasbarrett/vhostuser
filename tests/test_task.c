// CFLAGS: -Wl,--wrap=pipe -Wl,--wrap=read -Wl,--wrap=write -Wl,--wrap=close -Wl,--wrap=epoll_ctl
#include <src/task.c>
#include <src/log.c>

#include <assert.h>

#define MOCK_EPOLLFD 4
#define MOCK_PIPE_READ_FD 5
#define MOCK_PIPE_WRITE_FD 6

int test_task_called = 0;
int test_task(void *self, int epollfd) {
    assert(self == NULL);
    assert(epollfd == MOCK_EPOLLFD);
    test_task_called++;
    return 0;
}

int __wrap_pipe(int *pipedes) {
    pipedes[0] = MOCK_PIPE_READ_FD;
    pipedes[1] = MOCK_PIPE_WRITE_FD;
    return 0;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbytes) {
    assert(fd == MOCK_PIPE_READ_FD);
    assert(nbytes == sizeof(task_t));
    *((task_t*) buf) = (task_t) {
        .self = NULL,
        .call = test_task,
    };
    return sizeof(task_t);
}

ssize_t __wrap_write(int fd, void *buf, size_t nbytes) {
    assert(fd == MOCK_PIPE_WRITE_FD);
    assert(nbytes == sizeof(task_t));
    assert(((task_t*) buf)->self == NULL);
    assert(((task_t*) buf)->call == test_task);
    return sizeof(task_t);
}

int pipe_read_fd_closed = 0;
int pipe_write_fd_closed = 0;
int __wrap_close(int fd) {
    switch (fd) {
    case MOCK_PIPE_READ_FD:
        pipe_read_fd_closed = 1;
        break;
    case MOCK_PIPE_WRITE_FD:
        pipe_write_fd_closed = 1;
        break;
    default:
        assert(0);
    }
    return 0;
}

int __wrap_epoll_ctl(int epollfd, int op, int fd, struct epoll_event *event) {
    assert(epollfd == MOCK_EPOLLFD);
    assert(fd == MOCK_PIPE_READ_FD);
    return 0;
}

void test_task_queue(void) {
    task_queue_t queue;
    assert(task_queue_init(&queue) == 0);
    assert(task_queue_done(&queue) == 0);
    assert(queue.pipe[0] == MOCK_PIPE_READ_FD);
    assert(queue.pipe[1] == MOCK_PIPE_WRITE_FD);

    assert(task_queue_epoll_register(&queue, MOCK_EPOLLFD) == 0);

    assert(task_queue_push(&queue, NULL, test_task) == 0);
    assert(task_queue_poll(&queue, MOCK_EPOLLFD) == 0);
    assert(test_task_called);

    assert(task_queue_close(&queue) == 0);
    assert(task_queue_done(&queue) == 1);
    assert(queue.pipe[0] == MOCK_PIPE_READ_FD);
    assert(queue.pipe[1] == -1);

    assert(task_queue_epoll_deregister(&queue, MOCK_EPOLLFD) == 0);

    task_queue_deinit(&queue);
    assert(queue.pipe[0] == -1);
    assert(queue.pipe[1] == -1);
}

int main(void) {
    test_task_queue();
}
