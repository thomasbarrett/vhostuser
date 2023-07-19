#define _GNU_SOURCE
#include <task_queue.h>
#include <log.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>

int task_queue_init(task_queue_t *queue) {
    memset(queue, 0, sizeof(task_queue_t));
    if (pipe(queue->pipe) < 0) {
        return -1;
    }
    
    queue->read_pipe = (task_t) {
        .self = (void*) queue,
        .call = (int (*)(void*, int)) task_queue_poll,
    };

    return 0;
}

int task_queue_push(task_queue_t *queue, void *self, int (*call)(void*,int)) {
    task_t event = (task_t) {
        .self = self,
        .call = call,
    };
    if (write(queue->pipe[1], &event, sizeof(event)) < sizeof(event)) {
        return -1;
    }

    return 0;
}

int task_queue_close(task_queue_t *queue) {
    if (close(queue->pipe[1]) < 0) {
        return -1;
    }

    return 0;
}

int task_queue_poll(task_queue_t *queue, int epollfd) {
    if (queue->done) return 0;

    task_t event;
    int res = read(queue->pipe[0], &event, sizeof(event));
    if (res < 0) {
        if (errno == EAGAIN) {
            return 0;
        }

        error("Failed to read from task queue: %s", strerror(errno));
        return -1;
    }
    if (res == 0) {
        close(queue->pipe[0]);
        queue->done = 1;
        return 0;
    }
    if (res < sizeof(event)) {
        error("Failed to read full task_t from task queue");
        return -1;
    }

    event.call(event.self, epollfd);

    return 0;
}

int task_queue_epoll_register(task_queue_t *queue, int epollfd) {
    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.ptr = &queue->read_pipe;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, queue->pipe[0], &event) < 0) {
        error("Failed to add fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    return 0;
}
