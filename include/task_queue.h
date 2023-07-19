#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

typedef struct task_t {
    void *self;
    int (*call)(void *self, int epollfd);
} task_t;

typedef struct task_queue {
    int pipe[2];
    int done;
    task_t read_pipe;
} task_queue_t;

int task_queue_init(task_queue_t *queue);
int task_queue_epoll_register(task_queue_t *queue, int epollfd);
int task_queue_poll(task_queue_t *queue, int epollfd);
int task_queue_close(task_queue_t *queue);
int task_queue_push(task_queue_t *queue, void *self, int (*task)(void*,int));

#endif
