#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

typedef struct task_t {
    void *self;
    int (*call)(void *self, int epollfd);
} task_t;

typedef struct task_queue {
    int pipe[2];
    task_t read_pipe;
} task_queue_t;

/**
 * Initialize the task_queue_t.
 * 
 * \param queue: the task_queue_t.
 * \return 0 on success and -1 on error. 
 */
int task_queue_init(task_queue_t *queue);

/**
 * Deinitialize the task_queue_t.
 * 
 * \param queue: the task_queue_t.
 * \return 0 on success and -1 on error. 
 */
void task_queue_deinit(task_queue_t *queue);

/**
 * Close the task_queue_t. This indicates that no more events will be sent to the queue.
 * After this method is called, task_queue_done will return 1.
 * 
 * \param queue: the task_queue_t.
 * \return 0 on success and -1 on error. 
 */
int task_queue_close(task_queue_t *queue);

/**
 * Return 1 if the task_queue_t is closed and 0 otherwise.
 * 
 * \param queue: the task_queue_t.
 * \return 1 if the task_queue_t is closed and 0 otherwise.
 */
int task_queue_done(task_queue_t *queue);

/**
 * Register the task_queue_t with the specified epoll instance.
 * 
 * \param queue: the task_queue_t.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int task_queue_epoll_register(task_queue_t *queue, int epollfd);

/**
 * Deregister the task_queue_t with the specified epoll instance.
 * 
 * \param queue: the task_queue_t.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int task_queue_epoll_deregister(task_queue_t *queue, int epollfd);

/**
 * 
 */
int task_queue_poll(task_queue_t *queue, int epollfd);

/**
 * Push a task onto the task_queue_t.
 * 
 * \param queue: the task_queue_t.
 * \param self: the argument to be passed to the task function. 
 * \param task: the task function.
 */
int task_queue_push(task_queue_t *queue, void *self, int (*task)(void*,int));

#endif
