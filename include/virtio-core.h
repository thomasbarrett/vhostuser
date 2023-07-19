#ifndef VIRTIO_CORE_H
#define VIRTIO_CORE_H

#include <linux/virtio_ring.h>
#include <task_queue.h>
#include <guest_memory.h>
#include <bdev.h>
#include <metrics.h>

const char* virtio_status_str(uint8_t status);

typedef struct desc_state {
    uint8_t inflight;
} desc_state_t;

typedef struct queue_state {
    __virtio16 last_avail_idx;
    desc_state_t desc[];
} queue_state_t;

typedef struct virtio_ctx {
    struct vring vring;
    desc_state_t *desc;
    __virtio32 id;
    __virtio32 len;
    int eventfd;
} virtio_ctx_t;

int virtio_done(virtio_ctx_t *ctx);

struct device_queue;

typedef struct device_queue_vtable {
    int (*epoll_register)(struct device_queue *queue, int epollfd);
    int (*epoll_deregister)(struct device_queue *queue, int epollfd);
    int (*handle)(struct device_queue *queue, struct iovec *iov, size_t iov_len, virtio_ctx_t *virtio_ctx);
} device_queue_vtable_t;

#define device_queue_epoll_register(queue, ...) (queue->vtable.epoll_register(queue, __VA_ARGS__))
#define device_queue_epoll_deregister(queue, ...) (queue->vtable.epoll_deregister(queue, __VA_ARGS__))
#define device_queue_handle(queue, ...) (queue->vtable.handle(queue, __VA_ARGS__))

typedef struct device_queue {
    device_queue_vtable_t vtable;
} device_queue_t;

#define QUEUE_STATE_STOPPED    -1
#define QUEUE_STATE_DISABLED   0
#define QUEUE_STATE_ENABLED    1

typedef struct virt_queue {
    int index;
    int state;
    volatile int done;

    int err_eventfd;
    int call_eventfd;
    int kick_eventfd;

    uint32_t flags;
    struct vring vring;

    task_t epoll_ctx;

    queue_state_t *inflight_state;

    guest_memory_t *guest_memory;
    
    device_queue_t *impl;
    
    metric_client_t *metric_client;
    metric_counter_t kick_count;
} virt_queue_t;

/**
 * Initialize the virt_queue_t.
 * 
 * \param queue: the queue.
 * \param guest_memory: the guest memory.
 * \param impl: the device queue.
 * \param i: the queue index.
 */
void virt_queue_init(virt_queue_t *queue, metric_client_t *metric_client, guest_memory_t *guest_memory, device_queue_t *impl, int i);

/**
 * Deinitialize the virt_queue_t.
 * 
 * \param queue: the queue.
 */
void virt_queue_deinit(virt_queue_t *queue);

/**
 * Poll the virt_queue_t and handle any events.
 * 
 * \param queue: the queue.
 * \return 0 on success and -1 on error.
 */
int virt_queue_poll(virt_queue_t *queue, int _);

/**
 * Register the virt_queue_t with the specified epoll instance.
 * 
 * \param queue: the queue.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int virt_queue_epoll_register(virt_queue_t *queue, int epollfd);

/**
 * Deregister the virt_queue_t with the specified epoll instance.
 * 
 * \param queue: the queue.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int virt_queue_epoll_deregister(virt_queue_t *queue, int epollfd);

/**
 * Handle the buffer with the given descriptor id.
 * 
 * \param queue: the queue.
 * \param id: the buffer descriptor id.
 * \return 0 on success and -1 on error.
 */
int virt_queue_handle(virt_queue_t *queue, __virtio16 id);

#endif
