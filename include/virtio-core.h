#ifndef VIRTIO_CORE_H
#define VIRTIO_CORE_H

#include <linux/virtio_ring.h>
#include <task.h>
#include <guest.h>
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

struct device_queue;

typedef struct virtio_device_queue_vtable {
    int (*epoll_register)(void *self, int epollfd);
    int (*epoll_deregister)(void *self, int epollfd);
    int (*handle)(void *self, struct iovec *iov, size_t iov_len, task_t task);
} virtio_device_queue_vtable_t;

typedef struct virtio_device_queue {
    void *self;
    virtio_device_queue_vtable_t *vtable;
} virtio_device_queue_t;

#define virtio_device_queue_epoll_register(device_queue, ...) (device_queue.vtable->epoll_register(device_queue.self, __VA_ARGS__))
#define virtio_device_queue_epoll_deregister(device_queue, ...) (device_queue.vtable->epoll_deregister(device_queue.self, __VA_ARGS__))
#define virtio_device_queue_handle(device_queue, ...) (device_queue.vtable->handle(device_queue.self, __VA_ARGS__))

typedef struct virtio_device_vtable {
    int (*queue_count)(void *self);
    virtio_device_queue_t (*queue)(void *self, int i);
    ssize_t (*config_read)(void *self, void *buf, size_t count, off_t offset);
    uint64_t (*get_features)(void *self);
} virtio_device_vtable_t;

typedef struct virtio_device {
    void *self;
    virtio_device_vtable_t *vtable;
} virtio_device_t;

#define virtio_device_queue(device, ...) (device.vtable->queue(device.self, __VA_ARGS__))
#define virtio_device_get_features(device) (device.vtable->get_features(device.self))
#define virtio_device_queue_count(device) (device.vtable->queue_count(device.self))
#define virtio_device_config_read(device, ...) (device.vtable->config_read(device.self, __VA_ARGS__))

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
    
    virtio_device_queue_t device_queue;
    
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
int virt_queue_init(virt_queue_t *queue, metric_client_t *metric_client, guest_memory_t *guest_memory, virtio_device_queue_t device_queue, int i);

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
