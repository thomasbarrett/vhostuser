#ifndef VIRTIO_BLK_H
#define VIRTIO_BLK_H

#include <virtio-core.h>
#include <bdev.h>

#include <sys/uio.h>
#include <stdatomic.h>

/**
 * A virtio-blk device queue.
 */
typedef struct virtio_blk_queue {
    device_queue_vtable_t vtable;
    bdev_queue_t *bdev_queue;
    task_t poll;

    metric_client_t *metrics_client;
    metric_counter_t read_bytes_count;
    metric_counter_t reads_completed_count;
    metric_counter_t written_bytes_count;
    metric_counter_t writes_completed_count;
} virtio_blk_queue_t;

/**
 * Create a new virtio_blk_queue_t from a bdev_queue. The bdev_queue is owned by
 * the bdev_t to which it belongs, so the virtio_blk_queue_t must not outlive the
 * bdev_t.
 * 
 * \param bdev_queue: the bdev_t queue.
 */
virtio_blk_queue_t* virtio_blk_queue_create(bdev_queue_t *bdev_queue, int i, metric_client_t *metric_client);

/**
 * Destroy the virtio_blk_queue_t and free all resources
 */
void virtio_blk_queue_destroy(virtio_blk_queue_t *queue);

/**
 * Poll the virtio_blk_queue_t and handle any events.
 * 
 * \param queue: the queue.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_poll(virtio_blk_queue_t *queue, int);

/**
 * Register the virtio_blk_queue_t with the specified epoll instance.
 * 
 * \param queue: the queue.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_epoll_register(struct device_queue *queue, int epollfd);

/**
 * Deregister the virtio_blk_queue_t with the specified epoll instance.
 * 
 * \param queue: the queue.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_epoll_deregister(struct device_queue *queue, int epollfd);

/**
 * Ansyncronously handle the iovec buffers as a virtio-blk request. When the device is finished
 * with the buffers, it will call `virtio_done` using the given `virtio_ctx` to release the buffer back to
 * the driver. The queue must be polled in order for the io to complete. This can be be done manually
 * using the `virtio_blk_queue_poll` method, or by registering an event with an epoll instance.
 * 
 * \param queue: the queue.
 * \param iov: a pointer to an array of iovec buffers.
 * \param iovcnt: the number of buffers pointed to by the iov parameter.
 * \param virtio_ctx: the virtio context used
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_handle(struct device_queue *queue, struct iovec *iov, size_t iovcnt, virtio_ctx_t *virtio_ctx);

#endif
