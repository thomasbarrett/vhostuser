#ifndef VIRTIO_BLK_H
#define VIRTIO_BLK_H

#include <virtio-core.h>
#include <linux/virtio_blk.h>
#include <bdev.h>

#include <sys/uio.h>
#include <stdatomic.h>

struct virtio_blk_device;

typedef struct virtio_blk_queue {
    bdev_queue_t bdev_queue;
    task_t poll;

    struct virtio_blk_device *device;

    /* metrics */
    metric_counter_t read_bytes_count;        /* number of bytes read */
    metric_counter_t reads_completed_count;   /* number of read ios completed */  
    metric_counter_t written_bytes_count;     /* number of bytes written */
    metric_counter_t writes_completed_count;  /* number of write ios completed */
} virtio_blk_queue_t;

extern virtio_device_queue_vtable_t virtio_blk_queue_vtable;

typedef struct virtio_blk_device {
    struct virtio_blk_config config;
    bdev_t bdev;

    virtio_blk_queue_t *queues;
    size_t queue_count;
} virtio_blk_device_t;

extern virtio_device_vtable_t virtio_blk_vtable;

/**
 * Initialize the virtio_blk_device_t with the given bdev_t.
 * 
 * \param dev: the virtio_blk_device_t.
 * \param bdev: the bdev_t. 
 * \return 0 on success and -1 on error.
 */
int virtio_blk_device_init(virtio_blk_device_t *dev, bdev_t bdev);

/**
 * Deinitialize the virtio_blk_device_t virtio_blk_device_t.
 * 
  * \param dev: the virtio_blk_device_t.
 */
void virtio_blk_device_deinit(virtio_blk_device_t *dev);

/**
 * Return the queue count of the virtio_blk_device_t.
 * 
 * \param dev: the virtio_blk_device_t.
 * \return the queue count.
 */
int virtio_blk_device_queue_count(virtio_blk_device_t *dev);

/**
 * Return the ith virtio_device_queue_t. Note that `i` must be in the
 * range 0 <= i < virtio_blk_device_queue_count(dev).
 * 
 * \param dev: the virtio_blk_device_t.
 * \param i: the queue index.
 */
virtio_device_queue_t virtio_blk_device_queue(virtio_blk_device_t *dev, int i);

/**
 * Read `count` bytes from the virtio_blk_device_t config space at the
 * given `offset` into `buf`.
 * 
 * \param dev: the virtio_blk_device_t.
 * \param buf: the destination buffer.
 * \param count: the number of bytes to read.
 * \param offset: the offset into the config space.
 * \return the number of bytes read on success or -EINVAL on error.
 */
ssize_t virtio_blk_device_config_read(virtio_blk_device_t *dev, void *buf, size_t count, off_t offset);

/**
 * Register all virtio_blk_device_t metrics with the specified metric_client_t. This includes
 * virtio_blk_queue_t metrics for all device queues.
 * 
 * \param dev: the device.
 * \param metric_client: the client.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_device_metrics_register(virtio_blk_device_t *dev, metric_client_t *metric_client);

/**
 * Deregister all virtio_blk_device_t metrics with the specified metric_client_t. This includes
 * virtio_blk_queue_t metrics for all device queues.
 * 
 * \param dev: the device.
 * \param metric_client: the client.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_device_metrics_deregister(virtio_blk_device_t *dev, metric_client_t *metric_client);

/**
 * Create a new virtio_blk_queue_t from a bdev_queue. The bdev_queue is owned by
 * the bdev_t to which it belongs, so the virtio_blk_queue_t must not outlive the
 * bdev_t.
 * 
 * \param bdev_queue: the bdev_t queue.
 */
int virtio_blk_queue_init(virtio_blk_queue_t* queue, bdev_queue_t bdev_queue, virtio_blk_device_t *dev, int i);

/**
 * Destroy the virtio_blk_queue_t and free all resources
 */
void virtio_blk_queue_deinit(virtio_blk_queue_t *queue);

/**
 * Ansyncronously handle the buffers specified in `iov` as a virtio-blk request. When the device is finished
 * handling the request, it will run the `done` task. The queue must be polled in order for the io
 * to complete. This can be be done manually using the `virtio_blk_queue_poll` method, or by
 * registering an event with an epoll instance.
 * 
 * \param queue: the queue.
 * \param iov: an array of struct iovec.
 * \param iovcnt: the size of iov array.
 * \param task_t: the task to run on completion.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_handle(virtio_blk_queue_t *queue, struct iovec *iov, size_t iovcnt, task_t done);

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
int virtio_blk_queue_epoll_register(virtio_blk_queue_t *queue, int epollfd);

/**
 * Deregister the virtio_blk_queue_t with the specified epoll instance.
 * 
 * \param queue: the queue.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_epoll_deregister(virtio_blk_queue_t *queue, int epollfd);

/**
 * Register all virtio_blk_queue_t metrics with the specified metric_client_t.
 * 
 * \param queue: the queue.
 * \param metric_client: the client.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_metrics_register(virtio_blk_queue_t *queue, metric_client_t *metric_client);

/**
 * Deregister all virtio_blk_queue_t metrics with the specified metric_client_t.
 * 
 * \param queue: the queue.
 * \param metric_client: the client.
 * \return 0 on success and -1 on error.
 */
int virtio_blk_queue_metrics_deregister(virtio_blk_queue_t *queue, metric_client_t *metric_client);

#endif
