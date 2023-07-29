#include <virtio-blk.h>
#include <virtio-core.h>
#include <log.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/epoll.h>
#include <linux/virtio_blk.h>


typedef struct virtio_blk_io_ctx {
    virtio_blk_queue_t *queue;
    uint16_t tag;
    uint8_t *res;
    uint32_t command;
    task_t done_task;
    size_t size;
    size_t sector;
} virtio_blk_io_ctx_t;

int virtio_blk_device_init(virtio_blk_device_t *dev, bdev_t bdev) {
    memset(dev, 0, sizeof(virtio_blk_device_t));
    
    uint64_t size_bytes;
    if (bdev_size(bdev, &size_bytes) < 0) {
        return -1;
    }

    dev->bdev = bdev;
    dev->queues = calloc(bdev_queue_count(bdev), sizeof(virtio_blk_queue_t));
    if (dev->queues == NULL) {
        goto error0;
    }
    for (size_t i = 0; i < bdev_queue_count(bdev); i++) {   
        if (virtio_blk_queue_init(&dev->queues[i], bdev_queue(bdev, i), dev, i) < 0) {
            goto error1;
        }
        dev->queue_count++;
    }

    dev->config.capacity = size_bytes >> 9;
    dev->config.num_queues = dev->queue_count;
    dev->config.size_max = 16384;
    dev->config.seg_max = 32;

    return 0;
error1:
    for (size_t i = 0; i < dev->queue_count; i++) {
        virtio_blk_queue_deinit(&dev->queues[i]);
    }
error0:
    return -1;
}

void virtio_blk_device_deinit(virtio_blk_device_t *dev) {
    for (size_t i = 0; i < dev->queue_count; i++) {
        virtio_blk_queue_deinit(&dev->queues[i]);
    }
    free(dev->queues);
}

ssize_t virtio_blk_device_config_read(virtio_blk_device_t *dev, void *buf, size_t count, off_t offset) {
    if (offset + count > sizeof(struct virtio_blk_config)) {
        return -EINVAL;
    }

    memcpy(buf, ((char *) &dev->config) + offset, count);
    return count;
}

int virtio_blk_device_queue_count(virtio_blk_device_t *dev) {
    return dev->queue_count;
}

uint64_t virtio_blk_device_get_features(virtio_blk_device_t *dev) {
    return  1ULL << VIRTIO_F_VERSION_1 |
            1ULL << VIRTIO_BLK_F_MQ |
            1ULL << VIRTIO_BLK_F_SIZE_MAX |
            1ULL << VIRTIO_BLK_F_SEG_MAX;
}

virtio_device_queue_t virtio_blk_device_queue(virtio_blk_device_t *dev, int i) {
    assert(dev->queue_count > i);
    return (virtio_device_queue_t) {
        .self= &dev->queues[i],
        .vtable = &virtio_blk_queue_vtable,
    };
}

int virtio_blk_device_metrics_register(virtio_blk_device_t *dev, metric_client_t *metric_client) {
    for (size_t i = 0; i < dev->queue_count; i++) {
        virtio_blk_queue_metrics_register(&dev->queues[i], metric_client);
    }

    return 0;
}

int virtio_blk_device_metrics_deregister(virtio_blk_device_t *dev, metric_client_t *metric_client) {
    for (size_t i = 0; i < dev->queue_count;  i++) {
        virtio_blk_queue_metrics_deregister(&dev->queues[i], metric_client);
    }

    return 0;
}

virtio_device_queue_vtable_t virtio_blk_queue_vtable = {
    .epoll_register = (int (*)(void *self, int epollfd)) virtio_blk_queue_epoll_register,
    .epoll_deregister = (int (*)(void *self, int epollfd))virtio_blk_queue_epoll_deregister,
    .handle = (int (*)(void *self, struct iovec *iov, size_t iovcnt, task_t task)) virtio_blk_queue_handle,
};

virtio_device_vtable_t virtio_blk_vtable = {
    .queue = (virtio_device_queue_t (*)(void*, int)) virtio_blk_device_queue,
    .queue_count = (int (*)(void*)) virtio_blk_device_queue_count,
    .get_features = (uint64_t (*)(void *)) virtio_blk_device_get_features,
    .config_read = (ssize_t (*)(void*, void*, size_t, off_t)) virtio_blk_device_config_read,
};

int virtio_blk_queue_init(virtio_blk_queue_t *queue, bdev_queue_t bdev_queue, virtio_blk_device_t *dev, int i) {
    memset(queue, 0, sizeof(virtio_blk_queue_t));
    queue->bdev_queue = bdev_queue;
    queue->poll = (task_t) {
        .self = (void*) queue,
        .call = (int (*)(void*, int))(virtio_blk_queue_poll),
    };
    queue->device = dev;
    
    int res = bitmap_init(&queue->tags, bdev_queue_nr_tags(bdev_queue));
    if (res < 0) {
        goto error0;
    }

    queue->io_ctx = calloc(bdev_queue_nr_tags(bdev_queue), sizeof(virtio_blk_io_ctx_t));
    if (queue->io_ctx == NULL) {
        goto error1;
    }

    metric_label_t label = {0};
    strcpy(label.key, "queue");
    snprintf(label.val, METRICS_MAX_LABEL_VAL_SIZE, "%d", i);
    metric_counter_init(&queue->read_bytes_count, "virtio_blk_read_bytes", &label, 1);
    metric_counter_init(&queue->reads_submitted_count, "virtio_blk_reads_submitted", &label, 1);
    metric_counter_init(&queue->reads_completed_count, "virtio_blk_reads_completed", &label, 1);
    metric_counter_init(&queue->written_bytes_count, "virtio_blk_written_bytes", &label, 1);
    metric_counter_init(&queue->writes_submitted_count, "virtio_blk_writes_submitted", &label, 1);
    metric_counter_init(&queue->writes_completed_count, "virtio_blk_writes_completed", &label, 1);

    return 0;

error1:
    bitmap_deinit(&queue->tags);
error0:
    return -1;
}

void virtio_blk_queue_deinit(virtio_blk_queue_t *queue) {
    free(queue->io_ctx);
    bitmap_deinit(&queue->tags);
}


void virtio_blk_io_cb(void *ctx, ssize_t res) {
    virtio_blk_io_ctx_t *io_ctx = (virtio_blk_io_ctx_t*) ctx;
    if (res == io_ctx->size) {
        *(io_ctx->res) = VIRTIO_BLK_S_OK;
        switch (io_ctx->command) {
        case VIRTIO_BLK_T_IN:
            metric_counter_inc(&io_ctx->queue->reads_completed_count, 1);
            metric_counter_inc(&io_ctx->queue->read_bytes_count, io_ctx->size);
            break;
        case VIRTIO_BLK_T_OUT:
            metric_counter_inc(&io_ctx->queue->writes_completed_count, 1);
            metric_counter_inc(&io_ctx->queue->written_bytes_count, io_ctx->size);
            break;
        }
    } else {
        *(io_ctx->res) = VIRTIO_BLK_S_IOERR;
    }
    io_ctx->done_task.call(io_ctx->done_task.self, -1);
    bitmap_remove(&io_ctx->queue->tags, io_ctx->tag);
}

static size_t get_iov_len(struct iovec *iov, size_t iov_len) {
    size_t res = 0;
    for (size_t i = 0; i < iov_len; i++) {
        res += iov[i].iov_len;
    }

    return res;
}

void virtio_blk_handle_req(virtio_blk_queue_t *queue, struct virtio_blk_outhdr *hdr, struct iovec *iov, size_t iovcnt, uint8_t *res, task_t done_task) {
    bdev_queue_t bdev_queue = queue->bdev_queue;
    switch (hdr->type) {
    case VIRTIO_BLK_T_IN:
        {
            if (iovcnt == 1 && !bdev_queue.vtable->read) break;
            if (iovcnt > 1 && !bdev_queue.vtable->readv) break;
            int32_t tag = bitmap_find(&queue->tags, 0, 0);
            if (tag < 0) {
                error("Failed to find free tag");
                goto error;
            }
            bitmap_add(&queue->tags, tag);

            virtio_blk_io_ctx_t *io_ctx = &queue->io_ctx[tag];
            io_ctx->tag = tag;
            io_ctx->queue = queue;
            io_ctx->res = res;
            io_ctx->command = hdr->type;
            io_ctx->done_task = done_task;
            io_ctx->size = get_iov_len(iov, iovcnt);
            io_ctx->sector = hdr->sector;
            metric_counter_inc(&io_ctx->queue->reads_submitted_count, 1);
            if (iovcnt == 1) {
                bdev_queue_read(bdev_queue, tag, iov[0].iov_base, iov[0].iov_len, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            } else {
                bdev_queue_readv(bdev_queue, tag, iov, iovcnt, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_OUT:
        {
            if (iovcnt == 1 && !bdev_queue.vtable->write) break;
            if (iovcnt > 1 && !bdev_queue.vtable->writev) break;
            int32_t tag = bitmap_find(&queue->tags, 0, 0);
            if (tag < 0) {
                error("Failed to find free tag");
                goto error;
            }
            bitmap_add(&queue->tags, tag);

            virtio_blk_io_ctx_t *io_ctx = &queue->io_ctx[tag];
            io_ctx->tag = tag;
            io_ctx->queue = queue;
            io_ctx->res = res;
            io_ctx->command = hdr->type;
            io_ctx->done_task = done_task;
            io_ctx->size = get_iov_len(iov, iovcnt);
            io_ctx->sector = hdr->sector;
            metric_counter_inc(&io_ctx->queue->writes_submitted_count, 1);
            if (iovcnt == 1) {
                bdev_queue_write(bdev_queue, tag, iov[0].iov_base, iov[0].iov_len, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            } else {
                bdev_queue_writev(bdev_queue, tag, iov, iovcnt, hdr->sector << 9, virtio_blk_io_cb, io_ctx);
            }
            return;
        }
    case VIRTIO_BLK_T_FLUSH:
        {
            if (!bdev_queue.vtable->flush) break;
            int32_t tag = bitmap_find(&queue->tags, 0, 0);
            if (tag < 0) {
                error("Failed to find free tag");
                goto error;
            }
            bitmap_add(&queue->tags, tag);
            
            virtio_blk_io_ctx_t *io_ctx = &queue->io_ctx[tag];
            io_ctx->tag = tag;
            io_ctx->queue = queue;
            io_ctx->res = res;
            io_ctx->command = hdr->type;
            io_ctx->done_task = done_task;
            io_ctx->size = 0;
            io_ctx->sector = hdr->sector;
            bdev_queue_flush(bdev_queue, tag, virtio_blk_io_cb, io_ctx);
            return;
        }
    case VIRTIO_BLK_T_GET_ID:
        memcpy(iov[1].iov_base, "hello", strlen("hello"));
        *res = VIRTIO_BLK_S_OK;
        done_task.call(done_task.self, -1);
        return;       
    }

    error("Received unsupported virtio_blk io type: %d", hdr->type);
    *res = VIRTIO_BLK_S_UNSUPP;
    done_task.call(done_task.self, -1);

    return;
error:
    *res = VIRTIO_BLK_S_IOERR;
    done_task.call(done_task.self, -1);
}

void virtio_blk_outhdr_debug(struct virtio_blk_outhdr *hdr) {
    printf("struct virtio_blk_outhdr { "
        "type: %u, "
        "ioprio: %u, "
        "sector: %llx, "
        "}\n",
        hdr->type,
        hdr->ioprio,
        hdr->sector
    );
}

int virtio_blk_queue_poll(virtio_blk_queue_t *queue, int _) {
    if (bdev_queue_poll(queue->bdev_queue) < 0) {
        error("Failed to poll bdev queue", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_epoll_register(virtio_blk_queue_t *queue, int epollfd) {
    struct epoll_event event = {0};
    int fd = bdev_queue_eventfd(queue->bdev_queue);
    event.events = EPOLLIN;
    event.data.ptr = &queue->poll;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
        error("Failed to add fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_epoll_deregister(virtio_blk_queue_t*queue, int epollfd) {
    int fd = bdev_queue_eventfd(queue->bdev_queue);
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        error("Failed to remove fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int virtio_blk_queue_handle(virtio_blk_queue_t *queue, struct iovec *iov, size_t iovcnt, task_t task) {
    /* All virtio-blk requests must include at least a header and a status byte. */
    if (iovcnt < 2) {
        error("Received virtio-blk message with unsupported framing: iovcnt=%d", iovcnt);
        return -1;
    }
    /* Check that the first segment is the correct length to be a header. */
    if (iov[0].iov_len != sizeof(struct virtio_blk_outhdr)) {
        error("Received virtio-blk message with unsupported framing: iov[0].iov_len=%d", iov[0].iov_len);
        return -1;
    }
    /* Check that the last segment is the correct length to be a status byte. */
    if (iov[iovcnt - 1].iov_len != 1) {
        error("Received virtio-blk message with unsupported framing: iov[iovcnt - 1].iov_len=%d", iov[iovcnt - 1].iov_len);
        return -1;
    }

    struct iovec *data_iov = NULL;
    size_t data_iovcnt = iovcnt - 2;
    if (data_iovcnt > 0) {
        data_iov = &iov[1];
    }

    struct virtio_blk_outhdr* hdr = (struct virtio_blk_outhdr*) iov[0].iov_base;
    virtio_blk_handle_req(queue, hdr, data_iov, data_iovcnt, (uint8_t*) iov[iovcnt - 1].iov_base, task); 
    
    return 0;   
}

int virtio_blk_queue_metrics_register(virtio_blk_queue_t *queue, metric_client_t *metric_client) {
    metric_t *metrics[] = {
        &queue->read_bytes_count.metric,
        &queue->reads_submitted_count.metric,
        &queue->reads_completed_count.metric,
        &queue->written_bytes_count.metric,
        &queue->writes_submitted_count.metric,
        &queue->writes_completed_count.metric
    };

    for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++) {
        metric_client_register(metric_client, metrics[i]);
    }

    return 0;
}

int virtio_blk_queue_metrics_deregister(virtio_blk_queue_t *queue, metric_client_t *metric_client) {
     metric_t *metrics[] = {
        &queue->read_bytes_count.metric,
        &queue->reads_submitted_count.metric,
        &queue->reads_completed_count.metric,
        &queue->written_bytes_count.metric,
        &queue->writes_submitted_count.metric,
        &queue->writes_completed_count.metric
    };

    for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++) {
        metric_client_deregister(metric_client, metrics[i]);
    }

    return 0;
}
