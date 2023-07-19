#define _GNU_SOURCE
#include <virtio-core.h>
#include <task_queue.h>
#include <bdev.h>
#include <guest_memory.h>

#include <stdatomic.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <assert.h>
#include <log.h>
#include <errno.h>

static void vring_used_push(struct vring vring, desc_state_t *desc, __virtio32 id, __virtio32 len) {
   vring.used->ring[vring.used->idx % vring.num] = (vring_used_elem_t) {
        .id = id,
        .len = 0,
    };
    atomic_thread_fence(memory_order_release);
    desc->inflight = 0;
    vring.used->idx++;
}

int virtio_done(virtio_ctx_t *ctx) {
    vring_used_push(ctx->vring, ctx->desc, ctx->id, ctx->len);
    if (write(ctx->eventfd, &(uint64_t){1}, sizeof(uint64_t)) < 0) {
        printf("ERROR: failed to write to eventfd\n");
    }
    free(ctx);
    return 0;
}

void vring_desc_debug(vring_desc_t *desc) {
    debug("vring_desc_t { addr: %llu, len: 0x%u, flags: %u, next: %d }\n", desc->addr, desc->len, desc->flags, desc->next);
}

int virt_queue_read_desc_direct(guest_memory_t *mem, vring_desc_t *desc, struct iovec *iov, size_t i, size_t n) {
    if (i >= n) return -1;
    iov[i].iov_len = desc->len;
    if (guest_memory_guest_to_addr(mem, desc->addr, (void**) &iov[i].iov_base) < 0) {
        info("virt_queue_read_desc_direct: i: %d, n: %d", i, n);
        vring_desc_debug(desc);
        error("failed to translate address: %p", desc->addr);
        return -1;
    }

    return 1;
}

int virt_queue_read_desc_indirect(guest_memory_t *mem, vring_desc_t *desc, struct iovec *iov, size_t i, size_t n) {
    size_t iter = i;

    vring_desc_t *indirect_desc_table;
    if (guest_memory_guest_to_addr(mem, desc->addr, (void **) &indirect_desc_table) < 0) {
        error("Failed to translate address: %p", desc->addr);
        return -1;
    }

    for (size_t j = 0; j < desc->len / sizeof(vring_desc_t); j++) {
        int res = virt_queue_read_desc_direct(mem, &indirect_desc_table[j], iov, iter, n);
        if (res < 0) return -1;
        iter += res;
    }
    
    return iter - i;
}

int virt_queue_read_desc(guest_memory_t *mem, vring_desc_t *desc, struct iovec *iov, size_t i, size_t n) {
    if (desc->flags & VRING_DESC_F_INDIRECT) {
        return virt_queue_read_desc_indirect(mem, desc, iov, i, n);
    } else {
        return virt_queue_read_desc_direct(mem, desc, iov, i, n);
    }
}

int virt_queue_handle(virt_queue_t *queue, __virtio16 id) {
    struct iovec iov[130];
    size_t len = 0;
    uint32_t i = id;        
    while (queue->vring.desc[i].flags & VRING_DESC_F_NEXT) {
        int res = virt_queue_read_desc(queue->guest_memory, &queue->vring.desc[i], iov, len, 130);
        if (res < 0) {
            error("failed to read desc");
            return -1;
        }
        len += 1;

        i = queue->vring.desc[i].next;
        if (i >= queue->vring.num) {
            error("invalid next buffer id");
            return -1;
        }
    }
    int res = virt_queue_read_desc(queue->guest_memory, &queue->vring.desc[i], iov, len, 130);
    if (res < 0) {
        error("failed to read desc");
        return -1;
    }
    len += 1;

    virtio_ctx_t *virtio_ctx = calloc(1, sizeof(virtio_ctx_t));
    virtio_ctx->vring = queue->vring;
    virtio_ctx->desc = &queue->inflight_state->desc[id];
    virtio_ctx->id = id;
    virtio_ctx->len = 0;
    virtio_ctx->eventfd = queue->call_eventfd;

    // The back-end must process the ring without causing any side effects.
    if (queue->state == QUEUE_STATE_ENABLED || queue->state == QUEUE_STATE_DISABLED) {
        if (device_queue_handle(queue->impl, iov, len, virtio_ctx) < 0) {
            error("received invalid buffer from driver");
            virtio_done(virtio_ctx);
        }
    } else {
        warn("recieved buffers from driver while device stopped");
        virtio_done(virtio_ctx);
    }
    
    return 0;
}

int virt_queue_has_avail(virt_queue_t *queue) {
    return queue->vring.avail->idx != queue->inflight_state->last_avail_idx;
}

int virt_queue_pop(virt_queue_t *queue, __virtio16 *id) {
    if (virt_queue_has_avail(queue)) {
        atomic_thread_fence(memory_order_acquire);
        *id = queue->vring.avail->ring[queue->inflight_state->last_avail_idx++ % queue->vring.num];
        queue->inflight_state->desc[*id].inflight = 1;
        assert(*id < queue->vring.num);
        return 1;
    }

    return 0;
}

int virt_queue_epoll_register(virt_queue_t *queue, int epollfd) {
    struct epoll_event event = {0};
    int fd = queue->kick_eventfd;
    event.events = EPOLLIN;
    event.data.ptr = &queue->epoll_ctx;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) < 0) {
        error("Failed to add fd to epoll interface: %s", strerror(errno));
        return -1;
    }

    if (device_queue_epoll_register(queue->impl, epollfd) < 0) {
        error("Failed to register device queue with epoll interface");
        return -1;
    }

    return 0;
}

int virt_queue_epoll_deregister(virt_queue_t *queue, int epollfd) {
    int fd = queue->kick_eventfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        error("Failed to remove fd from epoll interface: %s", strerror(errno));
        return -1;
    }

    if (device_queue_epoll_deregister(queue->impl, epollfd) < 0) {
        error("Failed to deregister device queue from epoll interface");
        return -1;
    }

    return 0;
}

int virt_queue_poll(virt_queue_t *queue, int _) {
    uint64_t count;
    int res = read(queue->kick_eventfd, &count, sizeof(count));
    if (res < 0) {
        if (res == EAGAIN) {
            return 0;
        }

        error("Failed to read kick eventfd: %s", strerror(errno));
        return -1;
    }

    metric_counter_inc(&queue->kick_count);

    // The back-end must start ring upon receiving a kick.
    if (queue->state == QUEUE_STATE_STOPPED) {
        queue->state = QUEUE_STATE_DISABLED;
        return 0;
    }

    __virtio16 id;
    while(virt_queue_pop(queue, &id)) {
        if (virt_queue_handle(queue, id) < 0) {
            error("Failed to handle buffer: queue=%d, id=%d", queue->index, id);
            return -1;
        }
    }

    return 0;
}

void virt_queue_init(virt_queue_t *queue, metric_client_t *metric_client, guest_memory_t *guest_memory, device_queue_t *impl, int i) {
    queue->index = i;
    queue->guest_memory = guest_memory;
    queue->impl = impl;

    queue->state = QUEUE_STATE_DISABLED;

    queue->err_eventfd = -1;
    queue->call_eventfd = -1;
    queue->kick_eventfd = -1;

    queue->epoll_ctx = (task_t) {
        .self = (void*) queue,
        .call = (int (*)(void*, int))(virt_queue_poll),
    };

    queue->metric_client = metric_client;
    metric_label_t label = {0};
    strcpy(label.key, "queue");
    snprintf(label.val, METRICS_MAX_LABEL_VAL_SIZE, "%d", i);
    metric_counter_init(&queue->kick_count, "vhost_user_queue_kick", &label, 1);
    metric_client_register(queue->metric_client, &queue->kick_count.metric);
}

void virt_queue_deinit(virt_queue_t *queue) {
    metric_client_unregister(queue->metric_client, &queue->kick_count.metric);
    metric_counter_deinit(&queue->kick_count);
}
