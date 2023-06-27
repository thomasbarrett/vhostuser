#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>

#include <vhost-user.h>
#include <guest_memory.h>
#include <bdev.h>
#include <virtio-core.h>
#include <virtio-blk.h>
#include <log.h>

#include <sys/epoll.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/vhost.h>
#include <linux/virtio_blk.h>

#define SERVER_SOCK_FILE "/tmp/vhost-blk.sock"

#define DEVICE_QUEUE_COUNT 4

#define QUEUE_STATE_STOPPED    -1
#define QUEUE_STATE_DISABLED   0
#define QUEUE_STATE_ENABLED    1

guest_memory_t guest_memory;

typedef struct virt_queue {
    int index;
    int state;
    volatile int done;
    pthread_t thread_id;

    io_queue_t *io_queue;

    int err_eventfd;
    int call_eventfd;
    int kick_eventfd;
    uint32_t base_offset;

    uint32_t flags;
    struct vring vring;
    uint32_t last_avail_idx;
} virt_queue_t;

int virt_queue_read_desc_direct(guest_memory_t *mem, vring_desc_t *desc, struct iovec *iov, size_t i, size_t n) {
    if (i >= n) return -1;
    iov[i].iov_len = desc->len;
    if (guest_memory_guest_to_addr(mem, desc->addr, (void**) &iov[i].iov_base) < 0) {
        return -1;
    }

    return 1;
}

int virt_queue_read_desc_indirect(guest_memory_t *mem, vring_desc_t *desc, struct iovec *iov, size_t i, size_t n) {
    size_t iter = i;

    vring_desc_t *indirect_desc_table;
    if (guest_memory_guest_to_addr(mem, desc->addr, (void **) &indirect_desc_table) < 0) {
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

int virt_queue_poll(virt_queue_t *queue) {
    // The back-end must start ring upon receiving a kick.
    if (queue->state == QUEUE_STATE_STOPPED) {
        queue->state = QUEUE_STATE_DISABLED;
        return 0;
    }

    // The back-end must process the ring without causing any side effects.
    // TODO: process and discard buffers.
    if (queue->state == QUEUE_STATE_DISABLED) {
        printf("WARN: received kick for disabled virt-queue: %d\n", queue->index);
        return 0;
    }

    while(queue->vring.avail->idx != queue->last_avail_idx) {
        atomic_thread_fence(memory_order_acquire);
        uint32_t id = queue->vring.avail->ring[queue->last_avail_idx++ % queue->vring.num];
        struct iovec iov[130];

        size_t len = 0;
        uint32_t i = id;        
        while (queue->vring.desc[i].flags & VRING_DESC_F_NEXT) {
            int res = virt_queue_read_desc(&guest_memory, &queue->vring.desc[i], iov, len, 130);
            if (res < 0) {
                error("failed to read desc");
                return -1;
            }
            len += res;

            i = queue->vring.desc[i].next;
            if (i >= queue->vring.num) {
                error("invalid next buffer id");
                return -1;
            }
        }
        int res = virt_queue_read_desc(&guest_memory, &queue->vring.desc[i], iov, len, 130);
        if (res < 0) {
            error("failed to read desc");
            return -1;
        }
        len += res;

        virtio_ctx_t *virtio_ctx = calloc(1, sizeof(virtio_ctx_t));
        virtio_ctx->vring = queue->vring;
        virtio_ctx->id = id;
        virtio_ctx->len = len;
        virtio_ctx->eventfd = queue->call_eventfd;

        struct virtio_blk_outhdr* hdr = (struct virtio_blk_outhdr*) iov[0].iov_base;
        virtio_blk_handle(queue->io_queue, hdr, iov, (uint8_t*) iov[len - 1].iov_base, virtio_ctx);
    }

    return 0;
}

void* virt_queue_run(void *arg) {
    const size_t MAX_EVENTS = 4;
    struct epoll_event event;
    struct epoll_event events[MAX_EVENTS];

    virt_queue_t *queue = arg;
    
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("ERROR: failed to create epoll context");
        return (void*) (uintptr_t) -1ULL;
    }

    int kickfd = queue->kick_eventfd;
    event.events = EPOLLIN;
    event.data.fd = kickfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, kickfd, &event) == -1) {
        perror("ERROR: failed to add fd to epoll context");
        return (void*) (uintptr_t) -1ULL;
    }

    while(!queue->done) {
        int n = epoll_wait(epollfd, events, MAX_EVENTS, 100);
        if (n == -1) {
            perror("ERROR: failed to wait for epoll");
            return (void*) (uintptr_t) -1ULL;
        }
    
        for (size_t i = 0; i < n; i++) {
            if (events[i].data.fd == kickfd) {
                uint64_t count;
                read(queue->kick_eventfd, &count, sizeof(count));

                if (virt_queue_poll(queue) < 0) {
                    printf("ERROR: failed to poll virt-queue\n");
                    return (void*) (uintptr_t) -1ULL;
                }   
            }
        }
    }

    printf("INFO: virt_queue exiting: index %d\n", queue->index);
    return NULL;
}

typedef struct vhost_user_device {
    int owned;

    int client_fd;
    uint32_t protocol_features;

    int features_acked;
    uint32_t acked_features;
    uint32_t acked_protocol_features;

    int used_fd;
    struct virtio_blk_config config;

    virt_queue_t queues[DEVICE_QUEUE_COUNT];
} vhost_user_device_t;

vhost_user_device_t vhost_user_device;

void virt_queue_init(virt_queue_t *queue, int index) {
    queue->index = index;
    queue->state = QUEUE_STATE_DISABLED;
    queue->err_eventfd = -1;
    queue->call_eventfd = -1;
    queue->kick_eventfd = -1;
    queue->io_queue = mock_io_queue_create();
}

void vhost_user_device_init(vhost_user_device_t *dev) {
    memset(dev, 0, sizeof(vhost_user_device_t));
    dev->config.capacity = 2097152;
    dev->config.num_queues = 4;
    dev->config.size_max = 16384;
    dev->config.seg_max = 128;
    for (size_t i = 0; i < DEVICE_QUEUE_COUNT; i++) {
        virt_queue_init(&dev->queues[i], i);
    }
}

int vhost_user_device_message(vhost_user_device_t *dev, vhost_user_message_t *msg, int *fd);

int main() {
    int sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("failed to create socket");
        exit(1);
	}

    guest_memory_init(&guest_memory);
    vhost_user_device_init(&vhost_user_device);

	struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCK_FILE);
    unlink(SERVER_SOCK_FILE);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("failed to bind socket");
        exit(1);
    }

	struct sockaddr_un client;
    if(listen(sockfd, 1) < 0) {
        perror("failed to listen");
        exit(1);
    }

    socklen_t client_len = sizeof(client);
    vhost_user_device.client_fd = accept(sockfd, (struct sockaddr *) &client, &client_len);
    if (vhost_user_device.client_fd < 0) {
        perror("failed to accept");
        exit(1);
    }

    struct msghdr msg;
    struct iovec iov;
    uint8_t buf[4096] = {0};
    
    int fd;
    struct cmsghdr *cmsg;
    uint8_t fdbuf[CMSG_SPACE(sizeof(int))];

    int nread = 0;
    while (1) {

        if (nread == 0) {
            memset(fdbuf, 0, sizeof(fdbuf));
            memset(&msg, 0, sizeof(struct msghdr));
            iov.iov_base = buf;
            iov.iov_len = 4096;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = fdbuf;
            msg.msg_controllen = CMSG_LEN(sizeof(int));
            cmsg = CMSG_FIRSTHDR(&msg);
	        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            nread = recvmsg(vhost_user_device.client_fd, &msg, 0);
            if (nread < 0) {
                perror("read failed");
                exit(1);
            }

            if (cmsg->cmsg_type == SCM_RIGHTS) {
                fd = *(int*)CMSG_DATA(cmsg);
            } else {
                fd = -1;
            }
        }

        vhost_user_message_t *msg = (vhost_user_message_t*) (&buf);
        size_t msg_size = VHOST_USER_HEADER_SIZE + msg->header.size;
        vhost_user_device_message(&vhost_user_device, msg, &fd);
        memmove(buf, &buf[msg_size], nread - msg_size);
        nread -= msg_size;
    }

    guest_memory_deinit(&guest_memory);

	return 0;
}

int vhost_user_write(vhost_user_device_t *dev, vhost_user_message_t *resp) {
    size_t msg_size = VHOST_USER_HEADER_SIZE + resp->header.size;
    if (write(dev->client_fd, resp, msg_size) < msg_size) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_owner(vhost_user_device_t *dev, vhost_user_message_t *req) {
    if (dev->owned) return -1;    
    dev->owned = 1;
    return 0;
}

int vhost_user_device_reset_owner(vhost_user_device_t *dev, vhost_user_message_t *req) {
    dev->owned = 0;
    dev->acked_features = 0;
    dev->acked_protocol_features = 0;
    dev->features_acked = 0;
    return 0;
}

int vhost_user_device_get_features(vhost_user_device_t *dev, vhost_user_message_t *req) {
    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(uint64_t);
    resp.header.request = req->header.request;
    resp.body.u64 = 1ULL << VIRTIO_F_VERSION_1 |
                    1ULL << VIRTIO_RING_F_INDIRECT_DESC |
                    1ULL << VHOST_USER_F_PROTOCOL_FEATURES |
                    1ULL << VIRTIO_BLK_F_MQ |
                    1ULL << VIRTIO_BLK_F_SIZE_MAX |
                    1ULL << VIRTIO_BLK_F_SEG_MAX;

    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_features(vhost_user_device_t *dev, vhost_user_message_t *req) {
    dev->acked_features = req->body.u64;
    dev->features_acked = 1;
    if ((dev->acked_features & VHOST_USER_F_PROTOCOL_FEATURES) == 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_get_protocol_features(vhost_user_device_t *dev, vhost_user_message_t *req) {
    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(uint64_t);
    resp.header.request = req->header.request;
    resp.body.u64 = 1ULL << VHOST_USER_PROTOCOL_F_CONFIG |
                    1ULL << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
                    1ULL << VHOST_USER_PROTOCOL_F_MQ;

    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_protocol_features(vhost_user_device_t *dev, vhost_user_message_t *req) {
    dev->protocol_features = req->body.u64;

    return 0;
}

int vhost_user_device_get_queue_num(vhost_user_device_t *dev, vhost_user_message_t *req) {
    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(uint64_t);
    resp.header.request = req->header.request;
    resp.body.u64 = DEVICE_QUEUE_COUNT;

    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_get_max_mem_slots(vhost_user_device_t *dev, vhost_user_message_t *req) {
    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(uint64_t);
    resp.header.request = req->header.request;
    resp.body.u64 = 32;

    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_vring_call(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    uint8_t index = (uint8_t) req->body.u64;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    uint64_t invalid_fd = (req->body.u64 >> 8) & 0x1;
    assert(invalid_fd == 0);

    if (dev->queues[index].call_eventfd != -1) {
        close(dev->queues[index].call_eventfd);
    }

    dev->queues[index].call_eventfd = *fd;
    *fd = -1;
    write(dev->queues[index].call_eventfd, &(uint64_t){1}, sizeof(uint64_t));
    return 0;
}

int vhost_user_device_set_vring_err(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    uint8_t index = (uint8_t) req->body.u64;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    uint64_t invalid_fd = (req->body.u64 >> 8) & 0x1;
    assert(invalid_fd == 0);

    if (dev->queues[index].err_eventfd != -1) {
        close(dev->queues[index].err_eventfd);
    }

    dev->queues[index].err_eventfd = *fd;
    *fd = -1;

    return 0;
}

int vhost_user_device_get_config(vhost_user_device_t *dev, vhost_user_message_t *req) {
    uint8_t buffer[4096] = {0};
    vhost_user_message_t *resp = (vhost_user_message_t *) buffer;
    resp->header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp->header.size = sizeof(virtio_device_config_t) + req->body.config.size;
    resp->header.request = req->header.request;
    resp->body.config.offset = req->body.config.offset;
    resp->body.config.size = req->body.config.size;
    memcpy(&resp->body.config + 1, &((uint8_t*) &dev->config)[req->body.config.offset], req->body.config.size);
    if (vhost_user_write(dev, resp) < 0) {
        return -1;
    }


    return 0;
}

int vhost_user_device_set_vring_num(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    dev->queues[index].vring.num = req->body.state.num;
    return 0;
}

int vhost_user_device_set_vring_base(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    dev->queues[index].base_offset = req->body.state.num;
    return 0;
}

int vhost_user_device_set_vring_addr(vhost_user_device_t *dev, vhost_user_message_t *req) {
    struct vhost_vring_addr *vra = &req->body.addr;
    unsigned int index = vra->index;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    dev->queues[index].flags = vra->flags;

    int res;
    res = guest_memory_user_to_mmap(&guest_memory, vra->desc_user_addr, (void**) &dev->queues[index].vring.desc);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->desc_user_addr);
        return res;
    }
    
    res = guest_memory_user_to_mmap(&guest_memory, vra->used_user_addr,(void**) &dev->queues[index].vring.used);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->used_user_addr);
        return res;
    }

    res = guest_memory_user_to_mmap(&guest_memory, vra->avail_user_addr, (void**) &dev->queues[index].vring.avail);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->avail_user_addr);
        return res;
    }

    return 0;
}

int vhost_user_device_set_vring_kick(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    uint8_t index = (uint8_t) req->body.u64;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    uint64_t invalid_fd = (req->body.u64 >> 8) & 0x1;
    assert(invalid_fd == 0);

    if (dev->queues[index].kick_eventfd != -1) {
        close(dev->queues[index].kick_eventfd);
    }
    dev->queues[index].kick_eventfd = *fd;

    dev->queues[index].done = 0;
    int res = pthread_create(&dev->queues[index].thread_id, NULL, virt_queue_run, &dev->queues[index]);
    if (res != 0) {
        perror("failed to create thread");
        exit(1);
    }
    *fd = -1;
    
    return 0;
}

int vhost_user_device_get_vring_base(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);

    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(struct vhost_vring_state);
    resp.header.request = req->header.request;
    resp.body.state.index = index;
    resp.body.state.num = dev->queues[index].base_offset;

    dev->queues[index].done = 1;
    pthread_join(dev->queues[index].thread_id, NULL);
    dev->queues[index].state = QUEUE_STATE_STOPPED;
    
    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_vring_enable(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < DEVICE_QUEUE_COUNT);
    virt_queue_t *queue = &dev->queues[index];
    if (queue->state == QUEUE_STATE_STOPPED) {
        printf("ERROR: attempt to (dis/en)nable stopped virt queue\n");
        return -1;
    }

    dev->queues[index].state = req->body.state.num;
    
    return 0;
}

int vhost_user_device_add_memory_region(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    memory_region_desc_t *desc = (memory_region_desc_t *) &req->body.single_region_desc.desc;
    int res = guest_memory_add_region(&guest_memory, *fd, desc->size,  desc->mmap_offset, desc->guest_addr, desc->user_addr);
    *fd = -1;
    return res;
}

int vhost_user_device_message(vhost_user_device_t *dev, vhost_user_message_t *msg, int *fd) {
    switch (msg->header.request) {
    case VHOST_USER_SET_OWNER:
        return vhost_user_device_set_owner(dev, msg);
    case VHOST_USER_RESET_OWNER:
        return vhost_user_device_reset_owner(dev, msg);
    case VHOST_USER_GET_FEATURES:
        return vhost_user_device_get_features(dev, msg);
    case VHOST_USER_SET_FEATURES:
        return vhost_user_device_set_features(dev, msg);
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        return vhost_user_device_get_protocol_features(dev, msg);
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        return vhost_user_device_set_protocol_features(dev, msg);
    case VHOST_USER_GET_QUEUE_NUM:
        return vhost_user_device_get_queue_num(dev, msg);
    case VHOST_USER_GET_MAX_MEM_SLOTS:
        return vhost_user_device_get_max_mem_slots(dev, msg);
    case VHOST_USER_SET_VRING_CALL:
        return vhost_user_device_set_vring_call(dev, msg, fd);
    case VHOST_USER_SET_VRING_ERR:
        return vhost_user_device_set_vring_err(dev, msg, fd);
    case VHOST_USER_GET_CONFIG:
        return vhost_user_device_get_config(dev, msg);
     case VHOST_USER_SET_VRING_NUM:
        return vhost_user_device_set_vring_num(dev, msg);
    case VHOST_USER_SET_VRING_BASE:
        return vhost_user_device_set_vring_base(dev, msg);
    case VHOST_USER_SET_VRING_ADDR:
        return vhost_user_device_set_vring_addr(dev, msg);
    case VHOST_USER_SET_VRING_KICK:
        return vhost_user_device_set_vring_kick(dev, msg, fd);
    case VHOST_USER_GET_VRING_BASE:
        return vhost_user_device_get_vring_base(dev, msg);
    case VHOST_USER_SET_VRING_ENABLE:
        return vhost_user_device_set_vring_enable(dev, msg);
    case VHOST_USER_ADD_MEM_REG:
        return vhost_user_device_add_memory_region(dev, msg, fd);
    default:
        printf("ERROR: not implemented: %s\n", vhost_user_message_type_str(msg->header.request));
        return -1;
    }
}
