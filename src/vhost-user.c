#define _GNU_SOURCE
#include <vhost-user.h>
#include <virtio-blk.h>
#include <bdev.h>
#include <log.h>
#include <guest_memory.h>

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/virtio_blk.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdlib.h>

const char* vhost_user_message_type_str(vhost_user_message_type_t t) {
    switch (t) {
        case VHOST_USER_GET_FEATURES: return "VHOST_USER_GET_FEATURES";
        case VHOST_USER_SET_FEATURES: return "VHOST_USER_SET_FEATURES";
        case VHOST_USER_SET_OWNER: return "VHOST_USER_SET_OWNER";
        case VHOST_USER_RESET_OWNER: return "VHOST_USER_RESET_OWNER";
        case VHOST_USER_SET_MEM_TABLE: return "VHOST_USER_SET_MEM_TABLE"; 
        case VHOST_USER_SET_LOG_BASE: return "VHOST_USER_SET_LOG_BASE";
        case VHOST_USER_SET_LOG_FD: return "VHOST_USER_SET_LOG_FD";
        case VHOST_USER_SET_VRING_NUM: return "VHOST_USER_SET_VRING_NUM";
        case VHOST_USER_SET_VRING_ADDR: return "VHOST_USER_SET_VRING_ADDR";
        case VHOST_USER_SET_VRING_BASE: return "VHOST_USER_SET_VRING_BASE";
        case VHOST_USER_GET_VRING_BASE: return "VHOST_USER_GET_VRING_BASE";
        case VHOST_USER_SET_VRING_KICK: return "VHOST_USER_SET_VRING_KICK";
        case VHOST_USER_SET_VRING_CALL: return "VHOST_USER_SET_VRING_CALL";
        case VHOST_USER_SET_VRING_ERR: return "VHOST_USER_SET_VRING_ERR";
        case VHOST_USER_GET_PROTOCOL_FEATURES: return "VHOST_USER_GET_PROTOCOL_FEATURES";
        case VHOST_USER_SET_PROTOCOL_FEATURES: return "VHOST_USER_SET_PROTOCOL_FEATURES";
        case VHOST_USER_GET_QUEUE_NUM: return "VHOST_USER_GET_QUEUE_NUM";
        case VHOST_USER_SET_VRING_ENABLE: return "VHOST_USER_SET_VRING_ENABLE";
        case VHOST_USER_SEND_RARP: return "VHOST_USER_SEND_RARP";
        case VHOST_USER_NET_SET_MTU: return "VHOST_USER_NET_SET_MTU";
        case VHOST_USER_SET_BACKEND_REQ_FD: return "VHOST_USER_SET_BACKEND_REQ_FD";
        case VHOST_USER_IOTLB_MSG: return "VHOST_USER_IOTLB_MSG";
        case VHOST_USER_SET_VRING_ENDIAN: return "VHOST_USER_SET_VRING_ENDIAN";
        case VHOST_USER_GET_CONFIG: return "VHOST_USER_GET_CONFIG";
        case VHOST_USER_SET_CONFIG: return "VHOST_USER_SET_CONFIG";
        case VHOST_USER_CREATE_CRYPTO_SESSION: return "VHOST_USER_CREATE_CRYPTO_SESSION";
        case VHOST_USER_CLOSE_CRYPTO_SESSION: return "VHOST_USER_CLOSE_CRYPTO_SESSION";
        case VHOST_USER_POSTCOPY_ADVISE: return "VHOST_USER_POSTCOPY_ADVISE";
        case VHOST_USER_POSTCOPY_LISTEN: return "VHOST_USER_POSTCOPY_LISTEN";
        case VHOST_USER_POSTCOPY_END: return "VHOST_USER_POSTCOPY_END";
        case VHOST_USER_GET_INFLIGHT_FD: return "VHOST_USER_GET_INFLIGHT_FD";
        case VHOST_USER_SET_INFLIGHT_FD: return "VHOST_USER_SET_INFLIGHT_FD";
        case VHOST_USER_GPU_SET_SOCKET: return "VHOST_USER_GPU_SET_SOCKET";
        case VHOST_USER_RESET_DEVICE: return "VHOST_USER_RESET_DEVICE";
        case VHOST_USER_VRING_KICK: return "VHOST_USER_VRING_KICK";
        case VHOST_USER_GET_MAX_MEM_SLOTS: return "VHOST_USER_GET_MAX_MEM_SLOTS";
        case VHOST_USER_ADD_MEM_REG: return "VHOST_USER_ADD_MEM_REG";
        case VHOST_USER_REM_MEM_REG: return "VHOST_USER_REM_MEM_REG";
        case VHOST_USER_SET_STATUS: return "VHOST_USER_SET_STATUS";
        case VHOST_USER_GET_STATUS: return "VHOST_USER_GET_STATUS";
        default: return "UNKNOWN";
    }
}

void vhost_vring_addr_debug(struct vhost_vring_addr *vra) {
    printf("struct vhost_vring_addr { " 
        "index: %u, "
        "flags: %u, "
        "desc_user_addr: 0x%016llx, "
        "used_user_addr: 0x%016llx, "
        "avail_user_addr: 0x%016llx, "
        "log_guest_addr: 0x%016llx "
        "}\n",
        vra->index,
        vra->flags,
        vra->desc_user_addr,
        vra->used_user_addr,
        vra->avail_user_addr,
        vra->log_guest_addr    
    );
}

int vhost_user_device_init(vhost_user_device_t *dev, metric_client_t *metric_client, const char *sock_path, size_t queue_count, size_t queue_depth, task_queue_t **task_queues, size_t task_queue_count) {
    memset(dev, 0, sizeof(vhost_user_device_t));
    dev->bdev = aio_bdev_create("/dev/nvme0n1", queue_count, queue_depth);
    if (dev->bdev == NULL) {
        goto error0;
    }
    
    dev->config.capacity = 1875385008;
    dev->config.num_queues = queue_count;
    dev->config.size_max = 16384;
    dev->config.seg_max = 32;
    dev->client_fd = -1;
    dev->status = 0;

    if (guest_memory_init(&dev->guest_memory) < 0) {
        goto error1;
    }
    dev->queue_depth = queue_depth;
    for (size_t i = 0; i < queue_count; i++) {
        virtio_blk_queue_t *queue = virtio_blk_queue_create(bdev_get_queue(dev->bdev, i), i, metric_client);
        if (queue == NULL) goto error2;
        virt_queue_init(&dev->queues[i], metric_client, &dev->guest_memory, (device_queue_t*) queue, i);
        dev->queue_count++;
    }
    
    dev->task_queues = task_queues;
    dev->task_queue_count = task_queue_count;
    
    dev->accept_task = (task_t) {
        .self = dev,
        .call = (int (*)(void*, int)) vhost_user_accept,
    };

    dev->read_task = (task_t) {
        .self = dev,
        .call = (int (*)(void*, int)) vhost_user_device_poll,
    };

    dev->sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (dev->sock_fd < 0) {
		return -1;
	}

	struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock_path);
    unlink(sock_path);
    if (bind(dev->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		return -1;
    }

    if(listen(dev->sock_fd, 1) < 0) {
        return -1;
    }

    return 0;

error2:
    for (size_t i = 0; i < dev->queue_count; i++) {
        virtio_blk_queue_t *queue = (virtio_blk_queue_t *) &dev->queues[i].impl;
        virt_queue_deinit(&dev->queues[i]);
        virtio_blk_queue_destroy(queue);
    }
    guest_memory_deinit(&dev->guest_memory);
error1:
    aio_bdev_destroy(dev->bdev);
error0:
    return -1;
}

void vhost_user_device_deinit(vhost_user_device_t *dev) {
    for (size_t i = 0; i < dev->queue_count; i++) {
        virtio_blk_queue_t *queue = (virtio_blk_queue_t *) dev->queues[i].impl;
        virt_queue_deinit(&dev->queues[i]);
        virtio_blk_queue_destroy(queue);
    }
    guest_memory_deinit(&dev->guest_memory);
    aio_bdev_destroy(dev->bdev);
}

int vhost_user_write(vhost_user_device_t *dev, vhost_user_message_t *resp) {
    size_t msg_size = VHOST_USER_HEADER_SIZE + resp->header.size;
    if (write(dev->client_fd, resp, msg_size) < msg_size) {
        return -1;
    }

    return 0;
}

int vhost_user_write_fd(vhost_user_device_t *dev, vhost_user_message_t *resp, int fd) {
    size_t msg_size = VHOST_USER_HEADER_SIZE + resp->header.size;
    
    struct msghdr msg;
    struct cmsghdr *cmsg;
    uint8_t fdbuf[CMSG_SPACE(sizeof(int))];
    struct iovec io_vector[1];

    io_vector[0].iov_base = resp;
    io_vector[0].iov_len = msg_size;

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = &fdbuf;
    msg.msg_controllen = sizeof(fdbuf);
    msg.msg_iov = io_vector;
    msg.msg_iovlen = 1;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;

	if (sendmsg(dev->client_fd, &msg, 0) < msg_size) {
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
                    // 1ULL << VIRTIO_RING_F_INDIRECT_DESC |
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
                    1ULL << VHOST_USER_PROTOCOL_F_STATUS |
                    1ULL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD |
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
    resp.body.u64 = dev->queue_count;

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
    assert(index >= 0 && index < dev->queue_count);
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
    assert(index >= 0 && index < dev->queue_count);
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
    assert(index >= 0 && index < dev->queue_count);
    dev->queues[index].vring.num = req->body.state.num;
    return 0;
}

int vhost_user_device_set_vring_base(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < dev->queue_count);
    // dev->queues[index].last_avail_idx = req->body.state.num;
    return 0;
}

int vhost_user_device_set_vring_addr(vhost_user_device_t *dev, vhost_user_message_t *req) {
    struct vhost_vring_addr *vra = &req->body.addr;
    unsigned int index = vra->index;
    assert(index >= 0 && index < dev->queue_count);
    dev->queues[index].flags = vra->flags;

    int res;
    res = guest_memory_user_to_mmap(&dev->guest_memory, vra->desc_user_addr, (void**) &dev->queues[index].vring.desc);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->desc_user_addr);
        return res;
    }
    
    res = guest_memory_user_to_mmap(&dev->guest_memory, vra->used_user_addr,(void**) &dev->queues[index].vring.used);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->used_user_addr);
        return res;
    }

    res = guest_memory_user_to_mmap(&dev->guest_memory, vra->avail_user_addr, (void**) &dev->queues[index].vring.avail);
    if (res < 0) {
        printf("ERROR: failed to translate user address to mmap address: 0x%016llx\n", vra->avail_user_addr);
        return res;
    }

    return 0;
}

int vhost_user_device_set_vring_kick(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    uint8_t index = (uint8_t) req->body.u64;
    assert(index >= 0 && index < dev->queue_count);
    uint64_t invalid_fd = (req->body.u64 >> 8) & 0x1;
    assert(invalid_fd == 0);

    if (dev->queues[index].kick_eventfd != -1) {
        close(dev->queues[index].kick_eventfd);
    }
    dev->queues[index].kick_eventfd = *fd;
    *fd = -1;

    dev->queues[index].done = 0;

    for (size_t i = 0; i < dev->queue_depth; i++) {
        if (dev->queues[index].inflight_state->desc[i].inflight) {
            virt_queue_handle(&dev->queues[index], i);
        }
    }

    if (task_queue_push(dev->task_queues[index % dev->task_queue_count], &dev->queues[index], (int (*)(void *, int)) virt_queue_epoll_register) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_get_vring_base(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < dev->queue_count);

    if (task_queue_push(dev->task_queues[index % dev->task_queue_count], &dev->queues[index],  (int (*)(void *, int)) virt_queue_epoll_deregister) < 0) {
        return -1;
    }

    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(struct vhost_vring_state);
    resp.header.request = req->header.request;
    resp.body.state.index = index;
    resp.body.state.num = dev->queues[index].inflight_state->last_avail_idx;
    dev->queues[index].state = QUEUE_STATE_STOPPED;
    
    if (dev->queues[index].call_eventfd != -1) {
        close(dev->queues[index].call_eventfd);
        dev->queues[index].call_eventfd = -1;
    }

    if (dev->queues[index].kick_eventfd != -1) {
        close(dev->queues[index].kick_eventfd);
        dev->queues[index].kick_eventfd = -1;
    }

    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_vring_enable(vhost_user_device_t *dev, vhost_user_message_t *req) {
    size_t index = req->body.state.index;
    assert(index >= 0 && index < dev->queue_count);
    virt_queue_t *queue = &dev->queues[index];
    unsigned int state = req->body.state.num;
    if (queue->state == QUEUE_STATE_STOPPED) {
        error("failed to %s virt-queue: stopped", state ? "enable": "disable");
        return -1;
    }
    info("set state: %d.%d", index, state);
    dev->queues[index].state = state;
    
    return 0;
}

int vhost_user_device_add_memory_region(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    memory_region_desc_t *desc = (memory_region_desc_t *) &req->body.single_region_desc.desc;
    int res = guest_memory_add_region(&dev->guest_memory, *fd, desc->size,  desc->mmap_offset, desc->guest_addr, desc->user_addr);
    *fd = -1;
    return res;
}

int vhost_user_device_set_inflight_fd(vhost_user_device_t *dev, vhost_user_message_t *req, int *fd) {
    inflight_desc_t *desc = (inflight_desc_t *) &req->body.inflight_desc;
    if (desc->num_queues != dev->queue_count) return -1;
    if (desc->queue_size != dev->queue_depth) return -1;
    if (desc->mmap_offset != 0) return -1;
    size_t mmap_size = dev->queue_count * (sizeof(queue_state_t) + (dev->queue_depth) * sizeof(desc_state_t));
    if (desc->mmap_size != mmap_size) return -1;
    char *addr = mmap(NULL, desc->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, desc->mmap_offset);
    if (addr == MAP_FAILED) {
        return -1;
    }

    for (size_t i = 0; i < dev->queue_count; i++) {
        dev->queues[i].inflight_state = (queue_state_t*) (addr + i * (sizeof(queue_state_t) + (dev->queue_depth) * sizeof(desc_state_t)));
    }
    *fd = -1;
    
    return 0;
}

int vhost_user_device_get_inflight_fd(vhost_user_device_t *dev, vhost_user_message_t *req) {
  
    int fd = memfd_create("inflight", MFD_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    size_t mmap_size = dev->queue_count * (sizeof(queue_state_t) + (dev->queue_depth) * sizeof(desc_state_t));
    off_t mmap_offset = 0;
    if (ftruncate(fd, mmap_size) < 0) {
        return -1;
    }

    char *addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmap_offset);
    if (addr == MAP_FAILED) {
        return -1;
    }

    for (size_t i = 0; i < dev->queue_count; i++) {
        dev->queues[i].inflight_state = (queue_state_t*) (addr + i * (sizeof(queue_state_t) + (dev->queue_depth) * sizeof(desc_state_t)));
    }

    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(inflight_desc_t);
    resp.header.request = req->header.request;
    resp.body.inflight_desc.num_queues = dev->queue_count;
    resp.body.inflight_desc.queue_size = dev->queue_depth;
    resp.body.inflight_desc.mmap_size = mmap_size;
    resp.body.inflight_desc.mmap_offset = mmap_offset;

    if (vhost_user_write_fd(dev, &resp, fd) < 0) {
        goto error0;
    }

    return 0;

error0:
    close(fd);
    return -1;
}


int vhost_user_device_get_status(vhost_user_device_t *dev, vhost_user_message_t *req) {   
    vhost_user_message_t resp = {0};
    resp.header.flags = VHOST_USER_HEADER_FLAGS_V1 | VHOST_USER_HEADER_FLAGS_REPLY;
    resp.header.size = sizeof(uint64_t);
    resp.header.request = req->header.request;
    resp.body.u64 = dev->status;
    
    if (vhost_user_write(dev, &resp) < 0) {
        return -1;
    }

    return 0;
}

int vhost_user_device_set_status(vhost_user_device_t *dev, vhost_user_message_t *req) {
    dev->status = req->body.u64;
    info("Changed device status to %d", req->body.u64);
    return 0;
}

int vhost_user_device_handle(vhost_user_device_t *dev, vhost_user_message_t *msg, int *fd) {
    info("recv: %s", vhost_user_message_type_str(msg->header.request));
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
    case VHOST_USER_SET_INFLIGHT_FD:
        return vhost_user_device_set_inflight_fd(dev, msg, fd);
    case VHOST_USER_GET_INFLIGHT_FD:
        return vhost_user_device_get_inflight_fd(dev, msg);
    case VHOST_USER_GET_STATUS:
        return vhost_user_device_get_status(dev, msg);
    case VHOST_USER_SET_STATUS:
        return vhost_user_device_set_status(dev, msg);
    default:
        printf("ERROR: not implemented: %s\n", vhost_user_message_type_str(msg->header.request));
        return -1;
    }
}

int vhost_user_device_poll(vhost_user_device_t *dev, int _) {
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    uint8_t fdbuf[CMSG_SPACE(sizeof(int))];

    if (dev->read_state.buf_len == 0) {
        memset(fdbuf, 0, sizeof(fdbuf));
        memset(&msg, 0, sizeof(struct msghdr));
        iov.iov_base = dev->read_state.buf;
        iov.iov_len = 4096;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = fdbuf;
        msg.msg_controllen = CMSG_LEN(sizeof(int));
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        int nread = recvmsg(dev->client_fd, &msg, 0);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }

            return -1;
        }
        dev->read_state.buf_len += nread;
        if (cmsg->cmsg_type == SCM_RIGHTS) {
            dev->read_state.fd = *(int*)CMSG_DATA(cmsg);
        } else {
            dev->read_state.fd = -1;
        }
    }

    while (dev->read_state.buf_len > 0) {
        vhost_user_message_t *vhost_user_msg = (vhost_user_message_t*) (&dev->read_state.buf);
        size_t msg_size = VHOST_USER_HEADER_SIZE + vhost_user_msg->header.size;
        vhost_user_device_handle(dev, vhost_user_msg, &dev->read_state.fd);
        memmove(dev->read_state.buf, &dev->read_state.buf[msg_size], dev->read_state.buf_len - msg_size);
        dev->read_state.buf_len -= msg_size;
    }
   
    return 0;
}

int vhost_user_accept(vhost_user_device_t *dev, int epollfd) {
    struct sockaddr_un client;
    socklen_t client_len = sizeof(client);
    dev->client_fd = accept(dev->sock_fd, (struct sockaddr *) &client, &client_len);
    if (dev->client_fd < 0) {
       return -1;
    }

    int res = fcntl(dev->client_fd, F_GETFL, 0);
    if (res < 0) {
        return -1;
    }

    res = fcntl(dev->client_fd, F_SETFL, res | O_NONBLOCK);
    if (res < 0) {
        return -1;
    }

    struct epoll_event event = {0};
    int fd = dev->client_fd;
    event.events = EPOLLIN;
    event.data.ptr = &dev->read_task;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
        return -1;
    }

    return 0;
}

int vhost_user_device_epoll_register(vhost_user_device_t *dev, int epollfd) {
    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.ptr = &dev->accept_task;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, dev->sock_fd, &event) == -1) {
        return -1;
    }

    return 0;
}

int vhost_user_device_epoll_deregister(vhost_user_device_t *dev, int epollfd) {
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, dev->sock_fd, NULL) == -1) {
        return -1;
    }

    if (dev->client_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, dev->client_fd, NULL) == -1) {
            return -1;
        }
    }

    return 0;
}
