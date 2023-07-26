#ifndef VHOSTUSER_H
#define VHOSTUSER_H

#include <guest.h>
#include <virtio-core.h>
#include <virtio-blk.h>

#include <stdint.h>
#include <linux/vhost_types.h>

#define VHOST_USER_F_PROTOCOL_FEATURES 30

#define VHOST_USER_PROTOCOL_F_MQ                    0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD             1
#define VHOST_USER_PROTOCOL_F_RARP                  2
#define VHOST_USER_PROTOCOL_F_REPLY_ACK             3
#define VHOST_USER_PROTOCOL_F_MTU                   4
#define VHOST_USER_PROTOCOL_F_BACKEND_REQ           5
#define VHOST_USER_PROTOCOL_F_CROSS_ENDIAN          6
#define VHOST_USER_PROTOCOL_F_CRYPTO_SESSION        7
#define VHOST_USER_PROTOCOL_F_PAGEFAULT             8
#define VHOST_USER_PROTOCOL_F_CONFIG                9
#define VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD      10
#define VHOST_USER_PROTOCOL_F_HOST_NOTIFIER        11
#define VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD       12
#define VHOST_USER_PROTOCOL_F_RESET_DEVICE         13
#define VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS 14
#define VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS  15
#define VHOST_USER_PROTOCOL_F_STATUS               16
#define VHOST_USER_PROTOCOL_F_XEN_MMAP             17

#define VHOST_USER_GET_FEATURES          1
#define VHOST_USER_SET_FEATURES          2
#define VHOST_USER_SET_OWNER             3
#define VHOST_USER_RESET_OWNER           4
#define VHOST_USER_SET_MEM_TABLE         5
#define VHOST_USER_SET_LOG_BASE          6
#define VHOST_USER_SET_LOG_FD            7
#define VHOST_USER_SET_VRING_NUM         8
#define VHOST_USER_SET_VRING_ADDR        9
#define VHOST_USER_SET_VRING_BASE        10
#define VHOST_USER_GET_VRING_BASE        11
#define VHOST_USER_SET_VRING_KICK        12
#define VHOST_USER_SET_VRING_CALL        13
#define VHOST_USER_SET_VRING_ERR         14
#define VHOST_USER_GET_PROTOCOL_FEATURES 15
#define VHOST_USER_SET_PROTOCOL_FEATURES 16
#define VHOST_USER_GET_QUEUE_NUM         17
#define VHOST_USER_SET_VRING_ENABLE      18
#define VHOST_USER_SEND_RARP             19
#define VHOST_USER_NET_SET_MTU           20
#define VHOST_USER_SET_BACKEND_REQ_FD    21
#define VHOST_USER_IOTLB_MSG             22
#define VHOST_USER_SET_VRING_ENDIAN      23
#define VHOST_USER_GET_CONFIG            24
#define VHOST_USER_SET_CONFIG            25
#define VHOST_USER_CREATE_CRYPTO_SESSION 26
#define VHOST_USER_CLOSE_CRYPTO_SESSION  27
#define VHOST_USER_POSTCOPY_ADVISE       28
#define VHOST_USER_POSTCOPY_LISTEN       29
#define VHOST_USER_POSTCOPY_END          30
#define VHOST_USER_GET_INFLIGHT_FD       31
#define VHOST_USER_SET_INFLIGHT_FD       32
#define VHOST_USER_GPU_SET_SOCKET        33
#define VHOST_USER_RESET_DEVICE          34
#define VHOST_USER_VRING_KICK            35
#define VHOST_USER_GET_MAX_MEM_SLOTS     36
#define VHOST_USER_ADD_MEM_REG           37
#define VHOST_USER_REM_MEM_REG           38
#define VHOST_USER_SET_STATUS            39
#define VHOST_USER_GET_STATUS            40

typedef uint32_t vhost_user_message_type_t;

const char* vhost_user_message_type_str(vhost_user_message_type_t t);

#define VHOST_USER_BACKEND_IOTLB_MSG               1
#define VHOST_USER_BACKEND_CONFIG_CHANGE_MSG       2
#define VHOST_USER_BACKEND_VRING_HOST_NOTIFIER_MSG 3
#define VHOST_USER_BACKEND_VRING_CALL              4
#define VHOST_USER_BACKEND_VRING_ERR               5

typedef uint32_t vhost_user_backend_message_type_t;

typedef struct vring_address {
    uint32_t index;
    uint32_t flags;
    uint64_t size;
    uint64_t descriptor;
    uint64_t used;
    uint64_t available;
    uint64_t log;
} vhost_user_ring_address_t;

#define VHOST_USER_HEADER_FLAGS_V1          0x01
#define VHOST_USER_HEADER_FLAGS_REPLY       0x04
#define VHOST_USER_HEADER_FLAGS_NEED_REPLY  0x08

#define VHOST_USER_HEADER_SIZE sizeof(((vhost_user_message_t*) NULL)->header)

#define VIRTIO_FEATURE_PROTOCOL_FEATURES 30

typedef struct virtio_device_config {
    uint32_t offset;
    uint32_t size;
    uint32_t flags;
} __attribute__((__packed__)) virtio_device_config_t;

typedef struct memory_region_desc {
    uint64_t guest_addr;
    uint64_t size;
    uint64_t user_addr;
    uint64_t mmap_offset;
} memory_region_desc_t;

typedef struct single_memory_region_desc {
    uint64_t padding;
    memory_region_desc_t desc;
} single_single_memory_region_desc_t;

typedef struct inflight_desc {
    uint64_t mmap_size;
    uint64_t mmap_offset;
    uint16_t num_queues;
    uint16_t queue_size;
} inflight_desc_t;

typedef struct vhost_user_message {
    struct {
        uint32_t request;
        uint32_t flags;
        uint32_t size;
    } header;
    union {
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        virtio_device_config_t config;
        single_single_memory_region_desc_t single_region_desc;
        inflight_desc_t inflight_desc;
    } body;
} __attribute__((__packed__)) vhost_user_message_t;

void vhost_vring_addr_debug(struct vhost_vring_addr *vra);

#define DEVICE_QUEUE_COUNT_MAX 16
#define DEVICE_QUEUE_DEPTH_MAX 1024

#define BUFFER_SIZE 4096

typedef struct vhost_user_device {
    int owned;

    int sock_fd;
    int client_fd;
    uint32_t protocol_features;

    int features_acked;
    uint32_t acked_features;
    uint32_t acked_protocol_features;

    int used_fd;

    virtio_device_t device;

    size_t queue_count;
    size_t queue_depth;
    virt_queue_t queues[DEVICE_QUEUE_COUNT_MAX];
    
    task_queue_t **task_queues;
    size_t task_queue_count;

    guest_memory_t guest_memory;

    task_t accept_task;
    task_t read_task;

    uint64_t status;

    /* unix socket read buffer */
    struct {
        int fd;
        uint8_t buf[BUFFER_SIZE];
        size_t buf_len;
    } read_state;
} vhost_user_device_t;

int vhost_user_device_init(vhost_user_device_t *dev, metric_client_t *metric_client, const char *sock_path, virtio_device_t device, size_t queue_depth, task_queue_t **task_queues, size_t task_queue_count);
void vhost_user_device_deinit(vhost_user_device_t *dev);
int vhost_user_device_handle(vhost_user_device_t *dev, vhost_user_message_t *msg, int *fd);
int vhost_user_device_poll(vhost_user_device_t *dev, int _);
int vhost_user_device_epoll_register(vhost_user_device_t *dev, int epollfd);
int vhost_user_device_epoll_deregister(vhost_user_device_t *dev, int epollfd);
int vhost_user_accept(vhost_user_device_t *dev, int epollfd);

#endif
