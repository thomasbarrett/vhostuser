#include <vhost-user.h>

#include <stdio.h>

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
