#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdlib.h>
#include <sched.h>

#include <sys/sysinfo.h>
#include <vhost-user.h>
#include <guest.h>
#include <bdev.h>
#include <virtio-core.h>
#include <virtio-blk.h>
#include <log.h>
#include <task.h>

#define SERVER_SOCK_FILE "/tmp/vhost-blk.sock"

#define POLL_PENDING 0
#define POLL_READY 1

typedef struct io_thread_ctx {
    pthread_t thread_id;
    int index;
    task_queue_t task_queue;
} io_thread_ctx_t;

static volatile int done = 0;

void handle_sigint(int signal) {
    done = 1;
}

void* io_thread_run(void *arg) {
    io_thread_ctx_t *ctx = (io_thread_ctx_t*) arg;

    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        return (void*) (uintptr_t) -1ULL;
    }

    if (task_queue_epoll_register(&ctx->task_queue, epollfd) < 0) {
        return (void*) (uintptr_t) -1ULL;
    }

    const size_t EPOLL_MAX_EVENTS = 16;
    int EPOLL_TIMEOUT_MS = 100;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    while (!task_queue_done(&ctx->task_queue)) {
        int n = epoll_wait(epollfd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (n < 0) {
            return (void*) (uintptr_t) -1ULL;
        }

        for (size_t i = 0; i < n; i++) {
            task_t *ctx = (task_t*) events[i].data.ptr;
            if (ctx->call(ctx->self, epollfd) < 0) {
                return (void*) (uintptr_t) -1ULL;
            }
        }
    }

    close(epollfd);

    info("io_thread exiting: index %d", ctx->index);

    return NULL;
}

int main(void) {


    io_thread_ctx_t io_thread_ctx[DEVICE_QUEUE_COUNT_MAX];
    task_queue_t *task_queues[DEVICE_QUEUE_COUNT_MAX];

    const int thread_count = 4;
    for (size_t i = 0; i < thread_count; i++) {
        io_thread_ctx[i].index = i;

        if (task_queue_init(&io_thread_ctx[i].task_queue) < 0) {
            return -1;
        }

        int res = pthread_create(&io_thread_ctx[i].thread_id, NULL, io_thread_run, &io_thread_ctx[i]);
        if (res != 0) {
            return -1;
        }

        task_queues[i] = &io_thread_ctx[i].task_queue;
    }

    metric_client_t metric_client;
    if (metric_client_init(&metric_client, 8888) < 0) {
        return -1;
    }

    aio_bdev_t aio_bdev;
    int res = aio_bdev_init(&aio_bdev, "/dev/nvme3n1", 4, 128);
    if (res < 0) {
        return -1;
    }
    bdev_t bdev = (bdev_t) {
        .self = &aio_bdev,
        .vtable = &aio_bdev_vtable,
    };

    virtio_blk_device_t virtio_blk_device;
    if (virtio_blk_device_init(&virtio_blk_device, bdev) < 0) {
        return -1;
    }

    virtio_blk_device_metrics_register(&virtio_blk_device, &metric_client);

    signal(SIGINT, handle_sigint);

    virtio_device_t device = (virtio_device_t){
        .self = &virtio_blk_device,
        .vtable = &virtio_blk_vtable,
    };

    vhost_user_device_t vhost_user_device;
    if (vhost_user_device_init(&vhost_user_device, &metric_client, SERVER_SOCK_FILE, device, 128, task_queues, thread_count) < 0) {
        return -1;
    }

    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        return -1;
    }

    if (metric_client_epoll_register(&metric_client, epollfd) < 0) {
        return -1;
    }
    
    if (vhost_user_device_epoll_register(&vhost_user_device, epollfd) < 0) {
        return -1;
    }

    const size_t EPOLL_MAX_EVENTS = 16;
    int EPOLL_TIMEOUT_MS = 500;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    while (!done) {
        int res = epoll_wait(epollfd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (res < 0) {
            /* Exit the loop cleanly upon receiving SIGINT */
            if (errno == EINTR) continue;

            return -1;
        }

        for (size_t i = 0; i < res; i++) {
            task_t *ctx = (task_t*) events[i].data.ptr;
            if (ctx->call(ctx->self, epollfd) < 0) {
                return -1;
            }
        }
    }

    info("waiting for queues to exit");

    for (size_t i = 0; i < vhost_user_device.queue_count; i++) {
        if (vhost_user_device.queues[i].done == 0) {
            task_queue_close(&io_thread_ctx[i].task_queue);
            pthread_join(io_thread_ctx[i].thread_id, NULL);
        }
    }

    vhost_user_device_deinit(&vhost_user_device);
    virtio_blk_device_metrics_deregister(&virtio_blk_device, &metric_client);
    virtio_blk_device_deinit(&virtio_blk_device);
    aio_bdev_deinit(&aio_bdev);
    
    metric_client_deinit(&metric_client);

	return 0;
}

// typedef struct device {
//     aio_bdev_t aio_bdev;
//     virtio_blk_device_t virtio_blk_device;
//     vhost_user_device_t vhost_user_device;
// } device_t;

// #define APPLICATION_DEVICE_COUNT_MAX 16
// #define APPLICATION_IO_THREAD_COUNT_MAX 16

// typedef struct application {
//     io_thread_ctx_t io_thread_ctx[APPLICATION_IO_THREAD_COUNT_MAX];
//     size_t io_thread_count;
    
//     task_queue_t *io_thread_task_queues[APPLICATION_IO_THREAD_COUNT_MAX];

//     int epollfd;
//     metric_client_t metric_client;
//     device_t *devices[APPLICATION_DEVICE_COUNT_MAX];
//     size_t device_count;
// } application_t;

// int device_init(device_t *device, metric_client_t *metric_client, task_queue_t *task_queues, size_t io_thread_count, const char *path) {
//     if (aio_bdev_init(&device->aio_bdev, path, io_thread_count, 128) < 0) {
//         goto error0;
//     }

//     if (virtio_blk_device_init(&device->virtio_blk_device, (bdev_t) {
//         .self = &device->aio_bdev,
//         .vtable = &aio_bdev_vtable,
//     }) < 0) {
//         goto error1;
//     }

//     if (vhost_user_device_init(&device->vhost_user_device, &metric_client, SERVER_SOCK_FILE, (virtio_device_t) {
//         .self = &device->virtio_blk_device,
//         .vtable = &virtio_blk_vtable,
//     }, 128, task_queues, io_thread_count) < 0) {
//         goto error2;
//     }

// error2:
//     virtio_blk_device_deinit(&device->virtio_blk_device);
// error1:
//     aio_bdev_deinit(&device->aio_bdev);
// error0:
//     return -1;
// }

// int device_deinit(device_t *device) {
//     vhost_user_device_deinit(&device->vhost_user_device);
//     virtio_blk_device_deinit(&device->virtio_blk_device);
//     aio_bdev_deinit(&device->aio_bdev);
// }
