#include <src/vhost-user.c>
#include <src/guest_memory.c>
#include <src/virtio-core.c>
#include <src/log.c>
#include <src/task_queue.c>
#include <src/virtio-blk.c>
#include <src/metrics.c>
#include <src/http.c>

bdev_t* aio_bdev_create(char *path, size_t queue_count, size_t queue_depth) {
    return NULL;
}

void aio_bdev_destroy(bdev_t *bdev) {

}

int main(void) {
    return 0;
}
