#include <src/vhost-user.c>
#include <src/guest.c>
#include <src/virtio-core.c>
#include <src/log.c>
#include <src/task.c>
#include <src/bitmap.c>
#include <src/virtio-blk.c>
#include <src/metrics.c>
#include <src/http.c>

bdev_vtable_t aio_bdev_vtable = {0};

int aio_bdev_init(aio_bdev_t* self, char *path, size_t queue_count, size_t queue_depth) {
    return 0;
}

void aio_bdev_deinit(aio_bdev_t *bdev) {

}

int main(void) {
    return 0;
}
