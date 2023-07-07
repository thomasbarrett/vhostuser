#include <src/queue.c>
#include <assert.h>

void test_queue_init(void) {
    queue_t q;

    assert(queue_init(&q, 4) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);

    queue_deinit(&q);
}

void test_queue_pop(void) {
    queue_t q;
    uint32_t e;
    assert(queue_init(&q, 4) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);

    assert(queue_push(&q, 42) == 0);
    assert(queue_size(&q) == 1);
    assert(queue_capacity(&q) == 4);

    assert(queue_pop(&q, &e) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);
    assert(e == 42);

    queue_deinit(&q);
}

void test_queue_pop_error_empty(void) {
    queue_t q;
    uint32_t e;

    assert(queue_init(&q, 4) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);

    assert(queue_pop(&q, &e) == -1);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);

    queue_deinit(&q);
}

void test_queue_push(void) {
    queue_t q;
    assert(queue_init(&q, 4) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 4);

    assert(queue_push(&q, 1) == 0);
    assert(queue_size(&q) == 1);
    assert(queue_capacity(&q) == 4);

    queue_deinit(&q);
}

void test_queue_push_error_full(void) {
    queue_t q;
    assert(queue_init(&q, 3) == 0);
    assert(queue_size(&q) == 0);
    assert(queue_capacity(&q) == 3);

    assert(queue_push(&q, 1) == 0);
    assert(queue_size(&q) == 1);
    assert(queue_capacity(&q) == 3);
    assert(queue_push(&q, 2) == 0);
    assert(queue_size(&q) == 2);
    assert(queue_capacity(&q) == 3);
    assert(queue_push(&q, 3) == 0);
    assert(queue_size(&q) == 3);
    assert(queue_capacity(&q) == 3);
    assert(queue_push(&q, 4) == -1);
    assert(queue_size(&q) == 3);
    assert(queue_capacity(&q) == 3);

    queue_deinit(&q);
}

int main(void) {
    test_queue_init();
    test_queue_push();
    test_queue_push_error_full();
    test_queue_pop();
    test_queue_pop_error_empty();
    return 0;
}
