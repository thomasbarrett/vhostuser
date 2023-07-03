#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stddef.h>

typedef struct queue {
    size_t front;
    size_t rear;
    size_t size;
    size_t capacity;
    uint32_t *data;
} queue_t;

int queue_init(queue_t *q, size_t capacity);
void queue_deinit(queue_t *q);
int queue_push(queue_t *q, uint32_t b);
int queue_pop(queue_t *q, uint32_t *b);
size_t queue_size(queue_t *q);
size_t queue_capacity(queue_t *q);
void queue_clear(queue_t *q);

#endif /* QUEUE_H */
