#include <bitmap.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int bitmap_init(bitmap_t *map, uint16_t size) {
    memset(map, 0, sizeof(bitmap_t));
    map->size = size;
    map->word_count = (uint16_t) (((uint32_t) size + 31) >> 5);
    map->words = calloc(map->word_count, sizeof(uint32_t));
    if (map->words == NULL) {
        return -1;
    }

    return 0;
}

void bitmap_deinit(bitmap_t *map) {
    free(map->words);
}

int bitmap_has(bitmap_t *map, uint16_t i) {
    assert(i < map->size);
    uint16_t q = i >> 5;
    uint16_t r = i - q;
    return 1 & (map->words[q] >> r);
}

void bitmap_add(bitmap_t *map, uint16_t i) {
    assert(i < map->size);
    uint16_t q = i >> 5;
    uint16_t r = i - q;
    map->words[q] |= (uint32_t) 1 << r;
}

void bitmap_remove(bitmap_t *map, uint16_t i) {
    assert(i < map->size);
    uint16_t q = i >> 5;
    uint16_t r = i - q;
    map->words[q] &= ~((uint32_t) 1 << r);
}

int32_t bitmap_find(bitmap_t *map, uint16_t start, int b) {
    for (uint16_t i = start; i < map->size; i++) {
        if (bitmap_has(map, i) == b) {
            return i;
        }
    }

    return -1;
}
