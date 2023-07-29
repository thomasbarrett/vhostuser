#ifndef BITmap_H
#define BITmap_H

#include <stdint.h>
#include <stddef.h>

typedef struct bitmap {
    uint16_t size;
    uint16_t word_count;
    uint32_t *words;
} bitmap_t;

/**
 * Initialize the map.
 * 
 * \param map: the map.
 * \param size: the map size.
 */
int bitmap_init(bitmap_t *map, uint16_t size);

/**
 * Deinitialize the map.
 * 
 * \param map: the map.
 * \param size: the map size.
 */
void bitmap_deinit(bitmap_t *map);

/**
 * Return 
 *  
 * \param map: the map.
 * \param i: the index.
 */
int bitmap_has(bitmap_t *map, uint16_t i);

/**
 * Add the given index to the map.
 *
 * \param map: the map.
 * \param i: the index.
 */
void bitmap_add(bitmap_t *map, uint16_t i);

/**
 * Remove the given index from the map.
 *
 * \param map: the map.
 * \param i: the index.
 */
void bitmap_remove(bitmap_t *map, uint16_t i);

/**
 * Find the first map index with the given value.
 * 
 * \param map: the map.
 * \param start: the start index.
 * \param b: the value.
 */
int32_t bitmap_find(bitmap_t *map, uint16_t start, int b);

#endif
