#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>

#define MAX_GUEST_MEMORY_REGIONS 16

typedef struct guest_memory_region {
    int fd;
    void *addr;
    uint64_t guest_addr;
    uint64_t size;
    uint64_t user_addr;
} guest_memory_region_t;

typedef struct guest_memory {
    guest_memory_region_t regions[MAX_GUEST_MEMORY_REGIONS];
    size_t regions_len;
} guest_memory_t;

void guest_memory_init(guest_memory_t *mem);
void guest_memory_deinit(guest_memory_t *mem);
int guest_memory_add_region(guest_memory_t *mem, int fd, uint64_t size, uint64_t mmap_offset, uint64_t guest_addr, uint64_t user_addr);
int guest_memory_user_to_guest(guest_memory_t *mem, uint64_t user_addr, uint64_t *guest_addr);
int guest_memory_guest_to_addr(guest_memory_t *mem, uint64_t guest_addr, void **addr);
int guest_memory_user_to_mmap(guest_memory_t *mem, uint64_t user_addr, void **mmap_addr);

int guest_memory_region_init(guest_memory_region_t *reg, int fd, uint64_t size, uint64_t offset, uint64_t guest_addr, uint64_t user_addr);
void guest_memory_region_deinit(guest_memory_region_t *reg);

#endif /* MEMORY_H */
