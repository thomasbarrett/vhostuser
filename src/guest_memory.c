#include <guest_memory.h>
#include <unistd.h>
#include <sys/mman.h>

void guest_memory_init(guest_memory_t *mem) {
    mem->regions_len = 0;
}

void guest_memory_deinit(guest_memory_t *mem) {
    for (size_t i = 0; i < mem->regions_len; i++) {
        guest_memory_region_deinit(&mem->regions[i]);
    }
    mem->regions_len = 0;
}

int guest_memory_add_region(guest_memory_t *mem, int fd, uint64_t size, uint64_t mmap_offset, uint64_t guest_addr, uint64_t user_addr) {
    if (mem->regions_len == MAX_GUEST_MEMORY_REGIONS) return -1;
    return guest_memory_region_init(&mem->regions[mem->regions_len++], fd, size, mmap_offset, guest_addr, user_addr);
}

int guest_memory_region_init(guest_memory_region_t *reg, int fd, uint64_t size, uint64_t mmap_offset, uint64_t guest_addr, uint64_t user_addr) {
    reg->fd = fd;
    reg->addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmap_offset);
    if (reg->addr == MAP_FAILED) {
        return -1;
    }
    reg->guest_addr = guest_addr;
    reg->size = size;
    reg->user_addr = user_addr;

    return 0;
}

void guest_memory_region_deinit(guest_memory_region_t *reg) {
    munmap(reg->addr, reg->size);
    close(reg->fd);
}

int guest_memory_user_to_mmap(guest_memory_t *mem, uint64_t user_addr, void **mmap_addr) {
    for (size_t i = 0; i < mem->regions_len; i++) {
        guest_memory_region_t *region = &mem->regions[i];
        if (region->user_addr <= user_addr && (region->user_addr + region->size) > user_addr) {
            *mmap_addr = ((uint8_t*) region->addr) + (user_addr - region->user_addr);
            return 0;
        }
    }

    return -1;
}

int guest_memory_user_to_guest(guest_memory_t *mem, uint64_t user_addr, uint64_t *guest_addr) {
    for (size_t i = 0; i < mem->regions_len; i++) {
        guest_memory_region_t *region = &mem->regions[i];
        if (region->user_addr <= user_addr && (region->user_addr + region->size) > user_addr) {
            *guest_addr = region->guest_addr + (user_addr - region->user_addr);
            return 0;
        }
    }

    return -1;
}

int guest_memory_guest_to_addr(guest_memory_t *mem, uint64_t guest_addr, void **addr) {
    for (size_t i = 0; i < mem->regions_len; i++) {
        guest_memory_region_t *region = &mem->regions[i];
        if (region->guest_addr <= guest_addr && (region->guest_addr + region->size) > guest_addr) {
            *addr = ((uint8_t*) region->addr) + (guest_addr - region->guest_addr);
            return 0;
        }
    }

    return -1;
}
