// CFLAGS: -Wl,--wrap=mmap -Wl,--wrap=munmap -Wl,--wrap=close
#include <src/guest.c>
#include <assert.h>

void* __wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, __off_t offset) {
    assert(addr == NULL);
    assert(len == 0x1000);
    assert(offset == 0x1000);
    assert(fd = 3);
    return (void*) 0x20000;
}

int __wrap_munmap(void *addr, size_t len) {
    assert(addr == (void*) 0x20000);
    assert(len = 0x1000);
    return 0;
}

int __wrap_close(int fd) {
    assert(fd == 3);
    return 0;
}

void test_guest_memory_init(void) {
    guest_memory_t mem;

    guest_memory_init(&mem);
    guest_memory_deinit(&mem);
}

void test_guest_memory_guest_to_addr(void) {
    guest_memory_t mem;
    void *addr;

    guest_memory_init(&mem);
    assert(guest_memory_add_region(&mem, 3, 0x1000, 0x1000, 0x2000, 0x10000) == 0);
    assert(guest_memory_guest_to_addr(&mem, 0x2000, &addr) == 0);
    assert(addr == (void*) 0x20000);
    assert(guest_memory_guest_to_addr(&mem, 0x2001, &addr) == 0);
    assert(addr == (void*) 0x20001);
    assert(guest_memory_guest_to_addr(&mem, 0x2fff, &addr) == 0);
    assert(addr == (void*) 0x20fff);
    assert(guest_memory_guest_to_addr(&mem, 0x3000, &addr) == -1);
    guest_memory_deinit(&mem);
}

void test_guest_memory_user_to_guest(void) {
    guest_memory_t mem;
    uint64_t addr;

    guest_memory_init(&mem);
    assert(guest_memory_add_region(&mem, 3, 0x1000, 0x1000, 0x2000, 0x10000) == 0);
    assert(guest_memory_user_to_guest(&mem, 0x10000, &addr) == 0);
    assert(addr == 0x2000);
    assert(guest_memory_user_to_guest(&mem, 0x10001, &addr) == 0);
    assert(addr == 0x2001);
    assert(guest_memory_user_to_guest(&mem, 0x10fff, &addr) == 0);
    assert(addr == 0x2fff);
    assert(guest_memory_user_to_guest(&mem, 0x11000, &addr) == -1);
    guest_memory_deinit(&mem);
}

void test_guest_memory_user_to_mmap(void) {
    guest_memory_t mem;
    void *addr;

    guest_memory_init(&mem);
    assert(guest_memory_add_region(&mem, 3, 0x1000, 0x1000, 0x2000, 0x10000) == 0);
    assert(guest_memory_user_to_mmap(&mem, 0x10000, &addr) == 0);
    assert(addr == (void*) 0x20000);
    assert(guest_memory_user_to_mmap(&mem, 0x10001, &addr) == 0);
    assert(addr == (void*) 0x20001);
    assert(guest_memory_user_to_mmap(&mem, 0x10fff, &addr) == 0);
    assert(addr == (void*) 0x20fff);
    assert(guest_memory_user_to_mmap(&mem, 0x11000, &addr) == -1);
    guest_memory_deinit(&mem);
}

int main(void) {
    test_guest_memory_init();
    test_guest_memory_guest_to_addr();
    test_guest_memory_user_to_guest();
    test_guest_memory_user_to_mmap();
    return 0;
}
