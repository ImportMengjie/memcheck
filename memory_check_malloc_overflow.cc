#include <errno.h>
#include <execinfo.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

extern "C" {

void print_stacktrace() {
    int size = 32;
    void *array[32];
    int stack_num = backtrace(array, size);
    char **stacktrace = backtrace_symbols(array, stack_num);
    for (int i = 0; i < stack_num; ++i) {
        fprintf(stderr, "memcheck %s\n", stacktrace[i]);
    }
    free(stacktrace);
}

const uint64_t magic = (0x55555555ul << 32) + 0x55555555ul;

struct Header {
    size_t size;
    uint64_t boundary;
};

struct Footer {
    uint64_t boundary;
};

void *malloc(size_t size) {
    char *data = (char *)mmap(NULL, size + sizeof(struct Header) + sizeof(struct Footer), PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) return NULL;

    ((struct Header *)data)->size = size;
    ((struct Header *)data)->boundary = magic;
    ((struct Footer *)(data + sizeof(struct Header) + size))->boundary = magic;
    return data + sizeof(struct Header);
}

void free(void *block) {
    // static uint i = 0;
    if (!block) return;
    struct Header *header = (struct Header *)((char *)block - sizeof(struct Header));
    uint64_t header_boundary = header->boundary;
    uint64_t footer_boundary = ((struct Footer *)((char *)block + header->size))->boundary;
    // if (0 == i++ % 200000) {
    //     fprintf(stderr, "memcheck call free: header:%lu, footer: %lu, size: %d\n", header_boundary, footer_boundary, header->size);
    // }
    if (header_boundary != magic || footer_boundary != magic) {
        fprintf(stderr, "memcheck error: header:%lu, footer: %lu\n", header_boundary, footer_boundary);
        print_stacktrace();
    }
    size_t size = ((struct Header *)((char *)block - sizeof(struct Header)))->size + sizeof(struct Header) + sizeof(struct Footer);
    if (munmap((char *)block - sizeof(struct Header), size) != 0) {
        fprintf(stderr, "munmap error, errono: %s", strerror(errno));
        print_stacktrace();
    }
}

void *calloc(size_t num, size_t nsize) { return malloc(num * nsize); }

void *realloc(void *block, size_t size) {
    if (!block || !size) return malloc(size);
    struct Header *head = (struct Header *)block - 1;
    if (head->size >= size) return block;
    char *ret = (char *)malloc(size);
    if (ret) {
        for (int i = 0; i < head->size; i++) ret[i] = ((char *)block)[i];
        free(block);
    }
    return ret;
}
}
