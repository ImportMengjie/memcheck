#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <malloc.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <unordered_map>

#define SIZE_OF_STACKTRACE 32
#define SIZE_OF_CHUNCK_INFO_LEN 100000
#define DUMMY_BUFFER_SIZE 204800

typedef void *(*malloc_func_type)(size_t size);
typedef void (*free_func_type)(void *);
typedef void *(*calloc_func_type)(size_t nmemb, size_t size);
typedef void *(*realloc_func_type)(void *, size_t size);

static malloc_func_type glibc_malloc = NULL;
static free_func_type glibc_free = NULL;

extern "C" {
void *dummy_malloc(size_t size);
void dummy_free(void *ptr);
void *dummy_calloc(size_t nmemb, size_t size);
void *dummy_realloc(void *block, size_t size);
}

static malloc_func_type run_malloc = dummy_malloc;
static free_func_type run_free = dummy_free;
static calloc_func_type run_calloc = dummy_calloc;
static realloc_func_type run_relloc = dummy_realloc;

template <typename T>
class MyAllocator {
public:
    using value_type = T;

    MyAllocator() noexcept = default;

    template <typename U>
    MyAllocator(const MyAllocator<U> &) noexcept {}

    T *allocate(std::size_t n) { return static_cast<T *>(glibc_malloc(n * sizeof(T))); }

    void deallocate(T *p, std::size_t n) noexcept {
        destroy(p);
        glibc_free(p);
    }

    void destroy(T *p) { p->~T(); }
};

template <typename T, typename U>
bool operator==(const MyAllocator<T> &, const MyAllocator<U> &) {
    return true;
}

template <typename T, typename U>
bool operator!=(const MyAllocator<T> &, const MyAllocator<U> &) {
    return false;
}

template <class T, size_t SIZE>
class CycleQueue {
private:
    T data_[SIZE];
    int head_ = 0;
    int tail_ = 0;
    std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;

public:
    CycleQueue() = default;

    void push(const T &item) {
        std::unique_lock<std::mutex> lk(mutex_);
        not_full_.wait(lk, [this] {
            if ((tail_ + 1) % SIZE == head_) {
                std::cerr << "memcheck: Queue is full, wait.." << std::endl;
                return false;
            }
            return true;
        });
        data_[tail_] = item;
        tail_ = (tail_ + 1) % SIZE;
        not_empty_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lk(mutex_);
        not_empty_.wait(lk, [this] {
            if (head_ == tail_) {
                std::cerr << "memcheck: Queue is empty, waiting.." << std::endl;
                return false;
            }
            return true;
        });
        T item = data_[head_];
        head_ = (head_ + 1) % SIZE;
        not_full_.notify_one();
        return item;
    }

    bool fullPop(T &result) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto len = (tail_ - head_ + SIZE) % SIZE;
        if (SIZE - len <= 100) {
            result = data_[head_];
            head_ = (head_ + 1) % SIZE;
            not_full_.notify_one();
            return true;
        }
        return false;
    }
};

struct ChunckInfo {
    void *array[SIZE_OF_STACKTRACE];
    int stack_num = 0;
    size_t size;
    void *mem;
    bool remalloc = false;
};

CycleQueue<ChunckInfo, SIZE_OF_CHUNCK_INFO_LEN> chunckInfoQueue;
std::unordered_map<void *, ChunckInfo, std::hash<void *>, std::equal_to<void *>, MyAllocator<std::pair<const void *, ChunckInfo>>>
    chunckInfoMap;
std::recursive_mutex chunckInfoMapMutex;

const uint8_t magic_byte = 0x55;
thread_local bool hook = true;

void pop_full_chuck_info_queue() {
    ChunckInfo info;
    if (chunckInfoQueue.fullPop(info)) {
        bool error = false;
        for (size_t i = 0; i < info.size; ++i) {
            if (((char *)info.mem)[i] != magic_byte) {
                if (false == error) std::cerr << "memcheck: error p: " << info.mem;
                std::cerr << ", " << i << ": " << +((uint8_t *)info.mem)[i];
                error = true;
            }
        }
        if (error) {
            std::cerr << std::endl;
            char **stacktrace = backtrace_symbols(info.array, info.stack_num);
            for (int i = 0; i < info.stack_num; ++i) {
                std::cerr << "memcheck " << stacktrace[i] << std::endl;
            }
            std::cerr << std::endl;
            glibc_free(stacktrace);
            std::terminate();
        }
        glibc_free(info.mem);
    }
}

extern "C" {

void *dummy_malloc(size_t size) {
    char *data = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return data;
}

void *dummy_calloc(size_t nmemb, size_t size) {
    char *ptr = (char *)dummy_malloc(nmemb * size);
    for (size_t i = 0; i < nmemb * size; ++i) *((char *)(ptr + i)) = 0;
    return ptr;
}

void *dummy_realloc(void *block, size_t size) { return dummy_malloc(size); }

void dummy_free(void *ptr) {}

void *malloc(size_t size) { return run_malloc(size); }

void *memcheck_malloc(size_t size) {
    void *ret = glibc_malloc(size);
    if (!hook) {
        return ret;
    }
    hook = false;
    ChunckInfo info;
    info.stack_num = backtrace(info.array, SIZE_OF_STACKTRACE);
    info.size = size;
    info.mem = ret;
    {
        std::lock_guard<std::recursive_mutex> lk(chunckInfoMapMutex);
        chunckInfoMap[ret] = info;
    }
    pop_full_chuck_info_queue();
    hook = true;
    return ret;
}

void free(void *block) { return run_free(block); }

void memcheck_free(void *block) {
    if (!hook) glibc_free(block);
    if (!block) return;
    hook = false;
    ChunckInfo info;
    info.size = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(chunckInfoMapMutex);
        if (chunckInfoMap.count(block)) {
            info = chunckInfoMap[block];
            chunckInfoMap.erase(block);
        } else {
            std::cerr << "memcheck double free: " << block << std::endl;
            glibc_free(block);
            std::terminate();
            return;
        }
    }
    std::memset(block, magic_byte, info.size);
    pop_full_chuck_info_queue();
    chunckInfoQueue.push(info);
    hook = true;
}

void *calloc(size_t num, size_t nsize) { return run_calloc(num, nsize); }

void *memcheck_calloc(size_t num, size_t nsize) {
    void *ret = malloc(num * nsize);
    if (ret) {
        std::memset(ret, 0, nsize * num);
    }
    return ret;
}

void *realloc(void *block, size_t size) { return run_relloc(block, size); }

void *memcheck_realloc(void *block, size_t size) {
    if (!block || !size) return malloc(size);
    {
        std::lock_guard<std::recursive_mutex> lk(chunckInfoMapMutex);
        if (chunckInfoMap.count(block)) {
            auto &info = chunckInfoMap[block];
            if (info.size >= size) return block;
            char *new_mem = (char *)malloc(size);
            if (new_mem) {
                for (int i = 0; i < info.size; i++) new_mem[i] = ((char *)info.mem)[i];
                glibc_free(info.mem);
                info.mem = new_mem;
                info.size = size;
                info.remalloc = true;
            }
            return new_mem;
        } else {
            std::cerr << "memcheck double free: " << block << std::endl;
            std::terminate();
            return NULL;
        }
    }
}

static void __attribute__((constructor)) init() {
    hook = false;
    run_malloc = dummy_malloc;
    run_free = dummy_free;
    run_calloc = dummy_calloc;
    run_relloc = dummy_realloc;
    glibc_malloc = (malloc_func_type)dlsym(RTLD_NEXT, "malloc");
    glibc_free = (free_func_type)dlsym(RTLD_NEXT, "free");
    if (glibc_malloc == NULL || glibc_free == NULL) std::terminate();
    run_malloc = memcheck_malloc;
    run_free = memcheck_free;
    run_calloc = memcheck_calloc;
    run_relloc = memcheck_realloc;
    fprintf(stderr, "memcheck inited..\n");
    hook = true;
    // fprintf(stderr, "memcheck dummy_size: %lu , buf_size: %d, buf_addr: %p\n", tmppos, DUMMY_BUFFER_SIZE, tmpbuf);
    // std::cerr << "memcheck dummy_size: " << tmppos << ", allocs: " << tmpallocs << ", buf_size: " << DUMMY_BUFFER_SIZE;
}

static void __attribute__((destructor)) destructor() { fprintf(stderr, "memcheck destructor..\n"); }
}
