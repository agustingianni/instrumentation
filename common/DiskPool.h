//
// Created by Agustin Gianni on 11/18/16.
//

#ifndef DISKPOOL_H
#define DISKPOOL_H

#include <cstddef>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <iostream>

#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#if defined(TARGET_MAC)
#include <sys/syscall.h>
int ftruncate(int fildes, off_t length)
{
    return syscall(SYS_ftruncate, fildes, length);
}

int madvise(void *addr, size_t len, int advice)
{
    return syscall(SYS_madvise, addr, len, advice);
}
#endif

constexpr size_t KB(size_t size) { return size * 1024; }
constexpr size_t MB(size_t size) { return KB(size) * 1024; }
constexpr size_t GB(size_t size) { return MB(size) * 1024; }

// Implement a memory map policy using 'mmap'.
struct mmap_policy {
    static void* load(const char* filename, size_t size)
    {
        auto fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
            std::cerr << "Failed to open file: " << strerror(errno) << std::endl;
            abort();
        }

        if (ftruncate(fd, size) == -1) {
            close(fd);
            std::cerr << "Failed to ftruncate file: " << strerror(errno) << std::endl;
            abort();
        }

        auto address = reinterpret_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0));
        if (address == MAP_FAILED) {
            close(fd);
            std::cerr << "Failed to map file: " << strerror(errno) << std::endl;
            abort();
        }

        if (close(fd) != 0) {
            unload(address, size);
            std::cerr << "Failed to close file: " << strerror(errno) << std::endl;
            abort();
        }

        return address;
    }

    static void unload(void* address, size_t size)
    {
        if (munmap(address, size) != 0) {
            std::cerr << "Failed to unmap file: " << strerror(errno) << std::endl;
            abort();
        }
    }

    static void flush(void* address, size_t size)
    {
        if (madvise(address, size, MADV_DONTNEED)) {
            std::cerr << "Failed to flush memory: " << strerror(errno) << std::endl;
            abort();
        }
    }
};

// Implement a policy that increments the value non atomically.
template <typename T = size_t>
class RawIncrement {
private:
    T m_top{ 0 };

public:
    T increment(T size)
    {
        auto tmp = m_top;
        m_top += size;
        return tmp;
    }
};

// Implement a policy that uses std::atomic to increment the value.
// template <typename T = size_t> class AtomicIncrement {
// private:
//     std::atomic<T> m_top{0};

// public:
//     T increment(T size) {
//         return m_top.fetch_add(size, std::memory_order_relaxed);
//     }
// };

// A 'DiskPool' is a named file backed memory allocator.
template <typename IncrementPolicy = RawIncrement<size_t>, typename FileMapPolicy = mmap_policy>
class DiskPool : public IncrementPolicy {
protected:
    uint8_t* m_address;
    size_t m_size;

public:
    DiskPool(const char* filename, size_t size)
        : m_size{ size }
    {
        m_address = static_cast<uint8_t*>(FileMapPolicy::load(filename, m_size));
    }

    ~DiskPool()
    {
        FileMapPolicy::unload(m_address, m_size);
    }

    uint8_t* alloc(size_t size)
    {
        return m_address + IncrementPolicy::increment(size);
    }

    void flush() const
    {
        FileMapPolicy::flush(m_address, m_size);
    }

private:
    // Avoid moves and copies.
    DiskPool(const DiskPool&) = delete;
    DiskPool& operator=(const DiskPool&) = delete;
    DiskPool(DiskPool&&) = delete;
    DiskPool& operator=(DiskPool&&) = delete;
};

// Define basic DiskPool implementations to be used by the client.
using DiskPoolRaw = DiskPool<RawIncrement<size_t>>;
// using DiskPoolAtomic = DiskPool<AtomicIncrement<size_t>>;

#endif //DISKPOOL_H
