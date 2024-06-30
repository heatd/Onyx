/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>

#include <onyx/cpu.h>
#include <onyx/scheduler.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>

#include <onyx/atomic.hpp>

#ifdef CONFIG_KASAN_MINIMAL_QUARANTINE
#define QUARANTINE_DEFAULT_MAX_SIZE_PCPU 0x8000
#define QUARANTINE_DEFAULT_MAX_SIZE      0x1000000
#else
#define QUARANTINE_DEFAULT_MAX_SIZE      0x10000000
#define QUARANTINE_DEFAULT_MAX_SIZE_PCPU 0x100000
#endif

void kmem_free_kasan(void *ptr);

/**
 * @brief Each quarantine chunk is a pointer to the next chunk, or nullptr
 * It fits nicely with the slab allocator's bufctl structure, since that structure
 * is approx. struct bufctl {struct bufctl *next; unsigned int flags;}; and our structure
 * overlays on top of bufctl. This makes it so SLAB's double-free detection using flags will
 * still work.
 *
 */
struct quarantine_chunk
{
    struct quarantine_chunk *next;
};

/**
 * @brief Each quarantine queue is just a simple, manual singly-linked-list of quarantine_chunks.
 * The quarantine queues track their maximum size and the current size, as to know when to flush.
 * They also track the number of flushes.
 */
struct quarantine_queue
{
    quarantine_chunk *global_queue_head_{nullptr}, *global_queue_tail_{nullptr};
    size_t max_size_;
    size_t cur_size_{0};
    size_t nr_flushes_{0};

    constexpr quarantine_queue(size_t max_size) : max_size_{max_size}
    {
    }

    /**
     * @brief Check if the queue is overflowing (cur_size > max_size)
     *
     * @return True if overflowing, else false
     */
    bool overflowing() const
    {
        return cur_size_ >= max_size_;
    }

    /**
     * @brief Add a chunk to the queue
     *
     * @param chunk Chunk to add
     * @param chunk_size Size of the chunk, in bytes
     */
    void add_chunk(quarantine_chunk *chunk, size_t chunk_size)
    {
        chunk->next = nullptr;

        if (!global_queue_head_)
        {
            global_queue_head_ = chunk;
        }

        if (global_queue_tail_)
        {
            global_queue_tail_->next = chunk;
        }

        global_queue_tail_ = chunk;

        cur_size_ += chunk_size;
    }

    /**
     * @brief Reset the queue.
     * Also increments nr_flushes_.
     *
     */
    void reset()
    {
        cur_size_ = 0;
        global_queue_head_ = global_queue_tail_ = nullptr;
        nr_flushes_++;
    }

    /**
     * @brief Transfer another queue's elements to this queue.
     * The other queue will be reset().
     *
     * @param q Queue whose elements we want to add
     */
    void xfer_in(quarantine_queue &q)
    {
        if (!q.global_queue_head_)
            return;
        if (!global_queue_head_)
        {
            global_queue_head_ = q.global_queue_head_;
            global_queue_tail_ = q.global_queue_tail_;
        }
        else
        {
            global_queue_tail_->next = q.global_queue_head_;
            global_queue_tail_ = q.global_queue_tail_;
        }

        cur_size_ += q.cur_size_;

        q.reset();
    }
};

struct quarantine_percpu
{
    quarantine_queue queue{QUARANTINE_DEFAULT_MAX_SIZE_PCPU};
    atomic<int> touched;
} __align_cache;

/**
 * @brief Our quarantine (used for KASAN now, possibly more in the future) is based
 * on small percpu queues and a very large global queue. The point of this quarantine is
 * to let objects sit for a good while before they're reused, so KASAN and others are more
 * effective.
 */
class quarantine
{
private:
    quarantine_queue queue_{QUARANTINE_DEFAULT_MAX_SIZE};
    spinlock queue_lock_;
    quarantine_percpu pcpu_[CONFIG_SMP_NR_CPUS];

    /**
     * @brief Add a chunk to the global quarantine queue
     *
     * @param chunk Chunk to add
     * @param chunk_size Size of the chunk, in bytes
     */
    void add_chunk_global(quarantine_chunk *chunk, size_t chunk_size);

    /**
     * @brief Flush this cpu's pcpu quarantine queue
     *
     */
    void flush_pcpu();

public:
    constexpr quarantine()
    {
        spinlock_init(&queue_lock_);
    }

    /**
     * @brief Add a chunk to the quarantine
     *
     * @param chunk Pointer to the chunk
     * @param chunk_size Size of the chunk, in bytes
     */
    void add_chunk(quarantine_chunk *chunk, size_t chunk_size);

    /**
     * @brief Pop all of the quarantine's elements
     *
     */
    void pop();

    /**
     * @brief Pop the global queue and unlock, before freeing.
     *
     */
    void pop_and_unlock(scoped_lock<spinlock> &g);

    /**
     * @brief Flush the Quarantine
     *
     */
    void flush();
};

/**
 * @brief Add a chunk to the global quarantine queue
 *
 * @param chunk Chunk to add
 * @param chunk_size Size of the chunk, in bytes
 */
void quarantine::add_chunk_global(quarantine_chunk *chunk, size_t chunk_size)
{
    scoped_lock g{queue_lock_};

    queue_.add_chunk(chunk, chunk_size);

    if (queue_.overflowing())
    {
        pop();
    }
}

/**
 * @brief Pop all of the quarantine's elements
 *
 */
void quarantine::pop()
{
    // Go through each element in the list, free it using kmem_free_kasan()
    quarantine_chunk *c = queue_.global_queue_head_;

    while (c)
    {
        auto next = c->next;
        kmem_free_kasan(c);
        c = next;
    }

    queue_.reset();
}

/**
 * @brief Pop the global queue and unlock, before freeing.
 *
 */
void quarantine::pop_and_unlock(scoped_lock<spinlock> &g)
{
    // We're using a variant of pop() to be able to transfer the whole queue to a local one
    // and therefore free the queue_lock_, which would block every other thread on this very
    // expensive operation.
    quarantine_queue q{queue_.max_size_};
    q.xfer_in(queue_);

    g.unlock();

    // Now free

    quarantine_chunk *c = q.global_queue_head_;

    while (c)
    {
        auto next = c->next;
        kmem_free_kasan(c);
        c = next;
    }
}

/**
 * @brief Add a chunk to the quarantine
 *
 * @param chunk Pointer to the chunk
 * @param chunk_size Size of the chunk, in bytes
 */
void quarantine::add_chunk(quarantine_chunk *chunk, size_t chunk_size)
{
    // First, we try to add ourselves to the percpu queue, similar to the
    // slab allocator's magazines
    // The <touched> member serves a similar purpose to the slab allocator's touched.
    // i.e it makes sure there's no CPU getting interrupted for flushing when running this
    // semi-critical section.

    sched_disable_preempt();

    auto &pcpu = pcpu_[get_cpu_nr()];
    pcpu.touched.store(1, mem_order::release);

    pcpu.queue.add_chunk(chunk, chunk_size);

    if (pcpu.queue.overflowing())
    {
        // If we're overflowing, we'll transfer the whole list to the global queue
        scoped_lock g{queue_lock_};
        queue_.xfer_in(pcpu.queue);

        // Since pop may take a while, release the pcpu touched
        pcpu.touched.store(0, mem_order::release);

        // If the queue is now overflowing, now that we've added our pcpu queue to it, pop.
        // We're using a variant of pop() to be able to transfer the whole queue to a local one
        // and therefore free the queue_lock_, which would block every other thread on this very
        // expensive operation.
        if (queue_.overflowing())
            pop_and_unlock(g);
    }

    pcpu.touched.store(0, mem_order::release);

    sched_enable_preempt();
}

constinit static quarantine kasan_quarantine;

/**
 * @brief Add a chunk to the KASAN quarantine
 * Note that the quarantine is careful enough not to overwrite
 * bufctl's flags. This makes normal double-free detection still work.
 *
 * @param ptr Pointer to the chunk
 * @param chunk_size Size of the chunk, in bytes
 */
void kasan_quarantine_add_chunk(void *ptr, size_t chunk_size)
{
    kasan_quarantine.add_chunk((quarantine_chunk *) ptr, chunk_size);
}

/**
 * @brief Flush this cpu's pcpu quarantine queue
 *
 */
void quarantine::flush_pcpu()
{
    auto &pcpu = pcpu_[get_cpu_nr()];
    if (pcpu.touched)
        return;

    scoped_lock g{queue_lock_};
    queue_.xfer_in(pcpu.queue);
}

/**
 * @brief Flush the quarantine
 *
 */
void quarantine::flush()
{
    // Flush every CPU's queue directly. Each object goes back to the slab allocator
    sched_disable_preempt();

    smp::sync_call([](void *ctx) { ((quarantine *) ctx)->flush_pcpu(); }, this, cpumask::all());

    sched_enable_preempt();

    // Flush the global queue
    scoped_lock g{queue_lock_};
    pop();
}

/**
 * @brief Flush the KASAN memory quarantine
 *
 */
extern "C" void kasan_flush_quarantine()
{
    kasan_quarantine.flush();
}
