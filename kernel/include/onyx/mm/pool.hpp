/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_MM_POOL_HPP
#define _ONYX_MM_POOL_HPP

#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>
#include <onyx/conditional.h>
#include <onyx/enable_if.h>
#include <onyx/mm/kasan.h>
#include <onyx/new.h>
#include <onyx/page.h>
#include <onyx/scoped_lock.h>
#include <onyx/vm.h>

#include <onyx/pair.hpp>
#include <onyx/utility.hpp>

#define OBJECT_POOL_ALLOCATE_WARM_CACHE

#ifdef CONFIG_POOL_CANARY
#define OBJECT_CANARY 0xcacacacacacacaca
#endif

#define OBJECT_POOL_DEFER_UNMAP

static constexpr size_t object_pool_alignment = 16UL;

template <typename T, bool use_vm>
class memory_pool_segment;

template <typename T>
struct memory_chunk
{
    struct memory_chunk *next;
    void *segment;
#ifdef OBJECT_CANARY
    unsigned long object_canary;
    unsigned long pad0;
#endif
    /* Note that this is 16-byte aligned */
} __attribute__((packed));

class memory_pool_segment_vm
{
protected:
    void *vmalloc_segment;

    void free(size_t pages)
    {
        vfree(vmalloc_segment, pages);
    }

    memory_pool_segment_vm() : vmalloc_segment{}
    {
    }

    bool valid_segment()
    {
        return vmalloc_segment != nullptr;
    }

public:
    void set_vmalloc_seg(void *seg)
    {
        vmalloc_segment = seg;
    }
};

class memory_pool_segment_pages
{
protected:
    struct page *pages;

    void free(size_t nr_pgs)
    {
        free_pages(pages);
    }

    memory_pool_segment_pages() : pages{}
    {
    }

    bool valid_segment()
    {
        return pages != nullptr;
    }

public:
    void set_pages(struct page *pages)
    {
        this->pages = pages;
    }
};

template <typename T, bool use_virtual_memory>
class memory_pool_segment : public conditional<use_virtual_memory, memory_pool_segment_vm,
                                               memory_pool_segment_pages>::type
{
private:
    size_t size;
    using segment_base = typename conditional<use_virtual_memory, memory_pool_segment_vm,
                                              memory_pool_segment_pages>::type;

public:
    size_t used_objs;
    memory_pool_segment *prev, *next;

    memory_pool_segment() : segment_base{}, size{}, used_objs{}, prev{nullptr}, next{nullptr}
    {
    }

    memory_pool_segment(size_t size)
        : segment_base{}, size{size}, used_objs{}, prev{nullptr}, next{nullptr}
    {
    }
    ~memory_pool_segment()
    {
        /* If mmap_segment is null, it's an empty object(has been std::move'd) */
        if (segment_base::valid_segment())
        {
            assert(used_objs == 0);
            // std::cout << "Freeing segment " << mmap_segment << "\n";
            segment_base::free(size >> PAGE_SHIFT);
        }
    }

    memory_pool_segment(const memory_pool_segment &rhs) = delete;
    memory_pool_segment &operator=(const memory_pool_segment &rhs) = delete;

    memory_pool_segment(memory_pool_segment &&rhs)
    {
        if (this == &rhs)
            return;

        if constexpr (use_virtual_memory)
        {
            segment_base::vmalloc_segment = rhs.vmalloc_segment;
            rhs.vmalloc_segment = nullptr;
        }
        else
        {
            segment_base::pages = rhs.pages;
            rhs.pages = nullptr;
        }

        size = rhs.size;
        used_objs = rhs.used_objs;
        prev = next = nullptr;

        rhs.size = SIZE_MAX;
        rhs.used_objs = 0;
        rhs.prev = rhs.next = nullptr;
    }

    memory_pool_segment &operator=(memory_pool_segment &&rhs)
    {
        if (this == &rhs)
            return *this;

        if constexpr (use_virtual_memory)
        {
            segment_base::vmalloc_segment = rhs.vmalloc_segment;
            rhs.vmalloc_segment = nullptr;
        }
        else
        {
            segment_base::pages = rhs.pages;
            rhs.pages = nullptr;
        }

        size = rhs.size;
        used_objs = rhs.used_objs;

        rhs.size = SIZE_MAX;
        rhs.used_objs = 0;

        return *this;
    }

    static constexpr bool is_large_object()
    {
        return sizeof(T) >= PAGE_SIZE / 8;
    }

    static constexpr size_t default_pool_size = PAGE_SIZE;

    static constexpr size_t size_of_chunk()
    {
        return cul::align_up2(sizeof(T), object_pool_alignment) + sizeof(memory_chunk<T>);
    }

    static constexpr size_t size_of_inline_segment()
    {
        return cul::align_up2(sizeof(memory_pool_segment), object_pool_alignment);
    }

    static constexpr size_t memory_pool_size()
    {
        if (is_large_object())
        {
            return cul::align_up2(size_of_inline_segment() + size_of_chunk() * 24,
                                  (size_t) PAGE_SIZE);
        }
        else
            return default_pool_size;
    }

    constexpr size_t number_of_objects()
    {
        return (memory_pool_size() - size_of_inline_segment()) / size_of_chunk();
    }

    NO_ASAN
    cul::pair<memory_chunk<T> *, memory_chunk<T> *> setup_chunks()
    {
        memory_chunk<T> *prev = nullptr;
        memory_chunk<T> *curr =
            reinterpret_cast<memory_chunk<T> *>((unsigned char *) this + size_of_inline_segment());
        auto first = curr;
        auto nr_objs = number_of_objects();

        while (nr_objs--)
        {
            curr->segment = reinterpret_cast<void *>(this);
#ifdef OBJECT_CANARY
            curr->object_canary = OBJECT_CANARY;
#endif
            curr->next = nullptr;
            if (prev)
                prev->next = curr;

            prev = curr;
            curr = reinterpret_cast<memory_chunk<T> *>(reinterpret_cast<unsigned char *>(curr) +
                                                       size_of_chunk());
        }

#ifdef CONFIG_KASAN
        if constexpr (use_virtual_memory)
        {
            kasan_alloc_shadow((unsigned long) this, size - size_of_inline_segment(), false);
            kasan_set_state((unsigned long *) this, size_of_inline_segment(), 0);
        }
#endif
        return cul::pair<memory_chunk<T> *, memory_chunk<T> *>(first, prev);
    }

    bool empty()
    {
        return used_objs == 0;
    }
};

#define MEMORY_POOL_USE_VM        (1 << 0)
#define MEMORY_POOL_USABLE_ON_IRQ (1 << 1)

template <typename T, int pool_flags = 0>
class memory_pool
{
private:
    memory_chunk<T> *free_chunk_head, *free_chunk_tail;
    struct spinlock lock;
    memory_pool_segment<T, pool_flags & MEMORY_POOL_USE_VM> *segment_head, *segment_tail;
    size_t nr_objects;

public:
    static constexpr bool using_vm = pool_flags & MEMORY_POOL_USE_VM;
    static constexpr bool usable_onirq = pool_flags & MEMORY_POOL_USABLE_ON_IRQ;

    static_assert(!(usable_onirq && using_vm),
                  "You may not use virtual memory mappings under IRQ context.");

    NO_ASAN
    void append_segment(memory_pool_segment<T, using_vm> *seg)
    {
        if (!segment_head)
        {
            segment_head = segment_tail = seg;
        }
        else
        {
            segment_tail->next = seg;
            seg->prev = segment_tail;
            segment_tail = seg;
        }

        seg->next = seg->prev = nullptr;
    }

    NO_ASAN void remove_segment(memory_pool_segment<T, using_vm> *seg)
    {
        if (seg->prev)
        {
            seg->prev->next = seg->next;
        }
        else
            segment_head = seg->next;

        if (seg->next)
            seg->next->prev = seg->prev;
        else
            segment_tail = seg->prev;

        seg->~memory_pool_segment<T, using_vm>();
    }

    NO_ASAN bool expand_pool()
    {
        // std::cout << "Expanding pool.\n";
        auto allocation_size = memory_pool_segment<T, using_vm>::memory_pool_size();

        memory_pool_segment<T, using_vm> seg{allocation_size};
        void *address = NULL;

        if constexpr (using_vm)
        {
            void *vmalloc_seg =
                vmalloc(allocation_size >> PAGE_SHIFT, VM_TYPE_REGULAR, VM_READ | VM_WRITE);
            if (!vmalloc_seg)
                return false;
            seg.set_vmalloc_seg(vmalloc_seg);
            address = vmalloc_seg;
        }
        else
        {
            struct page *pages = alloc_pages(allocation_size >> PAGE_SHIFT,
                                             PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
            if (!pages)
                return false;
            seg.set_pages(pages);
            address = PAGE_TO_VIRT(pages);
        }

        nr_objects += seg.number_of_objects();

        // std::cout << "Added " << new_mmap_region << " size " << allocation_size << "\n";

        auto &mmap_seg = *static_cast<memory_pool_segment<T, using_vm> *>(address);
        mmap_seg = cul::move(seg);

        auto pair = mmap_seg.setup_chunks();
        free_chunk_head = pair.first;
        free_chunk_tail = pair.second;

        append_segment(&mmap_seg);

        return true;
    }

    NO_ASAN
    inline memory_chunk<T> *ptr_to_chunk(T *ptr)
    {
        /* Memory is layed out like this:
         * ----------------------------------
         * memory_chunk<T>
         * ..................................
         * T data
         * ..................................
         * Possible padding in between chunks
         * ----------------------------------*/

        memory_chunk<T> *c = reinterpret_cast<memory_chunk<T> *>(ptr) - 1;
        return c;
    }

    NO_ASAN
    void free_list_purge_segment_chunks(memory_pool_segment<T, using_vm> *seg)
    {
        // std::cout << "Removing chunks\n";
        auto l = free_chunk_head;
        memory_chunk<T> *prev = nullptr;
        while (l)
        {
            // std::cout << "Hello " << l << "\n";
            if (l->segment == reinterpret_cast<void *>(seg))
            {
                // std::cout << "Removing chunk " << l << "\n";
                if (prev)
                    prev->next = l->next;
                else
                    free_chunk_head = l->next;

                if (!l->next)
                    free_chunk_tail = prev;
            }
            else
                prev = l;

            l = l->next;
        }
    }

    NO_ASAN
    void append_chunk_tail(memory_chunk<T> *chunk)
    {
        if (!free_chunk_tail)
        {
            free_chunk_head = free_chunk_tail = chunk;
        }
        else
        {
            free_chunk_tail->next = chunk;
            free_chunk_tail = chunk;
            assert(free_chunk_head != nullptr);
        }
    }

    NO_ASAN
    void append_chunk_head(memory_chunk<T> *chunk)
    {
        if (!free_chunk_head)
        {
            free_chunk_head = free_chunk_tail = chunk;
        }
        else
        {
            auto curr_head = free_chunk_head;
            free_chunk_head = chunk;
            free_chunk_head->next = curr_head;
            assert(free_chunk_tail != nullptr);
        }
    }

    NO_ASAN
    void purge_segment(memory_pool_segment<T, using_vm> *segment)
    {
        if (segment->empty())
        {
            /* We can still have free objects on the free list. Remove them. */
            free_list_purge_segment_chunks(segment);
            remove_segment(segment);
        }
    }

public:
    size_t used_objects;

    constexpr memory_pool()
        : free_chunk_head{nullptr}, free_chunk_tail{nullptr}, lock{}, segment_head{},
          segment_tail{}, nr_objects{0}, used_objects{0}
    {
    }

    void print_segments()
    {
    }

    ~memory_pool()
    {
        assert(used_objects == 0);
    }

    NO_ASAN
    T *allocate()
    {
        scoped_lock<spinlock, usable_onirq> guard{lock};

        while (!free_chunk_head)
        {
            if (!expand_pool())
            {
                // std::cout << "mmap failed\n";
                return nullptr;
            }
        }

        auto return_chunk = free_chunk_head;

        free_chunk_head = free_chunk_head->next;

        if (!free_chunk_head)
            free_chunk_tail = nullptr;

        reinterpret_cast<memory_pool_segment<T, using_vm> *>(return_chunk->segment)->used_objs++;
        used_objects++;

#ifdef OBJECT_CANARY
        assert(return_chunk->object_canary == OBJECT_CANARY);
#endif
#ifdef CONFIG_KASAN
        if constexpr (using_vm)
            kasan_set_state((unsigned long *) (return_chunk + 1), sizeof(T), 0);
#endif
        return reinterpret_cast<T *>(return_chunk + 1);
    }

    NO_ASAN
    void free(T *ptr)
    {
        auto chunk = ptr_to_chunk(ptr);
#ifdef CONFIG_KASAN
        if constexpr (using_vm)
            kasan_set_state((unsigned long *) ptr, sizeof(T), 1);
#endif
        // std::cout << "Removing chunk " << chunk << "\n";
        scoped_lock<spinlock, usable_onirq> guard{lock};

        chunk->next = nullptr;
#ifdef OBJECT_CANARY
        assert(chunk->object_canary == OBJECT_CANARY);
#endif

#ifndef OBJECT_POOL_ALLOCATE_WARM_CACHE
        append_chunk_tail(chunk);
#else
        append_chunk_head(chunk);
#endif

        used_objects--;
        auto segment = reinterpret_cast<memory_pool_segment<T, using_vm> *>(chunk->segment);
        segment->used_objs--;

#ifndef OBJECT_POOL_DEFER_UNMAP
        purge_segment(segment);
#endif
    }

    NO_ASAN
    void purge()
    {
        scoped_lock<spinlock, usable_onirq> g{lock};
        auto s = segment_head;

        while (s)
        {
            auto next = s->next;
            purge_segment(s);
            s = next;
        }
    }
};

#endif
