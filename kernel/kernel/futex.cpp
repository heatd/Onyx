/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <onyx/fnv.h>
#include <onyx/futex.h>
#include <onyx/list.h>
#include <onyx/pagecache.h>
#include <onyx/process.h>
#include <onyx/user.h>
#include <onyx/wait_queue.h>

#include <onyx/hashtable.hpp>
#include <onyx/memory.hpp>
#include <onyx/pair.hpp>

/* This union describes the key used to match futexes with each other.
 * For private mappings, we use the mm_address_space address of the process and
 * the pointer to futex value.
 * For shared mappings, we're going to use the vmo's address and the page_offset.
 * Note that the offset within the page is always used and has some lower bits used,
 * since they need to be clear(the address needs to be 4-byte aligned).
 */

#define FUTEX_OFFSET_SHARED  (1 << 0)
#define FUTEX_OFFSET_PRIVATE (1 << 1)

namespace futex
{

struct futex_key
{
    union {
        struct
        {
            struct vm_object *vmo;
            size_t page_offset;
            unsigned int off;
        } shared;

        struct
        {
            struct mm_address_space *as;
            int *ptr;
            unsigned int off;
        } private_mapping;

        struct
        {
            uint64_t data[2];
            unsigned int offset;
            unsigned int padding;
        } both;
    };

    futex_key()
    {
        /* Explicitly zero everything */
        shared.vmo = nullptr;
        shared.page_offset = 0;
        private_mapping.as = nullptr;
        private_mapping.ptr = nullptr;
        both.offset = 0;
        both.padding = 0;
    }

    bool operator==(const futex_key &k) const
    {
        if (both.offset != k.both.offset)
        {
            printk("%d != %d\n", both.offset, k.both.offset);
            return false;
        }

        bool _private = k.both.offset & FUTEX_OFFSET_PRIVATE;

        if (_private)
        {
            return private_mapping.as == k.private_mapping.as &&
                   private_mapping.ptr == k.private_mapping.ptr;
        }
        else
            return shared.page_offset == k.shared.page_offset && shared.vmo == k.shared.vmo;
    }
};

class futex_queue
{
public:
    futex_key key;
    bool awaken;
    wait_queue wq;
    list_head_cpp<futex_queue> list_node;

    futex_queue(futex_key key) : key(key), awaken(false), wq{}, list_node{this}
    {
        init_wait_queue_head(&wq);
    }

    ~futex_queue()
    {
    }

    int wait(hrtime_t _timeout, struct spinlock *s)
    {
        MUST_HOLD_LOCK(s);
        return wait_for_event_locked_timeout_interruptible(&wq, awaken, _timeout, s);
    }

    int wait(struct spinlock *s)
    {
        MUST_HOLD_LOCK(s);
        return wait_for_event_locked_interruptible(&wq, awaken, s);
    }

    void wake()
    {
        list_remove(&list_node);
        awaken = true;

        COMPILER_BARRIER();

        wait_queue_wake_all(&wq);
    }

    futex_key &get_key()
    {
        return key;
    }

    bool was_awaken() const
    {
        return awaken;
    }

    void requeue(const futex_key &new_key, struct list_head *new_head);
};

inline uint32_t __futex_hash(futex_key &key)
{
    return fnv_hash(&key.both, sizeof(key.both));
}

uint32_t futex_hash(futex_queue &queue)
{
    return __futex_hash(queue.get_key());
}

/* We're holding a system-wide hashtable for futexes. Each bucket has a separate
 * lock to encourage concurrency. Futexes are hashed by the fnv of the futex key, whose values
 * depend on the type of mapping.
 */

static constexpr size_t futex_hashtable_buckets = 1024;
static cul::hashtable2<futex_queue, futex_hashtable_buckets, uint32_t, futex_hash> futex_hashtable;
static struct spinlock futex_hashtable_locks[futex_hashtable_buckets];

uint32_t get_hashtable(futex_key &key)
{
    auto hash = __futex_hash(key);
    auto index = futex_hashtable.get_hashtable_index(hash);

    spin_lock(&futex_hashtable_locks[index]);

    return index;
}

cul::pair<uint32_t, uint32_t> lock_two_hashes(futex_key &key1, futex_key &key2)
{
    const auto hash1 = __futex_hash(key1);
    const auto hash2 = __futex_hash(key2);

    auto index1 = futex_hashtable.get_hashtable_index(hash1);
    auto index2 = futex_hashtable.get_hashtable_index(hash2);

    if (index1 < index2)
    {
        spin_lock(&futex_hashtable_locks[index1]);
        spin_lock(&futex_hashtable_locks[index2]);
    }
    else if (index1 > index2)
    {
        spin_lock(&futex_hashtable_locks[index2]);
        spin_lock(&futex_hashtable_locks[index1]);
    }
    else
    {
        /* Only lock once if it's the same bucket */
        spin_lock(&futex_hashtable_locks[index1]);
    }

    return {index1, index2};
}

void unlock_two_hashes(uint32_t index1, uint32_t index2)
{
    if (index1 > index2)
    {
        spin_unlock(&futex_hashtable_locks[index1]);
        spin_unlock(&futex_hashtable_locks[index2]);
    }
    else if (index1 < index2)
    {
        spin_unlock(&futex_hashtable_locks[index2]);
        spin_unlock(&futex_hashtable_locks[index1]);
    }
    else
    {
        /* Only lock once if it's the same bucket */
        spin_unlock(&futex_hashtable_locks[index1]);
    }
}

int calculate_key(int *uaddr, int flags, futex_key &out_key)
{
    bool private_ftx = flags & FUTEX_PRIVATE_FLAG;
    auto address_space = get_current_address_space();
    auto offset_within_page = (unsigned long)uaddr & (PAGE_SIZE - 1);
    bool is_shared = false;

    /* If it was already specified to be a private futex(thanks user-space!),
     * we can just shortpath our way out.
     */

    if (private_ftx)
    {
    private_futex_out:
        out_key.private_mapping.as = address_space;
        out_key.private_mapping.ptr = uaddr;
        out_key.both.offset = offset_within_page | FUTEX_OFFSET_PRIVATE;
        return 0;
    }

    struct page *page;
    int st;
    st = get_phys_pages(uaddr, GPP_READ, &page, 1);

    if (!(st & GPP_ACCESS_OK))
        return -EFAULT;

    is_shared = st & GPP_ACCESS_SHARED;

    /* VMO mappings are marked as MAP_SHARED BUT don't have page->cache filled out.
     * TODO: We should be able to shared-wait on vmo mappings(maybe replace
     * page->cache with a page->owning_vmo or something like that(or a union)). */
    bool is_vmo_mapping = is_shared && page->cache == nullptr;

    if (!is_shared || is_vmo_mapping)
    {
        /* This is a private mapping, treat it like the above. */
        page_unpin(page);
        goto private_futex_out;
    }

    auto inode = page->cache->node;
    auto page_offset = page->cache->offset;
    auto vmo = inode->i_pages;

    out_key.shared.page_offset = page_offset;
    out_key.shared.vmo = vmo;
    out_key.both.offset = offset_within_page | FUTEX_OFFSET_SHARED;

    page_unpin(page);

    return 0;
}

int wait(int *uaddr, int val, int flags, const struct timespec *utimespec)
{
    bool has_timeout = false;
    struct timespec ts
    {
    };
    hrtime_t timeout = 0;
    int st = 0;

    if (utimespec != nullptr)
    {
        has_timeout = true;
        if (copy_from_user(&ts, utimespec, sizeof(ts)) < 0)
            return -EFAULT;

        if (!timespec_valid(&ts, false))
            return -EINVAL;
    }

    timeout = timespec_to_hrtime(&ts);

    futex_key key{};

    if ((st = calculate_key(uaddr, flags, key)) < 0)
        return st;

    futex_queue queue{key};

#if 0
	auto hash = __futex_hash(key);
	auto index = futex_hashtable.get_hashtable_index(hash);
	printk("wuaddr %p index %lu\n", uaddr, index);
#endif
    /* After making a queue entry for this thread and this key,
     * we're going to atomically calculate a hash index and lock that hash index,
     * then check for the value(and if doesn't match, return -EAGAIN), and finally, sleep.
     */
    auto hash_index = get_hashtable(key);
    auto list_head = futex_hashtable.get_hashtable(hash_index);
    auto lock = &futex_hashtable_locks[hash_index];

    unsigned int curr_val = 0;

    if (get_user32((unsigned int *)uaddr, &curr_val) < 0)
    {
        st = -EFAULT;
        goto out;
    }

    if (curr_val != (unsigned int)val)
    {
        st = -EAGAIN;
        goto out;
    }

    list_add_tail(&queue.list_node, list_head);

    if (has_timeout)
        st = queue.wait(timeout, lock);
    else
        st = queue.wait(lock);

    MUST_HOLD_LOCK(lock);

    if (!queue.was_awaken())
    {
        futex_hashtable.remove_element(queue);
    }

out:
    spin_unlock(&futex_hashtable_locks[hash_index]);
    return st;
}

int wake(int *uaddr, int flags, int to_wake)
{
    if (to_wake < 0)
        return -EINVAL;

    int st = 0;
    futex_key key{};

    if ((st = calculate_key(uaddr, flags, key)) < 0)
        return st;

        // printk("Shared: %s\n", key.both.offset & FUTEX_OFFSET_SHARED ? "yes" : "no");

#if 0
	auto hash = __futex_hash(key);
	auto index = futex_hashtable.get_hashtable_index(hash);

	printk("uaddr %p index %lu\n", uaddr, index);
#endif

    auto hash_index = get_hashtable(key);
    auto list_head = futex_hashtable.get_hashtable(hash_index);

    int awaken = 0;

    list_for_every_safe (list_head)
    {
        if (to_wake == 0)
            break;

        futex_queue *f = list_head_cpp<futex_queue>::self_from_list_head(l);

        MUST_HOLD_LOCK(&futex_hashtable_locks[hash_index]);

        if (f->get_key() == key)
        {
            f->wake();
            to_wake--;
            awaken++;
        }
    }

    spin_unlock(&futex_hashtable_locks[hash_index]);

    return awaken;
}

void futex_queue::requeue(const futex_key &new_key, struct list_head *new_head)
{
    key = new_key;
    list_remove(&list_node);
    list_add(&list_node, new_head);
}

int cmp_requeue(int *uaddr, int flags, int to_wake, int to_requeue, int *uaddr2, int val3,
                bool val3_valid = true)
{
    // printk("requeue %p, %d, %d, %p\n", uaddr, to_wake, to_requeue, uaddr2);

    if (to_wake < 0 || to_requeue < 0)
        return -EINVAL;

    int st = 0;
    futex_key key1{};
    futex_key key2{};

    if ((st = calculate_key(uaddr, flags, key1)) < 0)
        return st;

    if ((st = calculate_key(uaddr2, flags, key2)) < 0)
        return st;

    // printk("Shared: %s\n", key.offset & FUTEX_OFFSET_SHARED ? "yes" : "no");

    auto [hash_index1, hash_index2] = lock_two_hashes(key1, key2);

    auto wake_list = futex_hashtable.get_hashtable(hash_index1);
    auto requeue_list = futex_hashtable.get_hashtable(hash_index2);

    int awaken = 0, requeued = 0;

    /* Compare val3 now that we're locked */
    if (val3_valid)
    {
        unsigned int on_uaddr;
        if (get_user32((unsigned int *)uaddr, &on_uaddr) < 0)
        {
            st = -EFAULT;
            goto out;
        }

        if (on_uaddr != (unsigned int)val3)
        {
            st = -EAGAIN;
            goto out;
        }
    }

    list_for_every_safe (wake_list)
    {
        if (to_wake == 0 && to_requeue == 0)
            break;

        futex_queue *f = list_head_cpp<futex_queue>::self_from_list_head(l);

        if (f->get_key() == key1)
        {
            if (to_wake > 0)
            {
                f->wake();
                to_wake--;
                awaken++;
            }
            else
            {
                f->requeue(key2, requeue_list);
                to_requeue--;
                requeued++;
            }
        }
    }

    if (val3_valid)
    {
        /* If val3 is valid we know for sure that we're FUTEX_CMP_REQUEUE and not FUTEX_REQUEUE.
         * The semantics are slightly different: the first returns the number of waiters that
         * were woken up, while the second returns woken up + requeued.
         */
        st = awaken + requeued;
    }
    else
        st = awaken;

out:
    unlock_two_hashes(hash_index1, hash_index2);
    return st;
}

int requeue(int *uaddr, int flags, int to_wake, int to_requeue, int *uaddr2)
{
    return cmp_requeue(uaddr, flags, to_wake, to_requeue, uaddr2, 0, false);
}

}; // namespace futex

int futex_wake(int *uaddr, int nr_waiters)
{
    if ((unsigned long)uaddr & (4 - 1))
        return -EINVAL;

    return futex::wake(uaddr, 0, nr_waiters);
}

/* TODO: Add FUTEX_CLOCK_REALTIME support */
#define FUTEX_KNOWN_FLAGS (FUTEX_PRIVATE_FLAG)

static inline int get_val2(const struct timespec *t)
{
    return (int)(long)t;
}

int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2,
              int val3)
{
    int flags = (futex_op & ~FUTEX_OP_MASK);

    /* Error out on bad flags */
    if (flags & ~FUTEX_KNOWN_FLAGS)
        return -EINVAL;

    /* Bad pointer */
    if ((unsigned long)uaddr & (4 - 1))
        return -EINVAL;

    switch (futex_op & FUTEX_OP_MASK)
    {
    case FUTEX_WAIT:
        return futex::wait(uaddr, val, flags, timeout);
    case FUTEX_WAKE:
        return futex::wake(uaddr, flags, val);
    case FUTEX_CMP_REQUEUE:
        return futex::cmp_requeue(uaddr, flags, val, get_val2(timeout), uaddr2, val3);
    case FUTEX_REQUEUE:
        // printk("futex(%p, %d, %d)(op %d)\n", uaddr, futex_op, val, futex_op & FUTEX_OP_MASK);
        return futex::requeue(uaddr, flags, val, get_val2(timeout), uaddr2);
    default:
        return -ENOSYS;
    }
}
