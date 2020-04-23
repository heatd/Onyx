/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>

#include <onyx/list.h>
#include <onyx/futex.h>
#include <onyx/process.h>
#include <onyx/hashtable.hpp>
#include <onyx/wait_queue.h>
#include <onyx/user.h>
#include <onyx/fnv.h>
#include <onyx/smart.h>
#include <onyx/pagecache.h>

/* This union describes the key used to match futexes with each other.
 * For private mappings, we use the mm_address_space address of the process and
 * the pointer to futex value.
 * For shared mappings, we're going to use the vmo's address and the page_offset.
 * Note that the offset within the page is always used and has some lower bits used,
 * since they need to be clear(the address needs to be 4-byte aligned).
 */

#define FUTEX_OFFSET_SHARED          (1 << 0)
#define FUTEX_OFFSET_PRIVATE         (1 << 1)

namespace futex
{

struct futex_key
{
	union
	{
		struct
		{
			struct vm_object *vmo;
			size_t page_offset;
		} shared;

		struct
		{
			struct mm_address_space *as;
			int *ptr;
		} private_mapping;
		
		unsigned int offset;
	};
	
	futex_key()
	{
		/* Explicitly zero everything */
		shared.vmo = nullptr;
		shared.page_offset = 0;
		private_mapping.as = nullptr;
		private_mapping.ptr = nullptr;
		offset = 0;
	}

	bool operator==(const futex_key& k)
	{
		if(offset != k.offset)
			return false;
		
		bool _private = k.offset & FUTEX_OFFSET_PRIVATE;

		if(_private)
		{
			return private_mapping.as == k.private_mapping.as && private_mapping.ptr == k.private_mapping.ptr;
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
	struct list_head list_node;

	futex_queue(futex_key key) : key(key), awaken(false), wq{}, list_node{}
	{
		init_wait_queue_head(&wq);
	}

	~futex_queue(){}

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
		awaken = true;
		wait_queue_wake_all(&wq);
		list_remove(&list_node);
	}

	static futex_queue *find(futex_key& key);

	futex_key& get_key()
	{
		return key;
	}

	bool was_awaken()
	{
		return awaken;
	}
};

#if 0
uint32_t get_user_32(uint32_t *p)
{
	uint32_t ret;
	unsigned int pagefault = 0;
	__asm__ __volatile__("1: mov %2, %0\n"
	                     "2: movl $-14, %1\n"
						 ".pushsection .ehtable\n"
						 " .quad 1b\n"
						 " .quad 2b\n"
						 " .previous\n" : "=r"(ret), "=m"(pagefault) : "m"(p));
	return ret;
}
#endif

inline uint32_t __futex_hash(futex_key& key)
{
	return fnv_hash(&key, sizeof(key));
}

uint32_t futex_hash(futex_queue& queue)
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

uint32_t get_hashtable(futex_key& key)
{
	auto hash = __futex_hash(key);
	auto index = futex_hashtable.get_hashtable_index(hash);

	spin_lock(&futex_hashtable_locks[index]);

	return index;
}

int calculate_key(int *uaddr, int flags, futex_key& out_key)
{
	bool private_ftx = flags & FUTEX_PRIVATE_FLAG;
	auto address_space = get_current_address_space();
	auto offset_within_page = (unsigned long) uaddr & (PAGE_SIZE - 1);
	bool is_shared = false;

	/* If it was already specified to be a private futex(thanks user-space!),
	 * we can just shortpath our way out.
	 */

	if(private_ftx)
	{
private_futex_out:
		out_key.private_mapping.as = address_space;
		out_key.private_mapping.ptr = uaddr;
		out_key.offset = offset_within_page | FUTEX_OFFSET_PRIVATE;
		return 0;
	}

	struct page *page;
	int st;
	st = get_phys_pages(uaddr, GPP_READ, &page, 1);
	
	if(!(st & GPP_ACCESS_OK))
		return -EFAULT;

	is_shared = st & GPP_ACCESS_SHARED;

	/* VMO mappings are marked as MAP_SHARED BUT don't have page->cache filled out.
	 * TODO: We should be able to shared-wait on vmo mappings(maybe replace
	 * page->cache with a page->owning_vmo or something like that(or a union)). */
	bool is_vmo_mapping = is_shared && page->cache == nullptr;
	
	if(!is_shared || is_vmo_mapping)
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
	out_key.offset = offset_within_page | FUTEX_OFFSET_SHARED;

	page_unpin(page);

	return 0;
}

int wait(int *uaddr, int val, int flags, const struct timespec *utimespec)
{
	bool timeout_valid = false;
	struct timespec ts;
	hrtime_t timeout = 0;
	int st = 0;

	if(utimespec != nullptr)
	{
		timeout_valid = true;
		if(copy_from_user(&ts, utimespec, sizeof(ts)) < 0)
			return -EFAULT;
	}
	
	timeout = timespec_to_hrtime(&ts);

	futex_key key{};

	if((st = calculate_key(uaddr, flags, key)) < 0)
		return st;

	futex_queue queue{key};

	/* After making a queue entry for this thread and this key,
	 * we're going to atomically calculate a hash index and lock that hash index,
	 * then check for the value(and if doesn't match, return -EAGAIN), and finally, sleep.
	 */
	auto hash_index = get_hashtable(key);
	auto list_head = futex_hashtable.get_hashtable(hash_index);
	auto lock = &futex_hashtable_locks[hash_index];

	unsigned int curr_val = 0;

	if(get_user32((unsigned int*) uaddr, &curr_val) < 0)
	{
		st = -EFAULT;
		goto out;
	}

	if(curr_val != (unsigned int) val)
	{
		st = -EAGAIN;
		goto out;
	}

	list_add_tail(&queue.list_node, list_head);

	if(timeout_valid)
		st = queue.wait(timeout, lock);
	else
		st = queue.wait(lock);

	MUST_HOLD_LOCK(lock);

	if(!queue.was_awaken())
	{
		futex_hashtable.remove_element(queue);
	}

out:
	spin_unlock(&futex_hashtable_locks[hash_index]);
	return st;
}

int wake(int *uaddr, int flags, int to_wake)
{
	int st = 0;
	futex_key key{};

	if((st = calculate_key(uaddr, flags, key)) < 0)
		return st;

	//printk("Shared: %s\n", key.offset & FUTEX_OFFSET_SHARED ? "yes" : "no");

	/* After making a queue entry for this thread and this key,
	 * we're going to atomically calculate a hash index and lock that hash index,
	 * then check for the value(and if doesn't match, return -EAGAIN), and finally, sleep.
	 */

	auto hash_index = get_hashtable(key);
	auto list_head = futex_hashtable.get_hashtable(hash_index);

	int awaken = 0;

	list_for_every_safe(list_head)
	{
		if(to_wake == 0)
			break;	
		futex_queue *f = container_of(l, futex_queue, list_node);

		MUST_HOLD_LOCK(&futex_hashtable_locks[hash_index]);
		
		if(f->get_key() == key)
		{
			f->wake();
			to_wake--;
			awaken++;
		}
	}

	spin_unlock(&futex_hashtable_locks[hash_index]);

	return awaken;
}

};

extern "C" int futex_wake(int *uaddr, int nr_waiters)
{
	if((unsigned long) uaddr & (4 - 1))
		return -EINVAL;
	
	return futex::wake(uaddr, 0, nr_waiters);
}

/* TODO: Add FUTEX_CLOCK_REALTIME support */
#define FUTEX_KNOWN_FLAGS      (FUTEX_PRIVATE_FLAG)

extern "C" int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
	int flags = (futex_op & ~FUTEX_OP_MASK);

	/* Error out on bad flags */
	if(flags & ~FUTEX_KNOWN_FLAGS)
		return -EINVAL;

	/* Bad pointer */
	if((unsigned long) uaddr & (4 - 1))
		return -EINVAL;

	switch(futex_op & FUTEX_OP_MASK)
	{
		case FUTEX_WAIT:
			return futex::wait(uaddr, val, flags, timeout);
		case FUTEX_WAKE:
			return futex::wake(uaddr, flags, val);
		default:
			return -ENOSYS;
	}

}
