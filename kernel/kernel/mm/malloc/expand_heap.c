#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include "syscall.h"


/* Expand the heap in-place if brk can be used, or otherwise via mmap,
 * using an exponential lower bound on growth by mmap to make
 * fragmentation asymptotically irrelevant. The size argument is both
 * an input and an output, since the caller needs to know the size
 * allocated, which will be larger than requested due to page alignment
 * and mmap minimum size rules. The caller is responsible for locking
 * to prevent concurrent calls. */

struct heap
{
	void *starting_address;
	void *brk;
	unsigned long size;
};

struct heap *heap_get();

unsigned long get_brk()
{
	return (unsigned long) heap_get()->brk;
}

void *sbrk(intptr_t);

void *__expand_heap(size_t *pn)
{
	static uintptr_t brk;
	static unsigned mmap_step;
	size_t n = *pn;

	if (n > SIZE_MAX/2 - PAGE_SIZE) {
		errno = ENOMEM;
		return 0;
	}
	n += -n & PAGE_SIZE-1;

	if (!brk) {
		brk = get_brk();
		brk += -brk & PAGE_SIZE-1;
	}

	if (n < SIZE_MAX-brk && sbrk(n) != -1) {
		*pn = n;
		brk += n;
		return (void *)(brk-n);
	}

	return 0;
}
