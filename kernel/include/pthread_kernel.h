#ifndef _KERNEL_PTHREADS
#define _KERNEL_PTHREADS

#include <sys/types.h>

typedef struct pthread {
	struct pthread *self;
	void **dtv, *unused1, *unused2;
	uintptr_t sysinfo;
	uintptr_t canary, canary2;
	pid_t tid, pid;
	int tsd_used, errno_val;
	volatile int cancel, canceldisable, cancelasync;
	int detached;
	unsigned char *map_base;
	size_t map_size;
	void *stack;
	size_t stack_size;
	void *start_arg;
	void *(*start)(void *);
	void *result;
	struct __ptcb *cancelbuf;
	void **tsd;
	uint16_t attr;
	volatile int dead;
	struct {
		volatile void *volatile head;
		long off;
		volatile void *volatile pending;
	} robust_list;
	int unblock_cancel;
	volatile int timer_id;
	uint16_t locale;
	volatile int killlock[2];
	volatile int exitlock[2];
	volatile int startlock[2];
	//unsigned long sigmask[_NSIG/8/sizeof(long)];
	char *dlerror_buf;
	int dlerror_flag;
	void *stdio_locks;
	uintptr_t canary_at_end;
	void **dtv_copy;
}pthread_t;

#endif