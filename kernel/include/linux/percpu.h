#ifndef _LINUX_PERCPU_H
#define _LINUX_PERCPU_H

#include <linux/preempt.h>
#include <asm/percpu.h>

__BEGIN_CDECLS
bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
__END_CDECLS

#endif
