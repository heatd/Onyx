#ifndef _LINUX_PERCPU_H
#define _LINUX_PERCPU_H

#include <asm/percpu.h>

static inline bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr)
{
    return false;
}

#endif
