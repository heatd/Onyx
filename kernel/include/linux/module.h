#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#define module_param(...)

static inline bool __is_module_percpu_address(unsigned long addr, unsigned long *can_addr)
{
	return false;
}

#endif
