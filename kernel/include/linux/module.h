#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#include <linux/types.h>
#include <linux/moduleparam.h>
#include <onyx/module.h>

static inline bool __is_module_percpu_address(unsigned long addr, unsigned long *can_addr)
{
	return false;
}

#define MODULE_DESCRIPTION(...)
#define THIS_MODULE NULL

#define module_init(func) MODULE_INIT(func)
#define module_exit(func) MODULE_FINI(func)
#define MODULE_IMPORT_NS(ns)

#endif
