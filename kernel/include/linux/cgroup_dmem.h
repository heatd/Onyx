#ifndef _LINUX_CGROUP_DMEM_H
#define _LINUX_CGROUP_DMEM_H

#include <linux/types.h>

struct dmem_cgroup_region;
static inline struct dmem_cgroup_region *
dmem_cgroup_register_region(u64 size, const char *name_fmt, ...)
{
	return NULL;
}

static inline void dmem_cgroup_unregister_region(struct dmem_cgroup_region *)
{
}

#endif
