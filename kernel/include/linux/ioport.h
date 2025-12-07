#ifndef _LINUX_IOPORT_H
#define _LINUX_IOPORT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/minmax.h>

struct resource {
    resource_size_t   start;
    resource_size_t   end;
    const char       *name;
    long unsigned int flags;
    long unsigned int desc;
    struct resource  *parent;
    struct resource  *sibling;
    struct resource  *child;
};

extern struct resource iomem_resource;

#endif
