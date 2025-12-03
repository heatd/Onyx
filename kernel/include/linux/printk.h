#ifndef _LINUX_PRINTK_H
#define _LINUX_PRINTK_H

#include <stdio.h>
#include <linux/compiler.h>

__BEGIN_CDECLS

extern int oops_in_progress;

static inline void dump_stack(void)
{
    pr_err("todo dump stack\n");
}

#define KERN_CONT KERN_WARN
#define pr_cont(fmt, ...) printk(KERN_CONT pr_fmt(fmt), ##__VA_ARGS__)

#define KERN_WARNING KERN_WARN

__END_CDECLS

#endif
