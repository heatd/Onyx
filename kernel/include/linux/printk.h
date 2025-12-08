#ifndef _LINUX_PRINTK_H
#define _LINUX_PRINTK_H

#include <stdbool.h>
#include <stdio.h>

#include <linux/compiler.h>

__BEGIN_CDECLS

extern int oops_in_progress;

static inline void dump_stack(void)
{
    pr_err("todo dump stack\n");
}

#define KERN_WARNING KERN_WARN

struct va_format {
	const char *fmt;
	va_list *va;
};

int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize,
		       char *linebuf, size_t linebuflen, bool ascii);

enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};
void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, bool ascii);

__END_CDECLS

#endif
