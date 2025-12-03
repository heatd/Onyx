#ifndef _LINUX_KALLSYMS_H
#define _LINUX_KALLSYMS_H

#include <linux/printk.h>

#define KSYM_NAME_LEN 512


static inline const char *kallsyms_lookup(unsigned long addr,
					  unsigned long *symbolsize,
					  unsigned long *offset,
					  char **modname, char *namebuf)
{
	return 0;
}

static inline void print_ip_sym(const char *loglvl, unsigned long ip)
{
	printk("%s[<%p>] %pS\n", loglvl, (void *) ip, (void *) ip);
}

#endif
