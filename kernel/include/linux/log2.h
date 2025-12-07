#ifndef _LINUX_LOG2_H
#define _LINUX_LOG2_H

#include <linux/compiler.h>
#include <stdbool.h>

static __always_inline __attribute__((const))
bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

#endif
