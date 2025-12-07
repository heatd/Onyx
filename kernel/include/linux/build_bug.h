#ifndef _LINUX_BUILD_BUG_H
#define _LINUX_BUILD_BUG_H

#include <linux/compiler.h>

#define BUILD_BUG_ON(cond) _Static_assert(!(cond), #cond)
/* TODO */
#define BUILD_BUG_ON_NOT_POWER_OF_2(val) do {} while (0)

#define BUILD_BUG_ON_ZERO(e, ...) \
	__BUILD_BUG_ON_ZERO_MSG(e, ##__VA_ARGS__, #e " is true")

#define BUILD_BUG_ON_INVALID(e) ((void)(sizeof((__force long)(e))))

#define BUILD_BUG_ON_MSG(cond, msg) _Static_assert(!(cond), msg)

#endif
