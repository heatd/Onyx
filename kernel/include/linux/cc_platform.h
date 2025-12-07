#ifndef _LINUX_CC_PLATFORM_H
#define _LINUX_CC_PLATFORM_H

#include <stdbool.h>

enum cc_attr {
	CC_ATTR_MEM_ENCRYPT,
	CC_ATTR_GUEST_MEM_ENCRYPT,
};

static inline bool cc_platform_has(enum cc_attr attr)
{
	return false;
}

#endif
