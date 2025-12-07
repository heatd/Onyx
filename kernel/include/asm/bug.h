#ifndef _ASM_BUG_H
#define _ASM_BUG_H

#include <onyx/bug.h>

#define WARN_ONCE(condition, ...) WARN_ON_ONCE(condition)
#define BUG() __builtin_trap()

#endif
