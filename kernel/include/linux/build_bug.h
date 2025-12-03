#ifndef _LINUX_BUILD_BUG_H
#define _LINUX_BUILD_BUG_H

#define BUILD_BUG_ON(cond) _Static_assert(!(cond), #cond)
/* TODO */
#define BUILD_BUG_ON_NOT_POWER_OF_2(val) do {} while (0);

#endif
