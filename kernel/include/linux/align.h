#ifndef _LINUX_ALIGN_H
#define _LINUX_ALIGN_H

#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define ALIGN(x, a) (((x) + (a) - 1) & -(a))

#endif
