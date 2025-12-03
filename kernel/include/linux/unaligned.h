/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_UNALIGNED_H
#define __LINUX_UNALIGNED_H

#include <string.h>

#define get_unaligned(ptr) 			\
({ 									\
 	__typeof__(*ptr) v; 			\
  	memcpy(&v, ptr, sizeof(*ptr));	\
	v;								\
})

#endif /* __LINUX_UNALIGNED_H */
