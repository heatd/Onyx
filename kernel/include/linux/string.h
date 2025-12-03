#ifndef _LINUX_STRING_H
#define _LINUX_STRING_H

#include <string.h>
#include <linux/types.h>

/**
 * memset_startat - Set a value starting at a member to the end of a struct
 *
 * @obj: Address of target struct instance
 * @v: Byte value to repeatedly write
 * @member: struct member to start writing at
 *
 * Note that if there is padding between the prior member and the target
 * member, memset_after() should be used to clear the prior padding.
 */
#define memset_startat(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetof(typeof(*(obj)), member), __val,		\
	       sizeof(*(obj)) - offsetof(typeof(*(obj)), member));	\
})

#endif
