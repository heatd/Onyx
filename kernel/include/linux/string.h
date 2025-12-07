#ifndef _LINUX_STRING_H
#define _LINUX_STRING_H

#include <string.h>

#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/limits.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/compiler.h>

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

#define strtomem_pad(dest, src, pad) \
do { \
	size_t src_size = strlen((src));     \
	size_t to_copy = min(sizeof(dest), src_size); \
 	memcpy((dest), (src), to_copy); \
	memset((dest) + to_copy, pad, sizeof(dest) - to_copy); \
} while (0)

static inline bool mem_is_zero(const void *s, size_t len)
{
	const u8 *p = s;

	while (len--) {
		if (*p != '\0')
			return false;
		p++;
	}

	return true;
}

static inline ssize_t sized_strscpy(char* dst, const char* src, size_t len)
{
	size_t i;

	if (len <= INT_MAX) {
		for (i = 0; i < len; i++)
			if ('\0' == (dst[i] = src[i]))
				return (ssize_t) i;
		if (i != 0)
			dst[--i] = '\0';
	}

	return -E2BIG;
}

/*
 * The 2 argument style can only be used when dst is an array with a
 * known size.
 */
#define __strscpy0(dst, src, ...)	\
	sized_strscpy(dst, src, sizeof(dst) + __must_be_array(dst) +	\
				__must_be_cstr(dst) + __must_be_cstr(src))
#define __strscpy1(dst, src, size)	\
	sized_strscpy(dst, src, size + __must_be_cstr(dst) + __must_be_cstr(src))

#define __strscpy_pad0(dst, src, ...)	\
	sized_strscpy_pad(dst, src, sizeof(dst) + __must_be_array(dst) +	\
				    __must_be_cstr(dst) + __must_be_cstr(src))
#define __strscpy_pad1(dst, src, size)	\
	sized_strscpy_pad(dst, src, size + __must_be_cstr(dst) + __must_be_cstr(src))

/**
 * strscpy - Copy a C-string into a sized buffer
 * @dst: Where to copy the string to
 * @src: Where to copy the string from
 * @...: Size of destination buffer (optional)
 *
 * Copy the source string @src, or as much of it as fits, into the
 * destination @dst buffer. The behavior is undefined if the string
 * buffers overlap. The destination @dst buffer is always NUL terminated,
 * unless it's zero-sized.
 *
 * The size argument @... is only required when @dst is not an array, or
 * when the copy needs to be smaller than sizeof(@dst).
 *
 * Preferred to strncpy() since it always returns a valid string, and
 * doesn't unnecessarily force the tail of the destination buffer to be
 * zero padded. If padding is desired please use strscpy_pad().
 *
 * Returns the number of characters copied in @dst (not including the
 * trailing %NUL) or -E2BIG if @size is 0 or the copy from @src was
 * truncated.
 */
#define strscpy(dst, src, ...)	\
	CONCATENATE(__strscpy, COUNT_ARGS(__VA_ARGS__))(dst, src, __VA_ARGS__)

	#define sized_strscpy_pad(dest, src, count)	({			\
	char *__dst = (dest);						\
	const char *__src = (src);					\
	const size_t __count = (count);					\
	ssize_t __wrote;						\
									\
	__wrote = sized_strscpy(__dst, __src, __count);			\
	if (__wrote >= 0 && __wrote < __count)				\
		memset(__dst + __wrote + 1, 0, __count - __wrote - 1);	\
	__wrote;							\
})

/**
 * strscpy_pad() - Copy a C-string into a sized buffer
 * @dst: Where to copy the string to
 * @src: Where to copy the string from
 * @...: Size of destination buffer
 *
 * Copy the string, or as much of it as fits, into the dest buffer. The
 * behavior is undefined if the string buffers overlap. The destination
 * buffer is always %NUL terminated, unless it's zero-sized.
 *
 * If the source string is shorter than the destination buffer, the
 * remaining bytes in the buffer will be filled with %NUL bytes.
 *
 * For full explanation of why you may want to consider using the
 * 'strscpy' functions please see the function docstring for strscpy().
 *
 * Returns:
 * * The number of characters copied (not including the trailing %NULs)
 * * -E2BIG if count is 0 or @src was truncated.
 */
#define strscpy_pad(dst, src, ...)	\
	CONCATENATE(__strscpy_pad, COUNT_ARGS(__VA_ARGS__))(dst, src, __VA_ARGS__)

char *kstrdup(const char *str, gfp_t gfp);
void *memdup_user_nul(const void __user *src, size_t len);
void *memdup_array_user(const void __user *src, size_t n, size_t size);
void kfree_const(const void *x);
const char *kstrdup_const(const char *s, gfp_t gfp);

static __always_inline size_t str_has_prefix(const char *str, const char *prefix)
{
	size_t len = strlen(prefix);
	return strncmp(str, prefix, len) == 0 ? len : 0;
}
#endif
