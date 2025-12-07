#ifndef _LINUX_COMPILER_H
#define _LINUX_COMPILER_H

#include <onyx/compiler.h>
#include <asm-generic/bitsperlong.h>

/* TODO */
#define __counted_by(member)
#define __always_unused                 __attribute__((__unused__))
#define __maybe_unused                  __attribute__((__unused__))
#define fallthrough                     __attribute__((fallthrough))
#define __user
#define __used                          __attribute__((__used__))

#define barrier() __asm__ __volatile__("": : :"memory")

#define __aligned(v) align(v)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define noinstr
#define noinline __noinline

#define __nonstring

#define __printf(fmt, firstvararg) __attribute__((__format__(__printf__, fmt, firstvararg)))

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 *
 * Details:
 * - sizeof() return an integer constant expression, and does not evaluate
 *   the value of its operand; it only examines the type of its operand.
 * - The results of comparing two integer constant expressions is also
 *   an integer constant expression.
 * - The first literal "8" isn't important. It could be any literal value.
 * - The second literal "8" is to avoid warnings about unaligned pointers;
 *   this could otherwise just be "1".
 * - (long)(x) is used to avoid warnings about 64-bit types on 32-bit
 *   architectures.
 * - The C Standard defines "null pointer constant", "(void *)0", as
 *   distinct from other void pointers.
 * - If (x) is an integer constant expression, then the "* 0l" resolves
 *   it into an integer constant expression of value 0. Since it is cast to
 *   "void *", this makes the second operand a null pointer constant.
 * - If (x) is not an integer constant expression, then the second operand
 *   resolves to a void pointer (but not a null pointer constant: the value
 *   is not an integer constant 0).
 * - The conditional operator's third operand, "(int *)8", is an object
 *   pointer (to type "int").
 * - The behavior (including the return type) of the conditional operator
 *   ("operand1 ? operand2 : operand3") depends on the kind of expressions
 *   given for the second and third operands. This is the central mechanism
 *   of the macro:
 *   - When one operand is a null pointer constant (i.e. when x is an integer
 *     constant expression) and the other is an object pointer (i.e. our
 *     third operand), the conditional operator returns the type of the
 *     object pointer operand (i.e. "int *"). Here, within the sizeof(), we
 *     would then get:
 *       sizeof(*((int *)(...))  == sizeof(int)  == 4
 *   - When one operand is a void pointer (i.e. when x is not an integer
 *     constant expression) and the other is an object pointer (i.e. our
 *     third operand), the conditional operator returns a "void *" type.
 *     Here, within the sizeof(), we would then get:
 *       sizeof(*((void *)(...)) == sizeof(void) == 1
 * - The equality comparison to "sizeof(int)" therefore depends on (x):
 *     sizeof(int) == sizeof(int)     (x) was a constant expression
 *     sizeof(int) != sizeof(void)    (x) was not a constant expression
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#define const_true(x) __builtin_choose_expr(__is_constexpr(x), x, false)

#define __BUILD_BUG_ON_ZERO_MSG(e, msg, ...) ((int)sizeof(struct {_Static_assert(!(e), msg);}))

#define is_signed_type(type) (((type)(-1)) < (__force type)1)
#define __cleanup(func)			__attribute__((__cleanup__(func)))
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))

#define check_mul_overflow(a, b, result) __builtin_mul_overflow((a), (b), (result))
#define check_add_overflow(a, b, result) __builtin_add_overflow((a), (b), (result))

#if __has_attribute(__error__)
#define __compiletime_error(message) __attribute__((error(message)))
#else
#define __compiletime_error(msg)
#endif

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/* &a[0] degrades to a pointer: a different type from an array */
#define __is_array(a)		(!__same_type((a), &(a)[0]))
#define __must_be_array(a)	__BUILD_BUG_ON_ZERO_MSG(!__is_array(a), \
							"must be array")

#define __is_byte_array(a)	(__is_array(a) && sizeof((a)[0]) == 1)
#define __must_be_byte_array(a)	__BUILD_BUG_ON_ZERO_MSG(!__is_byte_array(a), \
							"must be byte array")

							#if __has_builtin(__builtin_has_attribute)
#define __annotated(var, attr)	__builtin_has_attribute(var, attr)
#endif
/*
 * If the "nonstring" attribute isn't available, we have to return true
 * so the __must_*() checks pass when "nonstring" isn't supported.
 */
#if __has_attribute(__nonstring__) && defined(__annotated)
#define __is_cstr(a)		(!__annotated(a, nonstring))
#define __is_noncstr(a)		(__annotated(a, nonstring))
#else
#define __is_cstr(a)		(true)
#define __is_noncstr(a)		(true)
#endif

/* Require C Strings (i.e. NUL-terminated) lack the "nonstring" attribute. */
#define __must_be_cstr(p) \
	__BUILD_BUG_ON_ZERO_MSG(!__is_cstr(p), \
				"must be C-string (NUL-terminated)")
#define __must_be_noncstr(p) \
	__BUILD_BUG_ON_ZERO_MSG(!__is_noncstr(p), \
				"must be non-C-string (not NUL-terminated)")

#define __must_hold(x)

#endif
