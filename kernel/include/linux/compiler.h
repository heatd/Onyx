#ifndef _LINUX_COMPILER_H
#define _LINUX_COMPILER_H

#include <onyx/compiler.h>
#include <asm-generic/bitsperlong.h>

/* TODO */
#define __counted_by(member)
#define __force
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

#endif
