#ifndef _LINUX_IO_H
#define _LINUX_IO_H

#include <linux/types.h>
#include <linux/compiler_types.h>
#include <linux/sizes.h>
#include <linux/string.h>

void memcpy_fromio(void *dst, const volatile void __iomem *src, size_t count);
void memcpy_toio(volatile void __iomem *dst, const void *src, size_t count);
void memset_io(volatile void __iomem *buf, int value, size_t count);

static inline u32 readl(const volatile void __iomem *addr)
{
    return *(const volatile u32 *) addr;
}

#endif
