/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stdlib.h>
#include <string.h>

#include <onyx/scheduler.h>
#include <onyx/utils.h>
#include <onyx/vm.h>

void *memdup(const void *ptr, size_t size)
{
    void *new_ptr = malloc(size);
    if (!new_ptr)
        return NULL;
    memcpy(new_ptr, ptr, size);
    return new_ptr;
}

void *copy_page_to_page(void *p1, void *p2)
{
    return copy_page(PHYS_TO_VIRT(p1), p2);
}

void *copy_page(void *vaddr, void *p2)
{
    return memcpy(vaddr, PHYS_TO_VIRT(p2), PAGE_SIZE);
}

static inline int a_ctz_32(uint32_t x)
{
    static const char debruijn32[32] = {0,  1,  23, 2,  29, 24, 19, 3,  30, 27, 25,
                                        11, 20, 8,  4,  13, 31, 22, 28, 18, 26, 10,
                                        7,  12, 21, 17, 9,  6,  16, 5,  15, 14};
    return debruijn32[(x & -x) * 0x076be629 >> 27];
}

extern "C" int ffs(int x)
{
    return !x ? 0 : a_ctz_32(x) + 1;
}
