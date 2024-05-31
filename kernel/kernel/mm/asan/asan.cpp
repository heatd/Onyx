/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/mm/kasan.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/vm.h>
#include <onyx/vm_layout.h>

#include <platform/kasan.h>

#include <onyx/utility.hpp>

#define KADDR_SPACE_SIZE 0x800000000000
#define KADDR_START      0xffff800000000000

#define __alias(symbol) __attribute__((__alias__(#symbol)))

#define KASAN_SHIFT  3
#define KASAN_N_MASK ((1 << KASAN_SHIFT) - 1)

bool kasan_is_init = false;

#define ADDR_SPACE_SIZE (KADDR_SPACE_SIZE / 8)

unsigned long kasan_max = 0xfffffc0000000000;

static inline char *kasan_get_ptr(unsigned long addr)
{
    return (char *) KASAN_SHADOW_OFFSET + (addr >> KASAN_SHIFT);
}

void vterm_panic();

unsigned long kasan_get_freed_region_start(unsigned long addr)
{
    auto shadow = kasan_get_ptr(addr);

    unsigned long cursor = addr & ~7;

    while ((unsigned char) *shadow == KASAN_FREED)
    {
        --shadow, cursor -= 8;
    }

    return cursor + 8;
}

unsigned long kasan_get_freed_region_end(unsigned long addr)
{
    auto shadow = kasan_get_ptr(addr);

    unsigned long cursor = addr & ~7;

    while ((unsigned char) *shadow == KASAN_FREED)
    {
        ++shadow, cursor += 8;
    }

    return cursor;
}

void kasan_print_location(unsigned long addr)
{
    auto shadow = kasan_get_ptr(addr);

    unsigned char shadow_byte = *shadow;

    if (shadow_byte == KASAN_FREED)
    {
        unsigned long start = kasan_get_freed_region_start(addr);
        unsigned long end = kasan_get_freed_region_end(addr);
        pr_crit("%#lx is located %zu bytes inside of %zu-byte region [%#lx, %#lx)\n", addr,
                addr - start, end - start, start, end);
    }
}

struct multiwrite_state
{
    char *original;
    char *s;
    size_t len;
    size_t original_len;

    multiwrite_state(char *buf, size_t len) : original{buf}, s{buf}, len{len}, original_len{len}
    {
    }

    void print(const char *fmt, ...)
    {
        va_list va;
        va_start(va, fmt);
        int written = vsnprintf(s, len, fmt, va);
        if (written >= 0)
        {
            s += written;
            len -= written;

            if (*(s - 1) == '\n')
            {
                printk(KERN_CRIT "%s", original);
                s = original;
                len = original_len;
            }
        }

        va_end(va);
    }
};

static void kasan_dump_shadow(unsigned long addr)
{
    uintptr_t shadow = (uintptr_t) kasan_get_ptr(addr);
    pr_crit("Shadow memory state around the buggy address %#lx:\n", shadow);
    // Print at least 0x30 bytes of the shadow map before and after the invalid access.
    uintptr_t start_addr = (shadow & ~0x07) - 0x30;
    start_addr = cul::max(KASAN_VIRT_START, start_addr);
    // Print the shadow map memory state and look for the location to print a caret.
    bool caret = false;
    size_t caret_ind = 0;
    for (size_t i = 0; i < 14; i++)
    {
        char buf[200];
        struct multiwrite_state mws = {buf, 200};
        mws.print("0x%016lx:", start_addr);
        for (size_t j = 0; j < 8; j++)
        {
            mws.print(" 0x%02hhx", reinterpret_cast<uint8_t *>(start_addr)[j]);
            if (!caret)
            {
                if ((start_addr + j) == reinterpret_cast<uintptr_t>(kasan_get_ptr(addr)))
                {
                    caret = true;
                    caret_ind = j;
                }
            }
        }
        mws.print("\n");
        if (caret)
        {
            // The address takes 16 characters; add in space for ':', and "0x".
            mws.print("%*s", 16 + 1 + 2, "");
            // Print either a caret or spaces under the line containing the invalid access.
            for (size_t j = 0; j < 8; j++)
            {
                mws.print("  %2s ", j == caret_ind ? "^^" : "");
            }
            mws.print("\n");
            caret = false;
        }
        start_addr += 8;
    }

    pr_crit("\n");
    auto slab = kmem_pointer_to_slab_maybe((void *) addr);

    pr_crit("Memory information:\n");

    if (slab)
    {
        kmem_cache_print_slab_info_kasan((void *) addr, slab);

        kasan_print_location(addr);
        pr_crit("                    ");
    }

    auto mapping_info = get_mapping_info((void *) addr);

    if (mapping_info & PAGE_PRESENT)
    {
        pr_crit("mapped to %016lx\n", MAPPING_INFO_PADDR(mapping_info));
    }
    else
        pr_crit("not mapped\n");
}

void kasan_fail(unsigned long addr, size_t size, bool write, unsigned char b)
{
    /* Disable kasan so we can panic */
    kasan_is_init = false;

    vterm_panic();
    const char *event;
    const char *thing_accessed = "Accessed zone not marked as accessible";

    switch ((unsigned char) b)
    {
        case KASAN_FREED:
            event = "use-after-free";
            thing_accessed = "Accessed zone marked KASAN_FREED";
            break;
        case KASAN_REDZONE:
            thing_accessed = "Accessed zone marked KASAN_REDZONE";
            [[fallthrough]];
        default:
            event = "invalid access";
            break;
    };

    panic_start();

    pr_crit("\n================================================================================="
            "===="
            "========\n\n");

    kasan_dump_shadow(addr);

    char buffer[1024] = {0};
    snprintf(buffer, 1024,
             "kasan: "
             "detected memory error (%s) at %lx, %s of size %lu\nMemory error: %s(kasan code %x)",
             event, addr, write ? "write" : "read", size, thing_accessed, b);
    panic(buffer);
}

#define KASAN_MISALIGNMENT(x) ((x) &KASAN_N_MASK)

void kasan_check_memory_fast(unsigned long addr, size_t size, bool write)
{
    char b = *kasan_get_ptr(addr);

    unsigned int n = KASAN_MISALIGNMENT(addr);

    if (b == KASAN_ACCESSIBLE)
        return;

    if (b < 0)
    {
        kasan_fail(addr, size, write, b);
    }

    unsigned int first_n_accessible = b;

    if (n > first_n_accessible || n + size > first_n_accessible)
        kasan_fail(addr, size, write, b);
}

void kasan_check_memory(unsigned long addr, size_t size, bool write)
{
    size_t n_ = KASAN_MISALIGNMENT(addr);

    if ((unsigned long) kasan_get_ptr(addr) < KASAN_VIRT_START)
        panic("Bad kasan pointer %lx -> %p\n", addr, kasan_get_ptr(addr));

    if (n_ + size <= 8 && n_ == 0)
    {
        kasan_check_memory_fast(addr, size, write);
        return;
    }

    while (size != 0)
    {
        char b = *kasan_get_ptr(addr);

        unsigned int n = addr & KASAN_N_MASK;
        size_t to_set = size < 8 - n ? size : 8 - n;

        if (b == KASAN_ACCESSIBLE)
        {
            addr += to_set;
            size -= to_set;
        }
        else
        {
            if (b < 0)
                kasan_fail(addr, size, write, b);
            unsigned int first_n_accessible = b;

            if (n > first_n_accessible || n + to_set > first_n_accessible)
                kasan_fail(addr, size, write, b);

            addr += to_set;
            size -= to_set;
        }
    }

    kasan_is_init = true;
}

#define KASAN_LOAD(size)                            \
    USED void __asan_load##size(unsigned long addr) \
    {                                               \
        kasan_check_memory(addr, size, false);      \
    }                                               \
                                                    \
    USED void __asan_load##size##_noabort(unsigned long addr) __alias(__asan_load##size);

#define KASAN_STORE(size)                            \
    USED void __asan_store##size(unsigned long addr) \
    {                                                \
        kasan_check_memory(addr, size, true);        \
    }                                                \
                                                     \
    USED void __asan_store##size##_noabort(unsigned long addr) __alias(__asan_store##size);

extern "C"
{

KASAN_LOAD(1);
KASAN_LOAD(2);
KASAN_LOAD(4);
KASAN_LOAD(8);
KASAN_LOAD(16);

KASAN_STORE(1);
KASAN_STORE(2);
KASAN_STORE(4);
KASAN_STORE(8);
KASAN_STORE(16);

USED void __asan_loadN(unsigned long addr, size_t size)
{
    kasan_check_memory(addr, size, false);
}

USED void __asan_loadN_noabort(unsigned long addr, size_t size) __alias(__asan_loadN);

USED void __asan_storeN(unsigned long addr, size_t size)
{
    kasan_check_memory(addr, size, true);
}

USED void __asan_storeN_noabort(unsigned long addr, size_t size) __alias(__asan_storeN);

USED void __asan_report_store_n_noabort(unsigned long addr, size_t size)
{
    kasan_check_memory(addr, size, true);
}

USED void __asan_report_load_n_noabort(unsigned long addr, size_t size)
{
    kasan_check_memory(addr, size, false);
}

static unsigned long stray_shadow_unpoison = 0;

extern "C" void asan_unpoison_stack_shadow()
{
    // Called by code that needs to exit and not unwind the stack. This forcibly unpoisons the whole
    // stack.
    auto cur = get_current_thread();
    if (!cur)
    {
        stray_shadow_unpoison++;
        return;
    }

    unsigned long local_stack;
    unsigned long bottom = (unsigned long) &local_stack;
    auto len = ((unsigned long) cur->kernel_stack_top) - bottom;

    // This is needed when called at early boot/cpu0 init thread, where the cur stack != thread's
    // stack
    // TODO: Fix?
    if (len > 0x100000)
    {
        stray_shadow_unpoison++;
        return;
    }

    asan_unpoison_shadow(bottom, len);
}

extern "C" void asan_unpoison_stack_shadow_ctxswitch(struct registers *regs)
{
#ifdef __x86_64__
    auto to_sp = regs->rsp;
#endif
    // Called by code that needs to exit and not unwind the stack. This forcibly unpoisons the whole
    // stack.
    unsigned long local_stack;
    unsigned long bottom = (unsigned long) &local_stack;
    auto len = to_sp - bottom;
    if (len > 0x100000)
    {
        stray_shadow_unpoison++;
        return;
    }

    asan_unpoison_shadow(bottom, len);
}

USED void __asan_handle_no_return(void)
{
    asan_unpoison_stack_shadow();
}

USED void __asan_before_dynamic_init(void)
{
}

USED void __asan_after_dynamic_init(void)
{
}

USED void __asan_register_globals()
{
}
USED void __asan_unregister_globals()
{
}

#define ASAN_REPORT_ERROR(type, is_write, size)                                \
                                                                               \
    USED void __asan_report_##type##size(unsigned long addr)                   \
    {                                                                          \
        kasan_check_memory(addr, size, is_write);                              \
    }                                                                          \
    USED void __asan_report_exp_##type##size(unsigned long addr, uint32_t exp) \
    {                                                                          \
        kasan_check_memory(addr, size, is_write);                              \
    }                                                                          \
                                                                               \
    USED void __asan_report_##type##size##_noabort(unsigned long addr)         \
    {                                                                          \
        kasan_check_memory(addr, size, is_write);                              \
    }

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)

USED int __asan_option_detect_stack_use_after_return = 0;
USED unsigned long __asan_shadow_memory_dynamic_address = KASAN_VIRT_START;

#define DEFINE_ASAN_SET_SHADOW(byte)                                  \
    USED void __asan_set_shadow_##byte(const void *addr, size_t size) \
    {                                                                 \
        memset((void *) addr, 0x##byte, size);                        \
    }

DEFINE_ASAN_SET_SHADOW(00);
DEFINE_ASAN_SET_SHADOW(f1);
DEFINE_ASAN_SET_SHADOW(f2);
DEFINE_ASAN_SET_SHADOW(f3);
DEFINE_ASAN_SET_SHADOW(f5);
DEFINE_ASAN_SET_SHADOW(f8);

USED void __asan_init()
{
}
USED void __asan_version_mismatch_check_v8()
{
}

USED void *memcpy(void *dst, const void *src, size_t n)
{
    if (n == 0)
        return dst;

    kasan_check_memory((unsigned long) dst, n, true);
    kasan_check_memory((unsigned long) src, n, false);

    return __memcpy(dst, src, n);
}

USED void *memmove(void *dst, const void *src, size_t n)
{
    if (n == 0)
        return dst;

    kasan_check_memory((unsigned long) dst, n, true);
    kasan_check_memory((unsigned long) src, n, false);

    return __memmove(dst, src, n);
}

// TODO(heat): Make memset intercepted (since it may be implemented in assembly)
USED void *__asan_memset(void *dst, int c, size_t n)
{
    if (n == 0)
        return dst;

    kasan_check_memory((unsigned long) dst, n, true);
    return memset(dst, c, n);
}
}

void kasan_init()
{
}

[[gnu::weak]] int mmu_map_kasan_shadow(void *shadow_start, size_t pages)
{
    return -ENOMEM;
}

int kasan_alloc_shadow(unsigned long addr, size_t size, bool accessible)
{
    unsigned long kasan_start = (unsigned long) kasan_get_ptr(addr);
    unsigned long kasan_end = (unsigned long) kasan_get_ptr(addr + size);

    unsigned long actual_start = kasan_start, actual_end = kasan_end;

    /* Align the boundaries */

    kasan_start &= ~(PAGE_SIZE - 1);

    if (kasan_end & (PAGE_SIZE - 1))
    {
        kasan_end += PAGE_SIZE - (kasan_end & (PAGE_SIZE - 1));
    }

    /*printf("Kasan start: %lx\n", kasan_start);
    printf("Kasan end: %lx\n", kasan_end);
    printf("Actual start: %lx\nActual end: %lx\n", actual_start, actual_end);*/

    if (mmu_map_kasan_shadow((void *) kasan_start, (kasan_end - kasan_start) >> PAGE_SHIFT) < 0)
        return -ENOMEM;

    /* Mask excess bytes as redzones */
    /* memset((void *) kasan_start, KASAN_REDZONE, actual_start - kasan_start);
    memset((void *) actual_end, KASAN_REDZONE, kasan_end - actual_end);*/

    memset((void *) actual_start, accessible ? 0 : (unsigned char) KASAN_REDZONE,
           actual_end - actual_start);

    return 0;
}

void platform_serial_write(const char *s, size_t size);

void asan_poison_shadow(unsigned long addr, size_t size, uint8_t value)
{
#if 0
	if()
	{
		char buf[100];
		snprintf(buf, 100, "poisoning [%lx, %lx]\n", addr, addr + size);

		platform_serial_write(buf, strlen(buf));
	}
#endif

    auto shadow_start = kasan_get_ptr(addr);
    auto shadow_end = kasan_get_ptr(addr + size);

    uint8_t offset = KASAN_MISALIGNMENT(addr);
    uint8_t end_leftover = KASAN_MISALIGNMENT(addr + size);

    if (shadow_start == shadow_end)
    {
        // We're only poisoning a single byte of shadow
        // See if any part of the byte was already poisoned or not, and if so extend it

        auto shadow_val = *shadow_start;
        if (shadow_val > 0)
        {
            // This byte is partially poisoned, lets check if there's no holes in our new poisoning.
            if (offset + size == (uint8_t) shadow_val)
            {
                // This works! Check for a partial poisoning vs a complete one
                *shadow_start = offset == 0 ? value : offset;
            }
            else
            {
                // Is this valid?
                panic("bug?");
            }
        }
        else if (shadow_val > 0 && offset != 0)
        {
            // Is this valid?
            panic("bug?");
        }

        return;
    }

    if (offset != 0)
    {
        // same question as above
        assert(offset + size >= sizeof(uint8_t));
        // Lets poison the first byte like we did up there
        if (shadow_start[0] == 0)
            shadow_start[0] = offset;
        else if (shadow_start[0] > 0)
        {
            shadow_start[0] = cul::min(offset, (uint8_t) shadow_start[0]);
        }

        shadow_start++;
    }

    memset(shadow_start, value, shadow_end - shadow_start);

    if (end_leftover != 0)
    {
        // Check for a partial poisoning at the end, and try to do it if we can complete the byte
        auto val = shadow_end[0];
        if (val > 0 && end_leftover == val)
        {
            shadow_end[0] = value;
        }
    }
}

void asan_unpoison_shadow(unsigned long addr, size_t size)
{
    auto shadow_start = kasan_get_ptr(addr);
    auto shadow_end = kasan_get_ptr(addr + size);

    uint8_t offset = KASAN_MISALIGNMENT(addr);
    uint8_t end_leftover = KASAN_MISALIGNMENT(addr + size);

    assert(offset == 0);

    memset(shadow_start, 0, shadow_end - shadow_start);

    if (end_leftover != 0)
    {
        // entire byte is poisoned, unpoison the start
        if (shadow_end[0] < 0)
        {
            shadow_end[0] = offset;
        }
        else if (shadow_end[0] > 0)
        {
            // try to increse the unpoisoned region
            shadow_end[0] = cul::max(offset, (uint8_t) shadow_end[0]);
        }
    }
}

extern "C" void kasan_set_state(unsigned long *__ptr, size_t size, int state)
{
    unsigned long addr = (unsigned long) __ptr;

    if (state == 0)
        asan_unpoison_shadow(addr, size);
    else
        asan_poison_shadow(addr, size, state == 1 ? KASAN_FREED : KASAN_REDZONE);
}

#if 0
static const uint64_t kAllocaRedzoneSize = 32UL;
static const uint64_t kAllocaRedzoneMask = 31UL;
#endif

extern "C" USED void __asan_alloca_poison(unsigned long addr, unsigned long size)
{
    /*
        unsigned long LeftRedzoneAddr = addr - kAllocaRedzoneSize;
        unsigned long PartialRzAddr = addr + size;
        unsigned long RightRzAddr = (PartialRzAddr + kAllocaRedzoneMask) & ~kAllocaRedzoneMask;
        unsigned long PartialRzAligned = PartialRzAddr & ~7;
        asan_poison_shadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
        FastPoisonShadowPartialRightRedzone(PartialRzAligned, PartialRzAddr & 7,
                                            RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
        asan_poison_shadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
    */
}

extern "C" USED void __asan_allocas_unpoison(unsigned long top, unsigned long bottom)
{
    if ((!top) || (top > bottom))
        return;
    memset(reinterpret_cast<void *>(kasan_get_ptr(top)), 0, (bottom - top) >> 3);
}

/**
 * @brief Get the redzone's size for the objsize
 *
 * @param objsize Object size
 * @return Redzone's size, on each side of the object
 */
size_t kasan_get_redzone_size(size_t objsize)
{
    if (objsize >= 2048)
        return 512;
    else if (objsize >= 1024)
        return 256;
    else if (objsize >= 512)
        return 128;
    else if (objsize >= 128)
        return 64;
    else if (objsize < 32)
        return 16;
    else if (objsize < 128)
        return 32;
    else
        return 1024;
}
