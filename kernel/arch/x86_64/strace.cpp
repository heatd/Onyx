/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <math.h>
#include <multiboot2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/cpu.h>
#include <onyx/elf.h>
#include <onyx/modules.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/perf_probe.h>
#include <onyx/symbol.h>
#include <onyx/task_switching.h>
#include <onyx/utils.h>
#include <onyx/vm.h>

#define DEFAULT_UNWIND_NUMBER 6

static inline void get_frame_pointer(uint64_t **ptr)
{
    /* This piece of code uses something important in the SYSV AMD64 calling convention.
     * The frame address of a function is stored in the RBP register,
     * which allows us to skip the variables used by the stack_trace function,
     * which by turn makes the code slightly faster and less confusing
     */
    __asm__ __volatile__("mov %%rbp, %0" : "=m"(*ptr)::"memory");
}

unsigned long get_ulong_user(void *ptr, bool *error)
{
    unsigned long l = 0;
    if (copy_from_user(&l, ptr, sizeof(unsigned long)) < 0)
    {
        *error = true;
        return 0xffffffffffffffff;
    }

    *error = false;
    return l;
}

void stack_trace_user(uintptr_t *stack)
{
    uint64_t *rbp = stack;
    bool error = false;

    printk("User stack trace:\n");
    int i = 0;
    while (get_ulong_user(rbp, &error) != 0 && error == false)
    {
        uintptr_t rip = get_ulong_user((rbp + 1), &error);

        if (error == true)
            return;
        if (rip == 0)
            return;

        printk("<%d> %016lx\n", i++, rip);

        rbp = (uintptr_t *) get_ulong_user(rbp, &error);

        if (error == true)
            return;
    }
    printk("Stack trace ended.\n");
}

#ifdef CONFIG_STACK_TRACE_SERIAL
#include <onyx/serial.h>
static char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

#define stack_printk budget_printk
#else
#define stack_printk printk

#endif

NO_ASAN
__attribute__((no_sanitize_undefined)) void stack_trace_ex(uint64_t *stack)
{
    // Get all the unwinds possible using threading structures
    thread_t *thread = get_current_thread();
    size_t unwinds_possible = 0;
    if (!thread) // We're still in single tasking mode, just use a safe default
        unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
    else
        unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this */

    uint64_t *rbp = stack;
    for (size_t i = 0; i < unwinds_possible; i++)
    {
        if (thread)
        {
            if ((uintptr_t) rbp & 0x7)
                break;

            unsigned long stack_base = ((unsigned long) thread->kernel_stack_top) - 0x4000;

            if (rbp >= thread->kernel_stack_top)
                break;
            if (rbp + 1 >= thread->kernel_stack_top)
                break;
            if (rbp < (unsigned long *) stack_base)
                break;
        }

        char buffer[SYM_SYMBOLIZE_BUFSIZ];

        unsigned long ip = *(rbp + 1);

        if (!is_kernel_ip(ip))
            break;

        int st = sym_symbolize((void *) ip, cul::slice<char>{buffer, sizeof(buffer)});
        if (st < 0)
            break;

        pr_emerg("Stack trace #%lu: %s\n", i, buffer);

        rbp = (uint64_t *) *rbp;
        if (!rbp)
            break;
    }
}

NO_ASAN
size_t stack_trace_get(unsigned long *stack, unsigned long *pcs, size_t nr_pcs)
{
    thread_t *thread = get_current_thread();
    size_t unwinds_possible = 0;
    if (!thread) // We're still in single tasking mode, just use a safe default
        unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
    else
        unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this */

    unwinds_possible = min(unwinds_possible, nr_pcs);
    uint64_t *rbp = stack;
    size_t i;
    for (i = 0; i < unwinds_possible; i++)
    {
        if (thread)
        {
            if ((uintptr_t) rbp & 0x7)
                break;

            unsigned long stack_base = ((unsigned long) thread->kernel_stack_top) - 0x4000;

            if (rbp >= thread->kernel_stack_top)
                break;
            if (rbp + 1 >= thread->kernel_stack_top)
                break;
            if (rbp < (unsigned long *) stack_base)
                break;
        }

        if (!(void *) *(rbp + 1))
            break;

        auto ip = (unsigned long) *(rbp + 1);
        if (ip < VM_HIGHER_HALF)
            break;

        pcs[i] = ip;

        rbp = (uint64_t *) *rbp;
        if (!rbp)
        {
            /* So pc termination doesn't zero this entry, increment i */
            i++;
            break;
        }
    }

    if (i != unwinds_possible)
        pcs[i] = 0;

    return i;
}

NO_ASAN
void stack_trace()
{
    uint64_t *stack = nullptr;
    get_frame_pointer(&stack);
    stack_trace_ex(stack);
}

/* Maybe it's better to put this section in another file */
Elf64_Shdr *strtabs = NULL;
Elf64_Shdr *symtab = NULL;
char *strtab = NULL;

__attribute__((no_sanitize_undefined)) char *elf_get_string(Elf64_Word off)
{
    return strtab + off;
}

__attribute__((no_sanitize_undefined)) void init_elf_symbols(
    struct multiboot_tag_elf_sections *secs)
{
    secs = (struct multiboot_tag_elf_sections *) ((unsigned long) secs + PHYS_BASE);
    Elf64_Shdr *sections = (Elf64_Shdr *) (secs->sections);
    strtabs = &sections[secs->shndx];
    strtab = (char *) (strtabs->sh_addr + PHYS_BASE);

    for (unsigned int i = 0; i < secs->num; i++)
    {
        if (!strcmp(".symtab", elf_get_string(sections[i].sh_name)))
        {
            symtab = &sections[i];
        }
        if (!strcmp(".strtab", elf_get_string(sections[i].sh_name)))
        {
            strtab = (char *) (sections[i].sh_addr + PHYS_BASE);
        }
    }
}

void reclaim_elf_sections_memory(void);

void setup_kernel_symbols(struct module *m)
{
    const size_t num = symtab->sh_size / symtab->sh_entsize;
    Elf64_Sym *syms = (Elf64_Sym *) (symtab->sh_addr + PHYS_BASE);
    size_t useful_syms = 0;

    for (size_t i = 0; i < num; i++)
    {
        Elf64_Sym *sym = &syms[i];
        if (!is_useful_symbol(sym))
            continue;

        useful_syms++;
    }

    struct symbol *symtab = (symbol *) zalloc(sizeof(struct symbol) * useful_syms);

    assert(symtab != NULL);

    for (size_t i = 0, n = 0; i < num; i++)
    {
        Elf64_Sym *sym = &syms[i];
        if (!is_useful_symbol(sym))
            continue;

        /* TODO: Re-use more code between elf.c's module loading and this */

        struct symbol *s = &symtab[n];
        assert(setup_symbol(s, sym, elf_get_string(sym->st_name)) == 0);

        n++;
    }

    m->symtable = symtab;
    m->nr_symtable_entries = useful_syms;

    reclaim_elf_sections_memory();
}

static unsigned long strtab_start, strtab_end = 0;
static unsigned long symtab_start, symtab_end = 0;

void elf_sections_reserve(struct multiboot_tag_elf_sections *__secs)
{
    auto secs = (multiboot_tag_elf_sections *) x86_placement_map((unsigned long) __secs);
    uint32_t num_secs = secs->num;
    Elf64_Shdr *sections = (Elf64_Shdr *) (__secs->sections);
    strtabs = (Elf64_Shdr *) x86_placement_map((unsigned long) &sections[secs->shndx]);

    bootmem_reserve(strtabs->sh_addr, strtabs->sh_size);

    strtab = (char *) strtabs->sh_addr;

    for (unsigned int i = 0; i < num_secs; i++)
    {
        Elf64_Shdr *section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
        Elf64_Word name = section->sh_name;

        const char *str = elf_get_string(name);

        str = (char *) x86_placement_map((unsigned long) str);

        if (!strcmp(".symtab", str))
        {
            section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
            symtab_start = section->sh_addr;
            symtab_end = section->sh_addr + section->sh_size;

            bootmem_reserve(symtab_start, section->sh_size);
        }
        if (!strcmp(".strtab", str))
        {
            section = (Elf64_Shdr *) x86_placement_map((unsigned long) (sections + i));
            strtab_start = section->sh_addr;
            strtab_end = section->sh_addr + section->sh_size;
            bootmem_reserve(strtab_start, section->sh_size);
        }
    }
}

void reclaim_elf_sections_memory(void)
{
    if (strtab_start && strtab_end)
    {
        reclaim_pages(strtab_start, strtab_end);
    }

    if (symtab_start && symtab_end)
    {
        reclaim_pages(symtab_start, symtab_end);
    }
}
