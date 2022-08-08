/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <onyx/clock.h>
#include <onyx/compiler.h>
#include <onyx/log.h>
#include <onyx/mm/vm_object.h>
#include <onyx/panic.h>
#include <onyx/vdso.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#ifdef __x86_64__
#include <onyx/x86/tsc.h>
#endif

#include <sys/time.h>

extern Elf64_Ehdr __vdso_start;
extern size_t __vdso_end;

static char *elf_get_name(Elf64_Half off, char *buf)
{
    return buf + off;
}

class vdso
{
private:
    Elf64_Ehdr *vdso_start;
    size_t length;
    vm_object *vmo;
    bool vdso_setup;
    clock_time *clock_monotonic;
    clock_time *clock_realtime;
    unsigned long vdso_base;
    Elf64_Sym *vdso_symtab{nullptr};
    size_t nr_sym{0};
    char *vdso_strtab{nullptr};

    bool create_vmo()
    {
        vmo = vmo_create(length, nullptr);
        if (!vmo)
        {
            return false;
        }

        uintptr_t page = (uintptr_t) &__vdso_start;
        size_t vdso_size = (uintptr_t) &__vdso_end - page;
        size_t vdso_pages = vm_size_to_pages(vdso_size);

        page -= KERNEL_VIRTUAL_BASE;
        page += get_kernel_phys_offset();

        for (size_t i = 0; i < vdso_pages; i++, page += PAGE_SIZE)
        {
            auto p = page_add_page((void *) page);

            /* We ref 2 times - one for the vmo, and one because it's part of the kernel image */
            page_ref_many(p, 2);

            if (vmo_add_page(i << PAGE_SHIFT, p, vmo) < 0)
            {
                vmo_unref(vmo);
                return false;
            }
        }

        return true;
    }

public:
    vdso(Elf64_Ehdr *start, size_t length)
        : vdso_start{start}, length{length}, vmo{nullptr}, vdso_setup{false},
          clock_monotonic{nullptr}, clock_realtime{nullptr}
    {
    }

    vdso()
        : vdso_start{nullptr}, length{0}, vmo{nullptr}, vdso_setup{false}, clock_monotonic{nullptr},
          clock_realtime{nullptr}
    {
    }

    ~vdso()
    {
        if (vmo)
            vmo_unref(vmo);
    }

    bool init();

    template <typename Type>
    Type lookup_symbol(const char *name)
    {
        Elf64_Sym *s = vdso_symtab;
        for (size_t i = 0; i < nr_sym; i++, s++)
        {
            const char *symname = (const char *) elf_get_name(s->st_name, vdso_strtab);
            if (!strcmp(symname, name))
                return (Type) (vdso_base + s->st_value);
        }

        return nullptr;
    }

    int update_time(clockid_t id, struct clock_time *time);

    void *map();
};

#ifdef CONFIG_NO_VDSO

static vdso main_vdso{};

#else

static vdso main_vdso{&__vdso_start, (unsigned long) &__vdso_end - (unsigned long) &__vdso_start};

#endif

__attribute__((no_sanitize_undefined)) bool vdso::init()
{
    char *file = (char *) &__vdso_start;
    Elf64_Ehdr *header = (Elf64_Ehdr *) &__vdso_start;

    assert(header->e_ident[EI_MAG0] == '\x7f');

    Elf64_Shdr *s = (Elf64_Shdr *) (file + header->e_shoff);
    Elf64_Shdr *shname = &s[header->e_shstrndx];
    Elf64_Phdr *ph = (Elf64_Phdr *) (file + header->e_phoff);
    vdso_base = (uintptr_t) file + ph->p_offset;

    char *shname_buf = (char *) (file + shname->sh_offset);
    for (Elf64_Half i = 0; i < header->e_shnum; i++)
    {
        char *name = elf_get_name(s[i].sh_name, shname_buf);
        if (!strcmp(name, ".symtab"))
        {
            vdso_symtab = reinterpret_cast<Elf64_Sym *>(file + s[i].sh_offset);
            nr_sym = s[i].sh_size / s[i].sh_entsize;
        }
        else if (!strcmp(name, ".strtab"))
        {
            vdso_strtab = reinterpret_cast<char *>(file + s[i].sh_offset);
        }
    }

    if (!create_vmo())
        return false;

#ifdef __x86_64__
    auto time = lookup_symbol<vdso_time *>("__time");
    /* Configure the vdso with tsc stuff */
    tsc_setup_vdso(time);
#endif

    clock_monotonic = lookup_symbol<clock_time *>("clock_monotonic");
    clock_realtime = lookup_symbol<clock_time *>("clock_realtime");

    /* Update the vdso for the first time */
    main_vdso.update_time(CLOCK_MONOTONIC, get_raw_clock_time(CLOCK_MONOTONIC));
    main_vdso.update_time(CLOCK_REALTIME, get_raw_clock_time(CLOCK_REALTIME));

    vdso_setup = true;

    return true;
}

void *vdso::map()
{
    return vm_map_vmo(VM_ADDRESS_USER, VM_TYPE_SHARED, vm_size_to_pages(length),
                      VM_USER | VM_READ | VM_EXEC, vmo);
}

void *vdso_map(void)
{
#ifdef CONFIG_NO_VDSO
    return NULL;
#else
    return main_vdso.map();
#endif
}

int vdso::update_time(clockid_t id, struct clock_time *time)
{
    if (!vdso_setup)
        return 0;
    /* First, get the corresponding symbol */
    struct clock_time *t = NULL;
    if (id == CLOCK_REALTIME)
        t = clock_realtime;
    else if (id == CLOCK_MONOTONIC)
        t = clock_monotonic;

    /* If we didn't find the symbol/the clock isn't in the vdso, return an error */
    if (!t)
        return errno = EINVAL, -1;

    /* FIXME: Probably something like a seqlock would be good for this (like pvclock does) */
    t->epoch = time->epoch;
    t->tick = time->tick;

    return 0;
}

int vdso_update_time(clockid_t id, clock_time *time)
{
    return main_vdso.update_time(id, time);
}

/* Ubsan is being stupid so I need to shut it up */
void vdso_init()
{
    uintptr_t page = (uintptr_t) &__vdso_start;
    size_t vdso_size = (uintptr_t) &__vdso_end - page;
    size_t vdso_pages = vm_size_to_pages(vdso_size);

    page -= KERNEL_VIRTUAL_BASE;

    for (size_t i = 0; i < vdso_pages; i++, page += PAGE_SIZE)
    {
        auto p = page_add_page((void *) page);
        page_ref(p);
    }

    main_vdso.init();
}
