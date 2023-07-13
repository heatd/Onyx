/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/binfmt.h>
#include <onyx/exec.h>
#include <onyx/kunit.h>
#include <onyx/process.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <platform/elf.h>

#if (__SIZE_WIDTH__ == 64 && !defined(ELF_COMPAT))

using elf_ehdr = Elf64_Ehdr;
using elf_phdr = Elf64_Phdr;
using elf_half = Elf64_Half;
using elf_dyn = Elf64_Dyn;
#define ELF_BITS 64

#define ELFCLASS ELFCLASS64

#elif (__SIZE_WIDTH__ == 32 || defined(ELF_COMPAT))

using elf_ehdr = Elf32_Ehdr;
using elf_phdr = Elf32_Phdr;
using elf_half = Elf32_Half;
using elf_dyn = Elf32_Dyn;

#define ELFCLASS ELFCLASS32
#define ELF_BITS 32

#ifdef EM_CURRENT_COMPAT

// Re-define EM_CURRENT for COMPAT
#undef EM_CURRENT
#define EM_CURRENT EM_CURRENT_COMPAT

#endif

#endif

#define ELF_NAMESPACE __PASTE(elf, ELF_BITS)

namespace ELF_NAMESPACE
{

static bool elf_is_valid(elf_ehdr *header)
{
    if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3)
        return false;
    if (header->e_ident[EI_CLASS] != ELFCLASS)
        return false;
    if (header->e_ident[EI_DATA] != ELFDATA2LSB)
        return false;
    if (header->e_ident[EI_VERSION] != EV_CURRENT)
        return false;
    if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV && header->e_ident[EI_OSABI] != ELFOSABI_LINUX)
        return false;
    if (header->e_ident[EI_ABIVERSION] != 0) /* SYSV specific */
        return false;
    if (header->e_machine != EM_CURRENT)
        return false;
    return true;
}

size_t elf_calculate_map_size(elf_phdr *phdrs, size_t num)
{
    size_t first_load = -1, last_load = -1;
    for (size_t i = 0; i < num; i++)
    {
        if (phdrs[i].p_type == PT_LOAD)
        {
            last_load = i;

            if (first_load == (size_t) -1)
                first_load = i;
        }
    }

    if (first_load == (size_t) -1)
        return -1;

    return (phdrs[last_load].p_vaddr + phdrs[last_load].p_memsz) -
           (phdrs[first_load].p_vaddr & -PAGE_SIZE);
}

static unsigned long elf_load_address(elf_phdr *phdrs, elf_half phnum)
{
    for (elf_half i = 0; i < phnum; i++, phdrs++)
    {
        if (phdrs->p_type == PT_LOAD)
        {
            return (unsigned long) phdrs->p_vaddr - phdrs->p_offset;
        }
    }

    return 0;
}

bool elf_phdrs_valid(const elf_phdr *phdrs, size_t nr_phdrs)
{
    long last = -1;

    for (size_t i = 0; i < nr_phdrs; i++, phdrs++)
    {
        if (phdrs->p_type != PT_LOAD)
            continue;

        if ((unsigned long) phdrs->p_vaddr > arch_low_half_max ||
            (unsigned long) phdrs->p_memsz > arch_low_half_max ||
            (unsigned long) phdrs->p_vaddr + phdrs->p_memsz > arch_low_half_max)
            return false;

        // ELF PT_LOAD segments must be ordered by rising vaddr
        // This also deals with overlap
        if (last != -1 && (unsigned long) last > phdrs->p_vaddr)
        {
            return false;
        }

        // p_memsz >= p_filesz
        if (phdrs->p_memsz < phdrs->p_filesz)
            return false;

        last = phdrs->p_vaddr + phdrs->p_memsz;
    }

    return true;
}

static void *elf_load(struct binfmt_args *args, elf_ehdr *header)
{
    bool is_interp = args->needs_interp;

    struct process *current = get_current_process();

    if (header->e_phentsize != sizeof(elf_phdr))
        return errno = ENOEXEC, nullptr;

    size_t program_headers_size;

    if (__builtin_mul_overflow(header->e_phnum, header->e_phentsize, &program_headers_size))
        return errno = ENOEXEC, nullptr;

    struct file *fd = args->file;
    void *base = nullptr;
    elf_dyn *dyn = nullptr;
    elf_phdr *uphdrs = nullptr;
    size_t needed_size = 0;
    void *load_address = nullptr;

    int st = 0;

    elf_phdr *phdrs = (elf_phdr *) malloc(program_headers_size);
    if (!phdrs)
    {
        errno = ENOMEM;
        goto error0;
    }

    /* Read the program headers */
    if (read_vfs(header->e_phoff, program_headers_size, phdrs, args->file) !=
        (ssize_t) program_headers_size)
    {
        errno = EIO;
        goto error1;
    }

    if (!elf_phdrs_valid(phdrs, header->e_phnum))
    {
        errno = ENOEXEC;
        goto error1;
    }

    needed_size = elf_calculate_map_size(phdrs, header->e_phnum);

    if (needed_size == (size_t) -1)
    {
        errno = ENOEXEC;
        goto error1;
    }

    if ((st = flush_old_exec(args->state)) < 0)
    {
        errno = -st;
        goto error1;
    }

    // Note that if we're not ET_DYN(so, ET_EXEC) the base is implicitly zero and we don't need
    // to allocate any space on the address space, therefore we don't need to mmap it.
    if (header->e_type == ET_DYN)
    {
        base = vm_mmap(nullptr, vm_size_to_pages(needed_size) << PAGE_SHIFT, PROT_NONE,
                       MAP_ANONYMOUS | MAP_PRIVATE, nullptr, 0);
        if (!base)
        {
            errno = ENOMEM;
            goto error1;
        }
    }

#if 0
    printk("initial mmap %p to %p\n", base,
           (void *) ((unsigned long) base + (vm_size_to_pages(needed_size) << PAGE_SHIFT)));
#endif
    header->e_entry += (uintptr_t) base;

    for (elf_half i = 0; i < header->e_phnum; i++)
    {
        if (phdrs[i].p_type == PT_NULL)
            continue;

        if (phdrs[i].p_type == PT_INTERP)
        {
            /* The interpreter can't have an interpreter of its own */
            if (is_interp)
            {
                errno = ENOEXEC;
                goto error2;
            }

            /* We allocate one more byte for the nullptr byte so we don't get buffer overflow'd */
            args->interp_path = (char *) malloc(phdrs[i].p_filesz + 1);
            if (!args->interp_path)
            {
                errno = ENOMEM;
                goto error2;
            }

            args->interp_path[phdrs[i].p_filesz] = '\0';

            auto len =
                read_vfs(phdrs[i].p_offset, phdrs[i].p_filesz, args->interp_path, args->file);
            if (len < 0 || (size_t) len != phdrs[i].p_filesz)
            {
                free(args->interp_path);
                args->interp_path = nullptr;
                errno = ENOEXEC;
                goto error2;
            }

            args->needs_interp = true;
        }

        if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dyn = (elf_dyn *) (phdrs[i].p_vaddr + (uintptr_t) base);
        }

        if (phdrs[i].p_type == PT_PHDR)
        {
            uphdrs = (elf_phdr *) (phdrs[i].p_vaddr + (uintptr_t) base);
        }

        if (phdrs[i].p_type == PT_LOAD)
        {
            phdrs[i].p_vaddr += (uintptr_t) base;
            // Note: We calculate addr based on the aligned offset instead of the opposite
            // because in this case, offset can never underflow and create a valid mmap
            // that will SIGBUS on access.
            unsigned long offset = phdrs[i].p_offset & -PAGE_SIZE;
            unsigned long addr = phdrs[i].p_vaddr - (phdrs[i].p_offset & (PAGE_SIZE - 1));
            size_t total_size = phdrs[i].p_memsz + (phdrs[i].p_vaddr - addr);
            size_t pages = vm_size_to_pages(total_size);

            /* Sanitize the address first */
            if (vm_sanitize_address((void *) addr, pages) < 0)
            {
                errno = ENOEXEC;
                goto error2;
            }

            int prot = ((phdrs[i].p_flags & PF_R) ? PROT_READ : 0) |
                       ((phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0) |
                       ((phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0);

            // printk("mmaping [%lx, %lx]\n", addr, (unsigned long) addr + (pages << PAGE_SHIFT));
            if (!vm_mmap((void *) addr, pages << PAGE_SHIFT, prot, MAP_PRIVATE | MAP_FIXED, fd,
                         offset))
            {
                goto error2;
            }

            if (phdrs[i].p_filesz != phdrs[i].p_memsz)
            {
                if (!(prot & PROT_WRITE))
                {
                    /* This malicious binary is trying to get us to segfault by writing to
                     * read-only memory
                     */
                    errno = ENOEXEC;
                    goto error2;
                }

                uint8_t *bss_base =
                    (uint8_t *) ((unsigned long) phdrs[i].p_vaddr + phdrs[i].p_filesz);
                uint8_t *zero_pages_base = (uint8_t *) page_align_up(bss_base);
                size_t bss_size = phdrs[i].p_memsz - phdrs[i].p_filesz;
                size_t to_zero = zero_pages_base - bss_base;
                if (to_zero > bss_size)
                    to_zero = bss_size;

                size_t zero_pages_len = bss_size - to_zero;

                if (zero_pages_len)
                {
                    size_t zero_pages = zero_pages_len / PAGE_SIZE;
                    if (zero_pages_len % PAGE_SIZE)
                        zero_pages++;

                    if (!vm_mmap(zero_pages_base, zero_pages << PAGE_SHIFT, prot,
                                 MAP_PRIVATE | MAP_FIXED | MAP_ANON, nullptr, 0))
                    {
                        errno = ENOMEM;
                        goto error2;
                    }
                }

                if (to_zero)
                {
                    if (user_memset(bss_base, 0, to_zero) < 0)
                    {
                        errno = EFAULT;
                        goto error2;
                    }
                }
            }
        }
    }

    load_address = (void *) elf_load_address(phdrs, header->e_phnum);
    free(phdrs);
    phdrs = nullptr;

    if (!load_address)
    {
        errno = ENOEXEC;
        goto error2;
    }

    if (is_interp)
        current->interp_base = (void *) base;
    else
        current->image_base = (void *) base;

    if (!is_interp)
    {
        current->info.phent = header->e_phentsize;
        current->info.phnum = header->e_phnum;
        if (!uphdrs)
        {
            uphdrs = (elf_phdr *) ((unsigned long) load_address + header->e_phoff);
        }

        current->info.phdr = (unsigned long) uphdrs;
        current->info.dyn = (unsigned long) dyn;
        current->info.program_entry = (void *) (unsigned long) header->e_entry;
        // printk("phdrs: %p\n", current->info.phdr);
        if (apply_sugid_permissions(fd))
            current->set_secure();
    }
    else
    {
        current->info.dyn = (unsigned long) dyn;
    }

    /* TODO: Unmap holes */

    return (void *) (unsigned long) header->e_entry;
error2:
    if (base)
        vm_munmap(get_current_address_space(), base, needed_size);
error1:
    free(phdrs);
error0:
    return nullptr;
}

void *elf64_load(struct binfmt_args *args, elf_ehdr *header)
{
    if (!elf_is_valid(header))
        return errno = ENOEXEC, nullptr;

    switch (header->e_type)
    {
        case ET_DYN:
        case ET_EXEC:
            return elf_load(args, header);
        default:
            return errno = ENOEXEC, nullptr;
    }
}

void *elf_load_binfmt(struct binfmt_args *args)
{
    bool is_interp = args->needs_interp;

    unique_ptr<elf_ehdr> header = make_unique<elf_ehdr>();
    if (!header)
        return errno = EINVAL, nullptr;

    if (ssize_t st = read_vfs(0, sizeof(elf_ehdr), header.get(), args->file); st < 0)
    {
        return errno = -st, nullptr;
    }

    void *entry = elf_load(args, header.get());

    if (!entry)
        return nullptr;

    if (args->needs_interp && !is_interp)
        entry = bin_do_interp(args);

    return entry;
}

bool elf_is_valid_exec(uint8_t *file)
{
    return elf_is_valid((elf_ehdr *) file);
}

struct binfmt elf_binfmt = {.signature = (unsigned char *) "\x7f"
                                                           "ELF",
                            .size_signature = 4,
                            .is_valid_exec = elf_is_valid_exec,
                            .callback = elf_load_binfmt,
                            .next = nullptr};

__init void __elf_init()
{
    install_binfmt(&elf_binfmt);
}

} // namespace ELF_NAMESPACE

#ifdef CONFIG_KUNIT

#ifndef ELF_COMPAT

TEST(elfldr, test_invalid_header)
{
    elf_ehdr eh;
    eh.e_ident[EI_MAG0] = ELFMAG0;
    eh.e_ident[EI_MAG1] = ELFMAG1;
    eh.e_ident[EI_MAG2] = ELFMAG2;
    eh.e_ident[EI_MAG3] = 'd';
    ASSERT_FALSE(ELF_NAMESPACE::elf_is_valid(&eh));
}

TEST(elfldr, test_bad_phdrs)
{
    elf_phdr phdrs[3];
    for (auto &p : phdrs)
    {
        p.p_type = PT_LOAD;
    }

    phdrs[0].p_vaddr = 0x400000;
    phdrs[0].p_memsz = phdrs[0].p_filesz = PAGE_SIZE;
    phdrs[1].p_vaddr = 0x430000;
    phdrs[1].p_memsz = phdrs[1].p_filesz = PAGE_SIZE;
    phdrs[2].p_vaddr = 0x410000;
    phdrs[2].p_memsz = phdrs[2].p_filesz = PAGE_SIZE;
    // Test OoO phdrs
    EXPECT_FALSE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 3));
    cul::swap(phdrs[2].p_vaddr, phdrs[1].p_vaddr);
    phdrs[0].p_memsz = 0x1000000;
    // Test overlap
    EXPECT_FALSE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 3));
    phdrs[0].p_memsz = PAGE_SIZE;
    phdrs[0].p_filesz = PAGE_SIZE * 2;
    // Test memsz < filesz
    EXPECT_FALSE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 3));
    phdrs[0].p_filesz = 0;

    // Test phdrs with bss segment
    EXPECT_TRUE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 3));

    phdrs[0].p_filesz = PAGE_SIZE;

    EXPECT_TRUE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 3));
}

TEST(elfldr, test_no_gap_regression)
{
    // Regression test for issue loading segments with no gap in between.
    elf_phdr phdrs[2];
    unsigned long vaddr = 0x4000000;
    for (auto &p : phdrs)
    {
        p.p_type = PT_LOAD;
        p.p_vaddr = vaddr;
        p.p_memsz = p.p_filesz = 0x1000;
        vaddr += p.p_memsz;
    }

    // 0 [0x4000000, 0x4001000]
    // 1 [0x4001000, 0x4002000]

    EXPECT_TRUE(ELF_NAMESPACE::elf_phdrs_valid(phdrs, 2));
}

#endif

#endif
