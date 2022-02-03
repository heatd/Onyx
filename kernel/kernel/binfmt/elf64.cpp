/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/binfmt/elf64.h>
#include <onyx/exec.h>
#include <onyx/process.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

static bool elf64_is_valid(Elf64_Ehdr *header)
{
    if (header->e_ident[EI_MAG0] != 0x7F || header->e_ident[EI_MAG1] != 'E' ||
        header->e_ident[EI_MAG2] != 'L' || header->e_ident[EI_MAG3] != 'F')
        return false;
    if (header->e_ident[EI_CLASS] != ELFCLASS64)
        return false;
    if (header->e_ident[EI_DATA] != ELFDATA2LSB)
        return false;
    if (header->e_ident[EI_VERSION] != EV_CURRENT)
        return false;
    if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
        return false;
    if (header->e_ident[EI_ABIVERSION] != 0) /* SYSV specific */
        return false;
    return true;
}

size_t elf_calculate_map_size(Elf64_Phdr *phdrs, size_t num)
{
    /* Took this idea from linux :) */

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
           (unsigned long) page_align_up((void *) phdrs[first_load].p_vaddr);
}

static void *elf_load_address(Elf64_Phdr *phdrs, Elf64_Half phnum)
{
    for (Elf64_Half i = 0; i < phnum; i++, phdrs++)
    {
        if (phdrs->p_type == PT_LOAD)
        {
            return (void *) (phdrs->p_vaddr - phdrs->p_offset);
        }
    }

    return nullptr;
}

static void *elf_load(struct binfmt_args *args, Elf64_Ehdr *header)
{
    bool is_interp = args->needs_interp;

    struct process *current = get_current_process();
    size_t program_headers_size = header->e_phnum * header->e_phentsize;
    struct file *fd = args->file;
    void *base = nullptr;
    Elf64_Dyn *dyn = nullptr;
    Elf64_Phdr *uphdrs = nullptr;
    size_t needed_size = 0;
    void *load_address = nullptr;

    int st = 0;

    Elf64_Phdr *phdrs = (Elf64_Phdr *) malloc(program_headers_size);
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

    if ((st = flush_old_exec(args->state)) < 0)
    {
        errno = -st;
        goto error1;
    }

    needed_size = elf_calculate_map_size(phdrs, header->e_phnum);

    if (needed_size == (size_t) -1)
    {
        errno = ENOEXEC;
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
	       (void *)((unsigned long) base + (vm_size_to_pages(needed_size) << PAGE_SHIFT)));
#endif
    header->e_entry += (uintptr_t) base;

    for (Elf64_Half i = 0; i < header->e_phnum; i++)
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

            read_vfs(phdrs[i].p_offset, phdrs[i].p_filesz, args->interp_path, args->file);
            args->needs_interp = true;
        }

        if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dyn = (Elf64_Dyn *) (phdrs[i].p_vaddr + (uintptr_t) base);
        }

        if (phdrs[i].p_type == PT_PHDR)
        {
            uphdrs = (Elf64_Phdr *) (phdrs[i].p_vaddr + (uintptr_t) base);
        }

        if (phdrs[i].p_type == PT_LOAD)
        {
            phdrs[i].p_vaddr += (uintptr_t) base;
            uintptr_t aligned_address = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1);
            size_t total_size = phdrs[i].p_memsz + (phdrs[i].p_vaddr - aligned_address);
            size_t pages = vm_size_to_pages(total_size);
            size_t misalignment = phdrs[i].p_vaddr - aligned_address;

            /* Sanitize the address first */
            if (vm_sanitize_address((void *) aligned_address, pages) < 0)
            {
                errno = EINVAL;
                goto error2;
            }

            int prot = ((phdrs[i].p_flags & PF_R) ? PROT_READ : 0) |
                       ((phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0) |
                       ((phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0);

            // printk("mmaping [%lx, %lx]\n", aligned_address, aligned_address + (pages <<
            // PAGE_SHIFT));
            if (!vm_mmap((void *) aligned_address, pages << PAGE_SHIFT, prot,
                         MAP_PRIVATE | MAP_FIXED, fd, phdrs[i].p_offset - misalignment))
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

                uint8_t *bss_base = (uint8_t *) (phdrs[i].p_vaddr + phdrs[i].p_filesz);
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
                    if (user_memset(bss_base, 0, bss_size) < 0)
                    {
                        errno = EFAULT;
                        goto error2;
                    }
                }
            }
        }
    }

    load_address = elf_load_address(phdrs, header->e_phnum);
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
            uphdrs = (Elf64_Phdr *) ((unsigned long) load_address + header->e_phoff);
        }

        current->info.phdr = uphdrs;
        current->info.dyn = dyn;
        current->info.program_entry = (void *) header->e_entry;
        // printk("phdrs: %p\n", current->info.phdr);
    }
    else
    {
        current->info.dyn = dyn;
    }

    /* TODO: Unmap holes */

    return (void *) header->e_entry;
error2:
    if (base)
        vm_munmap(get_current_address_space(), base, needed_size);
error1:
    free(phdrs);
error0:
    return nullptr;
}

void *elf64_load(struct binfmt_args *args, Elf64_Ehdr *header)
{
    if (!elf64_is_valid(header))
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
