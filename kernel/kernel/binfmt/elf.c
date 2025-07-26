/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>
#include <stdio.h>

#include <onyx/binfmt.h>
#include <onyx/err.h>
#include <onyx/exec.h>
// #include <onyx/kunit.h>
#include <sys/procfs.h>

#include <onyx/coredump.h>
#include <onyx/mm/slab.h>
#include <onyx/process.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <platform/elf.h>

#if (__SIZE_WIDTH__ == 64 && !defined(ELF_COMPAT))

typedef Elf64_Ehdr elf_ehdr;
typedef Elf64_Phdr elf_phdr;
typedef Elf64_Half elf_half;
typedef Elf64_Dyn elf_dyn;
typedef Elf64_Nhdr elf_nhdr;
#define ELF_BITS 64

#define ELFCLASS ELFCLASS64

#elif (__SIZE_WIDTH__ == 32 || defined(ELF_COMPAT))

typedef Elf32_Ehdr elf_ehdr;
typedef Elf32_Phdr elf_phdr;
typedef Elf32_Half elf_half;
typedef Elf32_Dyn elf_dyn;
typedef Elf32_Nhdr elf_nhdr;

#define ELFCLASS ELFCLASS32
#define ELF_BITS 32

#ifdef EM_CURRENT_COMPAT

// Re-define EM_CURRENT for COMPAT
#undef EM_CURRENT
#define EM_CURRENT EM_CURRENT_COMPAT

#endif

#endif

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

static size_t elf_calculate_map_size(elf_phdr *phdrs, size_t num)
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

static bool elf_phdrs_valid(const elf_phdr *phdrs, size_t nr_phdrs)
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
            return false;

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

    if (header->e_phentsize != sizeof(elf_phdr))
        return errno = ENOEXEC, NULL;

    size_t program_headers_size;

    if (__builtin_mul_overflow(header->e_phnum, header->e_phentsize, &program_headers_size))
        return errno = ENOEXEC, NULL;

    struct file *fd = args->file;
    void *base = NULL;
    elf_dyn *dyn = NULL;
    elf_phdr *uphdrs = NULL;
    size_t needed_size = 0;
    void *load_address = NULL;

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
        base = vm_mmap(NULL, vm_size_to_pages(needed_size) << PAGE_SHIFT, PROT_NONE,
                       MAP_ANONYMOUS | MAP_PRIVATE, NULL, 0);
        if (IS_ERR(base))
        {
            errno = PTR_ERR(base);
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

            /* We allocate one more byte for the NULL byte so we don't get buffer overflow'd */
            args->interp_path = (char *) malloc(phdrs[i].p_filesz + 1);
            if (!args->interp_path)
            {
                errno = ENOMEM;
                goto error2;
            }

            args->interp_path[phdrs[i].p_filesz] = '\0';

            ssize_t len =
                read_vfs(phdrs[i].p_offset, phdrs[i].p_filesz, args->interp_path, args->file);
            if (len < 0 || (size_t) len != phdrs[i].p_filesz)
            {
                free(args->interp_path);
                args->interp_path = NULL;
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

            // printk("mmaping [%lx, %lx]\n", aligned_address, aligned_address + (pages <<
            // PAGE_SHIFT));
            void *res = vm_mmap((void *) addr, pages << PAGE_SHIFT, prot, MAP_PRIVATE | MAP_FIXED,
                                fd, offset);
            if (IS_ERR(res))
            {
                errno = PTR_ERR(res);
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

                    res = vm_mmap(zero_pages_base, zero_pages << PAGE_SHIFT, prot,
                                  MAP_PRIVATE | MAP_FIXED | MAP_ANON, NULL, 0);
                    if (IS_ERR(res))
                    {
                        errno = PTR_ERR(res);
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
    phdrs = NULL;

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
            set_task_flag(current, PROCESS_SECURE);
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
    return NULL;
}

static void *elf_load_binfmt(struct binfmt_args *args)
{
    bool is_interp = args->needs_interp;
    ssize_t st;
    elf_ehdr header;
    if ((st = read_vfs(0, sizeof(elf_ehdr), &header, args->file)) < 0)
        return errno = -st, NULL;

    void *entry = elf_load(args, &header);
    if (!entry)
        return NULL;

    if (args->needs_interp && !is_interp)
        entry = bin_do_interp(args);

    return entry;
}

static bool elf_is_valid_exec(uint8_t *file)
{
    return elf_is_valid((elf_ehdr *) file);
}

static struct binfmt elf_binfmt = {.signature = (unsigned char *) "\x7f"
                                                                  "ELF",
                                   .size_signature = 4,
                                   .is_valid_exec = elf_is_valid_exec,
                                   .callback = elf_load_binfmt,
                                   .next = NULL};

__init static void __elf_init()
{
    install_binfmt(&elf_binfmt);
}

/* TODO: this isn't correct */
#ifndef ELF_COMPAT

struct elf_core_thread
{
    struct elf_prstatus prstatus;
    elf_fpregset_t fpregs;
};

struct elf_core_notes
{
    unsigned int len;
    unsigned int nr_threads;
    struct elf_prpsinfo prpsinfo;
    struct elf_core_thread *threads;
    void *nt_files;
    unsigned int nt_files_len;
};

static unsigned int simple_notesize(unsigned int len, const char *name)
{
    return sizeof(elf_nhdr) + ALIGN_TO(strlen(name) + 1, 4) + ALIGN_TO(len, 4);
}

static void fill_out_ehdr(elf_ehdr *hdr, struct core_state *core)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->e_ident[EI_MAG0] = ELFMAG0;
    hdr->e_ident[EI_MAG1] = ELFMAG1;
    hdr->e_ident[EI_MAG2] = ELFMAG2;
    hdr->e_ident[EI_MAG3] = ELFMAG3;
    hdr->e_ident[EI_CLASS] = ELFCLASS;
    hdr->e_ident[EI_DATA] = ELFDATA2LSB;
    hdr->e_ident[EI_VERSION] = EV_CURRENT;
    hdr->e_version = EV_CURRENT;
    hdr->e_machine = EM_CURRENT;
    hdr->e_type = ET_CORE;
    hdr->e_phnum = core->nr_vmas + 1;
    hdr->e_phentsize = sizeof(elf_phdr);
    hdr->e_phoff = hdr->e_ehsize = sizeof(elf_ehdr);
}

static int fill_prpsinfo(struct elf_core_notes *notes)
{
    unsigned int args_len;
    struct mm_address_space *mm = current->address_space;
    struct elf_prpsinfo *psinfo = &notes->prpsinfo;

    notes->len += simple_notesize(sizeof(*psinfo), "CORE");

    memset(psinfo, 0, sizeof(*psinfo));
    psinfo->pr_flag = READ_ONCE(current->flags);
    memcpy(psinfo->pr_fname, current->comm, sizeof(current->comm));
    args_len = min(mm->arg_end - mm->arg_start, (unsigned long) ELF_PRARGSZ - 1);
    if (copy_from_user(psinfo->pr_psargs, (void *) mm->arg_start, args_len) < 0)
        return -EFAULT;
    /* Replace all found null bytes with ' ' and zero the last len */
    for (unsigned int i = 0; i < args_len; i++)
    {
        if (psinfo->pr_psargs[i] == '\0')
            psinfo->pr_psargs[i] = ' ';
    }

    psinfo->pr_psargs[args_len] = '\0';
    psinfo->pr_pid = task_tgid(current);
    rcu_read_lock();
    psinfo->pr_ppid = task_tgid(task_parent(current));
    psinfo->pr_pgrp = pid_nr(task_pgrp(current));
    psinfo->pr_pgrp = pid_nr(task_session(current));
    rcu_read_unlock();
    psinfo->pr_uid = current->cred.euid;
    psinfo->pr_gid = current->cred.egid;
    /* TODO: pr_sname, state, zomb. figure these out and do them properly */
    psinfo->pr_sname = 'R';
    return 0;
}

static void core_fill_fpregs(struct elf_core_thread *thr, struct process *task)
{
    unsigned int fpu_size = fpu_get_save_size();
    unsigned int copy = min(fpu_size, sizeof(elf_fpregset_t));

    /* Save the FPU if we haven't yet. suspended threads will already have done that. */
    if (task == current)
        save_fpu(task->thr->fpu_area);

    /* Copy the fpu area and zero the rest if required */
    memcpy(&thr->fpregs, task->thr->fpu_area, copy);
    if (fpu_size < sizeof(elf_fpregset_t))
        memset((u8 *) &thr->fpregs + copy, 0, sizeof(elf_fpregset_t) - copy);
    /* TODO: PROPERLY figure this out? X86_XSTATE support and similar... */
}

static void fill_notes_for_thread(struct core_state *core, struct elf_core_notes *notes,
                                  struct elf_core_thread *thr, struct process *thread)
{
    struct elf_prstatus *prs = &thr->prstatus;

    memset(prs, 0, sizeof(*prs));
    prs->pr_cursig = core->signo;
    prs->pr_info.si_signo = core->signo;
    prs->pr_info.si_code = core->siginfo->si_code;
    prs->pr_info.si_errno = core->siginfo->si_errno;
    /* TODO: (c)utime */
    prs->pr_fpvalid = 1;
    prs->pr_pid = pid_nr(task_pid(thread));
    rcu_read_lock();
    prs->pr_ppid = task_tgid(task_parent(thread));
    prs->pr_pgrp = pid_nr(task_pgrp(thread));
    prs->pr_pgrp = pid_nr(task_session(thread));
    rcu_read_unlock();
    memcpy(&prs->pr_sigpend, &thread->sigqueue.pending, sizeof(prs->pr_sigpend));
    memcpy(&prs->pr_sighold, &thread->sigmask, sizeof(prs->pr_sighold));
    core_fill_regs(&prs->pr_reg, thread);
    notes->len += simple_notesize(sizeof(*prs), "CORE");

    core_fill_fpregs(thr, thread);
    notes->len += simple_notesize(sizeof(thr->fpregs), "CORE");
}

static int fill_thread_notes(struct core_state *core, struct elf_core_notes *notes)
{
    struct core_thread *thread;
    struct elf_core_thread *thr;
    notes->nr_threads = core->nr_threads + 1;
    notes->threads = kvcalloc(notes->nr_threads, sizeof(struct elf_core_thread), GFP_KERNEL);
    if (!notes->threads)
        return -ENOMEM;

    thr = notes->threads;
    fill_notes_for_thread(core, notes, thr, current);
    thr++;

    list_for_each_entry (thread, &core->thread_list, list_node)
    {
        fill_notes_for_thread(core, notes, thr, thread->task);
        thr++;
    }

    return 0;
}

static int write_pt_note(struct core_state *core, unsigned long offset,
                         struct elf_core_notes *notes)
{
    elf_phdr phdr = {0};
    phdr.p_filesz = notes->len;
    phdr.p_flags = PF_R;
    phdr.p_offset = offset;
    phdr.p_type = PT_NOTE;
    return dump_write(core, &phdr, sizeof(phdr));
}

static int write_program_headers(struct core_state *core, struct elf_core_notes *notes)
{
    unsigned long offset, notes_off;
    struct core_vma *vma;

    /* Calculate the start offset of useful "data". After program headers. */
    offset = dump_offset(core) + (core->nr_vmas + 1) * sizeof(elf_phdr);

    if (!write_pt_note(core, offset, notes))
        return 0;

    notes_off = offset;
    offset += notes->len;
    offset = ALIGN_TO(offset, PAGE_SIZE);

    for (unsigned int i = 0; i < core->nr_vmas; i++)
    {
        elf_phdr phdr = {0};
        vma = core->vmas + i;
        phdr.p_align = PAGE_SIZE;
        phdr.p_filesz = vma->dump_len;
        phdr.p_memsz = vma->end - vma->start;
        phdr.p_paddr = phdr.p_vaddr = vma->start;
        phdr.p_offset = offset;
        phdr.p_flags = (vma->flags & VM_READ ? PF_R : 0) | (vma->flags & VM_WRITE ? PF_W : 0) |
                       (vma->flags & VM_EXEC ? PF_X : 0);
        phdr.p_type = PT_LOAD;
        if (!dump_write(core, &phdr, sizeof(phdr)))
            return 0;
        WARN_ON(vma->dump_len & (PAGE_SIZE - 1));
        WARN_ON(offset & (PAGE_SIZE - 1));
        offset = offset + vma->dump_len;
    }

    WARN_ON(notes_off != (size_t) dump_offset(core));
    return 1;
}

static int write_note(struct core_state *core, const char *name, const void *buf, size_t size,
                      int type)
{
    elf_nhdr note;
    note.n_namesz = strlen(name) + 1;
    note.n_descsz = size;
    note.n_type = type;
    if (!dump_write(core, &note, sizeof(note)) || !dump_write(core, name, note.n_namesz) ||
        !dump_align(core, 4) || !dump_write(core, buf, size) || !dump_align(core, 4))
        return 0;
    return 1;
}

static int write_thread_notes(struct core_state *core, struct elf_core_thread *thr)
{
    if (!write_note(core, "CORE", &thr->prstatus, sizeof(thr->prstatus), NT_PRSTATUS))
        return 0;
    if (!write_note(core, "CORE", &thr->fpregs, sizeof(thr->fpregs), NT_FPREGSET))
        return 0;
    return 1;
}

static int write_notes(struct core_state *core, struct elf_core_notes *notes)
{
    unsigned int i;

    if (!write_note(core, "CORE", &notes->prpsinfo, sizeof(notes->prpsinfo), NT_PRPSINFO))
        return 0;

    if (!write_note(core, "CORE", current->address_space->saved_auxv,
                    sizeof(current->address_space->saved_auxv), NT_AUXV))
        return 0;

    if (!write_note(core, "CORE", core->siginfo, sizeof(siginfo_t), NT_SIGINFO))
        return 0;

    if (notes->nt_files)
    {
        if (!write_note(core, "CORE", notes->nt_files, notes->nt_files_len, NT_FILE))
            return 0;
    }

    for (i = 0; i < notes->nr_threads; i++)
    {
        if (!write_thread_notes(core, &notes->threads[i]))
            return 0;
    }

    return 1;
}

struct nt_file_entry
{
    unsigned long start;
    unsigned long end;
    unsigned long pgoff;
};

static void fill_nt_files(struct core_state *core, struct elf_core_notes *notes)
{
    int nr_files = 0, file_idx;
    struct core_vma *vma;
    long *files;
    char *strings, *end, *pathname;
    size_t size, pathname_len;
    struct nt_file_entry *entries;

    notes->nt_files = NULL;
    for (unsigned int i = 0; i < core->nr_vmas; i++)
    {
        vma = core->vmas + i;
        if (vma->file && vma->file->f_path.mount)
            nr_files++;
    }

    /* No files? that's okay */
    if (nr_files == 0)
        return;

    /* Allocate a hopefully-okay-sized buffer for everything */
    size = nr_files * sizeof(struct nt_file_entry) + sizeof(long) * 2 + 64 * nr_files;
grow:
    files = kvmalloc(size, GFP_KERNEL);
    if (!files)
        return;

    strings = ((char *) files) + nr_files * sizeof(struct nt_file_entry) + sizeof(long) * 2;
    end = ((char *) files) + size;

    files[0] = nr_files;
    files[1] = PAGE_SIZE;
    entries = (struct nt_file_entry *) &files[2];
    file_idx = 0;

    for (unsigned int i = 0; i < core->nr_vmas; i++)
    {
        vma = core->vmas + i;
        if (!vma->file || !vma->file->f_path.mount)
            continue;

        entries[file_idx].start = vma->start;
        entries[file_idx].end = vma->end;
        entries[file_idx++].pgoff = vma->offset >> PAGE_SHIFT;
        pathname = d_path(&vma->file->f_path, strings, end - strings);
        if (IS_ERR(pathname))
        {
            /* grow and realloc the buffer */
            kvfree(files);
            size <<= 1;
            goto grow;
        }

        pathname_len = strlen(pathname) + 1;
        if (pathname != strings)
            memmove(strings, pathname, pathname_len);
        strings += pathname_len;
    }

    notes->nt_files_len = strings - (char *) files;
    notes->len += simple_notesize(notes->nt_files_len, "CORE");
    notes->nt_files = files;
}

int do_elf_coredump(struct core_state *core)
{
    /* Write out an ELF core file (like Linux or FreeBSD would do. We adopt Linux NOTES) */
    elf_ehdr hdr;
    int err = 0;
    struct elf_core_notes notes;

    /* Fill out generic Ehdr fields. Certain ones are left to get filled later */
    fill_out_ehdr(&hdr, core);
    if (!dump_write(core, &hdr, sizeof(hdr)))
        return 0;

    notes.len = 0;
    fill_prpsinfo(&notes);
    if (fill_thread_notes(core, &notes) < 0)
        return -ENOMEM;
    fill_nt_files(core, &notes);
    notes.len += simple_notesize(sizeof(current->address_space->saved_auxv), "CORE");
    notes.len += simple_notesize(sizeof(siginfo_t), "CORE");

    /* blart out PT_NOTE and other pts */
    if (!write_program_headers(core, &notes))
        goto out;

    if (!write_notes(core, &notes))
        goto out;

    /* Now align the offset and dump vmas */
    dump_align(core, PAGE_SIZE);
    for (unsigned int i = 0; i < core->nr_vmas; i++)
    {
        if (!dump_vma(core, &core->vmas[i]))
            goto out;
    }

    err = 1;
out:
    /* Tear down internal data structures (notes) */
    kvfree(notes.threads);
    kvfree(notes.nt_files);
    return err;
}

#endif

#ifdef __cplusplus
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
#endif
