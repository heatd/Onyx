/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "coredump: " fmt
#define DEFINE_CURRENT
#include <onyx/coredump.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/mm/slab.h>
#include <onyx/namei.h>
#include <onyx/process.h>
#include <onyx/signal.h>
#include <onyx/vfs.h>

static int coredump_create_core(struct core_state *core)
{
    char filename[32];
    struct file *filp;

    sprintf(filename, "core.%d", task_tgid(current));
    filp = c_vfs_open(AT_FDCWD, filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(filp))
        return PTR_ERR(filp);
    core->core_file = filp;
    return 0;
}

enum is_elf_result
{
    IS_NOT_ELF = 0,
    IS_ELF,
    IS_ELF_CONTIG
};

/**
 * @brief Check if we're an mmapped ELF file
 *
 * @param vma vma to check
 */
static enum is_elf_result is_elf_vma(struct vm_area_struct *vma, struct vm_area_struct *last_vma)
{
    char elfmag[4];

    if (!vma->vm_file)
        return IS_NOT_ELF;
    if (vma->anon_vma)
        return IS_NOT_ELF;

    if (vma->vm_offset != 0)
    {
        /* If we're not mapped at offset 0, try to figure out if we're contiguous to any other VMA
         * that was tagged as ELF. If we are, we can safely discard this as well */
        if (!last_vma || last_vma->vm_end != vma->vm_start)
            return IS_NOT_ELF;
        return vma->vm_file->f_ino == last_vma->vm_file->f_ino ? IS_ELF_CONTIG : IS_NOT_ELF;
    }

    if (copy_from_user(elfmag, (char *) vma->vm_start, sizeof(elfmag)) < 0)
        return IS_NOT_ELF;
    return !memcmp(elfmag, ELFMAG, 4) ? IS_ELF : IS_NOT_ELF;
}

static int coredump_collect_vmas(struct core_state *core)
{
    struct vm_area_struct *vma, *last_elf = NULL;
    struct mm_address_space *mm = current->address_space;
    unsigned int nr_vmas = 0;
    enum is_elf_result res;

    MA_STATE(mas, &mm->region_tree, 0, -1UL);

    rw_lock_read(&mm->vm_lock);
    /* TODO: We're not maintaining the VMA count, which makes it so we need to iterate this once */
    mas_for_each(&mas, vma, -1UL)
    {
        nr_vmas++;
    }

    mas_set_range(&mas, 0, -1UL);
    core->vmas = kvcalloc(nr_vmas, sizeof(struct core_vma), GFP_KERNEL);
    if (!core->vmas)
    {
        rw_unlock_read(&mm->vm_lock);
        return -ENOMEM;
    }
    core->nr_vmas = nr_vmas;
    nr_vmas = 0;

    mas_for_each(&mas, vma, -1UL)
    {
        struct core_vma *cvma = core->vmas + nr_vmas;
        cvma->start = vma->vm_start;
        cvma->end = vma->vm_end;
        cvma->flags = vma->vm_flags;
        if (vma->vm_file)
        {
            cvma->file = vma->vm_file;
            fd_get(cvma->file);
        }
        else
            cvma->file = NULL;
        cvma->offset = vma->vm_offset;
        cvma->dump_len = cvma->end - cvma->start;

        /* If this VMA is an mmapped ELF file, restrict the dump_len to contain only the first page.
         * This first page should have the BuildID PT_NOTE we want. See
         * https://fedoraproject.org/wiki/RolandMcGrath/BuildID#Finding_binaries_for_dumps for more
         * details.
         * TODO: Add coredump_filter configurability */
        if (0)
        {
            res = is_elf_vma(vma, last_elf);
            if (res != IS_NOT_ELF)
            {
                last_elf = vma;
                if (res == IS_ELF_CONTIG)
                    cvma->dump_len = 0;
                else
                    cvma->dump_len = PAGE_SIZE;
            }
        }

        if (cvma->flags & VM_DONTDUMP)
            cvma->dump_len = 0;

        nr_vmas++;
    }

    rw_unlock_read(&mm->vm_lock);
    return 0;
}

static void coredump_unlink_core(void)
{
    char filename[32];
    sprintf(filename, "core.%d", task_tgid(current));
    unlink_vfs(filename, 0, AT_FDCWD);
}

static void core_state_destroy(struct core_state *state)
{
    for (unsigned int i = 0; i < state->nr_vmas; i++)
    {
        if (state->vmas[i].file)
            fd_put(state->vmas[i].file);
    }

    kvfree(state->vmas);
    fd_put(state->core_file);
    state->core_file = NULL;
}

int do_elf_coredump(struct core_state *core);

static void coredump_suspend_threads(struct core_state *core)
{
    struct process *t;
    unsigned int nr_threads = 0;

    spin_lock(&current->sighand->signal_lock);
    current->sig->signal_group_exit_code = make_wait4_wstatus(core->signo, true, 0);
    current->sig->signal_group_flags |= SIGNAL_GROUP_EXIT;

    for_each_thread (current, t)
    {
        if (t == current)
            continue;
        if (test_task_flag(t, TF_POST_COREDUMP))
            continue;
        nr_threads++;
        sigaddset(&t->sigqueue.pending, SIGKILL);
        signal_interrupt_task(t, SIGKILL);
    }

    core->nr_threads = nr_threads;
    core->threads_pending = nr_threads;
    core->dumper = current;
    current->sig->core_state = core;

    set_current_state(THREAD_UNINTERRUPTIBLE);
    while (core->threads_pending > 0)
    {
        spin_unlock(&current->sighand->signal_lock);
        sched_yield();
        spin_lock(&current->sighand->signal_lock);
        set_current_state(THREAD_UNINTERRUPTIBLE);
    }

    set_current_state(THREAD_RUNNABLE);
    current->sig->core_state = NULL;
    spin_unlock(&current->sighand->signal_lock);
}

static void coredump_unfreeze(struct core_state *core)
{
    struct core_thread *thread, *next;
    struct process *task;

    /* Unfreeze all threads. */
    spin_lock(&current->sighand->signal_lock);

    list_for_each_entry_safe (thread, next, &core->thread_list, list_node)
    {
        task = thread->task;
        WRITE_ONCE(thread->task, NULL);
        list_remove(&thread->list_node);

        /* thread->task doesn't need any synchronization because thread_wake_up implies a
         * happens-before (with a full memory barrier) with regards to everything that happens
         * before (in the waking thread) and after (in the wakee) */
        thread_wake_up(task->thr);
    }

    spin_unlock(&current->sighand->signal_lock);
}

void do_coredump(int sig, siginfo_t *siginfo)
{
    struct core_state core = {
        .core_limit = rlim_get_cur(RLIMIT_CORE),
        .thread_list = LIST_HEAD_INIT(core.thread_list),
    };
    int err;

    coredump_suspend_threads(&core);

    err = coredump_create_core(&core);
    if (err)
        goto unfreeze;
    err = coredump_collect_vmas(&core);
    if (err)
    {
        fd_put(core.core_file);
        goto err_unlink_core;
    }

    core.signo = sig;
    core.siginfo = siginfo;
    err = do_elf_coredump(&core);
    core_state_destroy(&core);
    if (!err)
    {
    err_unlink_core:
        coredump_unlink_core();
    }

unfreeze:
    coredump_unfreeze(&core);
}

int dump_write(struct core_state *state, const void *buf, size_t len)
{
    unsigned long addr;
    ssize_t err;

    if (state->core_file->f_seek + len > state->core_limit)
        return 0;

    addr = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    err = write_vfs(state->core_file->f_seek, len, (void *) buf, state->core_file);
    thread_change_addr_limit(addr);
    if ((size_t) err != len)
        return 0;
    state->core_file->f_seek += err;
    return 1;
}

off_t dump_offset(struct core_state *state)
{
    return state->core_file->f_seek;
}

int dump_align(struct core_state *state, unsigned int alignment)
{
    off_t off = state->core_file->f_seek;
    if (off & (alignment - 1))
    {
        /* TODO: At the moment, the lseek system call is _trivial_, and we don't support dumping
         * using pipes */
        state->core_file->f_seek = ALIGN_TO(off, alignment);
    }

    return 1;
}

void dump_lseek(struct core_state *state, size_t off)
{
    state->core_file->f_seek += off;
}

static int write_out_pages(struct core_state *state, struct page **pages, unsigned int npages)
{
    int err = 1;
    struct page *page;
    /* TODO: iov_iter for C would allow us to just dump these pages man... */
    for (unsigned int i = 0; i < npages; i++)
    {
        page = pages[i];
        if (!page)
        {
            dump_lseek(state, PAGE_SIZE);
            continue;
        }

        err = dump_write(state, PAGE_TO_VIRT(page), PAGE_SIZE);
        if (!err)
            break;
    }

    for (unsigned int i = 0; i < npages; i++)
        if (pages[i])
            page_unref(pages[i]);
    return err;
}

int dump_vma(struct core_state *state, struct core_vma *vma)
{
    unsigned long addr = vma->start;
    unsigned long end = vma->start + vma->dump_len;
    unsigned int npages;
    int err;
    struct page *pages[64];

    while (addr < end)
    {
        npages = min((unsigned int) ((end - addr) >> PAGE_SHIFT), 64U);
        err = get_phys_pages((void *) addr, GPP_READ | GPP_DUMP, pages, npages);
        if (!(err & GPP_ACCESS_OK))
            return 0;

        addr += npages << PAGE_SHIFT;
        if (!write_out_pages(state, pages, npages))
            return 0;
    }

    return 1;
}
