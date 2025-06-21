/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <onyx/binfmt.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/dentry.h>
#include <onyx/elf.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/futex.h>
#include <onyx/gen/trace_vm.h>
#include <onyx/id.h>
#include <onyx/mm/slab.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/pid.h>
#include <onyx/proc_event.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/scoped_lock.h>
#include <onyx/seqlock.h>
#include <onyx/syscall.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>
#include <onyx/tty.h>
#include <onyx/user.h>
#include <onyx/utils.h>
#include <onyx/vdso.h>
#include <onyx/vector.h>
#include <onyx/vfork_completion.h>
#include <onyx/worker.h>

struct process *first_process = nullptr;
DEFINE_LIST(tasklist);

rwslock_t tasklist_lock;

[[noreturn]] void process_exit(unsigned int exit_code);

void process_append_to_global_list(struct process *p) REQUIRES(tasklist_lock)
{
    list_add_tail_rcu(&p->tasklist_node, &tasklist);
    if (!first_process)
        first_process = p;
}

atomic<pid_t> active_processes = 0;

/**
 * @brief Get the number of active processes
 *
 * @return The number of active processes
 */
pid_t process_get_active_processes()
{
    return active_processes;
}

static void task_init_signals(struct process *task)
{
    /* Init per-thread signal information */
    task->sigmask = task->original_sigset = {};
    sigaltstack_init(&task->altstack);
    sigqueue_init(&task->sigqueue);
}

process::process() : pgrp_node{this}, session_node{this}, thread_list_node{this}
{
    mutex_init(&condvar_mutex);
    active_processes++;
    flags = 0;
    thr = NULL;
    pid_ = 0;
    vdso = nullptr;
    exit_code = 0;
    personality = 0;
    parent = nullptr;
    spinlock_init(&sub_queue_lock);
    sub_queue = nullptr;
    nr_acks = nr_subs = 0;
    interp_base = image_base = nullptr;
    INIT_LIST_HEAD(&children_head);
    ctid = NULL;
    task_init_signals(this);
    majflt = minflt = 0;
    nvcsw = nivcsw = 0;
    spinlock_init(&alloc_lock);
}

process::~process()
{
    active_processes--;
}

bool process::set_cmdline(const std::string_view &path)
{
    scoped_mutex g{name_lock};

    cul::string p{path};

    if (!p)
        return false;

    cmd_line = cul::move(p);

    auto last_slash = cmd_line.rfind('/');
    if (last_slash == std::string_view::npos)
        last_slash = 0;
    else
    {
        // The name starts *after* the last slash
        last_slash++;
    }

    std::string_view sv{cmd_line.cbegin() + last_slash, cmd_line.cend()};
    size_t len = cul::min(sv.length(), (size_t) TASK_COMM_LEN - 1);
    memcpy(comm, sv.data(), len);
    comm[len] = '\0';

    return true;
}

struct process *process_alloc(void)
{
    unique_ptr<process> proc{(struct process *) kmalloc(sizeof(struct process), GFP_KERNEL)};
    if (!proc)
        return (struct process *) ERR_PTR(-ENOMEM);
    new (proc.get()) process;

    proc->refcount = REFCOUNT_INIT(1);
    creds_init(&proc->cred);
    if (!proc->set_cmdline(get_current_process()->cmd_line.c_str()))
        return (struct process *) ERR_PTR(-ENOMEM);
    return proc.release();
}

static void ioctx_init(struct ioctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->refs = REFCOUNT_INIT(1);
}

process *process_create(const std::string_view &cmd_line, ioctx *ctx, process *parent)
{
    /* FIXME: Failure here kinda sucks and is probably super leaky */
    struct pid *newpid, *pgrp, *session;
    unique_ptr<process> p{(struct process *) kmalloc(sizeof(struct process), GFP_KERNEL)};
    if (!p)
        return errno = ENOMEM, nullptr;

    new (p.get()) process;
    auto proc = p.get();

    proc->refcount = REFCOUNT_INIT(1);

    if (!proc->set_cmdline(cmd_line))
        return errno = ENOMEM, nullptr;

    creds_init(&proc->cred);

    /* XXX leak */
    newpid = pid_alloc(proc);
    if (IS_ERR(newpid))
        return errno = PTR_ERR(newpid), nullptr;

    proc->ctx = (struct ioctx *) kmalloc(sizeof(struct ioctx), GFP_KERNEL);
    if (!proc->ctx)
        return errno = ENOMEM, nullptr;
    ioctx_init(proc->ctx);
    proc->fs = (struct fsctx *) kmalloc(sizeof(struct fsctx), GFP_KERNEL);
    CHECK(proc->fs);
    fsctx_init(proc->fs);
    proc->fs->root = get_filesystem_root();
    proc->sig = (struct signal_struct *) kmalloc(sizeof(struct signal_struct), GFP_KERNEL);
    CHECK(proc->sig);
    memset((void *) proc->sig, 0, sizeof(struct signal_struct));

    proc->sig->refs = REFCOUNT_INIT(1);
    proc->sig->ctty = NULL;
    proc->sig->nr_threads = 1;
    proc->sig->group_notify_task = NULL;
    proc->sig->group_notify_pending = 0;
    seqlock_init(&proc->sig->stats_lock);
    INIT_LIST_HEAD(&proc->sig->thread_list);
    rwslock_init(&proc->sig->rlimit_lock);
    proc->sig->signal_group_flags = 0;
    proc->sig->tg_leader = proc;
    proc->sig->tgid = newpid;
    sigqueue_init(&proc->sig->shared_signals);
    list_add_tail_rcu(&proc->thread_list_node, &proc->sig->thread_list);
    init_wait_queue_head(&proc->sig->wait_child_event);
    spinlock_init(&proc->sig->pgrp_lock);

    itimer_init(proc);

    if (allocate_file_descriptor_table(proc) < 0)
        return nullptr;

    proc->fs->umask = S_IWOTH | S_IWGRP;
    proc->fs->cwd = proc->fs->root;
    path_get(&proc->fs->cwd);

    proc->sighand = (struct sighand_struct *) kmalloc(sizeof(*proc->sighand), GFP_KERNEL);
    CHECK(proc->sighand);
    sighand_init(proc->sighand);
    memset(proc->sighand->sigtable, 0, sizeof(proc->sighand->sigtable));

    session = pgrp = newpid;
    proc->init_default_limits();
    auto ex = mm_create();
    if (IS_ERR(ex))
        return errno = PTR_ERR(ex), nullptr;
    proc->address_space = ex;

    proc->thr = NULL;
    write_lock(&tasklist_lock);
    process_append_to_global_list(proc);
    pid_add_process(pgrp, proc, PIDTYPE_PGRP);
    pid_add_process(session, proc, PIDTYPE_SID);

    rcu_assign_pointer(proc->sig->process_group, pgrp);
    rcu_assign_pointer(proc->sig->session, session);

    write_unlock(&tasklist_lock);

    return p.release();
}

struct process *get_process_from_pid(pid_t pid)
{
    struct pid *p;
    struct process *task = NULL;

    rcu_read_lock();

    /* TODO: we're not using rcu pid lookup (in mtree) */
    p = pid_lookup(pid);
    if (p)
    {
        task = rcu_dereference(p->proc);
        if (task && !process_get_unless_dead(task))
            task = NULL;
    }

    rcu_read_unlock();
    return task;
}

struct process *get_process_from_pid_noref(pid_t pid)
{
    struct pid *p;
    struct process *task = NULL;

    rcu_read_lock();

    /* TODO: we're not using rcu pid lookup (in mtree) */
    p = pid_lookup(pid);
    if (p)
        task = rcu_dereference(p->proc);

    rcu_read_unlock();
    return task;
}

pid_t sys_getppid()
{
    if (get_current_process()->parent)
        return get_current_process()->parent->get_pid();
    else
        return 0;
}

template <typename Callable>
static void for_every_child(process *proc, Callable cb)
{
    struct process *p;
    list_for_each_entry (p, &proc->children_head, sibbling_node)
        if (cb(p) == false)
            break;
}

pid_t process_get_pgid(process *p)
{
    scoped_lock g{p->sig->pgrp_lock};
    return pid_nr(task_pgrp(p));
}

pid_t sys_getpid()
{
    return get_current_process()->sig->tg_leader->get_pid();
}

int sys_personality(unsigned long val)
{
    // TODO: Use this syscall for something. This might be potentially very useful
    get_current_process()->personality = val;
    return 0;
}

int process_attach(process *tracer, process *tracee)
{
    return errno = ESRCH, -1;
}

/* Finds a pid that tracer is tracing */
process *process_find_tracee(process *tracer, pid_t pid)
{
    return nullptr;
}

void for_every_process(process_visit_function_t func, void *ctx)
{
    struct process *task;

    read_lock(&tasklist_lock);
    list_for_each_entry_rcu (task, &tasklist, tasklist_node)
    {
        if (!func(task, ctx))
            break;
    }
    read_unlock(&tasklist_lock);
}

void process_dtor(struct process *p)
{
    p->~process();
}

namespace onx
{

namespace handle
{

expected<file *, int> process_handle_opener(unsigned int rsrc_type, unsigned long id, int flags)
{
    if (flags & ~ONX_HANDLE_OPEN_GENERIC_FLAGS)
        return unexpected<int>{-EINVAL};

    auto pid = static_cast<pid_t>(id);

    auto_process proc = get_process_from_pid(pid);

    if (!proc)
        return unexpected<int>{-ESRCH};

    auto handle_file = create_file(proc.get());
    if (handle_file) [[likely]]
    {
        // This is not ours anymore, so release it and return the file(that now owns the ref)
        proc.release();
        return handle_file;
    }

    return unexpected<int>{-ENOMEM};
}

} // namespace handle

} // namespace onx

ssize_t process::query_get_strings(void *ubuf, ssize_t len, unsigned long what, size_t *howmany,
                                   void *arg)
{
    switch (what)
    {
        case PROCESS_GET_NAME: {
            scoped_mutex g{name_lock};
            ssize_t length = (ssize_t) strlen(comm) + 1;
            *howmany = length;

            if (len < length)
            {
                return -ENOSPC;
            }

            if (copy_to_user(ubuf, comm, length - 1) < 0)
            {
                return -EFAULT;
            }

            // Don't forget to null-terminate the buffer!
            if (user_memset((void *) ((char *) ubuf + length - 1), '\0', 1) < 0)
            {
                return -EFAULT;
            }

            return length;
        }

        case PROCESS_GET_PATH: {
            ssize_t length = (ssize_t) cmd_line.length() + 1;
            *howmany = length;

            if (len < length)
            {
                return -ENOSPC;
            }

            if (copy_to_user(ubuf, cmd_line.c_str(), length) < 0)
            {
                return -EFAULT;
            }

            return length;
        }
    }

    return -EINVAL;
}

/**
 * @brief Handles the PROCESS_GET_MM_INFO query.
 *
 * @param ubuf User pointer to the buffer.
 * @param len Length of the buffer, in bytes.
 * @param what What query is this.
 * @param howmany Pointer to a variable that will be updated with the number of
 *                written or to-write bytes.
 * @param arg Unused in query_mm_info.
 * @return Number of bytes written, or negative error code.
 */
ssize_t process::query_mm_info(void *ubuf, ssize_t len, unsigned long what, size_t *howmany,
                               void *arg)
{
    auto mm = get_current_address_space();

    *howmany = sizeof(onx_process_mm_info);

    if (len < (ssize_t) sizeof(onx_process_mm_info))
        return -ENOSPC;

    onx_process_mm_info info;

    info.brk = (uint64_t) mm->brk;
    info.start = mm->start;
    info.end = mm->end;
    info.mmap_base = (uint64_t) mm->mmap_base;
    info.virtual_memory_size = mm->virtual_memory_size;
    info.shared_set_size = mm->shared_set_size;
    info.resident_set_size = mm->resident_set_size;
    info.page_faults = mm->page_faults;
    info.page_tables_size = mm->page_tables_size;

    if (copy_to_user(ubuf, &info, sizeof(info)) < 0)
        return -EFAULT;

    return sizeof(info);
}

ssize_t process::query(void *ubuf, ssize_t len, unsigned long what, size_t *howmany, void *arg)
{
    switch (what)
    {
        case PROCESS_GET_NAME:
        case PROCESS_GET_PATH:
            return query_get_strings(ubuf, len, what, howmany, arg);
        case PROCESS_GET_MM_INFO:
            return query_mm_info(ubuf, len, what, howmany, arg);
        case PROCESS_GET_VM_REGIONS:
            return query_vm_regions(ubuf, len, what, howmany, arg);
        default:
            return -EINVAL;
    }
}

/**
 * @brief Handles the PROCESS_GET_VM_REGIONS query.
 *
 * @param ubuf User pointer to the buffer.
 * @param len Length of the buffer, in bytes.
 * @param what What query is this.
 * @param howmany Pointer to a variable that will be updated with the number of
 *                written or to-write bytes.
 * @param arg Unused in query_mm_info.
 * @return Number of bytes written, or negative error code.
 */
ssize_t process::query_vm_regions(void *ubuf, ssize_t len, unsigned long what, size_t *howmany,
                                  void *arg)
{
    WARN_ON_ONCE(1);
    pr_warn_once("%s[%d]: PROCESS_GET_VM_REGIONS is insecure and unimplemented\n",
                 get_current_process()->comm, get_current_process()->pid_);
    return -ENOSYS;
}

/**
 * @brief Not-implemented syscall handler
 *
 */
int sys_nosys()
{
    return -ENOSYS;
}
