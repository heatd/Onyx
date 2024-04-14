/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
#include <onyx/file.h>
#include <onyx/futex.h>
#include <onyx/gen/trace_vm.h>
#include <onyx/id.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/pid.h>
#include <onyx/proc_event.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/scoped_lock.h>
#include <onyx/syscall.h>
#include <onyx/task_switching.h>
#include <onyx/thread.h>
#include <onyx/user.h>
#include <onyx/utils.h>
#include <onyx/vdso.h>
#include <onyx/vector.h>
#include <onyx/vfork_completion.h>
#include <onyx/worker.h>

ids *process_ids = nullptr;

process *first_process = nullptr;
static process *process_tail = nullptr;
static spinlock process_list_lock;

[[noreturn]] void process_exit(unsigned int exit_code);
void process_end(process *process);

void process_append_children(process *parent, process *children)
{
    scoped_lock g{parent->children_lock};

    process **pp = &parent->children;
    process *p = nullptr;

    while (*pp)
    {
        p = *pp;
        pp = &p->next_sibbling;
    }

    *pp = children;

    children->prev_sibbling = p;
}

void process_append_to_global_list(process *p)
{
    scoped_lock g{process_list_lock};

    if (process_tail)
    {
        process_tail->next = p;
        process_tail = p;
    }
    else
    {
        first_process = process_tail = p;
    }

    p->next = nullptr;
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

process::process() : pgrp_node{this}, session_node{this}
{
    init_wait_queue_head(&this->wait_child_event);
    mutex_init(&condvar_mutex);
    spinlock_init(&ctx.fdlock);
    active_processes++;
    refcount = 0;
    flags = 0;
    next = nullptr;
    nr_threads = 0;
    spinlock_init(&thread_list_lock);
    pid_ = 0;
    vdso = nullptr;
    memset(sigtable, 0, sizeof(sigtable));
    spinlock_init(&signal_lock);
    signal_group_flags = 0;
    exit_code = 0;
    personality = 0;
    parent = nullptr;
    user_time = system_time = children_stime = children_utime = 0;
    spinlock_init(&sub_queue_lock);
    sub_queue = nullptr;
    nr_acks = nr_subs = 0;
    interp_base = image_base = nullptr;
}

process::~process()
{
    // We might have died before assigning the process group
    if (process_group) [[likely]]
        process_group->remove_process(this, PIDTYPE_PGRP);
    if (session) [[likely]]
        session->remove_process(this, PIDTYPE_SID);
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

process *process_create(const std::string_view &cmd_line, ioctx *ctx, process *parent)
{
    /* FIXME: Failure here kinda sucks and is probably super leaky */
    if (unlikely(!process_ids))
    {
        process_ids = idm_add("pid", 1, UINTMAX_MAX);
        assert(process_ids != nullptr);
    }

    auto p = make_unique<process>();
    if (!p)
        return errno = ENOMEM, nullptr;

    auto proc = p.get();

    /* TODO: idm_get_id doesn't wrap? POSIX COMPLIANCE */
    proc->refcount = 1;
    proc->pid_ = idm_get_id(process_ids);
    assert(proc->pid_ != (pid_t) -1);

    if (!proc->set_cmdline(cmd_line))
        return errno = ENOMEM, nullptr;

    creds_init(&proc->cred);

    itimer_init(proc);

    proc->pid_struct = pid_create(proc);

    if (!proc->pid_struct)
        return errno = ENOMEM, nullptr;

    if (ctx)
    {
        fd_get(ctx->cwd);

        proc->ctx.cwd = ctx->cwd;

        if (copy_file_descriptors(proc, ctx) < 0)
        {
            fd_put(ctx->cwd);
            return nullptr;
        }
    }
    else
    {
        if (allocate_file_descriptor_table(proc) < 0)
            return nullptr;

        proc->ctx.umask = S_IWOTH | S_IWGRP;
    }

    if (parent)
    {
        /* Inherit the parent process' properties */
        proc->personality = parent->personality;
        proc->vdso = parent->vdso;
        process_inherit_creds(proc, parent);

        proc->image_base = parent->image_base;
        proc->interp_base = parent->interp_base;
        /* Inherit the signal handlers of the process and the
         * signal mask of the current thread
         */

        {
            scoped_lock g{proc->signal_lock};
            memcpy(&proc->sigtable, &parent->sigtable, sizeof(k_sigaction) * _NSIG);
        }

        /* Note that the signal mask is inherited at thread creation */

        /* Note that pending signals are zero'd, as per POSIX */

        process_append_children(parent, proc);

        proc->parent = parent;

        parent->process_group->inherit(proc, PIDTYPE_PGRP);
        proc->flags = parent->flags;

        proc->inherit_limits(parent);

        parent->session->inherit(proc, PIDTYPE_SID);

        // Inherit the controlling terminal
        proc->ctty = parent->ctty;
    }
    else
    {
        proc->pid_struct->add_process(proc, PIDTYPE_PGRP);
        proc->pid_struct->add_process(proc, PIDTYPE_SID);

        proc->init_default_limits();
        auto ex = mm_address_space::create();
        if (ex.has_error())
            return errno = -ex.error(), nullptr;
        proc->address_space = ex.value();
    }

    process_append_to_global_list(proc);

    INIT_LIST_HEAD(&proc->thread_list);

    return p.release();
}

process *get_process_from_pid(pid_t pid)
{
    /* TODO: Maybe storing processes in a tree would be a good idea? */
    scoped_lock g{process_list_lock};

    for (process *p = first_process; p != nullptr; p = p->next)
    {
        if (p->get_pid() == pid)
        {
            process_get(p);
            return p;
        }
    }

    return nullptr;
}

void unlock_process_list(void)
{
    spin_unlock(&process_list_lock);
}

pid_t sys_getppid()
{
    if (get_current_process()->parent)
        return get_current_process()->parent->get_pid();
    else
        return 0;
}

bool process_found_children(pid_t pid, process *proc)
{
    scoped_lock g{proc->children_lock};

    if (proc->children)
    {
        /* if we have children, return true */
        return true;
    }

    for (process *p = proc->children; p != nullptr; p = p->next_sibbling)
    {
        if (p->get_pid() == pid)
        {
            return true;
        }
    }

    return false;
}

void process_remove_from_list(process *process);

template <typename Callable>
static void for_every_child(process *proc, Callable cb)
{
    scoped_lock g{proc->children_lock};

    for (process *p = proc->children; p != nullptr; p = p->next_sibbling)
    {
        if (cb(p) == false)
            break;
    }
}

pid_t process_get_pgid(process *p)
{
    scoped_lock g{p->pgrp_lock};
    return p->process_group->get_pid();
}

#define WAIT_INFO_MATCHING_ANY (1 << 0)
#define WAIT_INFO_MATCH_PGID   (1 << 1)

struct wait_info
{
    int wstatus;
    rusage usage;
    pid_t pid;
    int status;
    unsigned int flags;
    unsigned int options;

    wait_info(pid_t pid, unsigned int options)
        : wstatus{}, usage{}, pid{pid}, status{-ECHILD}, flags{}, options{options}
    {
        /* pid = -1: matches any process;
         * pid < 0: matches processes with pgid = -pid;
         * pid = 0: matches processes with pgid = process' pgid.
         * pid > 0: matches processes with pid = pid.
         */
        if (pid == -1)
        {
            flags |= WAIT_INFO_MATCHING_ANY;
        }
        else if (pid < 0)
        {
            flags |= WAIT_INFO_MATCH_PGID;
            this->pid = -pid;
        }
        else if (pid == 0)
        {
            auto current = get_current_process();

            this->pid = process_get_pgid(current);

            flags |= WAIT_INFO_MATCH_PGID;
        }

        /* WEXITED is always implied for wait4 */
        this->options |= WEXITED;
    }

    bool reap_wait() const
    {
        return !(options & WNOWAIT);
    }
};

bool wait_matches_process(const wait_info &info, process *proc)
{
    if (info.flags & WAIT_INFO_MATCHING_ANY)
        return true;

    if (info.flags & WAIT_INFO_MATCH_PGID && process_get_pgid(proc) == info.pid)
        return true;

    if (info.pid == proc->get_pid())
        return true;

    return false;
}

int do_getrusage(int who, rusage *usage, process *proc)
{
    memset(usage, 0, sizeof(rusage));
    hrtime_t utime = 0;
    hrtime_t stime = 0;

    switch (who)
    {
        case RUSAGE_BOTH:
        case RUSAGE_CHILDREN:
            utime = proc->children_utime;
            stime = proc->children_stime;

            if (who == RUSAGE_CHILDREN)
                break;

            [[fallthrough]];
        case RUSAGE_SELF:
            utime += proc->user_time;
            stime += proc->system_time;
            break;

        default:
            return -EINVAL;
    }

    hrtime_to_timeval(utime, &usage->ru_utime);
    hrtime_to_timeval(stime, &usage->ru_stime);
    return 0;
}

int sys_getrusage(int who, rusage *user_usage)
{
    /* do_getrusage understands this flag but it isn't supposed to be exposed */
    if (who == RUSAGE_BOTH)
        return -EINVAL;

    rusage kusage;
    int st = 0;
    if ((st = do_getrusage(who, &kusage, get_current_process())) < 0)
        return st;

    return copy_to_user(user_usage, &kusage, sizeof(rusage));
}

void process_accumulate_rusage(process *child, const rusage &usage)
{
    auto us = get_current_process();

    __atomic_add_fetch(&us->children_stime, timeval_to_hrtime(&usage.ru_stime), __ATOMIC_RELAXED);
    __atomic_add_fetch(&us->children_utime, timeval_to_hrtime(&usage.ru_utime), __ATOMIC_RELAXED);
}

bool process_wait_exit(process *child, wait_info &winfo)
{
    if (!(child->signal_group_flags & SIGNAL_GROUP_EXIT))
        return false;

    scoped_lock g{child->signal_lock};

    if (!(child->signal_group_flags & SIGNAL_GROUP_EXIT))
        return false;

    if (!(winfo.options & WEXITED))
        return false;

    do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

    winfo.pid = child->get_pid();

    winfo.wstatus = child->exit_code;

    if (winfo.reap_wait())
    {
        auto current = get_current_process();
        process_accumulate_rusage(child, winfo.usage);
        spin_unlock(&current->children_lock);
        g.unlock();
        process_put(child);
        spin_lock(&current->children_lock);
    }

    return true;
}

bool process_wait_stop(process *child, wait_info &winfo)
{
    if (!(child->signal_group_flags & SIGNAL_GROUP_STOPPED))
        return false;

    scoped_lock g{child->signal_lock};

    if (!(child->signal_group_flags & SIGNAL_GROUP_STOPPED))
        return false;

    if (child->signal_group_flags & SIGNAL_GROUP_EXIT)
        return false;

    if (!(winfo.options & WSTOPPED))
        return false;

    /* We use exit_code = 0 to know it has been reaped */
    if (!child->exit_code)
        return false;

    do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

    winfo.pid = child->get_pid();

    winfo.wstatus = child->exit_code;

    if (winfo.reap_wait())
    {
        child->exit_code = 0;
    }

    return true;
}

bool process_wait_cont(process *child, wait_info &winfo)
{
    if (!(child->signal_group_flags & SIGNAL_GROUP_CONT))
        return false;

    scoped_lock g{child->signal_lock};

    if (!(child->signal_group_flags & SIGNAL_GROUP_CONT))
        return false;

    if (child->signal_group_flags & SIGNAL_GROUP_EXIT)
        return false;

    if (!(winfo.options & WCONTINUED))
        return false;

    do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

    winfo.pid = child->get_pid();

    winfo.wstatus = child->exit_code;

    if (winfo.reap_wait())
    {
        child->signal_group_flags &= ~SIGNAL_GROUP_CONT;
    }

    return true;
}

#define WINFO_STATUS_OK     1
#define WINFO_STATUS_NOHANG 2

bool wait_handle_processes(process *proc, wait_info &winfo)
{
    winfo.status = -ECHILD;
    for_every_child(proc, [&](process *child) -> bool {
        if (!wait_matches_process(winfo, child))
            return true;

        winfo.status = 0;

        if (!process_wait_exit(child, winfo) && !process_wait_stop(child, winfo) &&
            !process_wait_cont(child, winfo))
        {
            return true;
        }

        winfo.status = WINFO_STATUS_OK;

        /* We'll want to stop iterating after waiting for a child */
        return false;
    });

    if (winfo.status != WINFO_STATUS_OK && winfo.options & WNOHANG)
        winfo.status = WINFO_STATUS_NOHANG;

#if 0
	printk("winfo status: %d\n", winfo.status);
#endif

    return winfo.status != 0;
}

#define VALID_WAIT4_OPTIONS (WNOHANG | WUNTRACED | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT)

pid_t sys_wait4(pid_t pid, int *wstatus, int options, rusage *usage)
{
    auto current = get_current_process();

    if (options & ~VALID_WAIT4_OPTIONS)
        return -EINVAL;

    wait_info w{pid, (unsigned int) options};

    int st =
        wait_for_event_interruptible(&current->wait_child_event, wait_handle_processes(current, w));

#if 0
    printk("st %d w.status %d\n", st, w.status);
#endif

    if (st < 0)
        return st;

    if (w.status != WINFO_STATUS_OK)
        return w.status == WINFO_STATUS_NOHANG ? 0 : w.status;

#if 0
	printk("w.wstatus: %d\n", w.wstatus);
#endif

    if ((wstatus && copy_to_user(wstatus, &w.wstatus, sizeof(int)) < 0) ||
        (usage && copy_to_user(usage, &w.usage, sizeof(rusage)) < 0))
    {
        return -EFAULT;
    }

    return w.pid;
}

void process_copy_current_sigmask(thread *dest)
{
    memcpy(&dest->sinfo.sigmask, &get_current_thread()->sinfo.sigmask, sizeof(sigset_t));
}

#define FORK_SHARE_MM (1 << 0)
#define FORK_VFORK    (1 << 1)

pid_t sys_fork_internal(syscall_frame *ctx, unsigned int flags)
{
    process *proc;
    process *child;
    thread_t *to_be_forked;

    proc = (process *) get_current_process();
    to_be_forked = get_current_thread();
    /* Create a new process */

    {
        // We need to lock here to protect against concurrent changes
        scoped_mutex g{proc->name_lock};

        child = process_create(proc->cmd_line, &proc->ctx, proc);

        if (!child)
            return -ENOMEM;
    }

    child->flags |= PROCESS_FORKED;

    /* Fork the vmm data and the address space */
    if (flags & FORK_SHARE_MM)
    {
        child->address_space = proc->address_space;
        trace_vm_share_mm();
    }
    else
    {
        auto ex = mm_address_space::fork();
        if (ex.has_error())
            return ex.error();
        child->address_space = ex.value();
    }

    process_get(child);

    /* Fork and create the new thread */
    thread *new_thread = process_fork_thread(to_be_forked, child, ctx);

    if (!new_thread)
    {
        panic("TODO: Add process destruction here.\n");
    }

    process_copy_current_sigmask(new_thread);

    vfork_completion vfork_cmpl;
    if (flags & FORK_VFORK)
    {
        child->vfork_compl = &vfork_cmpl;
    }

    sched_start_thread(new_thread);

    if (flags & FORK_VFORK)
    {
        // We wait for the vforked child to do its thing, and then we wait until its safe to exit
        // i.e the child has finished waking up waiters.
        vfork_cmpl.wait();

        vfork_cmpl.wait_to_exit();
    }

    // Return the pid to the caller
    auto pid = child->get_pid();
    process_put(child);
    return pid;
}

pid_t sys_fork(syscall_frame *ctx)
{
    return sys_fork_internal(ctx, 0);
}

pid_t sys_vfork(syscall_frame *ctx)
{
    return sys_fork_internal(ctx, FORK_SHARE_MM | FORK_VFORK);
}

#define W_STOPPING         0x7f
#define W_CORE_DUMPED      (1 << 7)
#define W_SIG(sig)         (signum)
#define W_STOPPED_SIG(sig) (W_STOPPING | (sig << 8))
#define W_CONTINUED        0xffff
#define W_EXIT_CODE(code)  ((code & 0xff) << 8)

/* Wait status layout:
 * For exits: bits 0-7: MBZ;
 *            bits 8-15: Exit code & 0xff
 * For signal stops: bits 0-7: 0x7f
 *                   bits 8-15: Stopping signal
 * For signal conts: bits 0-15: 0xffff
 * For signal termination: bits 0-6: Signal number
 *                         bit 7: Set on core dumps
 * Any range of bits that's not specified here *must be zero*.
 */
int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
    int wstatus = core_dumped ? W_CORE_DUMPED : 0;

    if (signum == 0)
    {
        wstatus |= W_EXIT_CODE(exit_code);
    }
    else
    {
        if (signal_is_stopping(signum))
        {
            wstatus |= W_STOPPED_SIG(signum);
        }
        else if (signum == SIGCONT)
        {
            wstatus |= W_CONTINUED;
        }
        else
            wstatus |= signum;
    }

    return wstatus;
}

[[noreturn]] void process_exit_from_signal(int signum)
{
    process_exit(make_wait4_wstatus(signum, false, 0));
}

void sys_exit(int status)
{
    status &= 0xff;
    process_exit(make_wait4_wstatus(0, false, status));
}

pid_t sys_getpid()
{
    return get_current_process()->get_pid();
}

int sys_personality(unsigned long val)
{
    // TODO: Use this syscall for something. This might be potentially very useful
    get_current_process()->personality = val;
    return 0;
}

void process_destroy_aspace()
{
    process *current = get_current_process();
    vm_set_aspace(&kernel_address_space);
    kernel_address_space.ref();
    current->address_space = ref_guard<mm_address_space>{&kernel_address_space};
}

void process_remove_from_list(process *proc)
{
    {
        scoped_lock g{process_list_lock};
        /* TODO: Make the list a doubly-linked one, so we're able to tear it down more easily */
        if (first_process == proc)
        {
            first_process = first_process->next;
            if (process_tail == proc)
                process_tail = first_process;
        }
        else
        {
            process *p;
            for (p = first_process; p->next != proc && p->next; p = p->next)
                ;

            assert(p->next != nullptr);

            p->next = proc->next;

            if (process_tail == proc)
                process_tail = p;
        }
    }

    /* Remove from the sibblings list */

    scoped_lock g{proc->parent->children_lock};

    if (proc->prev_sibbling)
        proc->prev_sibbling->next_sibbling = proc->next_sibbling;
    else
        proc->parent->children = proc->next_sibbling;

    if (proc->next_sibbling)
        proc->next_sibbling->prev_sibbling = proc->prev_sibbling;
}

void process_wait_for_dead_threads(process *process)
{
    while (process->nr_threads)
    {
        cpu_relax();
    }
}

void process_end(process *process)
{
    process_remove_from_list(process);

    process_wait_for_dead_threads(process);

    if (process->ctx.cwd)
        fd_put(process->ctx.cwd);

    delete process;
}

void kill_orphaned_pgrp(process *proc)
{
    scoped_lock g{proc->pgrp_lock};

    auto pgrp = proc->process_group;

    if (pgrp->is_orphaned_and_has_stopped_jobs(proc))
    {
        pgrp->kill_pgrp(SIGHUP, 0, nullptr);
        pgrp->kill_pgrp(SIGCONT, 0, nullptr);
    }
}

void process_reparent_children(process *proc)
{
    scoped_lock g{proc->children_lock};

    /* In POSIX, reparented children get to be children of PID 1 */
    process *new_parent = first_process;

    // I think this is enough? I'm not sure though, Linux does it again on reparenting.
    kill_orphaned_pgrp(proc);

    if (!proc->children)
    {
        return;
    }

    for (process *c = proc->children; c != nullptr; c = c->next_sibbling)
        c->parent = new_parent;

    process_append_children(new_parent, proc->children);
}

void process_kill_other_threads(void)
{
    process *current = get_current_process();
    thread *current_thread = get_current_thread();

    process_for_every_thread(current, [&](thread *t) -> bool {
        if (t == current_thread)
            return true;

        scoped_lock g{t->sinfo.lock};

        t->sinfo.flags |= THREAD_SIGNAL_EXITING;
        t->sinfo.signal_pending = true;

        /* If it's in an interruptible sleep, very good. Else, it's either
         * in an uninterruptible sleep or it was stopped but got woken up by SIGKILL code before us.
         * It's impossible for a process to otherwise exit without every thread already
         * being SIGCONT'd.
         */
        if (t->status == THREAD_INTERRUPTIBLE)
            thread_wake_up(t);

        return true;
    });

    while (current->nr_threads != 1)
        cpu_relax();
}

[[noreturn]] void process_exit(unsigned int exit_code)
{
    auto current_thread = get_current_thread();
    process *current = get_current_process();

    if (current->get_pid() == 1)
    {
        printk("Panic: %s exited with exit code %u!\n", current->cmd_line.c_str(), exit_code);
        irq_enable();
        for (;;)
            sched_sleep_ms(10000);
    }

    for (auto &timer : current->timers)
        timer.disarm();

    process_kill_other_threads();

    process_destroy_file_descriptors(current);

    current->signal_group_flags |= SIGNAL_GROUP_EXIT;

    /* We destroy the address space after fds because some close() routines may require address
     * space access */
    process_destroy_aspace();

    if (current->vfork_compl)
    {
        current->vfork_compl->wake();
        current->vfork_compl = nullptr;
    }

    process_reparent_children(current);

    for (proc_event_sub *s = current->sub_queue; s; s = s->next)
    {
        s->valid_sub = false;
    }

    /* Set this in this order exactly */
    current_thread->flags = THREAD_IS_DYING;
    current_thread->status = THREAD_DEAD;

    {
        scoped_lock g{current->signal_lock};
        current->exit_code = exit_code;

        /* Finally, wake up any possible concerned parents */
        wait_queue_wake_all(&current->parent->wait_child_event);
    }

    siginfo_t info = {};

    info.si_signo = SIGCHLD;
    info.si_pid = current->get_pid();
    info.si_uid = current->cred.ruid;
    info.si_stime = current->system_time / NS_PER_MS;
    info.si_utime = current->user_time / NS_PER_MS;

    if (WIFEXITED(exit_code))
    {
        info.si_code = CLD_EXITED;
        info.si_status = WEXITSTATUS(exit_code);
    }
    else if (WIFSIGNALED(exit_code))
    {
        info.si_code = CLD_KILLED;
        info.si_status = WTERMSIG(exit_code);
    }

    kernel_raise_signal(SIGCHLD, current->parent, 0, &info);

    sched_yield();

    while (true)
        ;
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

void process_add_thread(process *proc, thread_t *thread)
{
    scoped_lock g{proc->thread_list_lock};

    list_add_tail(&thread->thread_list_head, &proc->thread_list);

    proc->nr_threads++;
}

void sys_exit_thread(int value)
{
    /* Okay, so the libc called us. That means we can start destroying the thread */
    /* NOTE: I'm not really sure if musl destroyed the user stack and fs,
     * and if we should anything to free them */

    thread *thread = get_current_thread();
    if (thread->ctid)
    {
        pid_t to_write = 0;
        if (copy_to_user(thread->ctid, &to_write, sizeof(to_write)) < 0)
            goto skip;
        futex_wake((int *) thread->ctid, INT_MAX);
    }
skip:
    /* Destroy the thread */
    thread_exit();
    /* aaaaand we'll never return back to user-space, so just hang on */
    sched_yield();
}

void process_increment_stats(bool is_kernel)
{
    process *process = get_current_process();
    /* We're not in a process, return! */
    if (!process)
        return;
    if (is_kernel)
        process->system_time++;
    else
        process->user_time++;
}

void for_every_process(process_visit_function_t func, void *ctx)
{
    scoped_lock g{process_list_lock};

    auto p = first_process;

    while (p != nullptr)
    {
        if (!func(p, ctx))
            return;

        p = p->next;
    }
}

void notify_process_stop_cont(process *proc, int signum)
{
    auto parent = proc->parent;

    /* init might get a SIGSTOP? idk */
    if (!parent)
        return;

    auto code = make_wait4_wstatus(signum, false, 0);

    proc->exit_code = code;

    wait_queue_wake_all(&parent->wait_child_event);

    siginfo_t info = {};
    info.si_code = signal_is_stopping(signum) ? CLD_STOPPED : CLD_CONTINUED;
    info.si_signo = SIGCHLD;
    info.si_pid = proc->get_pid();
    info.si_uid = proc->cred.ruid;
    info.si_stime = proc->system_time / NS_PER_MS;
    info.si_utime = proc->user_time / NS_PER_MS;
    info.si_status = signum;

    kernel_raise_signal(SIGCHLD, parent, 0, &info);
}

bool process::route_signal(struct sigpending *pend)
{
    scoped_lock g{thread_list_lock};
    bool done = false;

    /* Oh no, we're not going to be able to route this! */
    if (nr_threads == 0)
        return false;

    process_for_every_thread_unlocked(this, [&](thread *t) -> bool {
        auto &sinfo = t->sinfo;

        if (sinfo.try_to_route(pend))
        {
            done = true;
            return false;
        }

        return true;
    });

    auto first_elem = list_first_element(&thread_list);

    assert(first_elem != nullptr);

    auto first_t = container_of(first_elem, struct thread, thread_list_head);

    return first_t->sinfo.add_pending(pend);
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
    scoped_mutex g{address_space->vm_lock};
    size_t needed_len = 0;

    vm_for_every_region(*address_space, [&](vm_area_struct *region) -> bool {
        needed_len += sizeof(onx_process_vm_region);

        if (is_file_backed(region))
        {
            auto path = dentry_to_file_name(region->vm_file->f_dentry);

            needed_len += strlen(path) + 1;
            free(path);
        }

        if (needed_len % alignof(onx_process_vm_region))
        {
            needed_len = ALIGN_TO(needed_len, alignof(onx_process_vm_region));
        }

        return true;
    });

    *howmany = needed_len;

    if ((size_t) len < needed_len)
    {
        return -ENOSPC;
    }

    // Allocate a big buffer to serve as a temporary buffer.
    // Note that we can't copy things directly, because we hold the address space lock and
    // a copy_to_user may trigger a page fault, and then we would not be able to resolve it,
    // as the page fault handling code needs to hold the lock as well.
    cul::vector<char> buf;
    if (!buf.resize(needed_len))
        return -ENOMEM;

    // Note: since we hold the lock, the underlying data structure doesn't change,
    // and so, we have no risk of overflowing the buffer with more data.
    char *ptr = &buf[0];

    vm_for_every_region(*address_space, [&](vm_area_struct *region) -> bool {
        onx_process_vm_region *reg = (onx_process_vm_region *) ptr;
        reg->size = sizeof(onx_process_vm_region);
        reg->mapping_type = region->vm_maptype;
        reg->protection = 0;

        if (region->vm_flags & VM_READ)
            reg->protection |= VM_REGION_PROT_READ;
        if (region->vm_flags & VM_WRITE)
            reg->protection |= VM_REGION_PROT_WRITE;
        if (region->vm_flags & VM_EXEC)
            reg->protection |= VM_REGION_PROT_EXEC;
        if (region->vm_flags & VM_NOCACHE)
            reg->protection |= VM_REGION_PROT_NOCACHE;
        if (region->vm_flags & VM_WRITETHROUGH)
            reg->protection |= VM_REGION_PROT_WRITETHROUGH;
        if (region->vm_flags & VM_WC)
            reg->protection |= VM_REGION_PROT_WC;
        if (region->vm_flags & VM_WP)
            reg->protection |= VM_REGION_PROT_WP;

        reg->offset = region->vm_offset;
        reg->start = region->vm_start;
        reg->length = region->vm_end - region->vm_start;

        if (is_file_backed(region))
        {
            auto path = dentry_to_file_name(region->vm_file->f_dentry);
            strcpy(reg->name, path);
            reg->size += strlen(path) + 1;
        }

        if (reg->size % alignof(onx_process_vm_region))
        {
            reg->size = ALIGN_TO(reg->size, alignof(onx_process_vm_region));
        }

        ptr += reg->size;

        return true;
    });

    // We can't hold the lock anymore, due to the aforementioned reason.
    g.unlock();

    if (copy_to_user(ubuf, buf.begin(), needed_len) < 0)
        return -EFAULT;

    return needed_len;
}

/**
 * @brief Not-implemented syscall handler
 *
 */
int sys_nosys()
{
    return -ENOSYS;
}
