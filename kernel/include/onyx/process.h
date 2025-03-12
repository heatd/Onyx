/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PROCESS_H
#define _ONYX_PROCESS_H

#include <sys/resource.h>

#include <onyx/condvar.h>
#include <onyx/cpu.h>
#include <onyx/cred.h>
#include <onyx/elf.h>
#include <onyx/ioctx.h>
#include <onyx/itimer.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/pid.h>
#include <onyx/registers.h>
#include <onyx/rwlock.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/seqlock_types.h>
#include <onyx/signal.h>
#include <onyx/spinlock.h>
#include <onyx/syscall.h>
#include <onyx/types.h>
#include <onyx/vm.h>
#include <onyx/vm_layout.h>
#include <onyx/wait_queue.h>

#include <uapi/process.h>

#ifdef __cplusplus
#include <onyx/culstring.h>
#include <onyx/handle.h>

#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

#endif

#define TASK_COMM_LEN 16

struct proc_event_sub;
struct tty;
struct pid;

__BEGIN_CDECLS
static void process_get(struct process *process);
static void process_put(struct process *process);
__END_CDECLS

#define PROCESS_FORKED     (1 << 0)
#define PROCESS_SECURE     (1 << 1)
#define PROCESS_EXITING    (1 << 2)
#define PROCESS_ZOMBIE     (1 << 3)
#define PROCESS_DEAD       (1 << 4)
#define TF_SIGPENDING      (1 << 5)
#define TF_RESTORE_SIGMASK (1 << 6)
#define TF_STOP_PENDING    (1 << 7)

struct vfork_completion;

#ifdef __cplusplus
// clang-format off
#define CPP_DFLINIT {}
// clang-format on
#else
#define CPP_DFLINIT
#endif

/* signal_struct (in classic Linux style) represents per-process (instead of per-thread,
 * CLONE_THREAD) data. CLONE_THREAD processes share this struct. It contains signal stuff, and other
 * things too. */
struct signal_struct
{
    refcount_t refs;
    unsigned int nr_threads;
    struct list_head thread_list;
    struct process __rcu *tg_leader;
    unsigned int signal_group_flags;
    int signal_group_exit_code;
    unsigned int nr_group_stop_pending;
    unsigned int group_notify_pending;
    struct process *group_notify_task;
    struct spinlock pgrp_lock;
    struct pid __rcu *process_group;
    struct pid __rcu *session;
    struct pid *tgid;
    struct rlimit rlimits[RLIM_NLIMITS + 1];
    struct rwslock rlimit_lock;
    struct tty *ctty;
    struct itimer timers[ITIMER_COUNT];
    struct wait_queue wait_child_event;
    struct sigqueue shared_signals;
    /* These utime and stime store the utime and stime of *dead* tasks (zombie or not) */
    seqlock_t stats_lock;
    hrtime_t utime;
    hrtime_t stime;
    hrtime_t cutime;
    hrtime_t cstime;
    unsigned long majflt;
    unsigned long minflt;
    unsigned long cmajflt;
    unsigned long cminflt;
    unsigned long nvcsw;
    unsigned long nivcsw;
    unsigned long cnvcsw;
    unsigned long cnivcsw;
};

struct process
#ifdef __cplusplus
    : public onx::handle::handleable
#endif
{
#ifndef __cplusplus
    void *__vtable;
#endif
    refcount_t refcount;

    /* Program name points to the string in cmd_line */
#ifdef __cplusplus
    cul::string cmd_line;
    static_assert(sizeof(cmd_line) == 32);
#else
    char __refcount_pad[4];
    char __cmd_line[32];
#endif
    char comm[TASK_COMM_LEN];

    struct mutex name_lock;

    unsigned long flags;

    struct mm_address_space *address_space;

    /* IO Context of the process */
    struct ioctx *ctx;
    struct fsctx *fs;

    /* Process ID */
    pid_t pid_;

    /* Process' UID and GID */
    struct creds cred;

    /* Pointer to the VDSO */
    void *vdso;

    /* Signal information */
    struct sighand_struct *sighand;
    struct signal_struct *sig;
    sigset_t sigmask;
    struct sigqueue sigqueue;
    stack_t altstack;
    /** Used by pselect, ppoll, sigsuspend */
    sigset_t original_sigset;
    unsigned int exit_code;

    LIST_HEAD_CPP(process) pgrp_node;
    LIST_HEAD_CPP(process) session_node;
    LIST_HEAD_CPP(process) thread_list_node;

    /* Process personality */
    unsigned long personality;

    /* This process' parent */
    struct process __rcu *parent;

    /* proc_event queue */
    struct spinlock sub_queue_lock;
    struct proc_event_sub *sub_queue;
    unsigned long nr_subs;
    unsigned long nr_acks;

    void *interp_base;
    void *image_base;

    struct elf_info info CPP_DFLINIT;

    struct cond syscall_cond CPP_DFLINIT;
    struct mutex condvar_mutex CPP_DFLINIT;

    /* Protected by tasklist_lock */
    struct list_head tasklist_node;
    struct list_head children_head;
    struct list_head sibbling_node;

    struct pid __rcu *pid_struct;
    /* See CLONE_CHILD_CLEARTID */
    void *ctid;
    void *set_tid;

    struct vfork_completion *vfork_compl CPP_DFLINIT;
    /* There might be a nicer place to put this? */
    struct rcu_head rcu_head;

    struct thread *thr;

    unsigned long majflt;
    unsigned long minflt;
    unsigned long nvcsw;
    unsigned long nivcsw;

#ifdef __cplusplus
    process();
    virtual ~process();

    void ref()
    {
        process_get(this);
    }

    void unref()
    {
        process_put(this);
    }

    void handle_ref() override
    {
        ref();
    }

    void handle_unref() override
    {
        unref();
    }

    void remove_thread(thread *t)
    {
    }

    pid_t get_pid() const
    {
        return pid_;
    }

    int rlimit(int rsrc, struct rlimit *old, const struct rlimit *new_lim, unsigned int flags);

    struct rlimit get_rlimit(int rsrc);

    void init_default_limits();
    void inherit_limits(process *parent);

    ssize_t query(void *ubuf, ssize_t len, unsigned long what, size_t *howmany, void *arg) override;

    bool set_cmdline(const std::string_view &path);

    bool is_session_leader_unlocked() const
    {
        return rcu_dereference(sig->session) == sig->tgid;
    }

    bool is_pgrp_leader_unlocked() const
    {
        return rcu_dereference(sig->process_group) == sig->tgid;
    }

    mm_address_space *get_aspace() const
    {
        return address_space;
    }

    void set_secure()
    {
        flags |= PROCESS_SECURE;
    }

private:
    ssize_t query_get_strings(void *ubuf, ssize_t len, unsigned long what, size_t *howmany,
                              void *arg);

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
    ssize_t query_mm_info(void *ubuf, ssize_t len, unsigned long what, size_t *howmany, void *arg);

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
    ssize_t query_vm_regions(void *ubuf, ssize_t len, unsigned long what, size_t *howmany,
                             void *arg);
#endif
};

#ifndef __cplusplus
static_assert(offsetof(struct process, comm) == 48, "Layout of struct process looks odd");
#endif

__BEGIN_CDECLS

static inline bool test_task_flag(struct process *proc, unsigned long flag)
{
    return READ_ONCE(proc->flags) & flag;
}

static inline void clear_task_flag(struct process *proc, unsigned long flag)
{
    atomic_and_relaxed(proc->flags, ~flag);
}

static inline void set_task_flag(struct process *proc, unsigned long flag)
{
    atomic_or_relaxed(proc->flags, flag);
}

#define for_each_thread(p, t) \
    list_for_each_entry_rcu (t, &(p)->sig->thread_list, thread_list_node.__lh)

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
static inline int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
    int wstatus = core_dumped ? W_CORE_DUMPED : 0;

    if (signum == 0)
        wstatus |= W_EXIT_CODE(exit_code);
    else
    {
        if (signal_is_stopping(signum))
            wstatus |= W_STOPPED_SIG(signum);
        else if (signum == SIGCONT)
            wstatus |= W_CONTINUED;
        else
            wstatus |= signum;
    }

    return wstatus;
}

static inline bool task_is_session_leader(struct process *task)
{
    return task->sig->session == task->sig->tgid;
}

static inline bool task_is_pgrp_leader(struct process *task)
{
    return rcu_dereference(task->sig->process_group) == task->sig->tgid;
}

struct process *get_process_from_pid(pid_t pid);
struct thread *process_fork_thread(thread_t *src, struct process *dest, unsigned int flags,
                                   unsigned long stack, unsigned long tls);
int process_attach(struct process *tracer, struct process *tracee);
struct process *process_find_tracee(struct process *tracer, pid_t pid);
__attribute__((noreturn)) void process_exit_from_signal(int signum);
void process_end(struct process *p);
void process_dtor(struct process *p);

struct envarg_res
{
    char **s;
    int count;
    size_t total_size;
};

static inline void process_get(struct process *process)
{
    refcount_inc(&process->refcount);
}

static inline bool process_get_unless_dead(struct process *process)
{
    return refcount_inc_not_zero(&process->refcount);
}

static inline void process_put(struct process *process)
{
    if (refcount_dec_and_test(&process->refcount))
        process_end(process);
}

static inline bool same_thread_group(struct process *task1, struct process *task2)
{
    return task1->sig == task2->sig;
}

static inline bool thread_group_leader(struct process *task)
{
    return rcu_dereference(task->sig->tg_leader) == task;
}

static inline bool task_zombie(struct process *task)
{
    return test_task_flag(task, PROCESS_ZOMBIE);
}

static inline bool task_dead(struct process *task)
{
    return test_task_flag(task, PROCESS_DEAD);
}

static inline void task_make_zombie(struct process *task)
{
    set_task_flag(task, PROCESS_ZOMBIE);
}

static inline void task_make_dead(struct process *task)
{
    set_task_flag(task, PROCESS_DEAD);
}

struct stack_info
{
    void *base;
    void *top;
    size_t length;
};

int process_alloc_stack(struct stack_info *info);
__attribute__((pure)) static inline struct process *get_current_process()
{
    thread_t *thread = get_current_thread();
    return (thread == NULL) ? NULL : (struct process *) thread->owner;
}

#ifdef DEFINE_CURRENT
#define current get_current_process()
#endif

static inline mode_t get_current_umask()
{
    if (unlikely(!get_current_process()))
        return 0;
    return get_current_process()->fs->umask;
}

static inline mode_t do_umask(mode_t mode)
{
    return mode & ~get_current_umask();
}

/**
 * @brief Get the number of active processes
 *
 * @return The number of active processes
 */
pid_t process_get_active_processes();

extern rwslock_t tasklist_lock;

/* Supposed to be used with rcu_dereference_check and rcu_dereference_protected. NOP while we don't
 * have lockdep. */
#define lockdep_tasklist_lock_held()       (true)
#define lockdep_tasklist_lock_held_write() (true)

/* The _locked variants here can only be used if we hold tasklist_lock */
static inline struct pid *task_pgrp_locked(struct process *task)
{
    return rcu_dereference_protected(task->sig->process_group, lockdep_tasklist_lock_held());
}

static inline struct pid *task_session_locked(struct process *task)
{
    return rcu_dereference_protected(task->sig->session, lockdep_tasklist_lock_held());
}

static inline struct pid *task_pgrp(struct process *task)
{
    return rcu_dereference_check(task->sig->process_group, lockdep_tasklist_lock_held());
}

static inline struct pid *task_session(struct process *task)
{
    return rcu_dereference_check(task->sig->session, lockdep_tasklist_lock_held());
}

static inline struct process *task_parent(struct process *task)
{
    return rcu_dereference_check(task->parent, lockdep_tasklist_lock_held());
}

static inline struct process *task_parent_locked(struct process *task)
{
    return rcu_dereference_protected(task->parent, lockdep_tasklist_lock_held());
}

static inline struct pid *task_pid_locked(struct process *task)
{
    return rcu_dereference_protected(task->pid_struct, lockdep_tasklist_lock_held());
}

static inline struct pid *task_pid(struct process *task)
{
    return rcu_dereference_check(task->pid_struct, lockdep_tasklist_lock_held());
}

static inline struct pid *task_tgid_locked(struct process *task)
{
    return rcu_dereference_protected(task->sig->tgid, lockdep_tasklist_lock_held());
}

static inline pid_t task_tgid(struct process *task)
{
    pid_t pid;
    rcu_read_lock();
    pid = pid_nr(rcu_dereference(task->sig->tgid));
    rcu_read_unlock();
    return pid;
}

static inline struct registers *task_regs(struct process *proc)
{
    return ((struct registers *) proc->thr->kernel_stack_top) - 1;
}

static inline struct mm_address_space *get_current_address_space(void)
{
    struct thread *t = get_current_thread();
    return t ? t->aspace : &kernel_address_space;
}

struct process *process_alloc(void);
void process_append_to_global_list(struct process *p);

void exit_fs(struct process *p);
void exit_sighand(struct process *p);

/**
 * @brief Zap the current process' threads and swap pids
 * current will become the new thread group leader.
 *
 * @return 0 on success, -EINTR if another exec is in progress
 */
int zap_threads_exec(void);

/* Both members protected either by RCU or tasklist_lock */
extern struct process *first_process;
extern struct list_head tasklist;

/* I took this idea from linux :P */
#define RUSAGE_BOTH -2

static inline rlim_t rlim_get_cur(unsigned int rlimit)
{
    struct process *cur = get_current_process();
    return READ_ONCE(cur->sig->rlimits[rlimit].rlim_cur);
}

void task_ctime(struct process *task, hrtime_t *cutime, hrtime_t *cstime);
void tg_cputime(struct process *process, hrtime_t *utime, hrtime_t *stime);
void tg_cputime_clock_t(struct process *process, __clock_t *utime, __clock_t *stime);
__END_CDECLS

#ifdef __cplusplus

#include <onyx/auto_resource.h>

using auto_process = auto_resource<process>;

using process_visit_function_t = bool (*)(process *, void *);

void for_every_process(process_visit_function_t func, void *ctx);

template <typename Callable>
void process_for_every_thread_unlocked(process *p, Callable cb)
{
}

template <typename Callable>
void process_for_every_thread(process *p, Callable cb)
{
}

struct process *process_create(const std::string_view &cmd_line, struct ioctx *ctx,
                               struct process *parent);

/**
 * @brief Copy environ/arguments from userspace to the kernel
 *
 * @param envarg NULL-terminated vector of char*
 * @param current_size Current size of args/environ (for ARG_MAX calculation)
 * @return Expected containing an envarg_res with the result, or negative error codes
 */
expected<envarg_res, int> process_copy_envarg(const char **envarg, size_t current_size);

#endif

#endif
