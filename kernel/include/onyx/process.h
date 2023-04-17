/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_PROCESS_H
#define _ONYX_PROCESS_H

#include <sys/resource.h>
#include <onyx/types.h>

#include <onyx/condvar.h>
#include <onyx/cpu.h>
#include <onyx/cred.h>
#include <onyx/culstring.h>
#include <onyx/elf.h>
#include <onyx/handle.h>
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
#include <onyx/signal.h>
#include <onyx/spinlock.h>
#include <onyx/syscall.h>
#include <onyx/vm.h>
#include <onyx/vm_layout.h>
#include <onyx/wait_queue.h>

#include <uapi/process.h>

#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

struct proc_event_sub;
struct tty;

static void process_get(struct process *process);
static void process_put(struct process *process);

#define PROCESS_FORKED (1 << 0)
#define PROCESS_SECURE (1 << 1)

class vfork_completion
{
    wait_queue wq;
    atomic<bool> done;
    atomic<bool> may_exit;

public:
    vfork_completion()
    {
        init_wait_queue_head(&wq);
        done = false;
        may_exit = false;
    }

    int wait()
    {
        return wait_for_event(&wq, done);
    }

    void wake()
    {
        done = true;
        wait_queue_wake_all(&wq);
        may_exit = true;
    }

    void wait_to_exit()
    {
        while (!may_exit)
            cpu_relax();
    }
};

struct process : public onx::handle::handleable
{
    unsigned long refcount{};

    /* Program name points to the string in cmd_line */
    cul::string cmd_line{};
    std::string_view name{};

    mutex name_lock{};

    unsigned long flags{};

    /* The next process in the linked list */
    process *next{};

    unsigned long nr_threads{};

    list_head thread_list{};
    spinlock thread_list_lock{};

    ref_guard<mm_address_space> address_space{};

    /* IO Context of the process */
    ioctx ctx{};

    /* Process ID */
    pid_t pid_{};

    /* Process' UID and GID */
    creds cred{};

    /* Pointer to the VDSO */
    void *vdso{};

    /* Signal information */
    spinlock signal_lock{};
    k_sigaction sigtable[_NSIG]{};
    unsigned int signal_group_flags{};
    wait_queue wait_child_event{};
    unsigned int exit_code{};

    /* Process personality */
    unsigned long personality{};

    /* This process' parent */
    struct process *parent{};

    /* Linked list to the processes being traced */
    extrusive_list_head tracees{};

    /* User time and system time consumed by the process */
    hrtime_t user_time{};
    hrtime_t system_time{};
    hrtime_t children_utime{};
    hrtime_t children_stime{};

    /* proc_event queue */
    spinlock sub_queue_lock{};
    struct proc_event_sub *sub_queue{};
    unsigned long nr_subs{};
    unsigned long nr_acks{};

    void *interp_base{};
    void *image_base{};

    elf_info info{};

    cond syscall_cond{};
    mutex condvar_mutex{};

    spinlock children_lock{};
    process *children{}, *prev_sibbling{}, *next_sibbling{};

    itimer timers[ITIMER_COUNT]{};

    pid::auto_pid pid_struct{};

    spinlock pgrp_lock{};
    list_head_cpp<process> pgrp_node;
    pid::auto_pid process_group{};
    list_head_cpp<process> session_node;
    pid::auto_pid session{};

    struct rlimit rlimits[RLIM_NLIMITS + 1]{};
    rwslock rlimit_lock{};

    tty *ctty{};

    vfork_completion *vfork_compl{};

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

    bool route_signal(struct sigpending *pend);

    void remove_thread(thread *t)
    {
        scoped_lock g{thread_list_lock};

        nr_threads--;

        list_remove(&t->thread_list_head);
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
        return session == pid_struct;
    }

    bool is_pgrp_leader_unlocked() const
    {
        return process_group == pid_struct;
    }

    mm_address_space *get_aspace() const
    {
        return address_space.get();
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
};

struct process *process_create(const std::string_view &cmd_line, struct ioctx *ctx,
                               struct process *parent);

struct thread *process_create_main_thread(struct process *proc, thread_callback_t callback,
                                          void *sp);

struct process *get_process_from_pid(pid_t pid);
struct thread *process_fork_thread(thread_t *src, struct process *dest, struct syscall_frame *ctx);
void process_destroy_aspace();
int process_attach(struct process *tracer, struct process *tracee);
struct process *process_find_tracee(struct process *tracer, pid_t pid);

void process_end(struct process *p);
void process_add_thread(struct process *process, thread_t *thread);

struct envarg_res
{
    char **s;
    int count;
    size_t total_size;
};

/**
 * @brief Copy environ/arguments from userspace to the kernel
 *
 * @param envarg NULL-terminated vector of char*
 * @param current_size Current size of args/environ (for ARG_MAX calculation)
 * @return Expected containing an envarg_res with the result, or negative error codes
 */
expected<envarg_res, int> process_copy_envarg(const char **envarg, size_t current_size);

static inline void process_get(struct process *process)
{
    __atomic_add_fetch(&process->refcount, 1, __ATOMIC_ACQUIRE);
}

static inline void process_put(struct process *process)
{
    if (__atomic_sub_fetch(&process->refcount, 1, __ATOMIC_RELEASE) == 0)
        process_end(process);
}

struct stack_info
{
    void *base;
    void *top;
    size_t length;
};

int process_alloc_stack(struct stack_info *info);
static inline struct process *get_current_process()
{
    thread_t *thread = get_current_thread();
    return (thread == NULL) ? NULL : (struct process *) thread->owner;
}

static inline mm_address_space *get_current_address_space()
{
    thread *t = get_current_thread();
    return t ? t->get_aspace() : &kernel_address_space;
}

/**
 * @brief Get the number of active processes
 *
 * @return The number of active processes
 */
pid_t process_get_active_processes();

#ifdef __cplusplus

#include <onyx/auto_resource.h>

using auto_process = auto_resource<process>;

using process_visit_function_t = bool (*)(process *, void *);

void for_every_process(process_visit_function_t func, void *ctx);

/* I took this idea from linux :P */
#define RUSAGE_BOTH -2

int do_rusage(int who, rusage *usage, process *p);

void notify_process_stop_cont(process *proc, int signum);

template <typename Callable>
void process_for_every_thread_unlocked(process *p, Callable cb)
{

    list_for_every (&p->thread_list)
    {
        thread *t = container_of(l, struct thread, thread_list_head);

        if (!cb(t))
            return;
    }
}

template <typename Callable>
void process_for_every_thread(process *p, Callable cb)
{
    scoped_lock g{p->thread_list_lock};

    process_for_every_thread_unlocked(p, cb);
}

[[noreturn]] void process_exit_from_signal(int signum);

#endif

#endif
