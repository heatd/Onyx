/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
#include <onyx/registers.h>
#include <onyx/rwlock.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
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
#include <onyx/pid.h>

#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

#endif

#define TASK_COMM_LEN 16

struct proc_event_sub;
struct tty;
struct pid;

static void process_get(struct process *process);
static void process_put(struct process *process);

#define PROCESS_FORKED (1 << 0)
#define PROCESS_SECURE (1 << 1)

struct vfork_completion;

#ifdef __cplusplus
// clang-format off
#define CPP_DFLINIT {}
// clang-format on
#else
#define CPP_DFLINIT
#endif

struct process
#ifdef __cplusplus
    : public onx::handle::handleable
#endif
{
#ifndef __cplusplus
    void *__vtable;
#endif
    unsigned long refcount;

    /* Program name points to the string in cmd_line */
#ifdef __cplusplus
    cul::string cmd_line;
    static_assert(sizeof(cmd_line) == 32);
#else
    char __cmd_line[32];
#endif
    char comm[TASK_COMM_LEN];

    struct mutex name_lock;

    unsigned long flags;

    /* The next process in the linked list */
    struct process *next;

    unsigned long nr_threads;

    struct list_head thread_list;
    struct spinlock thread_list_lock;

#ifdef __cplusplus
    ref_guard<mm_address_space> address_space{};
#else
    struct mm_address_space *address_space;
#endif

    /* IO Context of the process */
    struct ioctx ctx;

    /* Process ID */
    pid_t pid_;

    /* Process' UID and GID */
    struct creds cred;

    /* Pointer to the VDSO */
    void *vdso;

    /* Signal information */
    struct spinlock signal_lock;
    struct k_sigaction sigtable[_NSIG];
    unsigned int signal_group_flags;
    struct wait_queue wait_child_event;
    unsigned int exit_code;

    /* Process personality */
    unsigned long personality;

    /* This process' parent */
    struct process *parent;

    /* User time and system time consumed by the process */
    hrtime_t user_time;
    hrtime_t system_time;
    hrtime_t children_utime;
    hrtime_t children_stime;

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

    struct spinlock children_lock CPP_DFLINIT;
    struct process *children CPP_DFLINIT, *prev_sibbling CPP_DFLINIT, *next_sibbling CPP_DFLINIT;

    struct itimer timers[ITIMER_COUNT] CPP_DFLINIT;

#ifdef __cplusplus
    pid::auto_pid pid_struct{};
#else
    struct pid *pid_struct;
#endif

    struct spinlock pgrp_lock CPP_DFLINIT;
    LIST_HEAD_CPP(process) pgrp_node;
#ifdef __cplusplus
    pid::auto_pid process_group{};
#else
    struct pid *process_group;
#endif
    LIST_HEAD_CPP(process) session_node;
#ifdef __cplusplus
    pid::auto_pid session{};
#else
    struct pid *session;
#endif

    struct rlimit rlimits[RLIM_NLIMITS + 1] CPP_DFLINIT;
    RWSLOCK rlimit_lock CPP_DFLINIT;

    struct tty *ctty CPP_DFLINIT;

    struct vfork_completion *vfork_compl CPP_DFLINIT;

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
#endif
};

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
__attribute__((pure)) static inline struct process *get_current_process()
{
    thread_t *thread = get_current_thread();
    return (thread == NULL) ? NULL : (struct process *) thread->owner;
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

struct process *process_create(const std::string_view &cmd_line, struct ioctx *ctx,
                               struct process *parent);

static inline mm_address_space *get_current_address_space()
{
    thread *t = get_current_thread();
    return t ? t->get_aspace() : &kernel_address_space;
}

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
