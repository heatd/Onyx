/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_SCHEDULER_H
#define _ONYX_SCHEDULER_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <onyx/assert.h>
#include <onyx/clock.h>
#include <onyx/cputime.h>
#include <onyx/list.h>
#include <onyx/percpu.h>
#include <onyx/preempt.h>
#include <onyx/signal.h>
#include <onyx/spinlock.h>

#define NUM_PRIO 40

#define SCHED_PRIO_VERY_LOW  0
#define SCHED_PRIO_LOW       10
#define SCHED_PRIO_NORMAL    20
#define SCHED_PRIO_HIGH      30
#define SCHED_PRIO_VERY_HIGH 39

using thread_callback_t = void (*)(void *);
struct process;
struct mm_address_space;
struct kcov_data;

#define THREAD_STRUCT_CANARY 0xcacacacafdfddead
#define THREAD_DEAD_CANARY   0xdeadbeefbeefdead

using thread_t = struct thread
{
    unsigned long refcount;
    unsigned long canary;
    /* Put arch-independent stuff right here */
    uintptr_t *kernel_stack;
    uintptr_t *kernel_stack_top;
    struct process *owner;
    thread_callback_t entry;
    uint32_t flags;
    int id;
    int status;
    int priority;
    unsigned int cpu;
    struct thread *next;
    struct thread *prev_prio, *next_prio;
    struct thread *prev_wait, *next_wait;
    unsigned char *fpu_area;
    struct thread *sem_prev;
    struct thread *sem_next;
    struct spinlock lock;
    int errno_val;
    struct signal_info sinfo;
    struct list_head thread_list_head;
    unsigned long addr_limit;
    struct list_head wait_list_head;
    /* Clear child tid address - It's set by sys_set_tid_address or by sys_clone itself
     * and it's used to futex_wake any threads blocked by join.
     */
    void *ctid;

    struct thread_cputime_info cputime_info;
    mm_address_space *aspace{};

#ifdef CONFIG_KCOV
    struct kcov_data *kcov_data{nullptr};
#endif
    /* And arch dependent stuff in this ifdef */
#ifdef __x86_64__
    void *fs;
    void *gs;
#elif defined(__riscv)
    void *tp;
#elif defined(__aarch64__)
    void *tpidr;
#endif

#ifdef __cplusplus
    thread()
        : refcount{}, canary{}, kernel_stack{}, kernel_stack_top{}, owner{}, entry{}, flags{}, id{},
          status{}, priority{}, cpu{}, next{}, prev_prio{}, next_prio{}, prev_wait{}, next_wait{},
          fpu_area{}, sem_prev{}, sem_next{}, lock{}, errno_val{}, thread_list_head{}, addr_limit{},
          wait_list_head{}, ctid{}, cputime_info{}
#ifdef __x86_64__
          ,
          fs{}, gs{}
#endif
    {
    }
#endif

    /**
     * @brief Sets the address space for the thread
     *
     */
    void set_aspace(mm_address_space *as)
    {
        aspace = as;
    }

    /**
     * @brief Gets the thread's address space
     *
     */
    mm_address_space *get_aspace() const
    {
        return aspace;
    }
};

#define THREAD_KERNEL        (1 << 0)
#define THREAD_NEEDS_RESCHED (1 << 1)
#define THREAD_IS_DYING      (1 << 2)
#define THREAD_SHOULD_DIE    (1 << 3)
#define THREAD_ACTIVE        (1 << 4)
#define THREAD_RUNNING       (1 << 5)

int sched_init(void);

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void *args);

void sched_remove_thread(thread_t *thread);

/* This symbol is percpu, don't use. */
extern struct thread *current_thread;

static inline struct thread *get_current_thread(void)
{
    return get_per_cpu(current_thread);
}

hrtime_t sched_sleep(unsigned long ns);

void sched_yield(void);

void thread_add(thread_t *add, unsigned int cpu);

void set_current_thread(thread_t *t);

void thread_destroy(thread_t *t);

void thread_set_state(thread_t *thread, int state);

void thread_wake_up(thread_t *thread);

void sched_sleep_until_wake(void);

void thread_wake_up_ftx(thread_t *thread);

void thread_reset_futex_state(thread_t *thread);

void sched_start_thread(thread_t *thread);

void sched_wake_up_available_threads(void);

void sched_block(struct thread *thread);

void __sched_block(struct thread *thread, unsigned long cpuflags);

void thread_exit();

struct thread *get_thread_for_cpu(unsigned int cpu);

void sched_start_thread_for_cpu(struct thread *thread, unsigned int cpu);

void sched_init_cpu(unsigned int cpu);

void thread_append_to_global_list(struct thread *t);

void thread_remove_from_list(struct thread *t);

struct thread *thread_get_from_tid(int tid);

extern "C" unsigned long thread_get_addr_limit(void);

void *sched_preempt_thread(void *current_stack);

int sched_transition_to_user_thread(struct thread *thread);

#define SCHED_NO_CPU_PREFERENCE (unsigned int) -1

static inline bool sched_needs_resched(struct thread *thread)
{
    return thread->flags & THREAD_NEEDS_RESCHED;
}

static inline void sched_should_resched(void)
{
    struct thread *t = get_current_thread();
    if (t)
        t->flags |= THREAD_NEEDS_RESCHED;
}

#define set_current_state(state)                                 \
    do                                                           \
    {                                                            \
        struct thread *__t = get_current_thread();               \
        assert(__t != NULL);                                     \
        __atomic_store_n(&__t->status, state, __ATOMIC_RELEASE); \
    } while (0);

static inline void thread_get(struct thread *thread)
{
    __atomic_add_fetch(&thread->refcount, 1, __ATOMIC_ACQUIRE);
}

static inline void thread_put(struct thread *thread)
{
    if (__atomic_sub_fetch(&thread->refcount, 1, __ATOMIC_ACQUIRE) == 0)
        thread_destroy(thread);
}

static inline void thread_set_flag(struct thread *thread, unsigned int flag)
{
    __atomic_or_fetch(&thread->flags, flag, __ATOMIC_RELAXED);
}

void sched_transition_to_idle(void);

static inline void sched_sleep_ms(unsigned long ms)
{
    sched_sleep(ms * NS_PER_MS);
}

/**
 * @brief Check if we can sleep (to be used by debugging functions)
 *
 * @return True if we can, else false
 */
bool __can_sleep_internal();

#define MAY_SLEEP() DCHECK(__can_sleep_internal())

#ifdef __cplusplus

namespace native
{
[[noreturn]] void arch_context_switch(thread *prev, thread *next);
int arch_transform_into_user_thread(thread *thread);
}; // namespace native

#endif

#endif
