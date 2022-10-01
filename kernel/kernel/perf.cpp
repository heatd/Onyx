/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/percpu.h>
#include <onyx/perf_probe.h>
#include <onyx/timer.h>

#ifdef __x86_64__
#include <onyx/x86/apic.h>
#endif

#include <onyx/atomic.hpp>

#define PERF_LOCK_EXCLUSIVE UINT_MAX

/**
 * @brief Protects the data structures below (particularly, fg).
 * It counts the number of cpus that have it grabbed, or PERF_LOCK_EXCLUSIVE.
 * EXCLUSIVE is held when setting up or disabling perf probing.
 */
cul::atomic_uint perf_lock;

/**
 * @brief Lock the perf lock in shared mode
 *
 */
static void perf_lock_shared()
{
    while (true)
    {
        auto old = perf_lock.load(mem_order::relaxed);
        if (old == PERF_LOCK_EXCLUSIVE)
        {
            do
            {
                cpu_relax();
                old = perf_lock.load(mem_order::relaxed);
            } while (old == PERF_LOCK_EXCLUSIVE);
        }

        if (perf_lock.compare_exchange_strong(old, old + 1, mem_order::acquire, mem_order::relaxed))
            [[likely]]
            return;
    }
}

/**
 * @brief Unlock the shared perf lock
 *
 */
static void perf_unlock_shared()
{
    perf_lock.sub_fetch(1, mem_order::release);
}

/**
 * @brief Lock the perf lock in exclusive mode
 *
 */
static void perf_lock_exclusive()
{
    irq_disable();

    while (true)
    {
        auto old = perf_lock.load(mem_order::relaxed);
        if (old != 0)
        {
            do
            {
                cpu_relax();
                old = perf_lock.load(mem_order::relaxed);
            } while (old != 0);
        }

        if (perf_lock.compare_exchange_strong(old, PERF_LOCK_EXCLUSIVE, mem_order::acquire,
                                              mem_order::relaxed)) [[likely]]
            return;
    }
}

/**
 * @brief Unlock the perf unlock in exclusive mode
 *
 */
static void perf_unlock_exclusive()
{
    perf_lock.store(0, mem_order::release);
    irq_enable();
}

bool perf_probe_enabled = false;
bool perf_probe_wait_enabled = false;
struct flame_graph_pcpu *fg;
clockevent *ce;

/**
 * @brief Enable wait perf probing
 *
 * @return 0 on success, negative error codes
 */
static int perf_probe_enable_wait()
{
    perf_lock_exclusive();

    if (perf_probe_enabled)
        return perf_unlock_exclusive(), -EINVAL;

    if (!fg)
    {
        fg = (flame_graph_pcpu *) calloc(sizeof(flame_graph_pcpu), get_nr_cpus());
        assert(fg != nullptr);
        for (unsigned int i = 0; i < get_nr_cpus(); i++)
        {
            fg[i].windex = 0;
            fg[i].nentries = FLAME_GRAPH_NENTRIES;
            fg[i].fge =
                (flame_graph_entry *) calloc(sizeof(flame_graph_entry), FLAME_GRAPH_NENTRIES);
            assert(fg[i].fge != nullptr);
        }
    }

    perf_probe_wait_enabled = true;

    perf_unlock_exclusive();

    return 0;
}

/**
 * @brief Check is wait perf probing is enabled
 *
 * @return True if enabled, else false
 */
bool perf_probe_is_enabled_wait()
{
    return perf_probe_wait_enabled;
}

extern cul::atomic_size_t used_pages;

/**
 * @brief Enable CPU perf probing
 *
 * @return 0 on success, negative error codes
 */
static int perf_probe_enable()
{
    perf_lock_exclusive();

    if (perf_probe_wait_enabled)
        return perf_unlock_exclusive(), -EINVAL;

    if (!fg)
    {
        fg = (flame_graph_pcpu *) calloc(sizeof(flame_graph_pcpu), get_nr_cpus());
        assert(fg != nullptr);
        for (unsigned int i = 0; i < get_nr_cpus(); i++)
        {
            fg[i].windex = 0;
            fg[i].nentries = FLAME_GRAPH_NENTRIES;
            fg[i].fge = (flame_graph_entry *) vmalloc(
                vm_size_to_pages(sizeof(flame_graph_entry) * FLAME_GRAPH_NENTRIES), VM_TYPE_REGULAR,
                VM_READ | VM_WRITE);
            assert(fg[i].fge != nullptr);
        }
    }

    if (!ce)
    {
        ce = (clockevent *) new clockevent;
        assert(ce != nullptr);
    }

    auto ev = ce;
    ev->callback = [](clockevent *ev_) {
#ifdef __x86_64__
        apic_send_ipi_all(0, X86_PERFPROBE);
#endif
        ev_->deadline = clocksource_get_time() + NS_PER_MS;
    };
    ev->deadline = clocksource_get_time() + 1 * NS_PER_MS;
    ev->flags = CLOCKEVENT_FLAG_ATOMIC | CLOCKEVENT_FLAG_PULSE;
    timer_queue_clockevent(ev);

    perf_probe_enabled = true;

    perf_unlock_exclusive();

    return 0;
}

/**
 * @brief Copy the probe buffers to userspace, and free them
 *
 * @param ubuf User buffer
 * @return 0 on success, negative error codes
 */
static int perf_probe_ucopy(void *ubuf)
{
    perf_lock_exclusive();

    if (!fg)
    {
        perf_unlock_exclusive();
        return -EINVAL;
    }

    unsigned char *ubuf2 = (unsigned char *) ubuf;
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        for (size_t j = 0; j < fg[i].nentries; j++)
        {
            auto fge = &fg[i].fge[j];
            if (copy_to_user(ubuf2, fge, sizeof(*fge)) < 0)
                return perf_unlock_exclusive(), -EFAULT;
            ubuf2 += sizeof(flame_graph_entry);
        }
    }

    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        vfree(fg[i].fge, vm_size_to_pages(sizeof(flame_graph_entry) * FLAME_GRAPH_NENTRIES));
    }

    free(fg);
    fg = nullptr;

    perf_unlock_exclusive();

    return 0;
}

/**
 * @brief Disable CPU perf probing
 *
 */
static void perf_disable_probing()
{
    perf_lock_exclusive();

    if (!perf_probe_enabled && !perf_probe_wait_enabled)
    {
        perf_unlock_exclusive();
        return;
    }

    if (ce)
    {
        timer_cancel_event(ce);
        delete ce;
        ce = nullptr;
    }

    perf_probe_enabled = false;

    perf_unlock_exclusive();
}

static int perf_probe_ioctl_enable_disable_cpu(void *argp)
{
    int is;
    if (copy_from_user(&is, argp, sizeof(is)) < 0)
        return -EFAULT;
    int st = 0;

    if ((bool) is)
        st = perf_probe_enable();
    else
    {
        perf_disable_probing();
    }

    return st;
}

static unsigned int perf_probe_ioctl_get_buflen()
{
    perf_lock_shared();

    if (!fg)
        return perf_unlock_shared(), -EINVAL;

    size_t len = 0;
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        len += fg[i].nentries * sizeof(flame_graph_entry);
    }

    perf_unlock_shared();

    return len;
}

static unsigned int perf_probe_ioctl_enable_disable_wait(void *argp)
{
    int is;
    if (copy_from_user(&is, argp, sizeof(is)) < 0)
        return -EFAULT;

    int st = 0;
    if ((bool) is)
        st = perf_probe_enable_wait();
    else
    {
        perf_lock_exclusive();
        perf_probe_wait_enabled = false;
        perf_unlock_exclusive();
    }

    return st;
}

unsigned int perf_probe_ioctl(int request, void *argp, struct file *file)
{
    switch (request)
    {
        case PERF_PROBE_ENABLE_DISABLE_CPU:
            return perf_probe_ioctl_enable_disable_cpu(argp);
        case PERF_PROBE_GET_BUFFER_LENGTH:
            return perf_probe_ioctl_get_buflen();
        case PERF_PROBE_READ_DATA:
            return perf_probe_ucopy(argp);
        case PERF_PROBE_ENABLE_DISABLE_WAIT:
            return perf_probe_ioctl_enable_disable_wait(argp);
    }

    return -ENOTTY;
}

PER_CPU_VAR(flame_graph_entry *curwait_fge) = nullptr;

/**
 * @brief Set up a wait probe. Called right before platform_yield()
 *
 * @param fge flame_graph_entry, stack allocated
 */
void perf_probe_setup_wait(struct flame_graph_entry *fge)
{
    const auto t0 = clocksource_get_time();
    fge->rips[31] = t0;
    write_per_cpu(curwait_fge, fge);
}

/**
 * @brief Commit the wait probe
 *
 * @param fge flame_graph_entry, stack allocated
 */
void perf_probe_commit_wait(const struct flame_graph_entry *fge)
{
    perf_lock_shared();

    if (!perf_probe_wait_enabled)
    {
        perf_unlock_shared();
        return;
    }

    auto _ = irq_save_and_disable();
    struct flame_graph_pcpu *pcpu = &fg[get_cpu_nr()];
    struct flame_graph_entry *e = &pcpu->fge[pcpu->windex % FLAME_GRAPH_NENTRIES];
    pcpu->windex++;
    memcpy(e, fge, sizeof(*fge));
    const auto t1 = clocksource_get_time();
    e->rips[31] = t1 - e->rips[31];
    irq_restore(_);

    perf_unlock_shared();
}

/**
 * @brief Try to take a trace for the wait probe
 *
 * @param regs Registers
 */
void perf_probe_try_wait_trace(struct registers *regs)
{
    auto curfge = get_per_cpu(curwait_fge);

    // It's possible curfge may no longer exist
    if (!curfge)
        return;

#ifdef __x86_64__
    curfge->rips[0] = regs->rip;
    curfge->rips[1] = 0;
    stack_trace_get((unsigned long *) regs->rbp, curfge->rips + 1, 30);
#endif
    write_per_cpu(curwait_fge, nullptr);
}

/**
 * @brief Check if CPU perf probing is enabled
 *
 * @return True if enabled, else false
 */
bool perf_probe_is_enabled()
{
    return perf_probe_enabled;
}

/**
 * @brief Do a CPU perf probe
 *
 * @param regs Registers
 */
void perf_probe_do(struct registers *regs)
{
    perf_lock_shared();

    if (!perf_probe_enabled)
    {
        perf_unlock_shared();
        return;
    }

    auto _ = irq_save_and_disable();
    struct flame_graph_pcpu *pcpu = &fg[get_cpu_nr()];
    struct flame_graph_entry *e = &pcpu->fge[pcpu->windex % FLAME_GRAPH_NENTRIES];
    (void) e;
    pcpu->windex++;
#ifdef __x86_64__
    e->rips[0] = regs->rip;
    e->rips[1] = 0;
    stack_trace_get((unsigned long *) regs->rbp, e->rips + 1, 31);
#endif
    irq_restore(_);

    perf_unlock_shared();
}

const file_ops perf_probe_fops = {.read = nullptr, // TODO
                                  .ioctl = perf_probe_ioctl};

/**
 * @brief Initialize perf-probe
 *
 */
void perf_init()
{
    auto ex = dev_register_chardevs(0, 1, 0, &perf_probe_fops, "perf-probe");

    ex.unwrap()->show(0644);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(perf_init);
