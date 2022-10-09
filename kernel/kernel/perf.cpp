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

/**
 * @brief Protects the data structures below (particularly, fg).
 * It counts the number of cpus that have it grabbed, or perf_lock.lock_write.
 * EXCLUSIVE is held when setting up or disabling perf probing.
 */
rwslock perf_lock;

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
    perf_lock.lock_write();

    if (perf_probe_enabled)
        return perf_lock.unlock_write(), -EINVAL;

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

    perf_probe_wait_enabled = true;

    perf_lock.unlock_write();

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
    perf_lock.lock_write();

    if (perf_probe_wait_enabled)
        return perf_lock.unlock_write(), -EINVAL;

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

    perf_lock.unlock_write();

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
    perf_lock.lock_write();

    if (!fg)
    {
        perf_lock.unlock_write();
        return -EINVAL;
    }

    sched_enable_preempt();

    unsigned char *ubuf2 = (unsigned char *) ubuf;
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        for (size_t j = 0; j < fg[i].nentries; j++)
        {
            auto fge = &fg[i].fge[j];
            if (copy_to_user(ubuf2, fge, sizeof(*fge)) < 0)
            {
                sched_disable_preempt();
                perf_lock.unlock_write();
                return -EFAULT;
            }
            ubuf2 += sizeof(flame_graph_entry);
        }
    }

    sched_disable_preempt();

    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        vfree(fg[i].fge, vm_size_to_pages(sizeof(flame_graph_entry) * FLAME_GRAPH_NENTRIES));
    }

    free(fg);
    fg = nullptr;

    perf_lock.unlock_write();

    return 0;
}

/**
 * @brief Disable CPU perf probing
 *
 */
static void perf_disable_probing()
{
    perf_lock.lock_write();

    if (!perf_probe_enabled && !perf_probe_wait_enabled)
    {
        perf_lock.unlock_write();
        return;
    }

    if (ce)
    {
        timer_cancel_event(ce);
        delete ce;
        ce = nullptr;
    }

    perf_probe_enabled = false;

    perf_lock.unlock_write();
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
    perf_lock.lock_read();

    if (!fg)
        return perf_lock.unlock_read(), -EINVAL;

    size_t len = 0;
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        len += fg[i].nentries * sizeof(flame_graph_entry);
    }

    perf_lock.unlock_read();

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
        perf_lock.lock_write();
        perf_probe_wait_enabled = false;
        perf_lock.unlock_write();
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
    if (perf_lock.try_read() < 0)
        return;

    if (!perf_probe_wait_enabled)
    {
        perf_lock.unlock_read();
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

    perf_lock.unlock_read();
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
    // Give up if we can't grab the lock
    if (perf_lock.try_read() < 0)
        return;

    if (!perf_probe_enabled)
    {
        perf_lock.unlock_read();
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

    perf_lock.unlock_read();
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
