/*
 * Copyright (c) 2019, 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdio.h>

#include <onyx/bitmap.h>
#include <onyx/cpu.h>
#include <onyx/init.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/smp.h>
#include <onyx/smp_sync_control.h>
#include <onyx/wait_queue.h>

#include <onyx/atomic.hpp>
#include <onyx/mm/pool.hpp>
#include <onyx/tuple.hpp>

extern unsigned char _start_smp;
extern unsigned char _end_smp;

extern "C" {

PER_CPU_VAR(unsigned int cpu_nr) = 0;
};

namespace smp
{

static cpumask online_cpus;
unsigned int nr_cpus = 0;
unsigned int nr_online_cpus = 0;
constexpr unsigned long smp_trampoline_phys = 0x0;

void set_number_of_cpus(unsigned int nr)
{
    nr_cpus = nr;
}

void set_online(unsigned int cpu)
{
    online_cpus.set_cpu(cpu);
    nr_online_cpus++;
}

void boot_cpus()
{
    printf("smpboot: booting cpus\n");
    memcpy((void *)(PHYS_BASE + (uintptr_t)smp_trampoline_phys), &_start_smp,
           (uintptr_t)&_end_smp - (uintptr_t)&_start_smp);

    for (unsigned int i = 0; i < nr_cpus; i++)
    {
        if (!online_cpus.is_cpu_set(i))
        {
            boot(i);
        }
    }

    printf("smpboot: done booting cpus, %u online\n", nr_online_cpus);
}

unsigned int get_online_cpus()
{
    return nr_online_cpus;
}

namespace internal
{

void sync_call_cntrlblk::complete()
{
    waiting_for_completion--;
}

void sync_call_cntrlblk::wait(sync_call_func local, void *context)
{
    bool has_done = false;
    while (waiting_for_completion != 0)
    {

        if (!has_done)
        {
            local(context);
            has_done = true;
        }

        cpu_relax();
    }

    if (!has_done)
        local(context);
}

} // namespace internal

struct sync_call_queue
{
    struct spinlock lock;
    struct list_head elem_list;

    void init()
    {
        spinlock_init(&lock);
        INIT_LIST_HEAD(&elem_list);
    }

    void add_elem(internal::sync_call_elem *elem)
    {
        scoped_lock<spinlock, true> g{lock};
        list_add_tail(&elem->node, &elem_list);
    }

    void handle_calls();
};

memory_pool<internal::sync_call_elem, MEMORY_POOL_USABLE_ON_IRQ> sync_call_pool;

void sync_call_queue::handle_calls()
{
    scoped_lock<spinlock, true> g{lock};

    list_for_every_safe (&elem_list)
    {
        auto elem = container_of(l, internal::sync_call_elem, node);

        list_remove(&elem->node);

        elem->control_block.f(elem->control_block.ctx);

        elem->control_block.complete();

        sync_call_pool.free(elem);
    }
}

PER_CPU_VAR(sync_call_queue percpu_queue);

void smp_bring_up_percpu(unsigned int cpu)
{
    auto cq = get_per_cpu_ptr_any(smp::percpu_queue, cpu);

    cq->init();
}

INIT_LEVEL_CORE_PERCPU_CTOR(smp_bring_up_percpu);

void sync_call_with_local(sync_call_func f, void *context, const cpumask &mask_,
                          sync_call_func local, void *context2)
{
    auto mask = mask_ & online_cpus;
    auto our_cpu = get_cpu_nr();
    bool execute_on_us = mask.is_cpu_set(our_cpu);

    mask.remove_cpu(our_cpu);

    internal::sync_call_cntrlblk control_block{f, context};

    mask.for_every_cpu([&](unsigned long cpu) -> bool {
        auto ptr = sync_call_pool.allocate();
        if (!ptr)
            panic("Out of memory on sync call");

        control_block.waiting_for_completion++;

        auto elem = new (ptr) internal::sync_call_elem{control_block};

        auto queue = get_per_cpu_ptr_any(percpu_queue, cpu);
        queue->add_elem(elem);

        cpu_send_sync_notif(static_cast<unsigned int>(cpu));
        return true;
    });

    if (execute_on_us)
        f(context);

    control_block.wait(local, context2);
}

void sync_call(sync_call_func f, void *context, const cpumask &mask)
{
    sync_call_with_local(
        f, context, mask, [](void *ctx) {}, nullptr);
}

void cpu_handle_sync_calls()
{
    auto queue = get_per_cpu_ptr(percpu_queue);
    queue->handle_calls();
}

} // namespace smp
