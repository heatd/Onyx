/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <onyx/cpu.h>
#include <onyx/device_tree.h>
#include <onyx/fpu.h>
#include <onyx/init.h>
#include <onyx/riscv/features.h>
#include <onyx/riscv/sbi.h>
#include <onyx/riscv/smp.h>
#include <onyx/types.h>

static const char *riscv_cpu_compatible_ids[] = {"riscv", nullptr};

cul::vector<device_tree::node *> cpus;
static cul::vector<u32> cpu2hart;

/**
 * @brief Get the CPU node's hart id
 *
 * @param node Node
 * @return HART id
 */
u32 riscv_cpu_get_hart(device_tree::node *node)
{
    u32 hart;
    if (node->get_property("reg", &hart) < 0)
    {
        panic("riscv cpu node does not have hart?");
    }
    return hart;
}

static u32 get_hart(unsigned int cpu)
{
    return cpu2hart[cpu];
}

int riscv_cpu_probe(device *dev_)
{
    device_tree::node *dev = (device_tree::node *) dev_;

    int len;
    auto prop = dev->get_property("status", &len);

    if (len > 0)
    {
        if (strcmp((const char *) prop, "okay"))
            return -1; // Not "okay", so skip.
    }

    if (!cpus.push_back(dev))
        return -ENOMEM;

    auto hart = riscv_cpu_get_hart(dev);

    if (!cpu2hart.push_back(hart))
        return -ENOMEM;

    return 0;
}

static driver riscv_cpu_driver = {
    .name = "riscv-cpu",
    .devids = riscv_cpu_compatible_ids,
    .probe = riscv_cpu_probe,
    .bus_type_node = &riscv_cpu_driver,
};

size_t riscv_find_hart(u32 hartid)
{
    for (size_t i = 0; i < cpu2hart.size(); i++)
    {
        if (cpu2hart[i] == hartid)
            return i;
    }

    panic("hartid %lu not found\n", hartid);
}

extern "C" void riscv_secondary_hart_start();

namespace smp
{

void boot(unsigned int cpu)
{
    auto hart = get_hart(cpu);

    auto pcpu_base = percpu_init_for_cpu(cpu);

    other_cpu_write(cpu_nr, cpu, cpu);

    do_init_level_percpu(INIT_LEVEL_CORE_PERCPU_CTOR, cpu);

    sched_init_cpu(cpu);

    unsigned long *stack = (unsigned long *) get_thread_for_cpu(cpu)->kernel_stack_top;

    stack[-1] = pcpu_base;

    const auto hart_entry =
        (unsigned long) riscv_secondary_hart_start - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset();

    auto st = sbi_hart_start(hart, hart_entry, (unsigned long) stack);

    if (st != SBI_SUCCESS)
    {
        printf("Failed to boot cpu%u (hart%u): %s\n", cpu, hart, sbi_strerror(st));
    }
    else
    {
        smp::set_online(cpu);
    }
}

} // namespace smp

namespace riscv
{

PER_CPU_VAR(u32 pending_ipi) = 0;

u32 get_pending_ipi()
{
    auto ipi = get_per_cpu_ptr(pending_ipi);

    return __atomic_exchange_n(ipi, 0, __ATOMIC_ACQ_REL);
}

void set_ipi(unsigned int cpu, u32 type)
{
    auto ipi = other_cpu_get_ptr(pending_ipi, cpu);
    __atomic_or_fetch(ipi, type, __ATOMIC_RELEASE);
}

void send_ipi(unsigned int cpu, u32 hart, u32 ipi_type)
{
    set_ipi(cpu, ipi_type);
    auto st = sbi_send_ipi(1, hart);

    if (st != SBI_SUCCESS)
    {
        panic("riscv/smp: Failed to send IPI: %s", sbi_strerror(st));
    }
}

} // namespace riscv

void cpu_send_sync_notif(unsigned int cpu)
{
    riscv::send_ipi(cpu, cpu2hart[cpu], RISCV_IPI_TYPE_SYNC_CALL);
}

void cpu_send_resched(unsigned int cpu)
{
    riscv::send_ipi(cpu, cpu2hart[cpu], RISCV_IPI_TYPE_RESCHED);
}

/**
 * @brief Fixup the hart list and make the boot hart CPU0
 *
 */
void riscv_fixup_harts()
{
    /* We may have booted as a hart which is not cpu@0, so fix that up since
     * our logical cpu number is 0.
     */
    auto index = riscv_find_hart(riscv_get_hartid());

    if (index != 0)
    {
        printf("riscv: We would be cpu#%lu, fixing up hart list...\n", index);
        cul::swap(cpus[0], cpus[index]);
        cul::swap(cpu2hart[0], cpu2hart[index]);
    }
}

void riscv_mp_init()
{
    do_init_level_percpu(INIT_LEVEL_CORE_PERCPU_CTOR, get_cpu_nr());
    device_tree::register_driver(&riscv_cpu_driver);
    smp::set_number_of_cpus(cpus.size());
    smp::set_online(0);
    riscv_fixup_harts();
    smp::boot_cpus();
}

INIT_LEVEL_EARLY_PLATFORM_ENTRY(riscv_mp_init);
