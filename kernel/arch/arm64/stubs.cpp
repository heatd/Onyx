
/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/ktrace.h>
#include <onyx/panic.h>
#include <onyx/platform.h>
#include <onyx/vm.h>

#define UNIMPLEMENTED panic("Not implemented!")

bool platform_has_msi()
{
    return false;
}

void halt()
{
    while (true)
    {
        __asm__ __volatile__("wfi");
    }
}

void cpu_kill_other_cpus()
{
}

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data)
{
    UNIMPLEMENTED;
}

thread *sched_create_thread(thread_callback_t callback, uint32_t flags, void *args)
{
    UNIMPLEMENTED;
}

bool platform_page_is_used(void *page)
{
    return false;
}

void arch_vm_init()
{
}

int process_alloc_stack(struct stack_info *info)
{
    UNIMPLEMENTED;
}

int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction,
                         struct registers *regs)
{
    UNIMPLEMENTED;
}

struct timer *platform_get_timer()
{
    UNIMPLEMENTED;
}

extern "C" void platform_yield()
{
    UNIMPLEMENTED;
}

extern "C" void thread_finish_destruction(thread *t)
{
    UNIMPLEMENTED;
}

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h)
{
    UNIMPLEMENTED;
}

void platform_mask_irq(unsigned int irq)
{
    UNIMPLEMENTED;
}

namespace smp
{

void boot(unsigned int nr)
{
    UNIMPLEMENTED;
}

} // namespace smp

void cpu_send_sync_notif(unsigned int cpu)
{
    UNIMPLEMENTED;
}

namespace native
{

void arch_save_thread(thread *thread, void *stack)
{
    UNIMPLEMENTED;
}

void arch_load_thread(thread *thread, unsigned int cpu)
{
    UNIMPLEMENTED;
}

void arch_load_process(process *process, thread *thread, unsigned int cpu)
{
    UNIMPLEMENTED;
}

void arch_context_switch(thread *prev, thread *next)
{
    UNIMPLEMENTED;
}

int arch_transform_into_user_thread(thread *thread)
{
    UNIMPLEMENTED;
}

} // namespace native

thread *process_fork_thread(thread_t *src, struct process *dest, struct syscall_frame *ctx)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_reboot(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_shutdown(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_halt(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_suspend(unsigned int flags)
{
    return -EIO;
}

extern "C" int return_from_execve(void *entry, void *stack)
{
    UNIMPLEMENTED;
}

void cpu_send_resched(unsigned int cpu)
{
    UNIMPLEMENTED;
}

bool cpu_send_message(unsigned int cpu, unsigned long message, void *arg, bool should_wait)
{
    UNIMPLEMENTED;
}

extern "C" int __enter_sleep_state(uint8_t)
{
    UNIMPLEMENTED;
}

uintptr_t get_rdsp_from_grub(void)
{
    return 0;
}

void reclaim_initrd(void)
{
}

void stack_trace()
{
    return;
}

size_t stack_trace_get(unsigned long *stack, unsigned long *pcs, size_t nr_pcs)
{
    return 0;
}

uint64_t get_posix_time_early()
{
    return 0;
}

void setup_kernel_symbols(struct module *m)
{
}

namespace entropy
{

namespace platform
{

unsigned long get_seed()
{
    return 0;
}

unsigned long get_hwrandom()
{
    return 0;
}

void init_random()
{
}

} // namespace platform

} // namespace entropy

void platform_init_acpi()
{
    UNIMPLEMENTED;
}

namespace ktrace
{

void ktracepoint::activate()
{
    UNIMPLEMENTED;
}

void ktracepoint::deactivate()
{
    UNIMPLEMENTED;
}

} // namespace ktrace
