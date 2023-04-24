/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/irq.h>
#include <onyx/scheduler.h>
#include <onyx/softirq.h>

void check_for_resched(struct irq_context *context)
{
    struct thread *curr = get_current_thread();
    if (curr && sched_needs_resched(curr))
    {
        curr->flags &= ~THREAD_NEEDS_RESCHED;
        context->registers = (registers_t *) sched_preempt_thread(context->registers);
    }
}

unsigned int arm64_irq_claim();
void arm64_irq_eoi(unsigned int irqn);

unsigned long irq_handler(struct registers *regs)
{
    /* Just return on the odd occasion that irqn > NR_IRQ */
    assert(irq_is_disabled() == true);

    auto irqn = arm64_irq_claim();

    struct irq_context context;
    context.registers = regs;
    context.irq_nr = irqn;

    dispatch_irq((unsigned int) irqn, &context);

    arm64_irq_eoi(irqn);

    /* It's implicit that irqs are enabled since we are in a handler */
    if (!sched_is_preemption_disabled() && softirq_pending())
    {
        softirq_handle();
    }

    check_for_resched(&context);

    return (unsigned long) context.registers;
}
