/*
 * Copyright (c) 2016, 2017, 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/init.h>
#include <onyx/irq.h>
#include <onyx/percpu.h>
#include <onyx/platform.h>

struct irq_line irq_lines[NR_IRQ] = {};
unsigned long rogue_irqs = 0;

static struct interrupt_handler *add_to_list(struct irq_line *line)
{
    auto handler = new interrupt_handler;
    if (!handler)
        return NULL;

    memset(handler, 0, sizeof(*handler));

    spin_lock(&line->list_lock);

    if (!line->irq_handlers)
    {
        line->irq_handlers = handler;
    }
    else
    {
        struct interrupt_handler *h = line->irq_handlers;
        for (; h->next != NULL; h = h->next)
            ;
        h->next = handler;
    }

    spin_unlock(&line->list_lock);

    return handler;
}

int install_irq(unsigned int irq, irq_t handler, struct device *device, unsigned int flags,
                void *cookie)
{

    assert(irq < NR_IRQ);
    assert(device != NULL);
    assert(handler != NULL);

    struct irq_line *line = &irq_lines[irq];

    struct interrupt_handler *h = add_to_list(line);
    if (!h)
        return -1;

    h->handler = handler;
    h->device = device;
    h->flags = flags;
    h->cookie = cookie;

    platform_install_irq(irq, h);

    printf("Installed handler (driver %s) for IRQ%u\n", device->driver_->name, irq);

    return 0;
}

void free_irq(unsigned int irq, struct device *device)
{
    struct irq_line *line = &irq_lines[irq];
    struct interrupt_handler *handler = NULL;

    spin_lock(&line->list_lock);

    assert(line->irq_handlers != NULL);

    if (line->irq_handlers->device == device)
    {
        handler = line->irq_handlers;
        line->irq_handlers = handler->next;
    }
    else
    {
        for (struct interrupt_handler *h = line->irq_handlers; h->next != NULL; h = h->next)
        {
            if (h->next->device == device)
            {
                handler = h->next;
                h->next = handler->next;
                break;
            }
        }
    }

    /* Assert if the device had no registered irq */
    assert(handler != NULL);

    free(handler);

    /* Mask the irq if the irq has no handler */
    if (line->irq_handlers == NULL)
        platform_mask_irq(irq);

    spin_unlock(&line->list_lock);
}

PER_CPU_VAR(bool in_irq) = false;

bool is_in_interrupt(void)
{
    return get_per_cpu(in_irq);
}

void dispatch_irq(unsigned int irq, struct irq_context *context)
{
    struct irq_line *line = &irq_lines[irq];

    write_per_cpu(in_irq, true);

    for (struct interrupt_handler *h = line->irq_handlers; h; h = h->next)
    {
        irqstatus_t st = h->handler(context, h->cookie);

        if (st == IRQ_HANDLED)
        {
            line->stats.handled_irqs++;
            h->handled_irqs++;
            write_per_cpu(in_irq, false);
            return;
        }
    }

    rogue_irqs++;
    line->stats.spurious++;
    write_per_cpu(in_irq, false);
}

void irq_init(void)
{
    dpc_init();
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(irq_init);
