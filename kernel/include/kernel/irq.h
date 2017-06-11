/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _IRQ_H
#define _IRQ_H
#include <stdbool.h>

#include <kernel/registers.h>
#ifdef __x86_64__
#include <kernel/apic.h>
#endif
typedef uintptr_t(*irq_t)(registers_t *);

typedef struct irq
{
	irq_t handler;
	struct irq *next;
}irq_list_t;

struct irq_work
{
	void (*callback)(void *, size_t);
	size_t payload_size;
	char payload[0];
};
#define IRQ_WORK_QUEUE_SIZE (8192)
extern volatile bool is_in_irq;
#ifdef __cplusplus
extern "C" {
#endif
int irq_schedule_work(void (*callback)(void *, size_t), size_t payload_size, void *payload);
bool isirq();
void irq_install_handler(int irq, irq_t handler);
void irq_uninstall_handler(int irq, irq_t handler);
void irq_init(void);
#ifdef __cplusplus
}
#endif
#endif
