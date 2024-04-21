/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_X86_APIC_H
#define _ONYX_X86_APIC_H

#include <stdio.h>

#include <onyx/types.h>
#include <onyx/vm.h>

#define IOAPIC_BASE_PHYS          0xFEC00000
#define IA32_APIC_BASE_MSR        0x1B
#define IA32_APIC_BASE_MSR_BSP    0x100 // Processor is a BSP
#define IA32_APIC_BASE_MSR_ENABLE 0x800

#define IOAPIC_PIN_DESTINATION_MODE    (1 << 11)
#define IOAPIC_PIN_DELIVERY_STATUS     (1 << 12)
#define IOAPIC_PIN_POLARITY_ACTIVE_LOW (1 << 13)
#define IOAPIC_PIN_TRIGGER_LEVEL       (1 << 15)
#define IOAPIC_PIN_MASKED              (1 << 16)
#define IOAPIC_DESTINATION(x)          ((u64) x << 56)
#define IOAPIC_DESTINATION_MASK        IOAPIC_DESTINATION(0xff)

void ioapic_early_init(void);
void apic_timer_init();
void ioapic_init();
void set_pin_handlers();
void ioapic_set_pin(bool active_high, bool level, uint32_t pin);
void ioapic_unmask_pin(uint32_t pin);
void ioapic_mask_pin(uint32_t pin);
uint32_t read_io_apic(uint32_t reg);
void write_io_apic(uint32_t reg, uint32_t value);
void lapic_init();

struct smp_header;

/**
 * @brief Wake up a processor
 * Wakes up a given CPU with the given lapic_id and the given smp_header parameters.
 *
 * @param lapic_id LAPIC id
 * @param s SMP header
 * @return True if woken up, else false.
 */
bool apic_wake_up_processor(uint32_t lapic_id, struct smp_header *s);
void apic_set_irql(int irql);
int apic_get_irql(void);
void apic_send_ipi(uint32_t id, uint32_t type, uint32_t page,
                   uint32_t extra_flags
#ifdef __cplusplus
                   = 0
#endif
);
void apic_send_ipi_all(uint32_t type, uint32_t page);
void lapic_send_eoi(void);
uint32_t apic_get_lapic_id(unsigned int cpu);
void apic_set_lapic_id(unsigned int cpu, uint32_t lapic_id);
volatile uint32_t *apic_get_lapic(unsigned int cpu);
void lapic_init_per_cpu(void);
u32 cpu2lapicid(u32 cpu);

#define irq_set_irql apic_set_irql
#define irq_get_irql apic_get_irql

#define LAPIC_ID_REG                      0x20
#define LAPIC_EOI                         0xB0
#define LAPIC_TSKPRI                      0x80
#define LAPIC_ICR                         0x300
#define LAPIC_IPIID                       0x310
#define LAPIC_LVT_TIMER                   0x320
#define LAPIC_PERFCI                      0x340
#define LAPIC_LI0                         0x350
#define LAPIC_LI1                         0x360
#define LAPIC_ERRINT                      0x370
#define LAPIC_SPUINT                      0xF0
#define LAPIC_TIMER_DIV                   0x3E0
#define LAPIC_TIMER_INITCNT               0x380
#define LAPIC_TIMER_CURRCNT               0x390
#define LAPIC_TIMER_IVT_MASK              0x10000
#define LAPIC_LVT_TIMER_MODE_PERIODIC     (1 << 17)
#define LAPIC_LVT_TIMER_MODE_TSC_DEADLINE (1 << 18)
#define APIC_DEFAULT_SPURIOUS_IRQ         15
#define NUM_IOAPIC_PINS                   24

#define ICR_DELIVERY_NORMAL 0
#define ICR_DELIVERY_LOWEST 1
#define ICR_DELIVERY_SMI    2
#define ICR_DELIVERY_NMI    4
#define ICR_DELIVERY_INIT   5
#define ICR_DELIVERY_SIPI   6

#define LAPIC_ICR_ASSERT       (1 << 14)
#define LAPIC_ICR_SEND_PENDING (1 << 12)
#define LAPIC_ICR_ALL          (2 << 18)

#endif
