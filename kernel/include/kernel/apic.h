/*
* Copyright (c) 2016 Pedro Falcato
* This file is part of Spartix, and is released under the terms of the MIT License
* - check LICENSE at the root directory for more information
*/
#ifndef _APIC_H
#define _APIC_H

#include <stdio.h>
#include <kernel/vmm.h>
#define IOAPIC_BASE_PHYS 0xFEC00000
#define IA32_APIC_BASE_MSR 0x1B
#define IA32_APIC_BASE_MSR_BSP 0x100 // Processor is a BSP
#define IA32_APIC_BASE_MSR_ENABLE 0x800

void ioapic_init();
void set_pin_handlers();
uint32_t read_io_apic(uint32_t reg);
void write_io_apic(uint32_t reg, uint32_t value);
void lapic_init();
void wake_up_processor(uint8_t);

#endif