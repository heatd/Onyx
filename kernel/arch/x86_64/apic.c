/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/apic.h>
#include <kernel/idt.h>
#include <acpi.h>
#include <kernel/panic.h>

volatile uint32_t *lapic = NULL;
uint32_t volatile *lapic_eoi = NULL;
volatile uint64_t ap_done = 0;
volatile uint64_t core_stack = 0;
int cores_turned_on = 0;
void idle_smp()
{
	asm volatile("hlt");
	cores_turned_on++;
	while(1);
}
void lapic_send_eoi()
{
	*lapic_eoi = 0;
}
void rdmsr(uint32_t msr, uint32_t *lo, uint32_t *hi)
{
   asm volatile("rdmsr" : "=a"(*lo), "=d"(*hi) : "c"(msr));
}
 
void wrmsr(uint32_t msr, uint32_t lo, uint32_t hi)
{
   asm volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(msr));
}

uint32_t volatile *lapic_ipiid = NULL;
uint32_t volatile *lapic_icr = NULL;
void lapic_init()
{
	uint32_t high, low;
	rdmsr(0x1b, &low, &high);
	uint64_t addr = low | ((uint64_t)high << 32);
	addr &= 0xFFFFF000;
	lapic = vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, VMM_TYPE_HW);
	paging_map_phys_to_virt((uintptr_t)lapic, addr, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	uint32_t volatile *lapic_enable = (uint32_t volatile*)((char *)lapic + 0xF0);
	printf("Mapped Lapic: %p\n", lapic);
	*lapic_enable |= 0x100;
	lapic_eoi = (uint32_t volatile*)((char *)lapic + 0xB0);
	lapic_ipiid = (uint32_t volatile*)((char *)lapic + 0x310);
	lapic_icr = (uint32_t volatile*)((char *)lapic + 0x300);
}
void send_ipi(uint8_t id, uint32_t type, uint32_t page)
{
	*lapic_ipiid |= (uint32_t)id << 24;
	uint64_t icr = type << 8;
	icr |= (1 << 14);
	*lapic_icr = icr;
}
void wake_up_processor(uint8_t lapicid)
{
	send_ipi(lapicid, 5, 0);
	core_stack = (volatile uint64_t)vmm_allocate_virt_address(VM_KERNEL, 2, VMM_TYPE_SHARED, VMM_WRITE) + 0x2000;
	vmm_map_range((void*)(core_stack - 0x2000), 2, VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC);
	send_ipi(lapicid, 6, 0);
	while(ap_done != 1);
	
	ap_done = 0;
}

volatile char *ioapic_base = NULL;
ACPI_TABLE_MADT *madt = NULL;
uint32_t read_io_apic(uint32_t reg)
{
	uint32_t volatile *ioapic = (uint32_t volatile*)ioapic_base;
	ioapic[0] = (reg & 0xFF);
	return ioapic[4];
}
void write_io_apic(uint32_t reg, uint32_t value)
{
	uint32_t volatile *ioapic = (uint32_t volatile*)ioapic_base;
	ioapic[0] = (reg & 0xFF);
	ioapic[4] = value;
}
uint64_t read_redirection_entry(uint32_t pin)
{
	uint64_t ret;
	ret = (uint64_t) read_io_apic(0x10 + pin * 2);
	ret |= (uint64_t) read_io_apic(0x10 + pin * 2 + 1) << 32;
	return ret;
}
void write_redirection_entry(uint32_t pin, uint64_t value)
{
	write_io_apic(0x10 + pin * 2, value & 0x00000000FFFFFFFF);
	write_io_apic(0x10 + pin * 2 + 1, value >> 32);
}
void set_pin_handlers()
{
	// The MADT's signature is "APIC"
	ACPI_STATUS st = AcpiGetTable((ACPI_STRING)"APIC", 0, (ACPI_TABLE_HEADER**)&madt);
	if(ACPI_FAILURE(st))
		panic("Failed to get the MADT");
	printf("MADT: %p\n", madt);
	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *)madt+1;
	for(int i = 0; i < 24; i++)
	{
		if(i <= 15)
		{
			// ISA Interrupt, set it like a standard ISA interrupt
			/*
			* ISA Interrupts have the following attributes:
			* - Active High
			* - Edge triggered
			* - Fixed delivery mode
			* They might be overwriten by the ISO descriptors in the MADT
			*/
			uint64_t entry = 0;
			entry |= 32 + i;
			write_redirection_entry(i, entry);
		}
		if(i > 15 && i <= 19)
		{
			// Maybe add a different behavior when we can? (After porting the PCI drivers)
			uint64_t entry = read_redirection_entry(i);
			write_redirection_entry(i, entry | (32 + i));
		}
		uint64_t entry = read_redirection_entry(i);
		write_redirection_entry(i, entry | (32 + i));
	}
	for(ACPI_SUBTABLE_HEADER *i = first; i < (ACPI_SUBTABLE_HEADER*)((char*)madt + madt->Header.Length); i = 
	(ACPI_SUBTABLE_HEADER*)((uint64_t)i + (uint64_t)i->Length))
	{
		if(i->Type == 2)
		{
			ACPI_MADT_INTERRUPT_OVERRIDE *mio = (ACPI_MADT_INTERRUPT_OVERRIDE*)i;
			printf("Interrupt override for GSI %d\n", mio->SourceIrq);
			uint64_t red = read_redirection_entry(mio->GlobalIrq);
			red |= 32 + mio->GlobalIrq;
			if(mio->IntiFlags & 0x3)
				red |= (1 << 13);
			if(mio->IntiFlags & 0b1100)
				red |= (1 << 15);
			write_redirection_entry(mio->GlobalIrq, red);
		}
	}
	
}
void ioapic_init()
{
	ioapic_base = (volatile char*)vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, VMM_TYPE_HW);
	if(!ioapic_base)
		panic("Virtual memory allocation for the I/O APIC failed!");
	paging_map_phys_to_virt((uintptr_t)ioapic_base, IOAPIC_BASE_PHYS, VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC);
	set_pin_handlers();
}
