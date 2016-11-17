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
#include <acpi.h>

#include <kernel/apic.h>
#include <kernel/idt.h>
#include <kernel/panic.h>
#include <kernel/pit.h>
#include <kernel/irq.h>
#include <kernel/task_switching.h>
#include <kernel/acpi.h>

volatile uint32_t *lapic = NULL;
volatile uint64_t ap_done = 0;
volatile uint64_t core_stack = 0;
int cores_turned_on = 0;
void idle_smp()
{
	asm volatile("hlt");
	cores_turned_on++;
	while(1);
}
void lapic_write(uint32_t addr, uint32_t val)
{
	volatile uint32_t *laddr = (volatile uint32_t *)((volatile char*) lapic + addr);
	*laddr = val;
}
uint32_t lapic_read(uint32_t addr)
{
	volatile uint32_t *laddr = (volatile uint32_t *)((volatile char*) lapic + addr);
	return *laddr;
}
void lapic_send_eoi()
{
	lapic_write(LAPIC_EOI, 0);
}
void rdmsr(uint32_t msr, uint32_t *lo, uint32_t *hi)
{
   asm volatile("rdmsr" : "=a"(*lo), "=d"(*hi) : "c"(msr));
}

void lapic_init()
{
	/* Get the BSP's LAPIC base address from the msr's */
	uint32_t high, low;
	rdmsr(0x1b, &low, &high);
	uint64_t addr = low | ((uint64_t)high << 32);
	addr &= 0xFFFFF000;
	/* Map the BSP's LAPIC */
	lapic = vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, VMM_TYPE_HW);
	paging_map_phys_to_virt((uintptr_t)lapic, addr, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);

	/* Enable the LAPIC by setting LAPIC_SPUINT to 0x100 OR'd with the default spurious IRQ(15) */
	lapic_write(LAPIC_SPUINT, 0x100 | APIC_DEFAULT_SPURIOUS_IRQ);
	
	/* Send an EOI because some interrupts might've gotten stuck when the interrupts weren't enabled */
	lapic_write(LAPIC_EOI, 0);
}
void send_ipi(uint8_t id, uint32_t type, uint32_t page)
{
	lapic_write(LAPIC_IPIID, (uint32_t)id << 24);
	uint64_t icr = type << 8;
	icr |= (1 << 14);
	lapic_write(LAPIC_ICR, (uint32_t) icr);
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
	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *)(madt+1);
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
			ACPI_MADT_INTERRUPT_OVERRIDE *mio = (ACPI_MADT_INTERRUPT_OVERRIDE*) i;
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
	/* Map the I/O APIC base */
	ioapic_base = (volatile char*)vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, VMM_TYPE_HW);
	if(!ioapic_base)
		panic("Virtual memory allocation for the I/O APIC failed!");
	paging_map_phys_to_virt((uintptr_t)ioapic_base, IOAPIC_BASE_PHYS, VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC);
	/* Execute _PIC */
	acpi_execute_pic(ACPI_PIC_IOAPIC);
	if(acpi_get_irq_routing_tables())
		panic("Failed to get IRQ routing tables!");
	/* Set each APIC pin's polarity, flags, and vectors to their defaults */
	set_pin_handlers();
}
static volatile uint64_t ticks = 0;
static int sched_quantum = 10;
static uintptr_t apic_timer_irq(registers_t *regs)
{
	ticks++;
	sched_quantum--;
	if(sched_quantum == 0)
	{
		sched_quantum = 10;
		uintptr_t s = sched_switch_thread((uintptr_t)regs);
		return s;
	}
	return 0;
}
void apic_timer_init()
{
	/* Set the timer divisor to 16 */
	lapic_write(LAPIC_TIMER_DIV, 3);
	
	asm volatile("sti");
	/* Initialize the PIT to 100 hz */
	pit_init(100);

	/* Make sure we're measuring ~1s, so let 1 tick pass */
	uint64_t t = pit_get_tick_count();
	while(t == pit_get_tick_count());
	
	/* 0xFFFFFFFF shouldn't overflow in 10ms */
	lapic_write(LAPIC_TIMER_INITCNT, 0xFFFFFFFF);

	/* Wait for the 10 ms*/
	t = pit_get_tick_count();
	while(t == pit_get_tick_count());

	/* Get the ticks that passed in 10ms */
	uint32_t ticks_in_10ms = 0xFFFFFFFF - lapic_read(LAPIC_TIMER_CURRCNT); 
	
	lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_IVT_MASK);
	
	/* Initialize the APIC timer with IRQ2, periodic mode and an init count of ticks_in_10ms/10(so we get a rate of 1000hz)*/
	lapic_write(LAPIC_TIMER_DIV, 3);

	lapic_write(LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_PERIODIC);
	lapic_write(LAPIC_TIMER_INITCNT, ticks_in_10ms/10);

	/* De-initialize the PIT's used resources */	
	pit_deinit();
	/* Install an IRQ handler for IRQ2 */
	irq_install_handler(2, apic_timer_irq);
}
uint64_t get_tick_count()
{
	return (uint64_t) ticks;
}