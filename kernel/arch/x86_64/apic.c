/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <acpi.h>
#include <stdbool.h>
#include <assert.h>

#include <onyx/apic.h>
#include <onyx/idt.h>
#include <onyx/panic.h>
#include <onyx/pit.h>
#include <onyx/irq.h>
#include <onyx/task_switching.h>
#include <onyx/acpi.h>
#include <onyx/cpu.h>
#include <onyx/registers.h>
#include <onyx/log.h>
#include <onyx/idt.h>
#include <onyx/process.h>
#include <onyx/clock.h>
#include <onyx/vm.h>

volatile uint32_t *bsp_lapic = NULL;
volatile uint64_t ap_done = 0;
volatile uint64_t core_stack = 0;
bool is_smp_enabled = 0;

void lapic_write(volatile uint32_t *lapic, uint32_t addr, uint32_t val)
{
	volatile uint32_t *laddr = (volatile uint32_t *)((volatile char*) lapic + addr);
	*laddr = val;
}

uint32_t lapic_read(volatile uint32_t *lapic, uint32_t addr)
{
	volatile uint32_t *laddr = (volatile uint32_t *)((volatile char*) lapic + addr);
	return *laddr;
}

void lapic_send_eoi()
{
	if(is_percpu_initialized() == false)
		lapic_write(bsp_lapic, LAPIC_EOI, 0);
	else
	{
		struct processor *proc = get_processor_data();
		lapic_write((volatile uint32_t *) proc->lapic, LAPIC_EOI, 0);
	}
}

void lapic_init(void)
{
	/* Get the BSP's LAPIC base address from the msr's */
	uint32_t high, low;
	rdmsr(0x1b, &low, &high);
	uint64_t addr = low | ((uint64_t)high << 32);
	addr &= 0xFFFFF000;
	/* Map the BSP's LAPIC */
	bsp_lapic = mmiomap((void*) addr, PAGE_SIZE, VM_WRITE | VM_NOEXEC
		| VM_NOCACHE);
	
	assert(bsp_lapic != NULL);

	/* Enable the LAPIC by setting LAPIC_SPUINT to 0x100 OR'd with the default spurious IRQ(15) */
	lapic_write(bsp_lapic, LAPIC_SPUINT, 0x100 | APIC_DEFAULT_SPURIOUS_IRQ);
	
	/* Send an EOI because some interrupts might've gotten stuck when the interrupts weren't enabled */
	lapic_write(bsp_lapic, LAPIC_EOI, 0);

	/* Set the task pri to 0 */
	lapic_write(bsp_lapic, LAPIC_TSKPRI, 0);
}

volatile char *ioapic_base = NULL;
ACPI_TABLE_MADT *madt = NULL;

uint32_t read_io_apic(uint32_t reg)
{
	uint32_t volatile *ioapic = (uint32_t volatile*) ioapic_base;
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

static int irqs;

void ioapic_set_pin(bool active_high, bool level, uint32_t pin)
{
	uint64_t entry = 0;
	entry |= irqs + pin;

	if(!active_high)
	{
		/* Active low */
		entry |= IOAPIC_PIN_POLARITY_ACTIVE_LOW;
	}
	if(level)
	{
		entry |= IOAPIC_PIN_TRIGGER_LEVEL;
	}
	write_redirection_entry(pin, entry);
}

void ioapic_unmask_pin(uint32_t pin)
{
	/*printk("Unmasking pin %u\n", pin);*/
	uint64_t entry = read_redirection_entry(pin);
	entry &= ~IOAPIC_PIN_MASKED;
	write_redirection_entry(pin, entry);
}

void ioapic_mask_pin(uint32_t pin)
{
	/*printk("Masking pin %u\n", pin);*/
	uint64_t entry = read_redirection_entry(pin);
	entry |= IOAPIC_PIN_MASKED;
	write_redirection_entry(pin, entry);
}

void set_pin_handlers(void)
{
	/* Allocate a pool of vectors and reserve them */
	irqs = x86_allocate_vectors(24);
	x86_reserve_vector(irqs + 0, irq0);
	x86_reserve_vector(irqs + 1, irq1);
	x86_reserve_vector(irqs + 2, irq2);
	x86_reserve_vector(irqs + 3, irq3);
	x86_reserve_vector(irqs + 4, irq4);
	x86_reserve_vector(irqs + 5, irq5);
	x86_reserve_vector(irqs + 6, irq6);
	x86_reserve_vector(irqs + 7, irq7);
	x86_reserve_vector(irqs + 8, irq8);
	x86_reserve_vector(irqs + 9, irq9);
	x86_reserve_vector(irqs + 10, irq10);
	x86_reserve_vector(irqs + 11, irq11);
	x86_reserve_vector(irqs + 12, irq12);
	x86_reserve_vector(irqs + 13, irq13);
	x86_reserve_vector(irqs + 14, irq14);
	x86_reserve_vector(irqs + 15, irq15);
	x86_reserve_vector(irqs + 16, irq16);
	x86_reserve_vector(irqs + 17, irq17);
	x86_reserve_vector(irqs + 18, irq18);
	x86_reserve_vector(irqs + 19, irq19);
	x86_reserve_vector(irqs + 20, irq20);
	x86_reserve_vector(irqs + 21, irq21);
	x86_reserve_vector(irqs + 22, irq22);
	x86_reserve_vector(irqs + 23, irq23);
	// The MADT's signature is "APIC"
	ACPI_STATUS st = AcpiGetTable((ACPI_STRING) "APIC", 0, (ACPI_TABLE_HEADER**) &madt);
	if(ACPI_FAILURE(st))
		panic("Failed to get the MADT");

	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *)(madt+1);
	for(int i = 0; i < 24; i++)
	{
		if(i <= 19)
		{
			// ISA Interrupt, set it like a standard ISA interrupt
			/*
			* ISA Interrupts have the following attributes:
			* - Active High
			* - Edge triggered
			* - Fixed delivery mode
			* They might be overwriten by the ISO descriptors in the MADT
			*/
			uint64_t entry;
			entry = IOAPIC_PIN_MASKED | (irqs + i);
			write_redirection_entry(i, entry);
		}

		uint64_t entry = read_redirection_entry(i);
		write_redirection_entry(i, entry | (32 + i));
	}

	for(ACPI_SUBTABLE_HEADER *i = first; i < (ACPI_SUBTABLE_HEADER*)((char*)madt + madt->Header.Length); i = 
	(ACPI_SUBTABLE_HEADER*)((uint64_t)i + (uint64_t)i->Length))
	{
		if(i->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE)
		{
			ACPI_MADT_INTERRUPT_OVERRIDE *mio = (ACPI_MADT_INTERRUPT_OVERRIDE*) i;
			INFO("apic", "Interrupt override for GSI %d to %d\n", mio->SourceIrq,
									      mio->GlobalIrq);
			uint64_t red = read_redirection_entry(mio->GlobalIrq);
			red |= 32 + mio->GlobalIrq;
			if((mio->IntiFlags & ACPI_MADT_POLARITY_MASK)
				== ACPI_MADT_POLARITY_ACTIVE_LOW)
				red |= (1 << 13);
			else
				red &= ~(1 << 13);
		
			if((mio->IntiFlags & ACPI_MADT_TRIGGER_LEVEL)
				== ACPI_MADT_TRIGGER_LEVEL)
				red |= (1 << 15);
			else
				red &= ~(1 << 15);

			printf("GSI %d %s:%s\n", mio->GlobalIrq, 
				red & (1 << 13) ? "low" : "high",
				red & (1 << 15) ? "level" : "edge");
			write_redirection_entry(mio->GlobalIrq, red);
		}
	}
	
}

void ioapic_early_init(void)
{
	/* Map the I/O APIC base */
	ioapic_base = mmiomap((void*) IOAPIC_BASE_PHYS, PAGE_SIZE,
		VM_WRITE | VM_NOEXEC | VM_NOCACHE);
	assert(ioapic_base != NULL);
}

void ioapic_init()
{
	/* Execute _PIC */
	acpi_execute_pic(ACPI_PIC_IOAPIC);
	/* Set each APIC pin's polarity, flags, and vectors to their defaults */
	set_pin_handlers();
}

volatile uint64_t boot_ticks = 0;
static int boot_sched_quantum = 10;

void apic_update_clock_monotonic(void)
{
	struct clock_time time;
	time.epoch = boot_ticks / 1000;
		
	/* It's actually possible that no clocksource exists this early on */
	struct clocksource *source = get_main_clock();
	if(source)
	{
		time.source = source;
		time.tick = source->get_ticks();
	}

	time_set(CLOCK_MONOTONIC, &time);
}

irqstatus_t apic_timer_irq(struct irq_context *ctx, void *cookie)
{
	if(unlikely(!is_percpu_initialized()))
	{
		boot_ticks++;
		apic_update_clock_monotonic();
		boot_sched_quantum--;
		return IRQ_HANDLED;
	}

	struct processor *cpu = get_processor_data();
	cpu->apic_ticks++;
	cpu->sched_quantum--;

	/* Let cpu 0 update the boot ticks and the monotonic clock */
	if(get_cpu_num() == 0)
	{
		boot_ticks++;
		apic_update_clock_monotonic();
	}

	process_increment_stats(is_kernel_ip(ctx->registers->rip));

	if(cpu->sched_quantum == 0)
	{
		/* If we don't have a current thread, do it the old way */
		if(likely(cpu->current_thread))
			cpu->current_thread->flags |= THREAD_NEEDS_RESCHED;
		else
			ctx->registers = sched_switch_thread(ctx->registers);
	}

	return IRQ_HANDLED;
}

unsigned long apic_rate = 0;
unsigned long us_apic_rate = 0;

uint64_t get_microseconds(void)
{
	struct processor *cpu = get_processor_data();
	return (apic_rate - lapic_read((volatile uint32_t *) cpu->lapic, LAPIC_TIMER_CURRCNT)) / us_apic_rate;
}

struct driver apic_driver =
{
	.name = "apic-timer"
};

struct device apic_timer_dev = 
{
	.name = "apic-timer"
};

void apic_timer_init(void)
{
	driver_register_device(&apic_driver, &apic_timer_dev);

	/* Set the timer divisor to 16 */
	lapic_write(bsp_lapic, LAPIC_TIMER_DIV, 3);

	printf("apic: calculating APIC timer frequency\n");
	
	/* Initialize the PIT to 100 hz oneshot */
	pit_init_oneshot(100);

	/* 0xFFFFFFFF shouldn't overflow in 10ms */
	lapic_write(bsp_lapic, LAPIC_TIMER_INITCNT, 0xFFFFFFFF);

	/* Use this moment to calculate the approx. tsc frequency too */
	uint64_t tsc = rdtsc();

	/* Wait for the 10 ms */
	pit_wait_for_oneshot();

	uint64_t end = rdtsc();
	/* Get the ticks that passed in 10ms */
	uint32_t ticks_in_10ms = 0xFFFFFFFF - lapic_read(bsp_lapic, LAPIC_TIMER_CURRCNT); 
	
	lapic_write(bsp_lapic, LAPIC_LVT_TIMER, LAPIC_TIMER_IVT_MASK);
	
	/* Initialize the APIC timer with IRQ2, periodic mode and an init count of ticks_in_10ms/10(so we get a rate of 1000hz)*/
	lapic_write(bsp_lapic, LAPIC_TIMER_DIV, 3);

	apic_rate = ticks_in_10ms / 10;

	printf("apic: apic timer rate: %lu\n", apic_rate);
	us_apic_rate = apic_rate / 1000;

	DISABLE_INTERRUPTS();
	lapic_write(bsp_lapic, LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_PERIODIC);
	lapic_write(bsp_lapic, LAPIC_TIMER_INITCNT, ticks_in_10ms / 10);

	x86_set_tsc_rate(clock_delta_calc(tsc, end) * 100);

	/* Install an IRQ handler for IRQ2 */
	
	assert(install_irq(2, apic_timer_irq, &apic_timer_dev, IRQ_FLAG_REGULAR,
		NULL) == 0);
	
	ENABLE_INTERRUPTS();
}

void apic_timer_smp_init(volatile uint32_t *lapic)
{
	/* Enable the local apic */
	lapic_write(lapic, LAPIC_SPUINT, 0x100 | APIC_DEFAULT_SPURIOUS_IRQ);

	/* Flush pending interrupts */
	lapic_write(bsp_lapic, LAPIC_EOI, 0);

	/* Set the task pri to 0 */
	lapic_write(bsp_lapic, LAPIC_TSKPRI, 0);

	/* Initialize the APIC timer with IRQ2, periodic mode and an init count of ticks_in_10ms/10(so we get a rate of 1000hz)*/
	lapic_write(lapic, LAPIC_TIMER_DIV, 3);

	lapic_write(lapic, LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_PERIODIC);
	lapic_write(lapic, LAPIC_TIMER_INITCNT, apic_rate);

	/* If this is called, that means we've enabled SMP and can use struct processor/%%gs*/
	is_smp_enabled = 1;
}

uint64_t get_tick_count()
{
	return boot_ticks;
}

void send_ipi(uint8_t id, uint32_t type, uint32_t page)
{
	lapic_write(bsp_lapic, LAPIC_IPIID, (uint32_t)id << 24);
	uint64_t icr = type << 8 | (page & 0xff);
	icr |= (1 << 14);
	lapic_write(bsp_lapic, LAPIC_ICR, (uint32_t) icr);
}

void apic_wake_up_processor(uint8_t lapicid)
{
	ap_done = 0;
	send_ipi(lapicid, 5, 0);
	uint64_t tick = get_tick_count();
	while(get_tick_count() - tick < 200)
		__asm__ __volatile__("hlt");
	
	/* Allocate a stack for the core */
	core_stack = (volatile uint64_t) get_pages(VM_KERNEL, VM_TYPE_STACK, 2,
		VM_WRITE | VM_NOEXEC , 0) + 0x2000;
	assert(core_stack != 0x2000);

	send_ipi(lapicid, 6, 0);
	tick = get_tick_count();
	while(get_tick_count() - tick < 1000)
	{
		if(ap_done == 1)
		{
			printf("AP core woke up! LAPICID %u at tick %lu\n", lapicid, get_tick_count());
			break;
		}
	}
	if(ap_done == 0)
	{
		send_ipi(lapicid, 6, 0);
		tick = get_tick_count();
		while(get_tick_count() - tick < 1000)
		{
			if(ap_done == 1)
			{
				printf("AP core woke up! LAPICID %u at tick %lu\n", lapicid, get_tick_count());
				break;
			}
		}
	}
	if(ap_done == 0)
	{
		printf("Failed to start an AP with LAPICID %d\n", lapicid);
	}
	ap_done = 0;
}

void apic_set_irql(int irql)
{
	/* Get the current process and use its lapic pointer */
	struct processor *proc = get_processor_data();
	lapic_write((volatile uint32_t *) proc->lapic, LAPIC_TSKPRI, irql);
}

int apic_get_irql(void)
{
	/* Get the current process and use its lapic pointer */
	struct processor *proc = get_processor_data();
	return (int) lapic_read((volatile uint32_t *) proc->lapic, LAPIC_TSKPRI);
}
