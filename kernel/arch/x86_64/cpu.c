/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: cpu.c
 *
 * Description: Contains CPU identification routines on the x86 architecture
 *
 * Date: 6/4/2016
 *
 *
 **************************************************************************/
#include <stdlib.h>
#include <cpuid.h>
#include <stdbool.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <acpi.h>
#include <assert.h>

#include <onyx/x86/pat.h>
#include <onyx/compiler.h>
USES_FANCY_START
#include <x86intrin.h>
#include <xmmintrin.h>
USES_FANCY_END
#include <onyx/log.h>
#include <onyx/cpu.h>
#include <onyx/gdt.h>
#include <onyx/panic.h>
#include <onyx/apic.h>
#include <onyx/pic.h>
#include <onyx/acpi.h>
#include <onyx/spinlock.h>
#include <onyx/registers.h>
#include <onyx/avx.h>
#include <onyx/irq.h>
#include <onyx/fpu.h>

#include <onyx/x86/platform_info.h>
#include <onyx/x86/tsc.h>
#include <onyx/x86/segments.h>
#include <onyx/x86/control_regs.h>

static cpu_t cpu;

static struct processor *cpus = NULL;
static int booted_cpus = 0;
extern ACPI_TABLE_MADT *madt;
int cpu_num = 0;
static struct spinlock ap_entry_spinlock;
extern volatile uint32_t *bsp_lapic;
volatile int initialized_cpus = 0;
extern volatile uint64_t boot_ticks;
static bool percpu_initialized = false;
extern tss_entry_t tss;
const int bits_per_long = sizeof(unsigned long) * 8;

struct x86_platform_info x86_platform = {0};

__attribute__((hot))
bool x86_has_cap(int cap)
{
	/* Get the index in native word sizes(DWORDS in 32-bit systems and QWORDS in 64-bit ones) */
	int q_index = cap / bits_per_long;
	int bit_index = cap % bits_per_long;
	return cpu.caps[q_index] & (1UL << bit_index);
}

bool x86_check_invariant_tsc(void)
{
	return cpu.invariant_tsc;
}

void x86_set_tsc_rate(uint64_t rate)
{
	cpu.tsc_rate = rate;
}

uint64_t x86_get_tsc_rate(void)
{
	return cpu.tsc_rate;
}

void __cpu_identify(void)
{
	uint32_t eax = 0;
	uint32_t ebx = 0;
	uint32_t ecx = 0;
	uint32_t edx = 0;
	if(!__get_cpuid(CPUID_FEATURES, &eax, &ebx, &ecx, &edx))
	{
		INFO("x86cpu", "CPUID_FEATURES not supported!\n");
	}
	cpu.caps[0] = edx | ((uint64_t) ecx << 32);

	eax = CPUID_FEATURES_EXT;
	ecx = 0;
	if(!__get_cpuid(CPUID_FEATURES_EXT, &eax, &ebx, &ecx, &edx))
	{
		INFO("x86cpu", "CPUID_FEATURES_EXT not supported!\n");
	}
	cpu.caps[1] = ebx | ((uint64_t) ecx << 32);
	cpu.caps[2] = edx;
	eax = CPUID_EXTENDED_PROC_INFO;
	if(!__get_cpuid(CPUID_EXTENDED_PROC_INFO, &eax, &ebx, &ecx, &edx))
	{
		INFO("x86cpu", "CPUID_EXTENDED_PROC_INFO not supported!\n");
	}
	cpu.caps[2] |= ((uint64_t) edx) << 32;
	cpu.caps[3] = ecx;

	if(!__get_cpuid(CPUID_ADVANCED_PM, &eax, &ebx, &ecx, &edx))
	{
		INFO("x86cpu", "CPUID_ADVANCED_PM not supported!\n");
	}

	cpu.invariant_tsc = (bool) (edx & (1 << 8));

}

char *cpu_get_name(void)
{
	uint32_t eax,ebx,edx,ecx = 0;
	__get_cpuid(0,&eax,&ebx,&ecx,&edx);
	
	uint32_t cpuid[4] = {0};
	cpuid[0] = ebx;
	cpuid[1] = edx;
	cpuid[2] = ecx;
	memcpy(&cpu.manuid,&cpuid,12);
	/* Zero terminate the string */
	cpu.manuid[12] = '\0';
	__get_cpuid(CPUID_MAXFUNCTIONSUPPORTED,&eax,&ebx,&ecx,&edx);
	cpu.max_function = eax;
	if(cpu.max_function >= 0x8000004)
	{
		__get_cpuid(CPUID_BRAND0,&eax,&ebx,&ecx,&edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr,&cpuid,16);
		__get_cpuid(CPUID_BRAND1,&eax,&ebx,&ecx,&edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr[16],&cpuid,16);
		__get_cpuid(CPUID_BRAND2,&eax,&ebx,&ecx,&edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr[32],&cpuid,16);
		cpu.brandstr[47] = '\0';
		// Get the address space sizes
		__get_cpuid(CPUID_ADDR_SPACE_SIZE, &eax, &ebx, &ecx, &edx);
		cpu.physicalAddressSpace = eax & 0xFF;
		cpu.virtualAddressSpace = (eax >> 8) & 0xFF;
	}
	return &cpu.manuid[0];
}

void cpu_get_sign(void)
{
	uint32_t eax = 0,ebx,edx,ecx = 0;
	__get_cpuid(CPUID_SIGN,&eax,&ebx,&ecx,&edx);
	cpu.stepping = eax & 0xF;
	cpu.model = (eax >> 4) & 0xF;
	cpu.family = (eax >> 8) & 0xF;
}

void cpu_identify(void)
{
	INFO("cpu", "Detected x86_64 CPU\n");
	INFO("cpu", "Manufacturer ID: %s\n", cpu_get_name());
	if(cpu.brandstr[0] != '\0')
		printf("Name: %s\n", cpu.brandstr);
	cpu_get_sign();
	INFO("cpu", "Stepping %i, Model %i, Family %i\n", cpu.stepping, cpu.model, cpu.family);
	__cpu_identify();
}

extern void syscall_ENTRY64(void);

void x86_setup_standard_control_registers(void)
{
	/* Note that we do not set floating point bits here, only in fpu_init and avx_init */
	const unsigned long cr0 = CR0_PE | CR0_PG | CR0_ET | CR0_WP;
	x86_write_cr0(cr0);
	const unsigned long cr4 = CR4_DE | CR4_MCE | CR4_PAE | CR4_PGE | CR4_PSE;
	/* Note that CR4_PGE could only be set at this point in time since Intel
	 * strongly recommends for it to be set after enabling paging
	*/
	x86_write_cr4(cr4);
}

void x86_init_percpu(void)
{
	/* Set up the standard control registers to set an equal playing field for every CPU */
	x86_setup_standard_control_registers();
	
	/* Do floating point initialization now*/
	fpu_init();
	avx_init();
	
	/* Now initialize caching structures */
	pat_init();

	uint64_t efer = rdmsr(IA32_EFER);
	efer |= IA32_EFER_SCE;
	wrmsr(IA32_EFER, efer);
	/* and finally, syscall instruction MSRs */
	wrmsr(IA32_MSR_STAR, (((uint64_t)((USER32_CS | X86_USER_MODE_FLAG) << 16) | KERNEL_CS) << 32));
	wrmsr(IA32_MSR_LSTAR, (uint64_t) syscall_ENTRY64);
	wrmsr(IA32_MSR_SFMASK, EFLAGS_INT_ENABLED | EFLAGS_DIRECTION |
		EFLAGS_TRAP | EFLAGS_ALIGNMENT_CHECK);
}

void cpu_init_late(void)
{
	/* Completely disable the PIC first */
	pic_remap();
	pic_disable();

	/* Initialize the APIC and LAPIC */
	ioapic_init();
	lapic_init();

	/* Initialize timers and TSC timekeeping */
	apic_timer_init();
	tsc_init();

	/* Initialize the VDSO now */
	vdso_init();

	x86_init_percpu();

	/* Setup the x86 platform defaults */
	x86_platform.has_legacy_devices = true;
	x86_platform.i8042 = I8042_EXPECTED_PRESENT;
	x86_platform.has_msi = true;
	x86_platform.has_rtc = true;
	x86_platform.has_vga = true;
}

bool is_percpu_initialized(void)
{
	return percpu_initialized;
}

int cpu_init_mp(void)
{
	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *) (madt + 1);
	/* Lets parse through the MADT to get the number of cores.
	 * Each LAPIC = 1 core */
	
	/* APs can't access ´cpus´ before we've finished, as it's subject to memory address changes */
	spin_lock(&ap_entry_spinlock);
	
	for(ACPI_SUBTABLE_HEADER *i = first;
	i < (ACPI_SUBTABLE_HEADER*) ((char*) madt + madt->Header.Length);
	i = (ACPI_SUBTABLE_HEADER*)((uint64_t) i + (uint64_t) i->Length))
	{
		if(i->Type == ACPI_MADT_TYPE_LOCAL_APIC)
		{
			ACPI_MADT_LOCAL_APIC *apic = (ACPI_MADT_LOCAL_APIC *) i;
			cpus = realloc(cpus, booted_cpus * sizeof(struct processor) + sizeof(struct processor));
			if(!cpus)
			{
				panic("Out of memory while allocating the processor structures\n");
			}

			memset(&cpus[booted_cpus], 0, sizeof(struct processor));
			cpus[booted_cpus].lapic_id = apic->Id;
			cpus[booted_cpus].cpu_num = booted_cpus;
			cpus[booted_cpus].self = &cpus[booted_cpus];
			cpus[booted_cpus].sched_quantum = 10;
			cpus[booted_cpus].current_thread = NULL;
			booted_cpus++;
			if(booted_cpus != 1)
				apic_wake_up_processor(apic->Id);
			cpu_num = booted_cpus;
		}
	}

	DISABLE_INTERRUPTS();
	/* Fill CPU0's data */
	cpus[0].lapic = (volatile char *) bsp_lapic;
	cpus[0].self = &cpus[0];
	cpus[0].apic_ticks = boot_ticks;
	cpus[0].sched_quantum = 10;
	cpus[0].current_thread = NULL;
	cpus[0].tss = &tss;
	wrmsr(GS_BASE_MSR, (uint64_t) &cpus[0]);
	spin_unlock(&ap_entry_spinlock);
	
	while(initialized_cpus + 1 != booted_cpus);
	struct acpi_processor *processors = acpi_enumerate_cpus();
	/* I guess we don't get to have thermal management then... */
	if(!processors)
		return booted_cpus;
	
	/* Copy the acpi information to a new structure */
	for(int i = 0; i < booted_cpus; i++)
	{
		cpus[i].acpi_processor = malloc(sizeof(struct acpi_processor));
		if(!cpus[i].acpi_processor)
			return booted_cpus;
		memcpy(cpus[i].acpi_processor, &processors[i], sizeof(struct acpi_processor));
	}

	/* ... and free the old buffer */
	free(processors);
	percpu_initialized = true;
	ENABLE_INTERRUPTS();
	return booted_cpus;
}

extern PML *boot_pml4;

void cpu_ap_entry(int cpu_num)
{
	spin_lock(&ap_entry_spinlock);

	uint64_t addr = rdmsr(IA32_APIC_BASE);
	addr &= 0xFFFFF000;
	/* Map the BSP's LAPIC */
	uintptr_t _lapic = (uintptr_t) mmiomap((void*) addr, PAGE_SIZE,
		VM_WRITE | VM_NOEXEC | VM_NOCACHE);
	assert(_lapic != 0);
	
	/* Fill the processor struct with the LAPIC data */
	cpus[cpu_num].lapic = (void *) _lapic;
	cpus[cpu_num].lapic_phys = (void*) addr;
	cpus[cpu_num].self = &cpus[cpu_num];

	/* Initialize the local apic + apic timer */
	apic_timer_smp_init((volatile uint32_t *) cpus[cpu_num].lapic);

	/* Fill this core's gs with &cpus[cpu_num] */
	wrmsr(GS_BASE_MSR, (uint64_t) &cpus[cpu_num]);

	init_tss();

	x86_init_percpu();

	initialized_cpus++;

	/* Enable interrupts */
	ENABLE_INTERRUPTS();

	spin_unlock(&ap_entry_spinlock);
	/* cpu_ap_entry() can't return, as there's no valid return address on the stack, so just hlt until the scheduler
	   preempts the AP
	*/
	/* TODO: Free the AP stacks */
	while(1);
}

int get_nr_cpus(void)
{
	return booted_cpus;
}

static void rep_movsb(void *dst, const void *src, size_t n)
{
    __asm__ __volatile__ ("rep movsb\n\t"
                         : "+D" (dst), "+S" (src), "+c" (n)
                         :
                         : "memory");
}

void *memcpy_fast(void *dst, void *src, size_t n)
{
	rep_movsb(dst, src, n);
	return dst;
}

struct processor *get_processor_data(void)
{
	if(unlikely(!percpu_initialized))
		return NULL;
	struct processor *proc;
	__asm__ __volatile__("movq %%gs:0x8, %0":"=r"(proc));
	return proc;
}

bool is_kernel_ip(uintptr_t ip)
{
	return ip >= VM_HIGHER_HALF;
}

int get_cpu_num(void)
{
	struct processor *p = get_processor_data();
	if(!p)
		return 0;
	return p->cpu_num;
}

struct processor *get_processor_data_for_cpu(int cpu)
{
	assert(cpu <= booted_cpus);
	return &cpus[cpu];
}

void cpu_notify(struct processor *p)
{
	apic_send_ipi(p->lapic_id, 0, X86_MESSAGE_VECTOR);
}

void cpu_wait_for_msg_ack(volatile struct cpu_message *msg)
{
	while(!msg->ack)
		cpu_relax();
	msg->ack = false;
}

struct cpu_message *cpu_alloc_msg_slot_irq(void)
{
	/* Like the next function, but for irqs */
	struct processor *p = get_processor_data();

	unsigned long spins = 5;
	/* Try spinning 5 times for a message slot */
	while(spins--)
	{
		spin_lock_irqsave(&p->outgoing_msg_lock);
		for(int i = 0; i < CPU_OUTGOING_MAX; i++)
		{
			if(p->outgoing_msg[i].sent == false)
			{
				p->outgoing_msg[i].sent = true;
				spin_unlock_irqrestore(&p->outgoing_msg_lock);
				return &p->outgoing_msg[i];
			}
		}

		spin_unlock_irqrestore(&p->outgoing_msg_lock);

		cpu_relax();
	}

	return NULL;
}

struct cpu_message *cpu_alloc_msg_slot(void)
{
	/* Try and alloc a message slot */

	if(is_in_interrupt())
		return cpu_alloc_msg_slot_irq();

	struct processor *p = get_processor_data();

	while(true)
	{
		spin_lock_irqsave(&p->outgoing_msg_lock);
		for(int i = 0; i < CPU_OUTGOING_MAX; i++)
		{
			if(p->outgoing_msg[i].sent == false)
			{
				p->outgoing_msg[i].sent = true;
				spin_unlock_irqrestore(&p->outgoing_msg_lock);
				return &p->outgoing_msg[i];
			}
		}

		spin_unlock_irqrestore(&p->outgoing_msg_lock);

		cpu_relax();
	}
	
}

extern struct serial_port com1;
void serial_write(const char *s, size_t size, struct serial_port *port);

void cpu_send_message(int cpu, unsigned long message, void *arg, bool should_wait)
{
	struct processor *p;
	struct cpu_message *msg = cpu_alloc_msg_slot();
	if(!msg)
		return;

	msg->ack = false;
	assert(cpu <= booted_cpus);
	p = get_processor_data_for_cpu(cpu);
	assert(p != NULL);

	/* CPU_KILL messages don't respect locks */
	if(likely(message != CPU_KILL))
		spin_lock(&p->message_queue_lock);
	if(unlikely(message == CPU_KILL))
	{
		if(!p->message_queue)
			p->message_queue = msg;
		p->message_queue->message = CPU_KILL;
		p->message_queue->ptr = NULL;
		p->message_queue->next = NULL;
	}
	else
	{
		if(!p->message_queue)
			p->message_queue = msg;
		else
		{
			struct cpu_message *m = p->message_queue;
			while(m->next) m = m->next;
			m->next = msg;
		}

		msg->message = message;
		msg->ptr = arg;
		msg->next = NULL;
		spin_unlock(&p->message_queue_lock);
	}

	cpu_notify(p);

	if(message != CPU_KILL && should_wait)
		cpu_wait_for_msg_ack((volatile struct cpu_message *) msg);

	((volatile struct cpu_message *) msg)->sent = false;
}

void cpu_kill(int cpu_num)
{
	printk("Killing cpu %u\n", cpu_num);
	cpu_send_message(cpu_num, CPU_KILL, NULL, false);
}

void cpu_kill_other_cpus(void)
{
	int curr_cpu = get_cpu_num();
	for(int i = 0; i < booted_cpus; i++)
	{
		if(i != curr_cpu)
			cpu_kill(i);
	}
}

void cpu_handle_kill(void)
{
	halt();
}

void cpu_try_resched(void *ptr)
{
	struct thread *thread = ptr;

	struct thread *current = get_current_thread();

	/* If the scheduled thread's prio is > than ours, resched! */
	if(thread->priority > current->priority)
	{
		sched_should_resched();
		return;
	}
}

void cpu_handle_message(struct cpu_message *msg)
{
	unsigned int this_cpu = get_cpu_num();
	const char *str = "";
	switch(msg->message)
	{
		case CPU_KILL:
			str = "CPU_KILL";
			msg->ack = true;
			cpu_handle_kill();
			break;
		case CPU_TRY_RESCHED:
			str = "CPU_TRY_RESCHED";
			cpu_try_resched(msg->ptr);
			msg->ack = true;
			break;
		case CPU_FLUSH_TLB:
			str = "CPU_FLUSH_TLB";
			/* The order of the ack is important here! */
			vm_do_shootdown(msg->ptr);
			msg->ack = true;
			break;
	}

	(void) this_cpu;
	(void) str;
	//printf("cpu#%u handling %p, message type %s\n", this_cpu, msg, str);

}

void *cpu_handle_messages(void *stack)
{
	struct processor *cpu = get_processor_data();

	spin_lock(&cpu->message_queue_lock);

	for(struct cpu_message *msg = cpu->message_queue; msg; msg = msg->next)
	{
		cpu_handle_message(msg);
	}

	cpu->message_queue = NULL;

	spin_unlock(&cpu->message_queue_lock);

	if(sched_needs_resched(get_current_thread()))
	{
		return sched_switch_thread(stack);
	}

	return stack;
}