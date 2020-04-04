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

#include <onyx/acpi.h>
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
#include <onyx/percpu.h>

#include <onyx/x86/msr.h>
#include <onyx/x86/platform_info.h>
#include <onyx/x86/tsc.h>
#include <onyx/x86/segments.h>
#include <onyx/x86/control_regs.h>

static cpu_t cpu;

static unsigned int booted_cpus = 1;
extern ACPI_TABLE_MADT *madt;
extern volatile uint32_t *bsp_lapic;
volatile unsigned int initialized_cpus = 0;
extern volatile uint64_t boot_ticks;
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

bool x86_has_usable_tsc(void)
{
	return cpu.invariant_tsc || cpu.constant_tsc;
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

	/* Intel manuals 17.17 Time-Stamp Counter describes this in detail.
	 * In short, Pentium M, Pentium 4, some Xeons and some P6's, the TSC increments with
	 * every internal processor cycle, so it's not constant because power management
	 * may throttle it back and forth. However, since family 0xf & model 0x2 and 
	 * family 0x6 & model 0xe, things have been defacto constant, even without the invariant_tsc
	 * flag.
	 */
	if((cpu.family == 0xf && cpu.model > 0x2) || (cpu.family == 0x6 && cpu.model >= 0xe))
		cpu.constant_tsc = true;

#if 0
	/* TODO: Add 15h support */
	if(__get_cpuid(0x15, &eax, &ebx, &ecx, &edx))
	{
		INFO("x86cpu", "0x15 supported!\n");
		halt();
	}
#endif

}

char *cpu_get_name(void)
{
	uint32_t eax, ebx, edx, ecx;
	__get_cpuid(0, &eax, &ebx, &ecx, &edx);
	
	uint32_t cpuid[4] = {0};
	cpuid[0] = ebx;
	cpuid[1] = edx;
	cpuid[2] = ecx;
	memcpy(&cpu.manuid, &cpuid, 12);

	/* Zero terminate the string */
	cpu.manuid[12] = '\0';

	if(!strcmp(cpu.manuid, "GenuineIntel"))
	{
		cpu.manufacturer = X86_CPU_MANUFACTURER_INTEL;
	}
	else if(!strcmp(cpu.manuid, "AuthenticAMD"))
	{
		cpu.manufacturer = X86_CPU_MANUFACTURER_AMD;
	}
	else
		cpu.manufacturer = X86_CPU_MANUFACTURER_UNKNOWN;

	__get_cpuid(CPUID_MAXFUNCTIONSUPPORTED, &eax, &ebx, &ecx, &edx);
	cpu.max_function = eax;
	if(cpu.max_function >= 0x8000004)
	{
		__get_cpuid(CPUID_BRAND0, &eax, &ebx, &ecx, &edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr, &cpuid, 16);
		__get_cpuid(CPUID_BRAND1, &eax, &ebx, &ecx, &edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr[16], &cpuid, 16);
		__get_cpuid(CPUID_BRAND2, &eax, &ebx, &ecx, &edx);
		cpuid[0] = eax;
		cpuid[1] = ebx;
		cpuid[2] = ecx;
		cpuid[3] = edx;
		memcpy(&cpu.brandstr[32], &cpuid, 16);
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
	uint32_t eax, ebx, edx, ecx;
	__get_cpuid(CPUID_SIGN, &eax, &ebx, &ecx, &edx);

	unsigned int stepping = eax & 0xf;
	unsigned int model = (eax >> 4) & 0xf;
	unsigned int family = (eax >> 8) & 0xf;
	unsigned int processor_type = (eax >> 12) & 0x3;
	unsigned int extended_model = (eax >> 16) & 0xf;
	unsigned int extended_family = (eax >> 20) & 0xff;

	unsigned int cpu_family = family;
	unsigned int cpu_model = model;
	if(family == 6 || family == 15)
		cpu_model = model + (extended_model << 4);
	if(family == 15)
		cpu_family = family + extended_family;
	
	printf("CPUID: %04x:%04x:%04x:%04x\n", cpu_family, cpu_model, stepping,
		processor_type);
	cpu.model = cpu_model;
	cpu.family = cpu_family;
	cpu.stepping = stepping;
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

void x86_init_percpu_intel(void)
{
	uint64_t misc_enable = rdmsr(IA32_MISC_ENABLE);
	misc_enable &= ~IA32_MISC_ENABLE_XD_BIT_DISABLE;

	if(x86_has_cap(X86_FEATURE_ERMS))
		misc_enable |= IA32_MISC_ENABLE_FAST_STRINGS_ENABLE;
	if(x86_has_cap(X86_FEATURE_EST))
		misc_enable |= IA32_MISC_ENABLE_ENHANCED_INTEL_SPEEDSTEP;
	if(x86_has_cap(X86_FEATURE_SSE3))
		misc_enable |= IA32_MISC_ENABLE_ENABLE_MONITOR_FSM;
	
	wrmsr(IA32_MISC_ENABLE, misc_enable);
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
	wrmsr(IA32_MSR_STAR, (((uint64_t)((USER32_CS) << 16) | KERNEL_CS) << 32));
	wrmsr(IA32_MSR_LSTAR, (uint64_t) syscall_ENTRY64);
	wrmsr(IA32_MSR_SFMASK, EFLAGS_INT_ENABLED | EFLAGS_DIRECTION |
		EFLAGS_TRAP | EFLAGS_ALIGNMENT_CHECK);
	

	if(cpu.manufacturer == X86_CPU_MANUFACTURER_INTEL)
	{
		x86_init_percpu_intel();
	}

	printf("cpu#%u tsc: %lu\n", get_cpu_nr(), rdtsc());
}

void cpu_init_late(void)
{
	/* Completely disable the PIC first */
	pic_remap();
	pic_disable();

	pat_init();

	/* Initialize the APIC and LAPIC */
	ioapic_init();
	lapic_init();

	/* Initialize timers and TSC timekeeping */
	apic_timer_init();

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

int cpu_init_mp(void)
{
	smp_parse_cpus(madt);

	smp_boot_cpus();

	ENABLE_INTERRUPTS();
	return booted_cpus;
}

extern PML *boot_pml4;

void smpboot_main(unsigned long gs_base)
{
	wrmsr(GS_BASE_MSR, gs_base);

	lapic_init_per_cpu();

	init_tss();

	x86_init_percpu();

	booted_cpus++;

	/* Enable interrupts */
	ENABLE_INTERRUPTS();

	/* smpboot_main() can't return, as there's no valid return address on the stack, so just hlt until the scheduler
	   preempts the AP
	*/
	while(1)
		__asm__ __volatile__("hlt");
}

unsigned int get_nr_cpus(void)
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

bool is_kernel_ip(uintptr_t ip)
{
	return ip >= VM_HIGHER_HALF;
}

void cpu_notify(unsigned int cpu_nr)
{
	apic_send_ipi(apic_get_lapic_id(cpu_nr), 0, X86_MESSAGE_VECTOR);
}

void cpu_wait_for_msg_ack(volatile struct cpu_message *msg)
{
	while(!msg->ack)
		cpu_relax();
	msg->ack = false;
}

PER_CPU_VAR(struct spinlock outgoing_msg_lock);
PER_CPU_VAR(struct cpu_message outgoing_msg[CPU_OUTGOING_MAX]);

struct cpu_message *cpu_alloc_msg_slot_irq(void)
{
	unsigned long spins = 5;
	/* Try spinning 5 times for a message slot */
	while(spins--)
	{
		struct spinlock *lock = get_per_cpu_ptr(outgoing_msg_lock);
		spin_lock_irqsave(lock);
		struct cpu_message *outgoing_msgs = (struct cpu_message *) get_per_cpu_ptr(outgoing_msg);
	
		for(int i = 0; i < CPU_OUTGOING_MAX; i++)
		{
			if(outgoing_msgs[i].sent == false)
			{
				outgoing_msgs[i].sent = true;
				spin_unlock_irqrestore(lock);
				return &outgoing_msgs[i];
			}
		}

		spin_unlock_irqrestore(lock);

		cpu_relax();
	}

	return NULL;
}

struct cpu_message *cpu_alloc_msg_slot(void)
{
	/* Try and alloc a message slot */

	if(is_in_interrupt())
		return cpu_alloc_msg_slot_irq();

	while(true)
	{
		struct spinlock *lock = get_per_cpu_ptr(outgoing_msg_lock);
		spin_lock_irqsave(lock);
		struct cpu_message *outgoing_msgs = (struct cpu_message *) get_per_cpu_ptr(outgoing_msg);


		for(int i = 0; i < CPU_OUTGOING_MAX; i++)
		{
			if(outgoing_msgs[i].sent == false)
			{
				outgoing_msgs[i].sent = true;
				spin_unlock_irqrestore(lock);
				return &outgoing_msgs[i];
			}
		}

		spin_unlock_irqrestore(lock);

		cpu_relax();
	}
	
}

extern struct serial_port com1;
void serial_write(const char *s, size_t size, struct serial_port *port);

PER_CPU_VAR(struct spinlock msg_queue_lock);
PER_CPU_VAR(struct cpu_message *msg_queue);

bool cpu_send_message(unsigned int cpu, unsigned long message, void *arg, bool should_wait)
{
	struct cpu_message *msg = cpu_alloc_msg_slot();
	if(!msg)
		return false;

	msg->ack = false;
	assert(cpu <= booted_cpus);
	struct spinlock *message_queue_lock = get_per_cpu_ptr_any(msg_queue_lock, cpu);
	struct cpu_message *message_queue = get_per_cpu_any(msg_queue, cpu);

	/* CPU_KILL messages don't respect locks */
	if(likely(message != CPU_KILL))
		spin_lock(message_queue_lock);

	if(unlikely(message == CPU_KILL))
	{
		if(!message_queue)
		{
			write_per_cpu_any(msg_queue, msg, cpu);
			message_queue = msg;
		}
	
		message_queue->message = CPU_KILL;
		message_queue->ptr = NULL;
		message_queue->next = NULL;
	}
	else
	{
		if(!message_queue)
		{
			write_per_cpu_any(msg_queue, msg, cpu);
			message_queue = msg;
		}
		else
		{
			struct cpu_message *m = message_queue;
			while(m->next) m = m->next;
			m->next = msg;
		}

		msg->message = message;
		msg->ptr = arg;
		msg->next = NULL;
		spin_unlock(message_queue_lock);
	}

	cpu_notify(cpu);

	if(message != CPU_KILL && should_wait)
		cpu_wait_for_msg_ack((volatile struct cpu_message *) msg);

	((volatile struct cpu_message *) msg)->sent = false;

	return true;
}

void cpu_kill(int cpu_num)
{
	printf("Killing cpu %u\n", cpu_num);
	cpu_send_message(cpu_num, CPU_KILL, NULL, false);
}

void cpu_kill_other_cpus(void)
{
	unsigned int curr_cpu = get_cpu_nr();
	for(unsigned int i = 0; i < booted_cpus; i++)
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
	unsigned int this_cpu = get_cpu_nr();
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

	struct spinlock *cpu_msg_lock = get_per_cpu_ptr(msg_queue_lock);

	spin_lock(cpu_msg_lock);

	struct cpu_message *m = get_per_cpu(msg_queue);

	for(struct cpu_message *msg = m; msg != NULL; msg = msg->next)
	{
		cpu_handle_message(msg);
	}

	write_per_cpu(msg_queue, NULL);

	spin_unlock(cpu_msg_lock);

	if(sched_needs_resched(get_current_thread()))
	{
		return sched_preempt_thread(stack);
	}

	return stack;
}
