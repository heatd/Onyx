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

#include <kernel/compiler.h>
USES_FANCY_START
#include <x86intrin.h>
#include <xmmintrin.h>
USES_FANCY_END
#include <kernel/log.h>
#include <kernel/cpu.h>
#include <kernel/gdt.h>
#include <kernel/panic.h>
#include <kernel/apic.h>
#include <kernel/pic.h>
#include <kernel/acpi.h>
#include <kernel/spinlock.h>
#include <kernel/registers.h>
#include <kernel/avx.h>
static cpu_t cpu;

static struct processor *cpus = NULL;
static int booted_cpus = 0;
extern ACPI_TABLE_MADT *madt;
int cpu_num = 0;
static spinlock_t ap_entry_spinlock;
extern volatile uint32_t *bsp_lapic;
volatile int initialized_cpus = 0;
extern volatile uint64_t boot_ticks;
static bool percpu_initialized = false;
extern tss_entry_t tss;
const int bits_per_long = sizeof(unsigned long) * 8;

__attribute__((hot))
bool x86_has_cap(int cap)
{
	/* Get the index in native word sizes(DWORDS in 32-bit systems and QWORDS in 64-bit ones) */
	int q_index = cap / bits_per_long;
	int bit_index = cap % bits_per_long;
	return cpu.caps[q_index] & (1UL << bit_index);
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
}

char *cpu_get_name()
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
	if( cpu.max_function >= 0x8000004 ) {
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
		__get_cpuid(CPUID_ASS, &eax, &ebx, &ecx, &edx);
		cpu.physicalAddressSpace = eax & 0xFF;
		cpu.virtualAddressSpace = (eax >> 8) & 0xFF;
	}
	return &cpu.manuid[0];
}

void cpu_get_sign()
{
	uint32_t eax = 0,ebx,edx,ecx = 0;
	__get_cpuid(CPUID_SIGN,&eax,&ebx,&ecx,&edx);
	cpu.stepping = eax & 0xF;
	cpu.model = (eax >> 4) & 0xF;
	cpu.family = (eax >> 8) & 0xF;
}

void cpu_identify()
{
	INFO("cpu", "Detected x86_64 CPU\n");
	INFO("cpu", "Manufacturer ID: %s\n", cpu_get_name());
	if(cpu.brandstr[0] != '\0')
		printf("Name: %s\n", cpu.brandstr);
	cpu_get_sign();
	INFO("cpu", "Stepping %i, Model %i, Family %i\n", cpu.stepping, cpu.model, cpu.family);
	__cpu_identify();
}

extern void syscall_ENTRY64();

void cpu_init_interrupts()
{
	avx_init();
	pic_remap();
	pic_disable();
	ioapic_init();
	lapic_init();
	apic_timer_init();

	wrmsr(IA32_MSR_STAR, 0, ((0x18 | 3) << 16) | 0x8);
	wrmsr(IA32_MSR_LSTAR, (unsigned long) syscall_ENTRY64 & 0xFFFFFFFF, (unsigned long) syscall_ENTRY64 >> 32);
	wrmsr(IA32_MSR_SFMASK, 0b11000000000, 0);
}

bool is_percpu_initialized(void)
{
	return percpu_initialized;
}

int cpu_init_mp()
{
	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *) (madt+1);
	/* Lets parse through the MADT to get the number of cores.
	 * Each LAPIC = 1 core */
	
	/* APs can't access ´cpus´ before we've finished, as it's subject to memory address changes */
	acquire_spinlock(&ap_entry_spinlock);
	
	for(ACPI_SUBTABLE_HEADER *i = first; i < (ACPI_SUBTABLE_HEADER*)((char*)madt + madt->Header.Length); i = 
	(ACPI_SUBTABLE_HEADER*)((uint64_t)i + (uint64_t)i->Length))
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
	cpus[0].lapic = (volatile char*) bsp_lapic;
	cpus[0].self = &cpus[0];
	cpus[0].apic_ticks = boot_ticks;
	cpus[0].sched_quantum = 10;
	cpus[0].current_thread = NULL;
	cpus[0].tss = &tss;
	wrmsr(GS_BASE_MSR, (uint64_t) &cpus[0] & 0xFFFFFFFF, (uint64_t) &cpus[0] >> 32);
	release_spinlock(&ap_entry_spinlock);
	
	while(initialized_cpus+1 != booted_cpus);
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

void cpu_ap_entry(int cpu_num)
{
	acquire_spinlock(&ap_entry_spinlock);

	uint32_t high, low;
	rdmsr(0x1b, &low, &high);
	uint64_t addr = low | ((uint64_t)high << 32);
	addr &= 0xFFFFF000;
	/* Map the BSP's LAPIC */
	uintptr_t _lapic = (uintptr_t) vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, VMM_TYPE_HW, 0);
	paging_map_phys_to_virt((uintptr_t)_lapic, addr, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	
	/* Fill the processor struct with the LAPIC data */
	cpus[cpu_num].lapic = (void *) _lapic;
	cpus[cpu_num].lapic_phys = (void*) addr;
	cpus[cpu_num].self = &cpus[cpu_num];

	/* Initialize AVX */
	avx_init();
	/* Initialize the local apic + apic timer */
	apic_timer_smp_init((volatile uint32_t *) cpus[cpu_num].lapic);

	/* Fill this core's gs with &cpus[cpu_num] */
	wrmsr(GS_BASE_MSR, (uint64_t) &cpus[cpu_num] & 0xFFFFFFFF, (uint64_t) &cpus[cpu_num] >> 32);
	/* Initialize syscall */
	wrmsr(IA32_MSR_STAR, 0, ((0x18 | 3) << 16) | 0x8);
	wrmsr(IA32_MSR_LSTAR, (unsigned long) syscall_ENTRY64 & 0xFFFFFFFF, (unsigned long) syscall_ENTRY64 >> 32);
	wrmsr(IA32_MSR_SFMASK, 0b11000000000, 0);

	gdt_init_percpu();
	initialized_cpus++;

	/* Enable interrupts */
	__asm__ __volatile__("sti");

	release_spinlock(&ap_entry_spinlock);
	/* cpu_ap_entry() can't return, as there's no valid return address on the stack, so just hlt until the scheduler
	   preempts the AP
	*/
	while(1);
}

int get_nr_cpus(void)
{
	return booted_cpus;
}

static void rep_movsb(void *dst, const void *src, size_t n)
{
    __asm__ __volatile__ ( "rep movsb\n\t"
                         : "+D" (dst), "+S" (src), "+c" (n)
                         :
                         : "memory" );
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
	send_ipi(p->lapic_id, 0, X86_MESSAGE_VECTOR);
}

void cpu_send_message(int cpu, unsigned long message, void *arg)
{
	struct processor 	*p;
	struct cpu_message	msg;
	assert(cpu <= booted_cpus);
	p = get_processor_data_for_cpu(cpu);
	assert(p != NULL);

	/* CPU_KILL messages don't respect locks */
	if(unlikely(message != CPU_KILL))
		acquire_spinlock(&p->message_queue_lock);
	if(unlikely(message == CPU_KILL))
	{
		if(!p->message_queue)
			p->message_queue = &msg;
		p->message_queue->message = CPU_KILL;
		p->message_queue->ptr = NULL;
		p->message_queue->next = NULL;
	}
	else
	{
		if(!p->message_queue)
			p->message_queue = &msg;
		else
		{
			struct cpu_message *m = p->message_queue;
			while(m->next) m = m->next;
			m->next = &msg;
		}
		msg.message = message;
		msg.ptr = arg;
		msg.next = NULL;
		release_spinlock(&p->message_queue_lock);
	}
	cpu_notify(p);
	//cpu_wait_for_msg_ack();
}

void cpu_kill(int cpu_num)
{
	printk("Killing cpu %u\n", cpu_num);
	cpu_send_message(cpu_num, CPU_KILL, NULL);
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
