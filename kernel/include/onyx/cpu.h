/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_CPU_H
#define _KERNEL_CPU_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#include <onyx/acpi.h>
#include <onyx/scheduler.h>
#ifdef __x86_64__
#include <onyx/tss.h>
#endif

#ifdef __x86_64__

#define CPUID_MANUFACTURERID 		0x00000000
#define CPUID_MAXFUNCTIONSUPPORTED 	0x80000000
#define CPUID_BRAND0			0x80000002
#define CPUID_BRAND1 			0x80000003
#define CPUID_BRAND2 			0x80000004
#define CPUID_ADVANCED_PM		0x80000007
#define CPUID_ADDR_SPACE_SIZE		0x80000008
#define CPUID_SIGN   			0x00000001
#define CPUID_FEATURES			0x00000001
#define CPUID_FEATURES_EXT		0x00000007
#define CPUID_EXTENDED_PROC_INFO	0x80000001

#define X86_FEATURE_FPU			(0)
#define X86_FEATURE_VME			(1)
#define X86_FEATURE_DE			(2)
#define X86_FEATURE_PSE			(3)
#define X86_FEATURE_TSC			(4)
#define X86_FEATURE_MSR			(5)
#define X86_FEATURE_PAE			(6)
#define X86_FEATURE_MCE			(7)
#define X86_FEATURE_CMPXCHG8B		(8)
#define X86_FEATURE_APIC		(9)
#define X86_FEATURE_SEP			(11)
#define X86_FEATURE_MTRR		(12)
#define X86_FEATURE_PGE			(13)
#define X86_FEATURE_MCA			(14)
#define X86_FEATURE_CMOV		(15)
#define X86_FEATURE_PAT			(16)
#define X86_FEATURE_PSE36		(17)
#define X86_FEATURE_PSN			(18)
#define X86_FEATURE_CLFLSH		(19)
#define X86_FEATURE_DS			(21)
#define X86_FEATURE_ACPI		(22)
#define X86_FEATURE_MMX			(23)
#define X86_FEATURE_FXSR		(24)
#define X86_FEATURE_SSE			(25)
#define X86_FEATURE_SSE2		(26)
#define X86_FEATURE_SS			(27)
#define X86_FEATURE_HTT			(28)
#define X86_FEATURE_TM			(29)
#define X86_FEATURE_IA64		(30)
#define X86_FEATURE_PBE			(31)
#define X86_FEATURE_SSE3		(32)
#define X86_FEATURE_PCLMULQDQ		(33)
#define X86_FEATURE_DTES64		(34)
#define X86_FEATURE_MONITOR		(35)
#define X86_FEATURE_DSCPL		(36)
#define X86_FEATURE_VMX			(37)
#define X86_FEATURE_SMX			(38)
#define X86_FEATURE_EST			(39)
#define X86_FEATURE_TM2			(40)
#define X86_FEATURE_SSSE3		(41)
#define X86_FEATURE_CNXTID		(42)
#define X86_FEATURE_SDBG		(43)
#define X86_FEATURE_FMA			(44)
#define X86_FEATURE_CX16		(45)
#define X86_FEATURE_XPTR		(46)
#define X86_FEATURE_PDCM		(47)
#define X86_FEATURE_PCID		(49)
#define X86_FEATURE_DCA			(50)
#define X86_FEATURE_SSE41		(51)
#define X86_FEATURE_SSE42		(52)
#define X86_FEATURE_X2APIC		(53)
#define X86_FEATURE_MOVBE		(54)
#define X86_FEATURE_POPCNT		(55)
#define X86_FEATURE_TSC_DEADLINE	(56)
#define X86_FEATURE_AES			(57)
#define X86_FEATURE_XSAVE		(58)
#define X86_FEATURE_OSXSAVE		(59)
#define X86_FEATURE_AVX			(60)
#define X86_FEATURE_F16C		(61)
#define X86_FEATURE_RDRND		(62)
#define X86_FEATURE_HYPERVISOR		(63)
#define X86_FEATURE_FSGSBASE		(64)
#define X86_FEATURE_TSC_ADJUST		(65)
#define X86_FEATURE_SGX			(66)
#define X86_FEATURE_BMI1		(67)
#define X86_FEATURE_HLE			(68)
#define X86_FEATURE_AVX2		(69)
#define X86_FEATURE_SMEP		(71)
#define X86_FEATURE_BMI2		(72)
#define X86_FEATURE_ERMS		(73)
#define X86_FEATURE_INVPCID		(74)
#define X86_FEATURE_RTM			(75)
#define X86_FEATURE_PQM			(76)
#define X86_FEATURE_FPUCSDS_DEPREC	(77)
#define X86_FEATURE_MPX			(78)
#define X86_FEATURE_PQE			(79)
#define X86_FEATURE_AVX512f		(80)
#define X86_FEATURE_AVX512dq		(81)
#define X86_FEATURE_RDSEED		(82)
#define X86_FEATURE_ADX			(83)
#define X86_FEATURE_SMAP		(84)
#define X86_FEATURE_AVX512ifma		(85)
#define X86_FEATURE_PCOMMIT		(86)
#define X86_FEATURE_CLFLUSHOPT		(87)
#define X86_FEATURE_CLWB		(88)
#define X86_FEATURE_INTEL_PT		(89)
#define X86_FEATURE_AVX512pf		(90)
#define X86_FEATURE_AVX512er		(91)
#define X86_FEATURE_AVX512cd		(92)
#define X86_FEATURE_SHA			(93)
#define X86_FEATURE_AVX512bw		(94)
#define X86_FEATURE_AVX512vl		(95)
#define X86_FEATURE_prefetchwt1		(96)
#define X86_FEATURE_AVX512vbmi		(97)
#define X86_FEATURE_UMIP		(98)
#define X86_FEATURE_PKU			(99)
#define X86_FEATURE_OSPKE		(100)
#define X86_FEATURE_AVX512vpopcntdq	(110)
#define X86_FEATURE_RDPID		(118)
#define X86_FEATURE_SGXLC		(126)
#define X86_FEATURE_AVX5124vnniw	(130)
#define X86_FEATURE_AVX5124fmaps	(131)
#define X86_FEATURE_PCONFIG		(146)
#define x86_FEATURE_SPEC_CTRL		(154)
#define X86_FEATURE_STIBP		(155)
#define X86_FEATURE_SSBD		(159)
#define X86_FEATURE_AMD_FPU		(160)
#define X86_FEATURE_AMD_VME		(161)
#define X86_FEATURE_AMD_DE		(162)
#define X86_FEATURE_AMD_PSE		(163)
#define X86_FEATURE_AMD_TSC		(164)
#define X86_FEATURE_AMD_MSR		(165)
#define X86_FEATURE_AMD_PAE		(166)
#define X86_FEATURE_AMD_MCE		(167)
#define X86_FEATURE_AMD_CMPXCHG8B	(168)
#define X86_FEATURE_AMD_APIC		(169)
#define X86_FEATURE_SYSCALL		(171)
#define X86_FEATURE_AMD_MTRR		(172)
#define X86_FEATURE_AMD_PGE		(173)
#define X86_FEATURE_AMD_MCA		(174)
#define X86_FEATURE_AMD_CMOV		(175)
#define X86_FEATURE_AMD_PAT		(176)
#define X86_FEATURE_AMD_PSE36		(177)
#define X86_FEATURE_MP			(179)
#define X86_FEATURE_NX			(180)
#define X86_FEATURE_MMXEXT		(182)
#define X86_FEATURE_AMD_MMX		(183)
#define X86_FEATURE_AMD_FXSR		(184)
#define X86_FEATURE_FXSR_OPT		(185)
#define X86_FEATURE_PDPE1GB		(186)
#define X86_FEATURE_RDTSCP		(187)
#define X86_FEATURE_LONG_MODE		(189)
#define X86_FEATURE_3DNOW_EXT		(190)
#define X86_FEATURE_3DNOW		(191)
#define X86_FEATURE_LAHF_LM		(192)
#define X86_FEATURE_CMP_LEGACY		(193)
#define X86_FEATURE_SVM			(194)
#define X86_FEATURE_EXTAPIC		(195)
#define X86_FEATURE_CR8_LEGACY		(196)
#define X86_FEATURE_ABM			(197)
#define X86_FEATURE_SSE4a		(198)
#define X86_FEATURE_MISALIGN_SSE	(199)
#define X86_FEATURE_3DNOW_PREFETCH	(200)
#define X86_FEATURE_OSVW		(201)
#define X86_FEATURE_IBS			(202)
#define X86_FEATURE_XOP			(203)
#define X86_FEATURE_SKINIT		(204)
#define X86_FEATURE_WDT			(205)
#define X86_FEATURE_LWP			(207)
#define X86_FEATURE_FMA4		(208)
#define X86_FEATURE_TCE			(209)
#define X86_FEATURE_NODEID_MSR		(211)
#define X86_FEATURE_TBM			(213)
#define X86_FEATURE_TOPOEXT		(214)
#define X86_FEATURE_PERFCTR_CORE	(215)
#define X86_FEATURE_PERFCTR_NB		(216)
#define X86_FEATURE_DBX			(218)
#define X86_FEATURE_PERFTSC		(219)
#define X86_FEATURE_PCX_L2I		(220)

#define X86_MESSAGE_VECTOR		(130)
typedef struct cpu
{
	char manuid[13];
	char brandstr[48];
	uint32_t max_function;
	uint32_t stepping, family, model, extended_model, extended_family;
	bool invariant_tsc;
	uint64_t tsc_rate;
	int virtualAddressSpace, physicalAddressSpace;
	/* Add more as needed */
	uint64_t caps[8];
} cpu_t;
__attribute__((hot))
bool x86_has_cap(int cap);
bool x86_check_invariant_tsc(void);
void x86_set_tsc_rate(uint64_t rate);
uint64_t x86_get_tsc_rate(void);

/* Linux kernel-like cpu_relax, does a pause instruction */
static inline void cpu_relax(void)
{
	__asm__ __volatile__("pause" ::: "memory");
}

#include <onyx/x86/irq.h>

#endif

struct processor
{
#if defined (__x86_64__)
	volatile char *lapic;
	struct processor *self;
	void *kernel_stack;
	void *scratch_rsp_stack;
	volatile char *lapic_phys;
	int cpu_num;
	int lapic_id;
	size_t apic_ticks;
	struct acpi_processor *acpi_processor;
	tss_entry_t *tss;
#else
#error "Implement this structure for your architecture"
#endif
	atomic_size_t active_threads;
	thread_t *thread_queues[NUM_PRIO];
	struct spinlock queue_locks[NUM_PRIO];
	size_t sched_quantum;
	thread_t *current_thread;
#ifdef __cplusplus
	unsigned long preemption_counter;
#else
	atomic_ulong preemption_counter;
#endif

	struct cpu_message *message_queue;
	struct spinlock message_queue_lock;
	unsigned char *percpu_copy;
};

#ifdef __cplusplus
extern "C"{
#endif

void cpu_identify(void);
void cpu_init_interrupts(void);
int cpu_init_mp(void);
int get_nr_cpus(void);
int get_cpu_num(void);
struct processor *get_processor_data(void);
struct processor *get_processor_data_for_cpu(int cpu);
bool is_percpu_initialized(void);
bool is_kernel_ip(uintptr_t ip);
void cpu_kill_other_cpus(void);
void cpu_kill(int cpu_num);
void cpu_send_message(int cpu, unsigned long message, void *arg);
void __cpu_handle_message(void);

struct cpu_message
{
	unsigned long message;
	void *ptr;
	volatile bool ack;
	struct cpu_message *next;
};
/* CPU messages */
#define CPU_KILL	(unsigned long) -1
#define CPU_TRY_RESCHED	(unsigned long)  0
#define CPU_FLUSH_TLB	(unsigned long)  1

#ifdef __cplusplus
}
#endif
#ifdef __x86_64__

static inline struct processor *get_processor_data_inl(void)
{
	struct processor *proc;
	__asm__ __volatile__("movq %%gs:0x8, %0":"=r"(proc));
	return proc;
}

#define DISABLE_INTERRUPTS() __asm__ __volatile__("cli")
#define ENABLE_INTERRUPTS() __asm__ __volatile__("sti")
#endif

static inline uintptr_t cpu_get_cr0(void)
{
	uintptr_t cr0;
	__asm__ __volatile__("mov %%cr0, %0":"=r"(cr0));
	return cr0;
}

static inline uintptr_t cpu_get_cr2(void)
{
	uintptr_t cr2;
	__asm__ __volatile__("mov %%cr2, %0":"=r"(cr2));
	return cr2;
}

static inline uintptr_t cpu_get_cr3(void)
{
	uintptr_t cr3;
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(cr3));
	return cr3;
}

static inline uintptr_t cpu_get_cr4(void)
{
	uintptr_t cr4;
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4));
	return cr4;
}

#endif
