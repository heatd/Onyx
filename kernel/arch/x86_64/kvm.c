/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <cpuid.h>
#include <onyx/cpu.h>

#include <onyx/x86/kvm.h>
#include <onyx/x86/msr.h>
#include <onyx/panic.h>

static bool clocksource2_supported = false;
static bool clocksource_supported = false;
static unsigned long wall_clock_msr;
static unsigned long system_time_msr;

void pvclock_init(void);
void kvm_init(void)
{
	uint32_t eax, ebx, ecx, edx;
	
	__cpuid(KVM_CPUID_SIGNATURE, eax, ebx, ecx, edx);

	if(!x86_has_cap(X86_FEATURE_HYPERVISOR))
	{
		/* Means we're definitely not running on kvm */
		return;
	}

	/* Check if we're running on kvm from the signature */
	if(ebx != KVM_CPUID_SIGNATURE_EBX)
		return;
	if(ecx != KVM_CPUID_SIGNATURE_ECX)
		return;
	if(edx != KVM_CPUID_SIGNATURE_EDX)
		return;

	/* Old hosts set eax to 0, but it should be interpreted as KVM_CPUID_FEATURES */
	if(eax == 0)
		eax = KVM_CPUID_FEATURES;
	
	__cpuid(KVM_CPUID_FEATURES, eax, ebx, ecx, edx);

	if(eax & KVM_FEATURE_CLOCKSOURCE2)
		clocksource2_supported = true;
	if(eax & KVM_FEATURE_CLOCKSOURCE)
		clocksource_supported = true;

	pvclock_init();
}

static struct pvclock_system_time *system_time;
static struct pvclock_wall_clock *wall_clock;
static volatile struct pvclock_system_time *vsystem_time;

static inline bool pvclock_system_time_updating(uint32_t version)
{
	/* Odd version numbers = under update */
	return version % 2;
}

unsigned long pvclock_get_tsc_frequency(void)
{
	uint32_t start_version = 0, end_version = 0;
	uint32_t tsc_mul = 0;
	int8_t tsc_shift = 0;

	do
	{
		start_version = vsystem_time->version;
		if(pvclock_system_time_updating(start_version))
		{
			continue;
		}

		tsc_mul = vsystem_time->tsc_to_system_mul;
		tsc_shift = vsystem_time->tsc_shift;
		
		end_version = vsystem_time->version;

	} while(start_version != end_version);
	
	uint64_t tsc_freq = 1000000000UL << 32;
	tsc_freq = tsc_freq / tsc_mul;
	if(tsc_shift > 0)
		tsc_freq >>= tsc_shift;
	else
		tsc_freq <<= -tsc_shift;
  
	return tsc_freq;
}

void pvclock_init(void)
{
	/* Nothing to do. */
	if(!clocksource2_supported && !clocksource_supported)
		return;
	if(clocksource2_supported)
	{
		wall_clock_msr = MSR_KVM_WALL_CLOCK_NEW;
		system_time_msr = MSR_KVM_SYSTEM_TIME_NEW;
	}
	else
	{
		wall_clock_msr = MSR_KVM_WALL_CLOCK;
		system_time_msr = MSR_KVM_SYSTEM_TIME;
	}

	struct page *p = alloc_page(0);
	if(!p)
		return;
	
	unsigned long paddr = (unsigned long) page_to_phys(p);

	system_time = (struct pvclock_system_time *) paddr;
	paddr = ALIGN_TO(paddr, 4);
	wall_clock = (struct pvclock_wall_clock *) paddr;

	vsystem_time = PHYS_TO_VIRT(system_time);

	wrmsr(system_time_msr, (unsigned long) system_time | MSR_KVM_SYSTEM_TIME_ENABLE);

	x86_set_tsc_rate(pvclock_get_tsc_frequency());
}