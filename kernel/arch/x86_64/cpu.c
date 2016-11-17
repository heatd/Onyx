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
#include <string.h>
#include <stdio.h>
#include <acpi.h>

#include <kernel/cpu.h>
#include <kernel/panic.h>
#include <kernel/apic.h>
#include <kernel/pic.h>
#include <kernel/acpi.h>
static cpu_t cpu;

char *cpu_get_name()
{
	uint32_t eax,ebx,edx,ecx = 0;
	int i = __get_cpuid(0,&eax,&ebx,&ecx,&edx);
	if( i == 0 ) {
		panic("cpuid instruction not supported");
		__builtin_unreachable();
	}
	uint32_t cpuid[4] = {0};
	cpuid[0] = ebx;
	cpuid[1] = edx;
	cpuid[2] = ecx;
	memcpy(&cpu.manuid,&cpuid,12);
	/* Zero terminate the string */
	cpu.manuid[12] = '\0';
	i = __get_cpuid(CPUID_MAXFUNCTIONSUPPORTED,&eax,&ebx,&ecx,&edx);
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
	printf("Detected x86_64 CPU\n");
	printf("Manufacturer ID: %s\n", cpu_get_name());
	if(cpu.brandstr[0] != '\0')
		printf("Name: %s\n", cpu.brandstr);
	cpu_get_sign();
	printf("Stepping %i, Model %i, Family %i\n", cpu.stepping, cpu.model, cpu.family);
}
void cpu_init_interrupts()
{
	pic_remap();
	ioapic_init();
	lapic_init();
	apic_timer_init();
}
uint8_t *lapic_ids = NULL;
static int booted_cpus = 0;
extern ACPI_TABLE_MADT *madt;
int cpu_init_mp()
{
	/* Lets parse through the MADT to get the number of cores.
	 * Each LAPIC = 1 core */
	ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *) (madt+1);
	for(ACPI_SUBTABLE_HEADER *i = first; i < (ACPI_SUBTABLE_HEADER*)((char*)madt + madt->Header.Length); i = 
	(ACPI_SUBTABLE_HEADER*)((uint64_t)i + (uint64_t)i->Length))
	{
		if(i->Type == ACPI_MADT_TYPE_LOCAL_APIC)
		{
			ACPI_MADT_LOCAL_APIC *apic = (ACPI_MADT_LOCAL_APIC *) i;
			booted_cpus++;
			if(booted_cpus != 1)
				apic_wake_up_processor(apic->Id);

		}
	}
	return booted_cpus;
}