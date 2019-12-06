/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _CARBON_SMP_H
#define _CARBON_SMP_H

#include <stddef.h>

#include <onyx/percpu.h>

#ifdef __cplusplus
namespace smp
{

void set_number_of_cpus(unsigned int nr);
void set_online(unsigned int cpu);
void boot(unsigned int cpu);
unsigned int get_online_cpus();

void boot_cpus();

};
#endif

struct smp_header
{
	volatile unsigned long thread_stack;
	volatile unsigned long gs_base;
	volatile unsigned long boot_done;
} __attribute__((packed));

#ifdef __cplusplus
extern "C"
{
#endif

unsigned int get_cpu_nr();
void smp_parse_cpus(void *madt);
void smp_boot_cpus();

#ifdef __cplusplus
}
#endif

#endif