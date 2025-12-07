#ifndef _ASM_PROCESSOR_H
#define _ASM_PROCESSOR_H

#include <onyx/cpu.h>
#include <asm/fpu.h>

struct cpuinfo_x86
{
    unsigned int x86_clflush_size;
};

#define X86_FEATURE_CLFLUSH X86_FEATURE_CLFLSH
#define X86_FEATURE_XMM4_1  X86_FEATURE_SSE41
extern struct cpuinfo_x86 boot_cpu_data;

static inline void clflushopt(volatile void *addr)
{
    __asm__ __volatile__("clflushopt %0" : "+m"(addr) :: "memory");
}

#define mb()	__asm__ __volatile__("mfence" ::: "memory")

#define static_cpu_has(cap) x86_has_cap(cap)
#define boot_cpu_has(cap) x86_has_cap(cap)

#endif
