#ifndef _ASM_SMP_H
#define _ASM_SMP_H

static inline void wbinvd_on_all_cpus(void)
{
    /* TODO */
	__asm__ __volatile__("wbinvd" ::: "memory");
}

#endif
