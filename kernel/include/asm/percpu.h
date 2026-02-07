#ifndef _ASM_PERCPU_H
#define _ASM_PERCPU_H

#include <onyx/percpu.h>

#define DECLARE_PER_CPU(type, name) extern type name
#define DEFINE_PER_CPU(type, name)  PER_CPU_VAR(type name)
#define EXPORT_PER_CPU_SYMBOL_GPL(var)

#define __this_cpu_read(var) get_per_cpu(var)
#define this_cpu_read(var)  get_per_cpu(var)
#define __this_cpu_inc(var) inc_per_cpu(var)
#define this_cpu_inc(var)   __this_cpu_inc(var)
#define __this_cpu_dec(var) dec_per_cpu(var)
#define this_cpu_dec(var)   __this_cpu_dec(var)

#define __this_cpu_dec_return(var) dec_and_return_per_cpu(var)
#define this_cpu_dec_return(var)   __this_cpu_dec_return(var)

#define __this_cpu_write(var, val) write_per_cpu(var, val)
#define this_cpu_write(var, val)   __this_cpu_write(var, val)

#define raw_cpu_read(var) this_cpu_read(var)

#define per_cpu(var, cpu) (*(other_cpu_get_ptr(var, cpu)))
#define this_cpu_ptr(var) (get_per_cpu_ptr(*var))

#endif
