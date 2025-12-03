#ifndef _LINUX_STACKTRACE_H
#define _LINUX_STACKTRACE_H

#include <onyx/perf_probe.h>

static inline unsigned int stack_trace_save(unsigned long *store, unsigned int size,
			      unsigned int skipnr)
{
    /* TODO: skipnr */
    return stack_trace_get((unsigned long *) __builtin_frame_address(0), store, size);
}

void stack_trace_print(const unsigned long *trace, unsigned int nr_entries,
		       int spaces);

#endif
