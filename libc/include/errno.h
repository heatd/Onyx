#ifndef	_ERRNO_H
#define _ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#include <bits/errno.h>

#ifdef __is_onyx_kernel

#include <onyx/percpu.h>

extern int __true_errno;

static int *__get_errno(void)
{
	/* The cast is needed to support C++ programs */
	return (int *) GET_PER_CPU_ADDR(__true_errno);
}

#define errno *__get_errno()
#else
int *__errno_location(void);
#define errno (*__errno_location())
#endif

#ifdef _GNU_SOURCE
extern char *program_invocation_short_name, *program_invocation_name;
#endif

#ifdef __cplusplus
}
#endif

#endif

