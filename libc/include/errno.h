#ifndef	_ERRNO_H
#define _ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#include <bits/errno.h>

#ifdef __is_onyx_kernel
extern int errno;
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

