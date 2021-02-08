#include <sys/resource.h>
#include <errno.h>
#include "syscall.h"
#include "libc.h"

int setrlimit(int resource, const struct rlimit *rlim)
{
	return syscall(SYS_rlimit, 0, resource, 0, rlim, 0);
}

weak_alias(setrlimit, setrlimit64);
