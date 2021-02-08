#include <sys/resource.h>
#include <errno.h>
#include "syscall.h"

int getrlimit(int resource, struct rlimit *rlim)
{
	return syscall(SYS_rlimit, 0, resource, rlim, 0, 0);
}

weak_alias(getrlimit, getrlimit64);
