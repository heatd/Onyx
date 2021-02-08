#include <unistd.h>
#include <sys/resource.h>

#include "syscall.h"

int rlimit(pid_t pid, int resource, struct rlimit *old,
           const struct rlimit *new, unsigned int flags)
{
	return syscall(SYS_rlimit, pid, resource, old, new, flags);
}
