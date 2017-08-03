#include <signal.h>
#include <errno.h>
#include "syscall.h"

int sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old)
{
	return syscall(SYS_rt_sigprocmask, how, set, old);
}
