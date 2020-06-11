#include <errno.h>
#include "syscall.h"

long __syscall_ret(unsigned long r)
{
	/* TODO: We need this cast because the kernel doesn't cast return values properly, just yet... */
	if ((int) r > -4096UL) {
		errno = -r;
		return -1;
	}
	return r;
}
