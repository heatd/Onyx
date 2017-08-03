#include <errno.h>
#include "syscall.h"

long __syscall_ret(unsigned long r)
{
	if ((int) r > -4096UL) {
		errno = -r;
		return -1;
	}
	return r;
}
