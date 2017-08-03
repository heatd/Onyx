#include <sys/ioctl.h>
#include <stdarg.h>
#include "syscall.h"

int ioctl(int fd, int req, ...)
{
	void *arg;
	va_list ap;
	va_start(ap, req);
	arg = va_arg(ap, void*);
	int status = syscall(SYS_ioctl, fd, req, arg);
	va_end(ap);
	return status;
}
