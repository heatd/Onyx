#include <sys/sysinfo.h>
#include "libc.h"
#include <errno.h>

int __lsysinfo(struct sysinfo *info)
{
	errno = ENOSYS;
	return -1;
}

weak_alias(__lsysinfo, sysinfo);
