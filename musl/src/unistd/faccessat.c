#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include "syscall.h"

int faccessat(int fd, const char *filename, int amode, int flag)
{
	return syscall(SYS_faccessat, fd, filename, amode, flag);
}
