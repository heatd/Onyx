#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "syscall.h"
#include "pthread_impl.h"

struct ctx {
	int fd;
	const char *filename;
	int amode;
	int p;
};

static int checker(void *p)
{
	struct ctx *c = p;
	int ret;
	if (__syscall(SYS_setregid, __syscall(SYS_getegid), -1)
	    || __syscall(SYS_setreuid, __syscall(SYS_geteuid), -1))
		__syscall(SYS_exit, 1);
	ret = __syscall(SYS_faccessat, c->fd, c->filename, c->amode, 0);
	__syscall(SYS_write, c->p, &ret, sizeof ret);
	return 0;
}

int faccessat(int fd, const char *filename, int amode, int flag)
{
	return syscall(SYS_faccessat, fd, filename, amode, flag);
}
