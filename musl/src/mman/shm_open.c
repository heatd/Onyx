#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include "syscall.h"

int shm_open(const char *name, int flag, mode_t mode)
{
	return syscall(SYS_shm_open, name, flag, mode);
}

int shm_unlink(const char *name)
{
	return syscall(SYS_shm_unlink, name);
}
