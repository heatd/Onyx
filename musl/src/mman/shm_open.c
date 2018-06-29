#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include "syscall.h"

#define SHM_PATH_PREFIX		"/dev/shm"
#define SHM_PATH_PREFIX_SIZE	sizeof(SHM_PATH_PREFIX)

int shm_open(const char *name, int flag, mode_t mode)
{
	char buf[NAME_MAX + SHM_PATH_PREFIX_SIZE + 2] = {0};
	strcpy(buf, SHM_PATH_PREFIX);
	memcpy(buf + SHM_PATH_PREFIX_SIZE, name, strlen(name));

	int fd = open(buf, flag | O_CLOEXEC, mode);

	return fd;
}

int shm_unlink(const char *name)
{
	char buf[NAME_MAX + SHM_PATH_PREFIX_SIZE + 2] = {0};
	strcpy(buf, SHM_PATH_PREFIX);
	memcpy(buf + SHM_PATH_PREFIX_SIZE, name, strlen(name));

	return unlink(name);
}
