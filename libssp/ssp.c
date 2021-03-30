/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>

#include <string.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>

uintptr_t __stack_chk_guard;

/* TODO: Musl's headers are really lacking on onyx stuff, and are even outdated
 * for linux stuff. Fix! */
#define SYS_getrandom 69

static ssize_t get_entropy(void *ptr, size_t size)
{
	return syscall(SYS_getrandom, ptr, size, 0);
}

__attribute__((constructor))
static void __initialize_ssp(void)
{
	uintptr_t guard;
	if(get_entropy(&guard, sizeof(uintptr_t)) < 0)
	{
		/* If getentropy failed for some reason, use /dev/urandom */
		int fd = open("/dev/urandom", O_RDONLY);
		if(fd < 0)
			abort();
		/* Don't bother closing fd if it failed */
		if(read(fd, &guard, sizeof(uintptr_t)) < 0)
			abort();
		close(fd);
	}

	__stack_chk_guard = guard;
}

static void die(void)
{
	/* Try to exit with a trap, and if that didn't work, try abort or exit */
	__builtin_trap();

	abort();

	_exit(0xffff);
}

void __stack_chk_fail(void)
{
	const char *msg = "*** stack smashing detected ***\n";
	int fd = open("/dev/tty", O_RDWR);
	if(fd < 0)
		die();
	
	write(fd, msg, strlen(msg));

	die();
}
