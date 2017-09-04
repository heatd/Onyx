/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: ssp.c
 *
 * Description: Contains the implementation of the GCC stack protector functions
 *
 * Date: 2/2/2016
 *
 *
 **************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#ifdef __is_onyx_kernel
#include <onyx/panic.h>
#endif
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xdeadc0de
#else
#define STACK_CHK_GUARD 0xdeadd00ddeadc0de
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

void __initialize_ssp()
{
	#if __STDC_HOSTED__
	/* If in user-space, seed ssp ourselves */
	/*TODO: Implement /dev/urandom and start using it, as /dev/random might block 
	 *TODO: Fix the kernel's entropy generator 
	*/
	/*int fd = open("/dev/random", O_RDONLY);
	read(fd, &__stack_chk_guard, 8);
	close(fd);*/
	srand(time(NULL));
	__stack_chk_guard = (uint64_t) rand() << 32 | rand();
	#endif

}
__attribute__((noreturn))
void __stack_chk_fail()
{
#if __STDC_HOSTED__
	abort(); // abort() right away, its unsafe!
#elif __is_onyx_kernel
	panic("Stack smashing detected");
#endif
}
