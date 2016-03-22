/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**************************************************************************
 *
 *
 * File: syscall.c
 *
 * Description: Contains the implementation of syscalls on x86
 *
 * Date: 4/2/2016
 *
 *
 **************************************************************************/
#include <stdint.h>
#include <kernel/registers.h>
#include <kernel/panic.h>
#include <kernel/tty.h>
#include <kernel/yield.h>
#include <unistd.h>
#include <stdlib.h>
#include <kernel/kheap.h>
#include <kernel/fd.h>
#include <kernel/sbrk.h>
#include <errno.h>
#include <kernel/process.h>
uint32_t syscall(uint32_t edi, uint32_t edx, uint32_t ecx, uint32_t ebx,
	    uint32_t eax)
{
	(void)edi;
	switch (eax) {
	case 0:{
			ssize_t ret =
			    sys_write(ebx, (const void *) ecx, edx);
			return ret;
		}
	case 1:{
			ssize_t ret =
			    sys_read(ebx, (const void *) ecx, edx);
			return ret;
		}
	case 2:
		asm volatile ("int $0x50");
		return 0;
	case 3:
		{
			void *res = __sbrk((int) ebx);
			return (int) res;
		}
	case 4:
		//fork(2)
		return 0;
	case 5:
		{
			pid_t pid = sys_getpid();
			return pid;
		}
	default:
		break;
	}
	return errno = 0x7fffffff;
}
