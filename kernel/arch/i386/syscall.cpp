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
#include <stdlib.h>
#include <kernel/kheap.h>
#include <kernel/fd.h>
#include <kernel/sbrk.h>
extern "C" void syscall(uint32_t edi,uint32_t edx,uint32_t ecx, uint32_t ebx, uint32_t eax)
{
	switch(eax)
	{
		case 0:
			sys_write(ebx,(const void*)ecx,edx);
			return;
		case 1:
			sys_read(ebx,(const void*)ecx,edx);
			return;
		case 2:
			asm volatile("int $0x50");
			return;
		case 3:
			__sbrk((int)ebx);
			return;
		default:
			break;
	}
}
