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
extern "C" void syscall()
{
	uint32_t eax,ebx,ecx,edx,edi;
	asm volatile("mov %%eax,%0":"=a"(eax));
	asm volatile("mov %%ebx,%0":"=a"(ebx));
	asm volatile("mov %%ecx,%0":"=a"(ecx));
	asm volatile("mov %%edx,%0":"=a"(edx));
	asm volatile("mov %%edi,%0":"=a"(edi));
	
	switch(eax){
		case 0:
			sys_write(ebx,(const void*)ecx,edx);
		case 1:
			sys_read(ebx,(const void*)ecx,edx);
		case 2:
			sys_yield();
		default:
			break;
	}
}
