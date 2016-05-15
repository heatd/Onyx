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
 * File: kernel.c
 *
 * Description: Main kernel file, contains the entry point and initialization
 *
 * Date: 30/1/2016
 *
 *
 **************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <multiboot2.h>
#include <stdio.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif
void KernelLate();
void InitKeyboard();
extern uint32_t end;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
#define UNUSED_PARAMETER(x) (void)x
extern "C" void KernelEarly(size_t magic)
{
	UNUSED_PARAMETER(magic);
}
extern "C" void KernelMain()
{

	printf("Spartix kernel %s branch %s build %d\n", KERNEL_VERSION,
	       KERNEL_BRANCH, &__BUILD_NUMBER);
	printf("Built on %d\n", &__BUILD_DATE);
	
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
void KernelLate()
{
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
