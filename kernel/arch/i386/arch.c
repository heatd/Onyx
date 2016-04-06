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
 * File: arch.c
 *
 * Description: Contains architecture specific initialization functions
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <kernel/idt.h>
#include <kernel/gdt.h>
#include <kernel/pic.h>
#include <kernel/cpu.h>
void init_sse();
void init_arch()
{
	/* Initialize SSE */
	init_sse();
	/* Initialize GDT */
	init_gdt();
	/* Initialize IDT */
	init_idt();
	/* Remap the PIC */
	pic_remap();
	/* Identify the CPU */
	cpu_identify();
	/* Note that interrupts are not enabled after this point, as not everything is ready to run
	   ex: scheduling
	*/
}
