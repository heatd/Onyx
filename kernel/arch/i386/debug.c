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
 * File: debug.c
 *
 * Description: Contains the implementation of debug procedures on the x86 architecture
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <kernel/registers.h>
__attribute__((noinline))
void get_thread_ctx(registers_t* regs)
{
	asm volatile("mov %%eax,%0":"=a"(regs->eax));
	asm volatile("mov %%ebx,%0":"=a"(regs->ebx));
	asm volatile("mov %%ecx,%0":"=a"(regs->ecx));
	asm volatile("mov %%edx,%0":"=a"(regs->edx));
	asm volatile("mov %%edi,%0":"=a"(regs->edi));
	asm volatile("mov %%ebp,%0":"=a"(regs->ebp));
	asm volatile("mov %%esp,%0":"=a"(regs->esp));
	regs->eip =(uint32_t)__builtin_return_address(0); // Find the return address in the stack frame (ebp + 4 in x86 architecure)
	regs->eflags = __builtin_ia32_readeflags_u32();
	asm volatile("mov %%esi,%0":"=a"(regs->esi));
	asm volatile("mov %%cs,%0":"=a"(regs->cs));
	asm volatile("mov %%ss,%0":"=a"(regs->ss));
}
__attribute__((noreturn,cold))
void halt()
{
	// IF = 0 (disable interrupts) and halt the processor
	asm volatile("cli");
	asm volatile("hlt");
	for(;;);
	// If execution passes this, the processor is broken (or the code is broken, i mean, the compiler, but whatever)
	__builtin_unreachable();
}
