/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/registers.h>
__attribute__((noinline))
void get_thread_ctx(registers_t *regs)
{
	asm volatile("mov %%rax,%0":"=a"(regs->rax));
	asm volatile("mov %%rbx,%0":"=a"(regs->rbx));
	asm volatile("mov %%rcx,%0":"=a"(regs->rcx));
	asm volatile("mov %%rdx,%0":"=a"(regs->rdx));
	asm volatile("mov %%rdi,%0":"=a"(regs->rdi));
	asm volatile("mov %%rbp,%0":"=a"(regs->rbp));
	asm volatile("mov %%rsp,%0":"=a"(regs->rsp));
	regs->rip =(uint64_t)__builtin_return_address(0); // Find the return address in the stack frame (ebp + 4 in x86 architecure)
	asm volatile("mov %%rsi,%0":"=a"(regs->rsi));
	asm volatile("mov %%cs,%0":"=a"(regs->cs));
	asm volatile("mov %%ss,%0":"=a"(regs->ss));
}
__attribute__((noreturn,cold))
void halt()
{
	asm volatile("cli \t\n hlt");
	// If execution goes past this, I don't know what the hell our kernel is running on
	for(;;);
	__builtin_unreachable();
}
