/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
/**************************************************************************
 *
 *
 * File: panic.c
 *
 * Description: Contains the implementation of the panic function
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <stdio.h>
#include <kernel/registers.h>
#include <kernel/compiler.h>
#include <kernel/panic.h>
const char *skull = "            _,,,,,,,_\n\
          ,88888888888,\n\
        ,888\'       \\`888,\n\
        888\' 0     0 \\`888\n\
       888      0      888\n\
       888             888\n\
       888    ,000,    888\n\
        888, 0     0 ,888\n\
        \'888,       ,888\'\n\
          \'8JGS8888888\'\n\
            \\`\\`\\`\\`\\`\\`\\`\\`\n";
int panicing = 0;
__attribute__ ((noreturn, cold, noinline))
void panic(const char *msg)
{
	panicing = 1;
	//printf("\n%s", skull);
	printk("panic: %s\n", msg);
	registers_t ctx;
	// Get thread's context
	get_thread_ctx(&ctx);
	printk("Thread context: \n");
#ifdef __x86_64__
	ctx.rip = (uint64_t) __builtin_return_address(0);


	printk
	    ("rax: %i\nrbx: %i\nrcx: %i\nrdx: %i\nrdi: %i\nrsi: %i\nrbp: 0x%x\nrsp: 0x%x\nrip: 00%x:0x%x\nss:  00%x\nrflags:%i\n",
	     ctx.rax, ctx.rbx, ctx.rcx, ctx.rdx, ctx.rdi, ctx.rsi, ctx.rbp,
	     ctx.rsp, ctx.cs, ctx.rip, ctx.ss);

	printk("Stack dump: \n");
	extern void *stack_trace();
	stack_trace();
#else
	#error "Implement thread context printing to your arch"
#endif
	halt();
	__builtin_unreachable();
}
