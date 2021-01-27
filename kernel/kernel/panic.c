/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
#include <inttypes.h>
#include <stdarg.h>

#include <onyx/cpu.h>
#include <onyx/registers.h>
#include <onyx/compiler.h>
#include <onyx/paging.h>
#include <onyx/vm.h>
#include <onyx/task_switching.h>
#include <onyx/process.h>
#include <onyx/panic.h>
#include <onyx/modules.h>

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

void stack_trace(void);

void page_print_shared(void);

void vterm_panic(void);

void bust_printk_lock(void);

#define PANIC_STACK_BUF_SZ      1024

__attribute__ ((noreturn, noinline))
void panic(const char *msg, ...)
{
	/* First, disable interrupts */
	irq_disable();

	char buffer[PANIC_STACK_BUF_SZ];
	panicing = 1;
	buffer[PANIC_STACK_BUF_SZ - 1] = '\0';

	va_list parameters;
	va_start(parameters, msg);

	vsnprintf(buffer, PANIC_STACK_BUF_SZ, msg, parameters);

	va_end(parameters);

	/* Turn off vterm multthreading */
	vterm_panic();

	bust_printk_lock();

	/* And dump the context to it */
#ifdef __x86_64__
#else
	#error "Implement thread context printing in your arch"
#endif
	printk("panic: %s\n", buffer);

	module_dump();
	printk("Stack dump: \n");

	stack_trace();
	printk("Killing cpus... ");
	cpu_kill_other_cpus();
	printk("Done.\n");
	//page_print_shared();
	halt();
	__builtin_unreachable();
}

void __assert_fail(const char * assertion, const char * file, int line, const char * function)
{
	panic("Assertion %s failed in %s:%u, in function %s\n", assertion, file, line, function);
}

void abort(void)
{
	panic("Abort!");
}
