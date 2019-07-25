/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <xmmintrin.h>

#include <signal.h>

#include <onyx/disassembler.h>
#include <onyx/process.h>
#include <onyx/signal.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/compiler.h>
#include <onyx/x86/mce.h>
#include <onyx/cpu.h>
#include <onyx/atomic.h>
#include <onyx/percpu.h>

const char* exception_msg[] = {
    "Division by zero exception",
    "Debug Trap",
    "Non-maskable interrupt",
    "Hit a breakpoint",
    "Overflow trap",
    "Fault: Bound range exceeded",
    "Invalid Instruction",
    "FPU not detected",
    "Critical error: DOUBLE FAULT",
    "Invalid TSS",
    "Segment not present",
    "Stack segment fault",
    "General Protection Fault",
    "Page fault at ",
    "",
    "x87 floating point exception",
    "Alignment check exception",
    "Machine check exception",
    "SIMD floating point exception",
    "Virtualization exception",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "Security exception"
};

void dump_interrupt_context(intctx_t *ctx)
{
	printk("Exception at %016lx\n", ctx->rip);
	printk("Registers: rax: %016lx\nrbx: %016lx\nrcx: %016lx\nrdx: %016lx\n"
	       "rdi: %016lx\nrsi: %016lx\nrbp: %016lx\nr8:  %016lx\nr9:  %016lx\n"
	       "r10: %016lx\nr11: %016lx\nr12: %016lx\nr13: %016lx\nr14: %016lx\n"
	       "r15: %016lx\nrsp: %016lx\nrflags: %016lx\nds: %016lx\ncs: %016lx\n", 
	ctx->rax, ctx->rbx, ctx->rcx, ctx->rdx, ctx->rdi, ctx->rsi, ctx->rbp, 
	ctx->r8, ctx->r9, ctx->r10, ctx->r11, ctx->r12, ctx->r13, ctx->r14, 
	ctx->r15, ctx->rsp, ctx->rflags, ctx->ds, ctx->cs);

	if(ctx->cs == 0x08) stack_trace_ex((uint64_t *) ctx->rbp);
}

static bool is_kernel_exception(intctx_t *ctx)
{
	/* We can't use %rip here since, for example, in a page fault, %rip is
	 * set to the target address before the page fault actually triggers.
	 * User-space cannot set cs.
	*/
	return ctx->cs == 0x08;
}

void div0_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Divide by zero exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGFPE, current);
}

unsigned long *pppp = (void *) 0xffffa000009d88f0;
int i = 0;
void debug_trap(intctx_t *ctx)
{
	/* if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Debug trap");
	}*/

	printk("Trap at %lx rbp %lx!\n", ctx->rip, ctx->rbp);
	//printk("Val: %lx\n", *pppp);
	//debug_opcode((uint8_t *) ctx->rip, ctx);
	printk("r13: %lx\n", ctx->r13);
	++i;
	return;
	struct process *current = get_current_process();

	kernel_raise_signal(SIGTRAP, current);
}

void nmi_exception(intctx_t *ctx)
{
	dump_interrupt_context(ctx);
	/* TODO: Handle this in a better, less destructive and useful fashion */
	panic("Unexpected NMI exception\n");
}

void overflow_trap(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Overflow trap");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGFPE, current);
}

void boundrange_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Bound range trap");
	}

	struct process *current = get_current_process();

	/* TODO: Is this the correct signal to send? */
	kernel_raise_signal(SIGFPE, current);
}

void invalid_opcode_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Invalid instruction exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGILL, current);
}

void device_not_avail_excp(intctx_t *ctx)
{
	/* We don't support FPU lazy switching right now, so we just send SIGFPE
	 * to the process
	*/
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("FPU exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGFPE, current);
}
void __double_fault(intctx_t *ctx)
{
	dump_interrupt_context(ctx);
	panic("Double fault");
}

void exception_panic(intctx_t *ctx)
{
	dump_interrupt_context(ctx);
	panic("Misc/Unknown exception triggered.");
}

void stack_segment_fault(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Stack segment fault");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGKILL, current);
}

void general_protection_fault(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		printk("GPF error code: %04x\n", (uint16_t) ctx->err_code);
		panic("General protection fault");
	}

	struct process *current = get_current_process();
	dump_interrupt_context(ctx);
	printk("GPF error code: %04x\n", (uint16_t) ctx->err_code);
	kernel_raise_signal(SIGSEGV, current);
	while(1);
}

void stack_trace_user(uintptr_t *stack);

void page_fault_handler(intctx_t *ctx)
{
	uintptr_t fault_address = cpu_get_cr2();
	uint16_t error_code = ctx->err_code;

	struct fault_info info;
	info.fault_address = fault_address;
	info.write = error_code & 0x2;
	info.read = info.write ? 0 : 1;
	info.exec = error_code & 0x10;
	info.user = error_code & 0x4;
	info.ip = ctx->rip;
	
	if(vm_handle_page_fault(&info) < 0)
	{
		//stack_trace_ex((uint64_t *) ctx->rbp);
		vm_do_fatal_page_fault(&info);
	}
}

void x87_fpu_exception(intctx_t *ctx)
{
	/* We don't support FPU lazy switching right now, so we just send SIGFPE
	 * to the process
	*/
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("FPU exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGFPE, current);
}

void alignment_check_excp(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Alignment check exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGSEGV, current);
}

void simd_fpu_exception(intctx_t *ctx)
{
	/* We don't support FPU lazy switching right now, so we just send SIGFPE
	 * to the process
	*/
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("FPU exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGFPE, current);
}

void virtualization_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Virtualization exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGSEGV, current);
}

void security_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Security exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGSEGV, current);
}

void breakpoint_exception(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Breakpoint exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGTRAP, current);
}

void invalid_tss_exception(intctx_t *ctx)
{
	dump_interrupt_context(ctx);
	panic("Invalid TSS exception");
}

void segment_not_present_excp(intctx_t *ctx)
{
	if(is_kernel_exception(ctx))
	{
		dump_interrupt_context(ctx);
		panic("Segment not present exception");
	}

	struct process *current = get_current_process();

	kernel_raise_signal(SIGSEGV, current);
}

void machine_check(intctx_t *ctx)
{
	do_machine_check(ctx);
}

void (* const int_handlers[])(intctx_t *ctx) = 
{
	div0_exception,
	debug_trap,
	nmi_exception,
	breakpoint_exception,
	overflow_trap,
	boundrange_exception,
	invalid_opcode_exception,
	device_not_avail_excp,
	__double_fault,
	exception_panic,
	invalid_tss_exception,
	segment_not_present_excp,
	stack_segment_fault,
	general_protection_fault,
	page_fault_handler,
	exception_panic,
	x87_fpu_exception,
	alignment_check_excp,
	machine_check,
	simd_fpu_exception,
	virtualization_exception,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	exception_panic,
	security_exception,
	exception_panic
};

PER_CPU_VAR(struct spinlock isr_lock);

static void exit_isr_handler(void)
{
	//spin_unlock(&GET_PER_CPU(isr_lock, struct spinlock));
}

static void enter_isr_handler(void)
{
	//spin_lock(&GET_PER_CPU(isr_lock, struct spinlock));
}

void dump_stack(uintptr_t *__rsp)
{
	unsigned char *rsp = (unsigned char *) __rsp;
	printk("Stack dump: ");
	/* Lets dump a comfortable number of bytes */
	for(int i = 0; i < 20; i++, rsp--)
		printk("%02x ", *rsp);
	printk("\n");
}

void isr_handler(intctx_t *ctx)
{
	int int_no = ctx->int_no;

	enter_isr_handler();

	int_handlers[int_no](ctx);

	exit_isr_handler();
}
