/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>

#include <onyx/ktrace.h>
#include <onyx/cpu.h>
#include <onyx/registers.h>
#include <platform/irq.h>
#include <onyx/x86/control_regs.h>
#include <onyx/panic.h>

extern "C" void __fentry__();
extern "C" void __return__();

namespace ktrace
{

/* We're using this byte sequence as the nop instruction to replace calls.
 * Note that it's exactly the same size as a call instruction (0xe8 + 4-byte offset). */
const uint8_t nop_5byte[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
const uint8_t nop_4byte[] = {0x0f, 0x1f, 0x40, 0x00};
const uint8_t nop_3byte[] = {0x0f, 0x1f, 0x00};
const uint8_t nop_2byte[] = {0x66, 0x90};
const uint8_t nop_1byte[] = {0x90};

constexpr size_t hotpatch_site_len = 5;
constexpr uint8_t int3_insn = 0xcc;
constexpr uint8_t call_insn = 0xe8;

extern "C" void ktrace_int3_handler(struct registers *regs)
{
	/* Adjust IP by hotpatch_site_len bytes */
	regs->rip += hotpatch_site_len;
}

extern "C" void x86_ktrace_entry(struct registers *regs)
{
	unsigned long caller = 0;
	
	caller = *(unsigned long *) regs->rsp;

	ktrace::log_func_entry(regs->rip - hotpatch_site_len, caller);
} 

void disable_writeprotect()
{
	unsigned long cr = x86_read_cr0();
	cr &= ~CR0_WP;

	x86_write_cr0(cr);
}

void enable_writeprotect()
{
	unsigned long cr = x86_read_cr0();
	cr |= CR0_WP;

	x86_write_cr0(cr);
}

enum class patch_action
{
	CALL = 0,
	NOP = 1
};

void patch_code(unsigned long __ip, unsigned long func, patch_action action)
{
	/* We're going to patch the code and freeze the system,
	 * so stop us from getting interrupted.
	*/
	unsigned long f = irq_save_and_disable();

	disable_writeprotect();

	volatile unsigned char *ip = (unsigned char *) __ip;

	/* Firstly, patch the ip so it triggers an int3 - this ensures the replace
	 * is definitely done atomically */

	*ip = int3_insn;

	if(action == patch_action::CALL)
	{
		/* Write out the address first, overwrite int3 later */
		auto address = ip + 1;
		
		unsigned long displacement = func - (__ip + hotpatch_site_len);

		for(unsigned int i = 0; i < hotpatch_site_len - 1; i++)
		{
			address[i] = displacement & 0xff;
			displacement >>= 8;
		}

		*ip = call_insn;
	}
	else if(action == patch_action::NOP)
	{
		/* Do the same, but for the nop */
		for(unsigned int i = 1; i < 5; i++)
		{
			ip[i] = nop_5byte[i];
		}

		ip[0] = nop_5byte[0];
	}
	
	enable_writeprotect();

	irq_restore(f);
}

void ktracepoint::activate()
{
	activated = true;
	patch_code(mcount_call_addr, (unsigned long) &__fentry__, patch_action::CALL);
}

void ktracepoint::deactivate()
{
	activated = false;
	patch_code(mcount_call_addr, 0, patch_action::NOP);
}

/* NOTE: We don't need to be as careful as above because this is early boot code, without
 * proper preemption or multi cpu stuff
 */

void __replace_instructions(void *ip, const void *instructions, size_t size)
{
	unsigned long f = irq_save_and_disable();

	disable_writeprotect();

	memcpy(ip, instructions, size);

	enable_writeprotect();

	irq_restore(f);
}

#define REPLACE_INSTR_N(N) \
while(size >= N)            \
{                           \
	__replace_instructions((void *) instr, __PASTE(__PASTE(nop_, N), byte), N); \
	size -= N;             \
	instr += N;            \
}

void nop_out(void *ip, size_t size)
{
	char *instr = (char *) ip;
	REPLACE_INSTR_N(5);
	REPLACE_INSTR_N(4);
	REPLACE_INSTR_N(3);
	REPLACE_INSTR_N(2);
	REPLACE_INSTR_N(1);
}

void replace_instructions(void *ip, const void *instructions, size_t size, size_t max)
{
	assert(size <= max);
	__replace_instructions(ip, instructions, size);
	nop_out((void *) ((char *) ip + size), max - size);
}

}
