/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/code_patch.h>
#include <onyx/cpu.h>
#include <onyx/irq.h>
#include <onyx/mutex.h>
#include <onyx/smp.h>
#include <onyx/x86/control_regs.h>

namespace code_patch
{

/* We're using this byte sequence as the nop instruction to replace calls.
 * Note that it's exactly the same size as a call instruction (0xe8 + 4-byte offset). */
const uint8_t nop_5byte[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
const uint8_t nop_4byte[] = {0x0f, 0x1f, 0x40, 0x00};
const uint8_t nop_3byte[] = {0x0f, 0x1f, 0x00};
const uint8_t nop_2byte[] = {0x66, 0x90};
const uint8_t nop_1byte[] = {0x90};

static void disable_writeprotect()
{
    unsigned long cr = x86_read_cr0();
    cr &= ~CR0_WP;
    x86_write_cr0(cr);
}

static void enable_writeprotect()
{
    unsigned long cr = x86_read_cr0();
    cr |= CR0_WP;
    x86_write_cr0(cr);
}

/* hotpatch_lock protects any new hot-patcher against current hot-patchers and serializer CPUs.
 * We keep a hotpatch_in_progress to sync up the patcher and serializing CPUs. We also have a
 * serializing CPUs that lets us sync when CPUs are/aren't serializing. This is all important,
 * as we must not let other CPUs have inconsistent views of the instruction stream or the .text
 * itself.
 */
mutex hotpatch_lock;
atomic<bool> hotpatch_in_progress;
atomic<unsigned long> serializing_cpus;

static void wait_for_serializing_cpus()
{
    while (serializing_cpus.load(mem_order::acquire) != 0)
        cpu_relax();
}

static void sync_icache(void * /*ctx*/)
{
    serializing_cpus.add_fetch(1, mem_order::release);
    /* SDM suggests we spin on the hotpatch_in_progress and then issue a serializing instruction
     * (i.e cpuid). */
    while (hotpatch_in_progress.load(mem_order::acquire))
        cpu_relax();
    serialize_insns();

    serializing_cpus.sub_fetch(1, mem_order::release);
}

static unsigned long start_hotpatch() ACQUIRE(hotpatch_lock)
{
    /* First we lock the mutex to exclude other patchers, then we disable IRQs (so we can't get
     * interrupted, this is atomic code) */
    mutex_lock(&hotpatch_lock);
    unsigned long f = irq_save_and_disable();
    hotpatch_in_progress.store(true, mem_order::release);

    /* IPI the other APs to get into sync_icache serializing code, waiting for hotpatch_in_progress
     */
    smp::sync_call(sync_icache, nullptr, cpumask::all_but_one(get_cpu_nr()), SYNC_CALL_NOWAIT);

    /* Wait for every CPU to hit the IPI and get into safe territory (not going to see incomplete
     * instructions or inconsistent icache)
     */
    unsigned int online_cpus = smp::get_online_cpus();

    // We may be called really early, before any cpu is deemed "online"
    if (online_cpus == 0)
        online_cpus = 1;

    while (serializing_cpus.load(mem_order::acquire) != online_cpus - 1)
        cpu_relax();

    /* Ready for writing, disable CR0.WP */
    disable_writeprotect();

    return f;
}

static void end_hotpatch(unsigned long flags) RELEASE(hotpatch_lock)
{
    /* Release hotpatch_in_progress (makes APs serialize and go away) */
    hotpatch_in_progress.store(false, mem_order::release);
    enable_writeprotect();
    irq_restore(flags);
    /* Wait a bit for the serializing cpus to go away. Now they should have a consistent .text and
     * icache stream. Notice we still hold the hotpatch lock, there's no way anyone can mess with
     * .text while we hold this.
     */
    wait_for_serializing_cpus();
    mutex_unlock(&hotpatch_lock);
}

void __replace_instructions(void *ip, const void *instructions, size_t size) REQUIRES(hotpatch_lock)
{
    memcpy(ip, instructions, size);
}

#define REPLACE_INSTR_N(N)                                                          \
    while (size >= (N))                                                             \
    {                                                                               \
        __replace_instructions((void *) instr, __PASTE(__PASTE(nop_, N), byte), N); \
        size -= (N);                                                                \
        instr += (N);                                                               \
    }

void __nop_out(void *ip, size_t size) REQUIRES(hotpatch_lock)
{
    char *instr = (char *) ip;
    REPLACE_INSTR_N(5);
    REPLACE_INSTR_N(4);
    REPLACE_INSTR_N(3);
    REPLACE_INSTR_N(2);
    REPLACE_INSTR_N(1);
}

void nop_out(void *ip, size_t size)
{
    unsigned long flags = start_hotpatch();
    __nop_out(ip, size);
    end_hotpatch(flags);
}

void replace_instructions(void *ip, const void *instructions, size_t size, size_t max)
{
    assert(size <= max);
    unsigned long flags = start_hotpatch();
    __replace_instructions(ip, instructions, size);
    __nop_out((void *) ((char *) ip + size), max - size);
    end_hotpatch(flags);
}

} // namespace code_patch
