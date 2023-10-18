/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/assert.h>
#include <onyx/code_patch.h>
#include <onyx/cpu.h>
#include <onyx/mutex.h>
#include <onyx/smp.h>
#include <onyx/vm.h>

#include <platform/jump_label.h>

#include <onyx/atomic.hpp>

#define ADDI_OPCODE    0b0010011
#define JAL_OPCODE     0b1101111
#define JALR_OPCODE    0b1100111
#define AUIPC_OPCODE   0b0010111
#define RV_ARG0(val)   ((val) << 7)
#define RV_FUNCT3(val) ((val) << 12)
#define RV_ARG1(val)   ((val) << 15)
#define RV_IMM(val)    ((val) << 21)

#define RVC_ADDI 0b01

namespace code_patch
{

const u32 nop_insn = ADDI_OPCODE | RV_ARG0(0) | RV_FUNCT3(0) | RV_ARG1(0) | RV_IMM(0);
const u32 cnop_insn = RVC_ADDI;

/* hotpatch_lock protects any new hot-patcher against current hot-patchers and
 * serializer CPUs. We keep a hotpatch_in_progress to sync up the patcher and
 * serializing CPUs. We also have a serializing CPUs that lets us sync when CPUs
 * are/aren't serializing. This is all important, as we must not let other CPUs
 * have inconsistent views of the instruction stream or the .text itself.
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

    return f;
}

static void end_hotpatch(unsigned long flags) RELEASE(hotpatch_lock)
{
    /* The riscv ISA manuals specify that we should barrier to make sure the write landed in memory,
     * before fence.i. (mem_order::release may be doing this, but lets be explicit and make sure.)
     */
    __asm__ __volatile__("fence rw, rw" ::: "memory");

    /* Release hotpatch_in_progress (makes APs serialize and go away) */
    hotpatch_in_progress.store(false, mem_order::release);
    /* Serialize the icache ourselves */
    serialize_insns();
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
    /* Check if the given ip is properly aligned */
    unsigned long dest = (unsigned long) ip;
    CHECK((dest & 1) == 0);
    /* We have no way of disabling WP like x86, so use the phys map as an alias mapping */
    struct kernel_limits limits;
    get_kernel_limits(&limits);
    void *dstp = (void *) (PHYS_BASE + limits.start_phys + (dest - limits.start_virt));
    memcpy(dstp, instructions, size);
}

/**
 * @brief Replaces instructions at ip with nops, optimised for performance
 *
 * @param ip Instruction pointer
 * @param size Size of region
 */
void __nop_out(void *ip, size_t size) REQUIRES(hotpatch_lock)
{
    while (size >= 4)
    {
        __replace_instructions(ip, &nop_insn, sizeof(nop_insn));
        ip = (void *) ((char *) ip + 4);
        size -= 4;
    }

    while (size >= 2)
    {
        __replace_instructions(ip, &cnop_insn, sizeof(cnop_insn));
        ip = (void *) ((char *) ip + 2);
        size -= 2;
    }

    CHECK(size == 0);
}

/**
 * @brief Replaces instructions at ip with nops, optimised for performance
 *
 * @param ip Instruction pointer
 * @param size Size of region
 */
void nop_out(void *ip, size_t size)
{
    unsigned long flags = start_hotpatch();
    __nop_out(ip, size);
    end_hotpatch(flags);
}

/**
 * @brief Replaces instructions at ip with instructions at *instructions, of size size, and nops
 * the rest
 *
 * @param ip
 * @param instructions
 * @param size
 * @param max
 */
void replace_instructions(void *ip, const void *instructions, size_t size, size_t max)
{
    unsigned long flags = start_hotpatch();
    __replace_instructions(ip, instructions, size);
    __nop_out((void *) ((char *) ip + size), max - size);
    end_hotpatch(flags);
}

} // namespace code_patch

#define _1MB 0x100000
size_t jump_label_gen_branch(struct jump_label *label, unsigned char *buf)
{
    s32 diff = label->dest;
    /* Note: JAL format:
     * | imm[20] | imm[10:1] | imm[11] | imm[19:12] | rd | opcode |
     */

    if (diff < _1MB && diff >= -_1MB)
    {
        /* We can get away with a single jal */
        const u32 opc = JAL_OPCODE | RV_ARG0(0) /* x0 */ | (((diff >> 12) & 0xff) << 12) |
                        (((diff >> 11) & 1) << 20) | (((diff >> 1) & 0x3ff) << 21) |
                        (((diff >> 20) & 1) << 31);
        memcpy(buf, &opc, sizeof(opc));
        return 4;
    }

#ifdef RISCV_JUMP_LABEL_AUIPC_JALR
    /* We need a auipc + jal codegen (hence us needing two dummy instructions). */
    /* We handle the 20bit imm and 12bit both being sign-extended by adding 0x800 to the auipc
     * imm. */
    u32 opc = AUIPC_OPCODE | RV_ARG0(5) /* t0 */ | (diff + 0x800) >> 20;
    memcpy(buf, &opc, sizeof(opc));
    opc = JALR_OPCODE | RV_ARG0(0) /* x0 */ | RV_FUNCT3(0) | RV_ARG1(5) /* t0 */ |
          ((diff & 0xfff) << 20);
    memcpy(buf + 4, &opc, sizeof(opc));
    return 8;
#else
    panic("riscv: jump_label has a jump out of range (diff %lx)", diff);
#endif
}
