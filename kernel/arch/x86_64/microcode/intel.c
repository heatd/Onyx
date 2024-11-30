/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "microcode: " fmt
#include <cpuid.h>
#include <stdio.h>

#include <onyx/cpio.h>
#include <onyx/cpu.h>
#include <onyx/types.h>
#include <onyx/x86/msr.h>

struct intel_ucode_header
{
    u32 version;
    s32 revision;
    u32 date;
    u32 signature;
    u32 csum;
    u32 loader_revision;
    u32 processor_flags;
    u32 data_size;
    u32 total_size;
    u8 reserved[12];
    u8 data[];
};

#define MSR_IA32_UCODE_TRIG 0x00000079
#define MSR_IA32_UCODE_REV  0x0000008b
#define IA32_PLATFORM_ID    0x17

u32 intel_ucode_revision(void)
{
    /* Intel SDM tells us to write 0 to UCODE_REV, then issue a cpuid eax=1, then read the msr */
    wrmsr(MSR_IA32_UCODE_REV, 0);
    __asm__ __volatile__("cpuid" ::"a"(1) : "memory", "ebx", "ecx", "edx");
    return rdmsr(MSR_IA32_UCODE_REV) >> 32;
}

static struct intel_ucode_header *found_ucode = NULL;

static unsigned int intel_processor_sig(void)
{
    u32 eax, ebx, ecx, edx;
    CHECK(__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 1);
    return eax;
}

static u32 __intel_ucode_csum(void *buf, u32 size)
{
    u32 sum = 0;
    u32 __attribute__((may_alias)) *ptr = (u32 *) buf;
    for (; size > 0; size -= 4)
        sum += *(ptr++);
    return sum;
}

static u32 intel_ucode_csum(struct intel_ucode_header *hdr)
{
    return __intel_ucode_csum(hdr, hdr->total_size);
}

struct intel_extsig
{
    u32 signature;
    u32 flags;
    u32 csum;
};

struct intel_extsig_hdr
{
    u32 nr_sigs;
    u32 csum;
    u32 rsv[3];
    struct intel_extsig signatures[];
};

static inline u32 intel_ucode_data_size(struct intel_ucode_header *hdr)
{
    return hdr->data_size ?: 2000;
}

static inline u32 intel_ucode_total_size(struct intel_ucode_header *hdr)
{
    return hdr->data_size ? hdr->total_size : 2048;
}

static bool intel_ucode_ok(struct intel_ucode_header *hdr)
{
    unsigned int data_size = intel_ucode_data_size(hdr);
    unsigned int total_size = intel_ucode_total_size(hdr);
    unsigned int extra_size = total_size - data_size - sizeof(struct intel_ucode_header);
    struct intel_extsig_hdr *exthdr;

    /* All of these prerequisites are documented in the Intel SDM volume 3, section 9.11 */

    /* SDM documents the loader revision as 1, for now */
    if (hdr->loader_revision != 1)
    {
        pr_err("Error: unknown loader revision %x\n", hdr->loader_revision);
        return false;
    }

    if (total_size % 1024)
    {
        pr_err("Error: total size %x is not 1024-aligned\n", total_size);
        return false;
    }

    if (data_size % 4)
    {
        pr_err("Error: data size %x is not dword aligned\n", data_size);
        return false;
    }

    if (((unsigned long) hdr->data) & 15)
    {
        pr_err("Error: microcode data is not 16-byte aligned\n");
        return false;
    }

    u32 csum = intel_ucode_csum(hdr);
    if (csum != 0)
    {
        pr_err("Error: microcode checksum %x is not 0\n", csum);
        return false;
    }

    if (extra_size == 0)
        return true;

    if (extra_size < 20)
    {
        pr_err("Error: invalid extended signature table (not enough extra size %u)\n", extra_size);
        return false;
    }

    exthdr = (struct intel_extsig_hdr *) (hdr->data + data_size);
    if (extra_size != 20 + (exthdr->nr_sigs * sizeof(struct intel_extsig)))
    {
        pr_err("Error: invalid extended signature table (extra size not expected)\n");
        return false;
    }

    if (__intel_ucode_csum(exthdr, extra_size) != 0)
    {
        pr_err("Error: Invalid checksum for the extended signature table\n");
        return false;
    }

    return true;
}

#define PLATFORM_ID_EQ(id0, id1) ((!(id0) && !(id1)) || ((id0) & (id1)))

static bool intel_ucode_matches(struct intel_ucode_header *hdr, unsigned int sig,
                                unsigned int platform_id)
{
    struct intel_extsig_hdr *exthdr;
    struct intel_extsig *extsig;

    if (hdr->signature == sig && PLATFORM_ID_EQ(hdr->processor_flags, platform_id))
        return true;
    if (hdr->total_size - intel_ucode_data_size(hdr) == 48)
        return false;

    exthdr = (struct intel_extsig_hdr *) (hdr->data + intel_ucode_data_size(hdr));
    for (unsigned int i = 0; i < exthdr->nr_sigs; i++)
    {
        extsig = &exthdr->signatures[i];
        if (extsig->signature == sig && PLATFORM_ID_EQ(extsig->flags, platform_id))
            return true;
    }

    return false;
}

static void *intel_find_ucode(void)
{
    struct intel_ucode_header *hdr;
    void *end;
    struct cpio_file out;
    unsigned int sig, platform_id = 0;
    if (find_early_cpio("kernel/x86/microcode/GenuineIntel.bin", &out) < 0)
        return NULL;

    end = out.data + out.size;
    sig = intel_processor_sig();

    if (bootcpu_info.model >= 5 || bootcpu_info.family > 6)
        platform_id = (1U << ((rdmsr(IA32_PLATFORM_ID) >> 50) & 7));

    for (hdr = out.data; (void *) hdr < end;
         hdr = (struct intel_ucode_header *) ((u8 *) hdr + intel_ucode_total_size(hdr)))
    {

        if (!intel_ucode_ok(hdr))
            return NULL;
        if (intel_ucode_matches(hdr, sig, platform_id))
            return hdr;
    }

    return NULL;
}

void intel_ucode_load(void)
{
    const struct intel_ucode_header *hdr = NULL;

    if (x86_has_cap(X86_FEATURE_HYPERVISOR))
    {
        /* Hypervisors do not support ucode loading */
        return;
    }

    if (!found_ucode)
    {
        found_ucode = intel_find_ucode();
        if (!found_ucode)
            return;
    }

    hdr = found_ucode;
    u32 curr_rev = intel_ucode_revision();

    if ((s32) curr_rev >= hdr->revision)
    {
        pr_info("best revision %x (vs %x) already loaded\n", curr_rev, hdr->revision);
        return;
    }

    /* wbinvd is not strictly required, but certain emails around the LKML tell us that it might be
     * informally required. Do so in order to flush out the caches. */
    __asm__ __volatile__("wbinvd" ::: "memory");
    wrmsr(MSR_IA32_UCODE_TRIG, (u64) &hdr->data);
    curr_rev = intel_ucode_revision();
    if ((s32) curr_rev != hdr->revision)
    {
        pr_err("microcode loading failed (curr_rev %x does not match %x)\n", curr_rev,
               hdr->revision);
        return;
    }

    pr_info("cpu%u loaded microcode revision %x\n", get_cpu_nr(), hdr->revision);
}
