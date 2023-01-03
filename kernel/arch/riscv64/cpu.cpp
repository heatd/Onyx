/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <ctype.h>

#include <onyx/device_tree.h>
#include <onyx/fpu.h>
#include <onyx/riscv/features.h>

uint32_t isa_features = 0;

/**
 * @brief Get the RISCV ISA features of the CPU
 *
 * @return A bitmask of the above defines
 */
uint32_t riscv_get_features()
{
    return isa_features;
}

PER_CPU_VAR(unsigned long hartid);

/**
 * @brief Set the current hartid
 *
 * @param hart hartid
 */
void riscv_set_hartid(unsigned long hart)
{
    write_per_cpu(hartid, hart);
}

/**
 * @brief Get the current hartid
 *
 * @return Current hartid
 */
unsigned long riscv_get_hartid()
{
    return get_per_cpu(hartid);
}

static bool feature_init = false;

static void riscv_cpu_features_enum()
{
    int len;
    auto cpu_node = device_tree::open_node("/cpus/cpu@0");

    if (!cpu_node)
        panic("riscv_cpu_init: CPU0 doesn't exist in device tree");

    const char *isa = (const char *) cpu_node->get_property("riscv,isa", &len);

    if (len < 0)
        panic("Couldn't read /cpus/cpu@0/riscv,isa");
    printf("riscv: ISA: %s\n", isa);
    // skip the rv64/32
    isa += 4;
    while (*isa)
    {
        if (!isalpha(*isa))
            break;
        int bit = *isa - 'a';
        isa_features |= (1 << bit);
        isa++;
    }

    feature_init = true;
}

void riscv_cpu_init(unsigned long hartid_)
{
    riscv_set_hartid(hartid_);

    if (!feature_init)
    {
        riscv_cpu_features_enum();
    }

    fpu_init();
}

bool platform_has_msi()
{
    return false;
}

void halt()
{
    irq_disable();
    while (true)
    {
        __asm__ __volatile__("wfi");
    }
}
