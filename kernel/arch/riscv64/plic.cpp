/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/device_tree.h>
#include <onyx/riscv/features.h>
#include <onyx/riscv/intrinsics.h>
#include <onyx/types.h>

#include <onyx/hwregister.hpp>

#define PLIC_PRIO(irq)        (irq * 0x4U)
#define PLIC_PENDING          0x1000
#define PLIC_ENABLES(context) (0x2000U + context * 0x80)
#define PLIC_CONTEXT(context) (0x200000U + context * 0x1000)
#define PLIC_THRESHOLD        0x0
#define PLIC_CLAIM            0x4

struct plic_context
{
    uint32_t hart;
    uint32_t plic_enables;
    uint32_t plic_ctx;
};

class plic_chip
{
private:
    mmio_range plic_base;
    device_tree::node *node;
    cul::vector<plic_context> contexts;
    uint32_t nirqs{0};

public:
    plic_chip(device_tree::node *node) : node{node}
    {
    }

    int init();

    void mask_all();

    void mask(unsigned int irq);

    void unmask(unsigned int irq);

    unsigned int claim();

    void complete(unsigned int intid);

    plic_context &current_context();

    DEFINE_MMIO_RW_FUNCTIONS(plic_base);
};

// TODO: Find a header for this?
/**
 * @brief Get the CPU node's hart id
 *
 * @param node Node
 * @return HART id
 */
u32 riscv_cpu_get_hart(device_tree::node *node);

int plic_chip::init()
{
    int len;
    const fdt32_t *ints = (const fdt32_t *) node->get_property("interrupts-extended", &len);
    const fdt32_t *nirq = (const fdt32_t *) node->get_property("riscv,ndev", nullptr);
    if (!nirq)
    {
        printf("plic: Error: riscv,ndev property not found!");
        return -EIO;
    }

    nirqs = fdt32_to_cpu(*nirq);

    auto resource = node->get_resource(DEV_RESOURCE_FLAG_MEM, 0);
    if (!resource)
    {
        printf("plic: Error: resource not found\n");
        return -EIO;
    }

    auto mapping =
        mmiomap((void *) resource->start(), resource->size(), VM_WRITE | VM_READ | VM_NOCACHE);
    if (!mapping)
    {
        return -ENOMEM;
    }

    plic_base.set_base(mapping);

    int context = 0;
    for (int i = 0; i < len / 4; i += 2, context++)
    {
        uint32_t hart_phandle = fdt32_to_cpu(ints[i + 0]);
        uint32_t intno = fdt32_to_cpu(ints[i + 1]);
        if (intno != 9)
            continue;

        auto interrupt_controller = device_tree::map_phandle(hart_phandle);

        if (!interrupt_controller)
        {
            panic("Interrupt controller phandle %u that plic maps to not found\n", hart_phandle);
        }

        auto cpu = interrupt_controller->parent;

        auto hart = riscv_cpu_get_hart(cpu);

        printk("hart %u intno %u @ context %u\n", hart, intno, context);
        bool success = contexts.push_back({hart, PLIC_ENABLES(context), PLIC_CONTEXT(context)});

        if (!success)
        {
            return -ENOMEM;
        }
    }

    mask_all();

    for (auto &context : contexts)
    {
        write32(context.plic_ctx + PLIC_THRESHOLD, 0);
    }

    riscv_or_csr(RISCV_SIE, RISCV_SIE_SEIE);

    return 0;
}

plic_context &plic_chip::current_context()
{
    const auto hartid = riscv_get_hartid();
    for (auto &context : contexts)
    {
        if (hartid == context.hart)
            return context;
    }

    panic("hartid %u not found for plic, how did we get an IRQ?", hartid);
}

void plic_chip::mask_all()
{
    for (auto &context : contexts)
    {
        for (unsigned int i = 1; i < nirqs; i++)
        {
            auto reg = context.plic_enables + 4 * (i / 32);
            write32(reg, read32(reg) & ~(1 << i % 32));
            write32(PLIC_PRIO(i), 1);
        }
    }
}

void plic_chip::mask(unsigned int irq)
{
    for (auto &context : contexts)
    {
        auto reg = context.plic_enables + 4 * (irq / 32);
        write32(reg, read32(reg) & ~(1 << (irq % 32)));
    }
}

void plic_chip::unmask(unsigned int irq)
{
    for (auto &context : contexts)
    {
        auto reg = context.plic_enables + 4 * (irq / 32);
        write32(reg, read32(reg) | (1 << (irq % 32)));
    }
}

unsigned int plic_chip::claim()
{
    auto &context = current_context();
    return read32(context.plic_ctx + PLIC_CLAIM);
}

void plic_chip::complete(unsigned int intid)
{
    auto &context = current_context();
    write32(context.plic_ctx + PLIC_CLAIM, intid);
}

plic_chip *irqchip = nullptr;

int plic_probe(device *dev)
{
    irqchip = new plic_chip{(device_tree::node *) dev};
    if (!irqchip)
        return -ENOMEM;
    return irqchip->init();
}

static const char *plic_compatible_ids[] = {"sifive,plic-1.0.0", "riscv,plic0", nullptr};

static driver plic_driver = {
    .name = "plic",
    .devids = plic_compatible_ids,
    .probe = plic_probe,
    .bus_type_node = &plic_driver,
};

void plic_init()
{
    device_tree::register_driver(&plic_driver);
}

int platform_install_irq(unsigned int irqn, struct interrupt_handler * /*h*/)
{
    if (!irqchip)
        return -EIO;
    irqchip->unmask(irqn);
    return 0;
}

void platform_mask_irq(unsigned int irq)
{
    if (!irqchip)
        return;
    irqchip->mask(irq);
}

unsigned int plic_claim()
{
    if (!irqchip)
        return 0;
    return irqchip->claim();
}

void plic_complete(unsigned int intid)
{
    if (!irqchip)
        return;
    irqchip->complete(intid);
}
