/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/arm64/gic.h>
#include <onyx/dev.h>
#include <onyx/dev_resource.h>
#include <onyx/device_tree.h>
#include <onyx/init.h>

#include <onyx/hwregister.hpp>

class gic_chip
{
private:
    device_tree::node *node_;
    hw_range gicd_range;
    hw_range gicc_range;
    unsigned int nr_irqs{0};

public:
    gic_chip(device_tree::node *node, hw_range &&gicd, hw_range &&gicc)
        : node_{node}, gicd_range{gicd}, gicc_range{gicc}
    {
    }

    int init();
    void unmask(unsigned int irqn);
    void mask(unsigned int irqn);
    unsigned int claim();
    void eoi(unsigned int irqn);
};

int gic_chip::init()
{
    // First, disable all kinds of interrupt forwarding
    gicd_range.write32(GICD_CTLR, 0);

    // Get the number of irqs implemented
    auto typer = gicd_range.read32(GICD_TYPER);
    nr_irqs = (GICD_TYPER_ITLINESNUMBER(typer) + 1) * 32;
    printk("gic: nr_irqs implemented: %u\n", nr_irqs);

    const auto iidr = gicd_range.read32(GICD_IIDR);
    printk("gic: implementer: %x\n", iidr);

    // Disable all interrupts
    for (unsigned int irq = 0; irq < nr_irqs; irq += 32)
        gicd_range.write32(GICD_ICENABLER(irq), 0xffffffff);

    // Enable the CPU interface
    gicc_range.write32(GICC_CTLR, GICC_CTLR_ENABLE);
    gicc_range.write32(GICC_PMR, 0xff);
    gicd_range.write32(GICD_CTLR, GICD_CTLR_ENABLE);

    return 0;
}

void gic_chip::unmask(unsigned int irqn)
{
    gicd_range.write32(GICD_ISENABLER(irqn), (1U << (irqn % 32)));
}

void gic_chip::mask(unsigned int irqn)
{
    gicd_range.write32(GICD_ICENABLER(irqn), (1U << (irqn % 32)));
}

unsigned int gic_chip::claim()
{
    return gicc_range.read32(GICC_IAR);
}

void gic_chip::eoi(unsigned int irqn)
{
    gicc_range.write32(GICC_EOIR, irqn);
}

static gic_chip *irqchip;

int gic_probe(device *dev)
{
    auto gicd_res = dev->get_resource(DEV_RESOURCE_FLAG_MEM);
    auto gicc_res = dev->get_resource(DEV_RESOURCE_FLAG_MEM, 1);

    if (!gicd_res || !gicc_res)
    {
        printf("gic: device tree node did not have GICD and GICC memory ranges\n");
        return -EIO;
    }

    hw_range gicd_range{gicd_res};
    hw_range gicc_range{gicc_res};

    if (!gicd_range.init(gicd_res) || !gicc_range.init(gicc_res))
    {
        printf("gic: Failed to initialize gicd/gicc hardware ranges\n");
        return -EIO;
    }

    irqchip = new gic_chip{(device_tree::node *) dev, cul::move(gicd_range), cul::move(gicc_range)};
    if (!irqchip)
        return -ENOMEM;
    return irqchip->init();
}

static const char *gic_compatible_ids[] = {"arm,cortex-a15-gic",
                                           /* TODO(pedro): more ids */ nullptr};

static driver gic_driver = {
    .name = "gic",
    .devids = gic_compatible_ids,
    .probe = gic_probe,
    .bus_type_node = &gic_driver,
};

void gic_init()
{
    device_tree::register_driver(&gic_driver);
}

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h)
{
    CHECK(irqchip != nullptr);
    irqchip->unmask(irqn);
    // TODO: edge, level, etc
    return 0;
}

void platform_mask_irq(unsigned int irq)
{
    CHECK(irqchip != nullptr);
    irqchip->mask(irq);
}

unsigned int arm64_irq_claim()
{
    CHECK(irqchip != nullptr);
    return irqchip->claim();
}

void arm64_irq_eoi(unsigned int irqn)
{
    CHECK(irqchip != nullptr);
    return irqchip->eoi(irqn);
}

INIT_LEVEL_EARLY_PLATFORM_ENTRY(gic_init);
