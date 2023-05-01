/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_IRQCHIP_H
#define _ONYX_IRQCHIP_H

#include <onyx/cpumask.h>
#include <onyx/irq.h>
#include <onyx/types.h>

/**
 * @brief Represents an IRQ on the interrupt controller
 *
 */
struct irqinfo
{
    /**
     * @brief IRQ number (as seen by the generic irq coe)
     *
     */
    unsigned int irq;
    /**
     * @brief Delivery flags (see IRQ_FLAG_*)
     *
     */
    unsigned int flags;
    /**
     * @brief IRQ delivery mask. The IRQ chip is not bound to
     * be able to deliver to *all* of them, but it must not deliver
     * to those not present in the mask.
     */
    cpumask delivery_mask;
};

/**
 * @brief Represents an individual interrupt chip in the kernel.
 *
 */
class irqchip
{
public:
    /**
     * @brief Prepare an IRQ on the interrupt chip for future delivery.
     * This routine should do irqchip-specific preparing, such as unmasking
     * and setting of IRQ flags like delivery mode, etc.
     *
     * @param irqinfo IRQ information
     * @return 0 on success, negative error codes
     */
    virtual int install_irq(const irqinfo &info) = 0;

    /**
     * @brief Mask an IRQ on the interrupt chip
     *
     * @param irq irqchip-specific interrupt number
     * @return 0 on success, negative error codes
     */
    virtual int mask_irq(unsigned int irq) = 0;

    /**
     * @brief Set an IRQ's flags, delivery mask, etc.
     * Modifies an IRQ line's flags, delivery mask, etc.
     * @param info Information to set
     * @return 0 on success, negative error codes
     */
    virtual int set_irq_info(const irqinfo &info) = 0;
};

#endif
