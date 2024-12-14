/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/cpu.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/platform.h>

#include <drivers/mmio.h>
#include <pci/pci-msi.h>
#include <pci/pci.h>

namespace pci
{

int pci_device::enable_msi(irq_t handler, void *cookie)
{
    if (!platform_has_msi())
        return -EIO;

    size_t offset = find_capability(PCI_CAP_ID_MSI, 0);
    if (offset == 0)
        return -EIO;

    u16 message_control = read(offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(u16));
    bool addr64 = message_control & PCI_MSI_MSGCTRL_64BIT;
    unsigned int num_vecs = 1 << PCI_MSI_MSGCTRL_MMC(message_control);

    struct pci_msi_data data;
    if (platform_allocate_msi_interrupts(num_vecs, addr64, &data, 0, get_cpu_nr()) < 0)
        return -1;

    for (unsigned int i = 0; i < num_vecs; i++)
    {
        assert(install_irq(data.irq_offset + i, handler, this, IRQ_FLAG_REGULAR, cookie) == 0);
    }

    message_control |= ilog2(num_vecs) << 4;
    message_control |= PCI_MSI_MSGCTRL_ENABLE;
    u32 message_addr = data.address;
    u32 message_addr_hi = data.address_high;
    u32 message_data = data.data;

    off_t message_data_off = addr64 ? offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 8
                                    : offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4;
    /* Now write everything back */
    write(message_addr, offset + PCI_MSI_MESSAGE_ADDRESS_OFF, sizeof(u32));
    if (addr64)
        write(message_addr_hi, offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4, sizeof(u32));
    write(message_data, message_data_off, sizeof(u16));
    write(message_control, offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(u16));

    return 0;
}

} // namespace pci

int pci_enable_msix(pci::pci_device *dev, unsigned int min_vecs, unsigned int max_vecs,
                    unsigned int flags)
{
    size_t off;
    u16 msg_ctrl;
    u16 supported_vecs;
    u32 table_word, pba_word;

    if (!platform_has_msi())
        return -EIO;

    off = dev->find_capability(PCI_CAP_ID_MSI_X);
    if (off == 0)
        return -EIO;

    msg_ctrl = dev->read(off + PCI_MSIX_MSG_CTRL_OFF, sizeof(u16));
    supported_vecs = PCI_MSIX_MSG_CTRL_TABLE_SIZE(msg_ctrl);
    if (supported_vecs < min_vecs)
        return -EIO;
    max_vecs = cul::min(max_vecs, (unsigned int) supported_vecs);
    table_word = dev->read(off + PCI_MSIX_TABLE_OFF, sizeof(u32));
    pba_word = dev->read(off + PCI_MSIX_PBA_OFF, sizeof(u32));

    dev->msix_table =
        (struct pci::msix_table_entry *) dev->map_bar(table_word & PCI_MSIX_BIR_MASK, VM_NOCACHE);
    dev->msix_pba = (u32 *) dev->map_bar(pba_word & PCI_MSIX_BIR_MASK, VM_NOCACHE);
    if (!dev->msix_table || !dev->msix_pba)
        return -ENOMEM;

    dev->msix_table = (struct pci::msix_table_entry *) (((u8 *) dev->msix_table) +
                                                        (table_word & PCI_MSIX_OFF_MASK));
    dev->msix_pba = (u32 *) (((u8 *) dev->msix_pba) + (pba_word & PCI_MSIX_OFF_MASK));

    dev->msix_irqs = (u32 *) kcalloc(max_vecs, sizeof(u32), GFP_KERNEL);
    if (!dev->msix_irqs)
        return -ENOMEM;

    struct pci_msi_data data;

    /* We round-robin the irqs between cpus, starting from 0 -> 0, and so on */
    for (unsigned int i = 0; i < max_vecs; i++)
    {
        if (platform_allocate_msi_interrupts(1, true, &data, 0, i % get_nr_cpus()) < 0)
            return -EIO;
        dev->msix_irqs[i] = data.irq_offset;
        mmio_writel((unsigned long) &dev->msix_table[i].msg_addr, data.address);
        mmio_writel((unsigned long) &dev->msix_table[i].msg_upper_addr, data.address_high);
        mmio_writel((unsigned long) &dev->msix_table[i].msg_data, data.data);
        mmio_writel((unsigned long) &dev->msix_table[i].msg_vec_ctl,
                    mmio_readl((unsigned long) &dev->msix_table[i].msg_vec_ctl) &
                        ~MSIX_VEC_CTL_MASKED);
    }

    msg_ctrl &= ~PCI_MSIX_MSG_CTRL_FUNCTION_MASK;
    msg_ctrl |= PCI_MSIX_MSG_CTRL_MSIX_EN;
    dev->write(msg_ctrl, off + PCI_MSIX_MSG_CTRL_OFF, sizeof(u16));
    dev->msix_enabled = true;
    dev->nr_msix_vectors = max_vecs;
    return 0;
}

static int pci_enable_msi(pci::pci_device *dev, unsigned int min_vecs, unsigned int max_vecs,
                          unsigned int flags)
{
    if (!platform_has_msi())
        return errno = EIO, -1;

    size_t offset = dev->find_capability(PCI_CAP_ID_MSI, 0);
    if (offset == 0)
        return -EIO;

    u16 message_control = dev->read(offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(u16));
    bool addr64 = message_control & PCI_MSI_MSGCTRL_64BIT;
    unsigned int num_vecs = 1 << PCI_MSI_MSGCTRL_MMC(message_control);
    if (num_vecs < min_vecs)
        return -EIO;
    num_vecs = cul::min(max_vecs, (unsigned int) num_vecs);

    struct pci_msi_data data;
    if (platform_allocate_msi_interrupts(num_vecs, addr64, &data, 0, get_cpu_nr()) < 0)
        return -1;

    message_control |= ilog2(num_vecs) << 4;
    message_control |= PCI_MSI_MSGCTRL_ENABLE;
    u32 message_addr = data.address;
    u32 message_addr_hi = data.address_high;
    u32 message_data = data.data;

    off_t message_data_off = addr64 ? offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 8
                                    : offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4;
    /* Now write everything back */
    dev->write(message_addr, offset + PCI_MSI_MESSAGE_ADDRESS_OFF, sizeof(u32));
    if (addr64)
        dev->write(message_addr_hi, offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4, sizeof(u32));
    dev->write(message_data, message_data_off, sizeof(u16));
    dev->write(message_control, offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(u16));
    dev->msi_enabled = true;
    dev->msi_base = data.irq_offset;
    dev->nr_msi_vectors = num_vecs;
    return 0;
}

int pci_alloc_irqs(pci::pci_device *dev, unsigned int min_vecs, unsigned int max_vecs,
                   unsigned int flags)
{
    int st = 0;
    if (flags & PCI_IRQ_MSIX)
    {
        st = pci_enable_msix(dev, min_vecs, max_vecs, flags);
        if (!st)
            return st;
    }

    if (flags & PCI_IRQ_MSI)
    {
        st = pci_enable_msi(dev, min_vecs, max_vecs, flags);
        if (!st)
            return st;
    }

    if (flags & PCI_IRQ_INTX)
    {
        dev->enable_irq();
        return 0;
    }

    bus_warn(dev, "Could not enable IRQs\n");
    return -EIO;
}

int pci_get_irq(pci::pci_device *dev, unsigned int irq)
{
    if (dev->msix_enabled)
    {
        if (WARN_ON(irq >= dev->nr_msix_vectors))
            return -EIO;
        return dev->msix_irqs[irq];
    }

    if (dev->msi_enabled)
    {
        if (WARN_ON(irq >= dev->nr_msi_vectors))
            return -EIO;
        return dev->msi_base + irq;
    }

    /* Legacy interrupt range - we only have a single one */
    if (WARN_ON(dev->read(PCI_REGISTER_COMMAND, sizeof(uint32_t)) & PCI_COMMAND_INTR_DISABLE))
        return -EIO;

    if (WARN_ON(irq > 0))
        return -EIO;
    return dev->get_intn();
}

int pci_install_irq(pci::pci_device *dev, unsigned int irq, irq_t handler, unsigned int flags,
                    void *cookie, const char *name, ...)
{
    /* Name and the ... is ignored, for now */
    int real_irq = pci_get_irq(dev, irq);
    if (real_irq < 0)
        return real_irq;

    return install_irq(real_irq, handler, dev, flags, cookie);
}

int pci_get_nr_vectors(pci::pci_device *dev)
{
    if (dev->msix_enabled)
        return dev->nr_msix_vectors;
    if (dev->msi_enabled)
        return dev->nr_msi_vectors;
    if (WARN_ON(dev->read(PCI_REGISTER_COMMAND, sizeof(uint32_t)) & PCI_COMMAND_INTR_DISABLE))
        return -EIO;
    return 1;
}
