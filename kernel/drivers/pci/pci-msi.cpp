/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/page.h>
#include <onyx/platform.h>

#include <pci/pci-msi.h>
#include <pci/pci.h>

extern char irq0_end;

namespace pci
{

int pci_device::enable_msi(irq_t handler, void *cookie)
{
    if (!platform_has_msi())
        return errno = EIO, -1;

    bool msix = false;
    (void)msix;
    /* TODO: Try to prioritize finding MSI-X capabiltiies */
    size_t offset = find_capability(PCI_CAP_ID_MSI, 0);
    if (offset == 0)
    {
        msix = false;
        if ((offset = find_capability(PCI_CAP_ID_MSI, 0)) == 0)
            return -1;
    }

    uint16_t message_control = read(offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(uint16_t));

    bool addr64 = message_control & PCI_MSI_MSGCTRL_64BIT;

    unsigned int num_vecs = 1 << PCI_MSI_MSGCTRL_MMC(message_control);

    struct pci_msi_data data;
    if (platform_allocate_msi_interrupts(num_vecs, addr64, &data) < 0)
        return -1;

    for (unsigned int i = 0; i < num_vecs; i++)
    {
        assert(install_irq(data.irq_offset + i, handler, this, IRQ_FLAG_REGULAR, cookie) == 0);
    }

    message_control |= ilog2(num_vecs) << 4;
    message_control |= PCI_MSI_MSGCTRL_ENABLE;
    uint32_t message_addr = data.address;
    uint32_t message_addr_hi = data.address_high;
    uint32_t message_data = data.data;

    off_t message_data_off = addr64 ? offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 8
                                    : offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4;
    /* Now write everything back */
    write(message_addr, offset + PCI_MSI_MESSAGE_ADDRESS_OFF, sizeof(uint32_t));
    if (addr64)
        write(message_addr_hi, offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4, sizeof(uint32_t));
    write(message_data, message_data_off, sizeof(uint16_t));
    write(message_control, offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(uint16_t));

    return 0;
}

} // namespace pci
