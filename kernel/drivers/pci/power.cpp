/*
 * Copyright (c) 2016-2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>

#include <onyx/dev.h>
#include <onyx/panic.h>

#include <pci/pci.h>

namespace pci
{

int pci_shutdown(struct device *__dev);

int pci_device::set_power_state(int power_state)
{
    pci_device *element = nullptr;
    void *saveptr = nullptr; /* Used by extrusive_list_get_element in a strtok_r kind of way */
    /* If we can't perform power management on this device, just return
     * success(it wasn't really an error was it?)
     */
    if (!has_power_management)
        return -ENOSYS;
    /* I guess we're already there, so just return */
    if (current_power_state == power_state)
        return 0;

    /* TODO: It's unsafe to cut power to the PCI bridge just like that, so we ignore setting it */
    if (type == PCI_TYPE_BRIDGE)
        return 0;

    /* Check if the desired power state is supported */
    if (supported_power_states & power_state)
        return -EINVAL; /* If not, just return */

    /* Set its children's power state as well */
    while ((element = (pci_device *) extrusive_list_get_element(&children, &saveptr)))
    {
        element->set_power_state(power_state);
    }
    /* Ok, if we can perform power management, get the PMCSR offset */
    uint16_t pmcsr_off = pm_cap_off + 4;

    uint16_t pmcsr = read(pmcsr_off, sizeof(uint16_t));

    /* Translate the argument into the actual bits */
    int p;
    switch (power_state)
    {
    case PCI_POWER_STATE_D0:
        p = 0;
        break;
    case PCI_POWER_STATE_D1:
        p = 1;
        break;
    case PCI_POWER_STATE_D2:
        p = 2;
        break;
    case PCI_POWER_STATE_D3:
        p = 3;
        break;
    default:
        panic("pci: Invalid target power state\n");
    }
    /* And set them in PMCSR, writing them back */
    // Zero out the old bits
    pmcsr &= ~((1 << 2) - 1);
    // OR the new power state
    pmcsr |= p;
    write(pmcsr, pmcsr_off, sizeof(uint16_t));
    return 0;
}

#if 0
int pci_shutdown(struct device *__dev)
{
	/* Okay, we're shutting down and our purpose here is to cut power to the device.
	 * Hopefully the device driver has already been notified that we're shutting down, so
	 * we're safe to cut power to the device by setting the power state to D3
	*/
	assert(__dev);
	return ((pci_device *) __dev)->set_power_state(PCI_POWER_STATE_D3);
}
#endif

} // namespace pci
