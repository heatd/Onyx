#ifndef _LINUX_PCI_H
#define _LINUX_PCI_H

#include <linux/device.h>

struct pci_bus {
    unsigned int number;
};

struct pci_dev {
    struct linux_device dev_;
    void *private_;
    struct pci_bus *bus;
    unsigned int devfn;
};

#define PCI_FUNC(devfn) ((devfn) & 7)
#define PCI_SLOT(devfn) ((devfn) >> 3)

#define dev_is_pci(dev) ((dev)->is_pci)

static inline struct pci_dev *to_pci_dev(struct linux_device *dev)
{
    return container_of(dev, struct pci_dev, dev_);
}

unsigned int pci_domain_nr(struct pci_bus *bus);

#endif
