/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/bus_type.h>
#include <onyx/cred.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/vector.h>

#include <pci/pci.h>
#include <uapi/pciio.h>

#include <onyx/slice.hpp>

/* /dev/pci implementation as per FreeBSD pci(4) */

namespace pci
{
extern bus_type pci;
}

using namespace pci;

struct matching_data
{
    cul::slice<pci_match_conf> matchlist;
    cul::vector<pci_device *> matches;
};

int devpci_do_matching(struct bus *bus, struct pci_conf_io *cio, matching_data &data)
{
    auto doesmatch = [](pci_device *dev, const pci_match_conf &m) -> bool {
        const auto addr = dev->addr();
        if (m.flags & PCI_GETCONF_MATCH_DOMAIN && addr.segment != m.pc_sel.pc_domain)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_BUS && addr.bus != m.pc_sel.pc_bus)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_DEV && addr.device != m.pc_sel.pc_dev)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_FUNC && addr.function != m.pc_sel.pc_func)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_VENDOR && dev->vid() != m.pc_vendor)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_DEVICE && dev->did() != m.pc_device)
            return false;
        if (m.flags & PCI_GETCONF_MATCH_CLASS && dev->pci_class() != m.pc_class)
            return false;
        // TODO: Is this strncmp correct? maybe not?
        if (m.flags & PCI_GETCONF_MATCH_NAME && strncmp(dev->name, m.pd_name, PCI_MAXNAMELEN))
            return false;
        return true;
    };

    list_for_every (&bus->device_list_head)
    {
        auto dev = list_head_cpp<pci_device>::self_from_list_head(l);

        for (auto &m : data.matchlist)
        {
            if (doesmatch(dev, m))
            {
                if (!data.matches.push_back(dev))
                    return -ENOMEM;
            }
        }
    }

    return 0;
}

static inline pcisel daddr_to_pcisel(const device_address &addr)
{
    return {addr.segment, addr.bus, addr.device, addr.function};
}

static inline device_address pcisel_to_daddr(const pcisel &addr)
{
    return {addr.pc_domain, addr.pc_bus, addr.pc_dev, addr.pc_func};
}

int devpci_do_getconf(struct pci_conf_io *cio)
{
    matching_data data;
    pci_conf *uconf;
    __u32 nr;
    int st = 0;

    auto npatterns = cio->num_patterns;

    if (!npatterns)
    {
        npatterns++;
    }

    const auto mconflen = sizeof(pci_match_conf) * npatterns;

    pci_match_conf *mconf = (pci_match_conf *) malloc(mconflen);
    if (!mconf)
        return -ENOMEM;

    if (!cio->num_patterns)
    {
        mconf->flags = 0;
    }
    else
    {
        if (copy_from_user(mconf, cio->patterns, mconflen) < 0)
        {
            st = -EFAULT;
            goto out;
        }
    }

    data.matchlist = {mconf, npatterns};

    pci::pci.for_every_bus([&](struct bus *bus) -> bool {
        st = devpci_do_matching(bus, cio, data);
        return st == 0;
    });

    if (st != 0)
        goto out;

    uconf = cio->matches;
    nr = cio->num_matches;

    cio->num_matches = 0;

    for (auto dev : data.matches)
    {
        if (!nr)
        {
            cio->status = PCI_GETCONF_MORE_DEVS;
            return 0;
        }

        pci_conf conf;
        conf.pc_sel = daddr_to_pcisel(dev->addr());
        conf.pc_subdevice = 0; // XXX todo sub{device, vendor}
        conf.pc_subvendor = 0;
        conf.pc_vendor = dev->vid();
        conf.pc_device = dev->did();
        conf.pc_class = dev->pci_class();
        conf.pc_subclass = dev->sub_class();
        conf.pc_progif = dev->prog_if();
        conf.pc_revid = 0; // XXX todo revid
        conf.pc_hdr = dev->header_type() & 0x7f;

#if 0
        printk("%04x:%02x:%02x:%02x\n", dev->addr().segment, dev->addr().bus, dev->addr().device,
               dev->addr().function);
#endif
        const auto driver = dev->driver_;

        if (driver)
        {
            strlcpy(conf.pd_name, driver->name, PCI_MAXNAMELEN);
        }

        conf.pd_unit = 0;

        if (copy_to_user(uconf, &conf, sizeof(conf)) < 0)
        {
            return -EFAULT;
        }

        uconf++, nr--;
        cio->num_matches++;
    }

    cio->status = PCI_GETCONF_LAST_DEVICE;

out:
    free(mconf);
    return st;
}

static int putciost(struct pci_conf_io *ucio, pci_conf_status status)
{
    return copy_to_user(&ucio->status, &status, sizeof(status));
}

int devpci_getconf(struct pci_conf_io *ucio)
{
    struct pci_conf_io cio;
    if (copy_from_user(&cio, ucio, sizeof(*ucio)) < 0)
        return -EFAULT;

    if (cio.num_patterns * sizeof(pci_match_conf) != cio.pat_buf_len)
    {
        return putciost(ucio, PCI_GETCONF_ERROR) ?: -EINVAL;
    }

    if (cio.num_matches * sizeof(pci_conf) != cio.match_buf_len)
    {
        return putciost(ucio, PCI_GETCONF_ERROR) ?: -EINVAL;
    }

    cio.status = PCI_GETCONF_ERROR;

    int st = devpci_do_getconf(&cio);

    if (copy_to_user(ucio, &cio, sizeof(cio)) < 0)
        return -EFAULT;
    return st;
}

/**
 * @brief Calculate the register limit for devpci
 *
 * @return The maximum register you can access, in this context for this user.
 */
__u16 devpci_reg_limit()
{
    if (is_root_user())
        return pcie_is_enabled() ? 4096 : 256;

    // Linux seems to believe the first 64 bytes are safe for non-root access
    return 64;
}

int devpci_read(struct pci_io *arg, struct file *file)
{
    struct pci_io io;
    if (copy_from_user(&io, arg, sizeof(io)) < 0)
        return -EFAULT;

    if (!fd_may_access(file, FILE_ACCESS_READ))
        return -EPERM;

    auto daddr = pcisel_to_daddr(io.pi_sel);
    auto dev = pci::get_device(daddr);

    if (!dev)
        return -ENODEV;
    if (io.pi_width > 4 || io.pi_width == 0 || io.pi_width & 1)
    {
        // Only valid widths are 1, 2, 4
        return -EINVAL;
    }

    const auto reglimit = devpci_reg_limit();

    if (io.pi_reg >= reglimit)
    {
        return is_root_user() ? -EINVAL : -EPERM;
    }

    const __u32 val = (__u32) dev->read(io.pi_reg, io.pi_width);

    return copy_to_user(&arg->pi_data, &val, sizeof(__u32));
}

int devpci_write(struct pci_io *arg, struct file *file)
{
    struct pci_io io;
    if (copy_from_user(&io, arg, sizeof(io)) < 0)
        return -EFAULT;

    if (!fd_may_access(file, FILE_ACCESS_WRITE))
        return -EPERM;

    if (!is_root_user())
        return -EPERM;

    auto daddr = pcisel_to_daddr(io.pi_sel);
    auto dev = pci::get_device(daddr);

    if (!dev)
        return -ENODEV;
    if (io.pi_width > 4 || io.pi_width == 0 || io.pi_width & 1)
    {
        // Only valid widths are 1, 2, 4
        return -EINVAL;
    }

    const auto reglimit = devpci_reg_limit();

    if (io.pi_reg >= reglimit)
    {
        return is_root_user() ? -EINVAL : -EPERM;
    }

    dev->write(io.pi_data, io.pi_reg, io.pi_width);

    return 0;
}

static int devpci_getbar(struct pci_bar_io *uio, struct file *file)
{
    struct pci_bar_io io;
    if (copy_from_user(&io, uio, sizeof(io)) < 0)
        return -EFAULT;

    if (!fd_may_access(file, FILE_ACCESS_READ))
        return -EPERM;

    auto daddr = pcisel_to_daddr(io.pbi_sel);
    auto dev = pci::get_device(daddr);

    if (!dev)
        return -ENODEV;

    if (io.pbi_reg < 0x10 || io.pbi_reg % 4)
        return -EINVAL;

    unsigned int bar = (io.pbi_reg - PCI_BAR0) / 4;

    if (bar >= dev->nr_bars())
        return -EINVAL;

    auto resource =
        dev->get_resource_busindex(DEV_RESOURCE_FLAG_MEM | DEV_RESOURCE_FLAG_IO_PORT, bar);

    if (!resource)
        return -EINVAL;

    io.pbi_base = resource->start();
    io.pbi_enabled = 1;
    io.pbi_length = resource->size();

    return copy_to_user(uio, &io, sizeof(io));
}

static unsigned int devpci_ioctl(int request, void *argp, struct file *file)
{
    switch (request)
    {
        case PCIOCGETCONF:
            return devpci_getconf((struct pci_conf_io *) argp);
        case PCIOCREAD:
            return devpci_read((struct pci_io *) argp, file);
        case PCIOCGETBAR:
            return devpci_getbar((struct pci_bar_io *) argp, file);
        case PCIOCWRITE:
            return devpci_write((struct pci_io *) argp, file);
    }

    return -ENOTTY;
}

static const file_ops devpci_ops = {.ioctl = devpci_ioctl};
void devpci_init()
{
    auto ex = dev_register_chardevs(0, 1, 0, &devpci_ops, "pci");

    ex.unwrap()->show(0644);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(devpci_init);
