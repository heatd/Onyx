/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>

#include "igpu_drv.h"
#include "intel_regs.h"

int igd_enable_power_well1_skylake(struct igpu_device *dev)
{
    uint32_t pwr_well_ctl = igpu_mmio_read(dev, PWR_WELL_CTL2);

    igpu_mmio_write(dev, PWR_WELL_CTL2, pwr_well_ctl | PWR_WELL_CTL_PW1_REQ);

    if (igpu_wait_bit(dev, PWR_WELL_CTL2, PWR_WELL_CTL_PW1_STATE, NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    if (igpu_wait_bit(dev, FUSE_STATUS, FUSE_STATUS_PG1_DISTRIB_STATUS, NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    return 0;
}

int igd_enable_power_well1_haswell(struct igpu_device *dev)
{
    uint32_t pwr_well_ctl = igpu_mmio_read(dev, PWR_WELL_CTL1);

    igpu_mmio_write(dev, PWR_WELL_CTL1, pwr_well_ctl | PWR_WELL_CTL_PW_REQ);

    if (igpu_wait_bit(dev, PWR_WELL_CTL1, PWR_WELL_CTL_PW_STATE, 10 * NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    return 0;
}

int igd_enable_power_well2_haswell(struct igpu_device *dev)
{
    uint32_t pwr_well_ctl = igpu_mmio_read(dev, PWR_WELL_CTL2);

    igpu_mmio_write(dev, PWR_WELL_CTL2, pwr_well_ctl | PWR_WELL_CTL_PW_REQ);

    if (igpu_wait_bit(dev, PWR_WELL_CTL2, PWR_WELL_CTL_PW_STATE, 10 * NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    return 0;
}

int igd_enable_power_well2_skylake(struct igpu_device *dev)
{
    uint32_t pwr_well_ctl = igpu_mmio_read(dev, PWR_WELL_CTL2);

    igpu_mmio_write(dev, PWR_WELL_CTL2, pwr_well_ctl | PWR_WELL_CTL_PW2_REQ);

    if (igpu_wait_bit(dev, PWR_WELL_CTL2, PWR_WELL_CTL_PW2_STATE, 10 * NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    if (igd_get_arch(dev) == INTEL_ARCH_SKYLAKE)
    {
        if (igpu_wait_bit(dev, FUSE_STATUS, FUSE_STATUS_PG2_DISTRIB_STATUS, 10 * NS_PER_MS, false) <
            0)
            return -ETIMEDOUT;
    }

    return 0;
}

int igd_enable_ddi(struct igpu_device *dev)
{
    uint32_t pwr_well_ctl = igpu_mmio_read(dev, PWR_WELL_CTL2);
    pwr_well_ctl |= PWR_WELL_CTL_MISC_IO_PWREQ;
    pwr_well_ctl |= PWR_WELL_CTL_DDIA_E_PWREQ;
    pwr_well_ctl |= PWR_WELL_CTL_DDIB_PWREQ;
    pwr_well_ctl |= PWR_WELL_CTL_DDIC_PWREQ;
    pwr_well_ctl |= PWR_WELL_CTL_DDID_PWREQ;

    uint32_t status_mask = PWR_WELL_CTL_MISC_IO_STATE | PWR_WELL_CTL_DDIA_E_STATE |
                           PWR_WELL_CTL_DDIB_STATE | PWR_WELL_CTL_DDIC_STATE |
                           PWR_WELL_CTL_DDID_STATE;

    igpu_mmio_write(dev, PWR_WELL_CTL2, pwr_well_ctl);

    if (igpu_wait_bit(dev, PWR_WELL_CTL2, status_mask, NS_PER_MS, false) < 0)
        return -ETIMEDOUT;

    return 0;
}

int igd_enable_power_skylake(struct igpu_device *dev)
{
    int st;

    igpu_mmio_write(dev, NDE_RSTWRN_OPT, NDE_RST_PCH_HANDSHAKE_ENABLE);

    if (igpu_wait_bit(dev, FUSE_STATUS, FUSE_STATUS_PG0_DISTRIB_STATUS, NS_PER_MS, false) < 0)
    {
        printk("PG0 timeout\n");
        return -ETIMEDOUT;
    }

    st = igd_enable_power_well1_skylake(dev);
    if (st < 0)
    {
        printk("PG1 timeout\n");
        return st;
    }

    st = igd_enable_power_well2_skylake(dev);

    if (st < 0)
    {
        printk("PG2 timeout\n");
        return st;
    }

    st = igd_enable_ddi(dev);

    if (st < 0)
    {
        printk("DDI timeout\n");
        return st;
    }

    return 0;
}

int igd_enable_power_haswell(struct igpu_device *dev)
{
    igpu_mmio_write(dev, NDE_RSTWRN_OPT, NDE_RST_PCH_HANDSHAKE_ENABLE);
    int st;

    st = igd_enable_power_well1_haswell(dev);
    if (st < 0)
    {
        printk("PG1 timeout\n");
        return st;
    }

    st = igd_enable_power_well2_haswell(dev);

    if (st < 0)
    {
        printk("PG2 timeout\n");
        return st;
    }

    return 0;
}

int igd_enable_power(struct igpu_device *dev)
{
    struct igpu_driver_data *data = dev->device->driver_data;

    assert(data->enable_power != NULL);

    return data->enable_power(dev);
}