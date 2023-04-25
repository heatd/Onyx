/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/clock.h>
#include <onyx/dev.h>
#include <onyx/device_tree.h>
#include <onyx/types.h>

#include <onyx/hwregister.hpp>

#define RTC_DR 0x0
#define RTC_LR 0x8
#define RTC_CR 0x0c

class pl031_dev
{
private:
    dev_resource *rsrc_;
    unsigned int irq_;
    hw_range range_;

public:
    pl031_dev(dev_resource *io, unsigned int irq) : rsrc_{io}, irq_{irq}, range_{rsrc_}
    {
    }

    int init();

    u64 get_time()
    {
        return range_.read32(RTC_DR);
    }

    int set_time(u64 time_epoch)
    {
        if (time_epoch > UINT32_MAX)
        {
            printf("pl031: The device does not support 64-bit time (tried to set time=%lx)\n",
                   time_epoch);
            return -EIO;
        }

        range_.write32(RTC_LR, (u32) time_epoch);
        return 0;
    }
};

#define RTC_CR_START (1 << 0)

int pl031_dev::init()
{
    if (!range_.init(rsrc_))
        return -ENOMEM;
    printf("pl031: initializing...\n");

    if (!(range_.read32(RTC_CR) & RTC_CR_START))
    {
        // We must only write the RTC start bit
        // *IF* it is not started already, else we reset the clock.
        range_.write32(RTC_CR, RTC_CR_START);
    }

    struct clock_time clk;
    clk.epoch = get_time();
    clk.measurement_timestamp = clocksource_get_time();
    time_set(CLOCK_REALTIME, &clk);
    return 0;
}

int pl031_dt_probe(device *fake_dev)
{
    auto dev = (device_tree::node *) fake_dev;

    // Find IRQ, IO resources
    auto irq_rc = dev->get_resource(DEV_RESOURCE_FLAG_IRQ);
    if (!irq_rc)
        return -1;

    auto iorsrc = dev->get_resource(DEV_RESOURCE_FLAG_MEM | DEV_RESOURCE_FLAG_IO_PORT);
    if (!iorsrc)
        return -1;

    unique_ptr<pl031_dev> gdev =
        make_unique<pl031_dev>(iorsrc, static_cast<uint16_t>(irq_rc->start()));
    if (!gdev)
        return -ENOMEM;

    if (int st = gdev->init(); st < 0)
        return st;
    gdev.release();
    return 0;
}

static const char *pl031_compatible_ids[] = {"arm,pl031", nullptr};

static driver pl031_driver = {
    .name = "pl031",
    .devids = pl031_compatible_ids,
    .probe = pl031_dt_probe,
    .bus_type_node = &pl031_driver,
};

int pl031_dt_init()
{
    device_tree::register_driver(&pl031_driver);
    return 0;
}

DRIVER_INIT(pl031_dt_init);
