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

class goldfish_rtc_dev
{
private:
    dev_resource *rsrc_;
    unsigned int irq_;
    hw_range range_;
    spinlock time_read_lock_;

#define GOLDFISH_RTC_TIME_LOW  0x00
#define GOLDFISH_RTC_TIME_HIGH 0x04

public:
    goldfish_rtc_dev(dev_resource *io, unsigned int irq) : rsrc_{io}, irq_{irq}, range_{rsrc_}
    {
        spinlock_init(&time_read_lock_);
    }

    int init();

    u64 get_time()
    {
        scoped_lock g{time_read_lock_};
        u64 timestamp_ns = range_.read32(GOLDFISH_RTC_TIME_LOW) |
                           ((u64) range_.read32(GOLDFISH_RTC_TIME_HIGH) << 32);
        return timestamp_ns / NS_PER_SEC;
    }
};

int goldfish_rtc_dev::init()
{
    if (!range_.init(rsrc_))
        return -ENOMEM;

    struct clock_time clk;
    clk.epoch = get_time();
    clk.measurement_timestamp = clocksource_get_time();
    time_set(CLOCK_REALTIME, &clk);
    return 0;
}

int goldfish_rtc_dt_probe(device *fake_dev)
{
    auto dev = (device_tree::node *) fake_dev;

    // Find IRQ, IO resources
    auto irq_rc = dev->get_resource(DEV_RESOURCE_FLAG_IRQ);
    if (!irq_rc)
        return -1;

    auto iorsrc = dev->get_resource(DEV_RESOURCE_FLAG_MEM | DEV_RESOURCE_FLAG_IO_PORT);
    if (!iorsrc)
        return -1;

    unique_ptr<goldfish_rtc_dev> gdev =
        make_unique<goldfish_rtc_dev>(iorsrc, static_cast<uint16_t>(irq_rc->start()));
    if (!gdev)
        return -ENOMEM;

    if (int st = gdev->init(); st < 0)
        return st;
    gdev.release();
    return 0;
}

static const char *goldfishrtc_compatible_ids[] = {"google,goldfish-rtc", nullptr};

static driver goldfishrtc = {
    .name = "goldfishrtc",
    .devids = goldfishrtc_compatible_ids,
    .probe = goldfish_rtc_dt_probe,
    .bus_type_node = &goldfishrtc,
};

int goldfishrtc_dt_init()
{
    device_tree::register_driver(&goldfishrtc);
    return 0;
}

DRIVER_INIT(goldfishrtc_dt_init);
