/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/date.h>
#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/port_io.h>

#include <drivers/nmi.h>
#include <drivers/rtc.h>

#define RTC_STATUS_B_UEI (1 << 4)
#define RTC_STATUS_B_PI  (1 << 6)

void nmi_enable()
{
    outb(0x70, inb(0x70) & 0x7F);
}

void nmi_disable()
{
    outb(0x70, inb(0x70) | 0x80);
}

static bool update_is_pending()
{
    outb(0x70, RTC_STATUS_REG_A);
    uint8_t b = inb(0x71);
    return b & 0x80;
}

bool enabled24_hour = false, binary_mode_enabled = false;

int rtc_get_date_reg(uint8_t reg)
{
    while (update_is_pending())
        ;

    nmi_disable();
    DISABLE_INTERRUPTS();
    outb(0x70, reg);
    uint8_t datereg = inb(0x71);
    ENABLE_INTERRUPTS();
    nmi_enable();
    int ret = datereg;
    if (!binary_mode_enabled)
    {
        ret = ((datereg / 16) * 10) + (datereg & 0xf);
        return ret;
    }
    else
        return ret;
}

int rtc_get_date_reg_early(uint8_t reg)
{
    while (update_is_pending())
        ;
    nmi_disable();
    outb(0x70, reg);
    uint8_t datereg = inb(0x71);
    nmi_enable();
    int ret = datereg;
    if (!binary_mode_enabled)
    {
        ret = ((datereg / 16) * 10) + (datereg & 0xf);
        return ret;
    }
    else
        return ret;
}

static date_t date;
void early_boot_rtc()
{
retry:
    date.seconds = rtc_get_date_reg_early(RTC_REG_SECONDS);
    date.minutes = rtc_get_date_reg_early(RTC_REG_MINUTES);
    date.hours = rtc_get_date_reg_early(RTC_REG_HOURS);
    date.day = rtc_get_date_reg_early(RTC_REG_MONTH_DAY);
    date.month = rtc_get_date_reg_early(RTC_REG_MONTH);
    date.year =
        rtc_get_date_reg_early(RTC_REG_CENTURY) * 100 + rtc_get_date_reg_early(RTC_REG_YEAR);

    if (date.seconds >= 60 || date.minutes >= 60 || date.hours >= 24 || date.day > 31 ||
        date.month > 12)
        goto retry;
    date.unixtime = get_unix_time(&date);
}

struct wallclock_source rtc_clock = {.clock_source = "x86 rtc", .get_posix_time = get_posix_time};

#define RTC_IRQ 8

void rtc_eoi()
{
    outb(0x70, RTC_STATUS_REG_C);
    inb(0x71);
}

irqstatus_t rtc_irq(struct irq_context *ctx, void *cookie)
{
    outb(0x70, RTC_STATUS_REG_C);
    uint8_t irq_reason = inb(0x71);

    if (irq_reason & RTC_STATUS_B_UEI)
    {
        struct timespec ts = {.tv_sec = get_posix_time()};
        time_set(CLOCK_REALTIME, &ts);
    }

    rtc_eoi();

    return IRQ_HANDLED;
}

#define RTC_PNP_STRING "PNP0B00"

struct acpi_dev_id rtc_dev_table[] = {{RTC_PNP_STRING}, {nullptr}};

int rtc_probe(struct device *device)
{
    INFO("rtc", "initializing\n");
    // Disable NMI's so we can access the CMOS without any risk of corruption
    nmi_disable();
    DISABLE_INTERRUPTS();
    outb(0x70, RTC_STATUS_REG_B);
    uint8_t b = inb(0x71);

    b |= RTC_STATUS_B_UEI;
    b &= ~RTC_STATUS_B_PI;

    outb(0x70, RTC_STATUS_REG_B);
    outb(0x71, b);

    // assert(install_irq(RTC_IRQ, rtc_irq, device, IRQ_FLAG_REGULAR, nullptr) == 0);
    /* Setup a frequency of 2hz by setting the divisor to 15 */
    outb(0x70, RTC_STATUS_REG_A);
    uint8_t st = inb(0x71);

    outb(0x70, RTC_STATUS_REG_A);
    outb(0x71, (st & 0xf0) | 15);
    outb(0x70, RTC_STATUS_REG_A);

    rtc_eoi();

    ENABLE_INTERRUPTS();
    nmi_enable();
    if (b & 2)
        enabled24_hour = true;
    if (b & 4)
        binary_mode_enabled = true;
    if (enabled24_hour)
        INFO("rtc", "24 hour mode set\n");
    if (binary_mode_enabled)
        INFO("rtc", "binary mode enabled\n");

    struct timespec ts = {.tv_sec = get_posix_time()};
    time_set(CLOCK_REALTIME, &ts);

    register_wallclock_source(&rtc_clock);

    return 0;
}

struct driver rtc_driver = {
    .name = "rtc", .devids = &rtc_dev_table, .probe = rtc_probe, .bus_type_node = {&rtc_driver}};

int init_rtc()
{
#ifdef CONFIG_ACPI
    acpi_bus_register_driver(&rtc_driver);
#endif
    return 0;
}

time_t get_posix_time()
{
retry:
    date.seconds = rtc_get_date_reg(RTC_REG_SECONDS);
    date.minutes = rtc_get_date_reg(RTC_REG_MINUTES);
    date.hours = rtc_get_date_reg(RTC_REG_HOURS);
    date.day = rtc_get_date_reg(RTC_REG_MONTH_DAY);
    date.month = rtc_get_date_reg(RTC_REG_MONTH);
    date.year = rtc_get_date_reg(RTC_REG_CENTURY) * 100 + rtc_get_date_reg(RTC_REG_YEAR);
    if (date.seconds >= 60 || date.minutes >= 60 || date.hours >= 24 || date.day > 31 ||
        date.month > 12)
        goto retry;
    date.unixtime = get_unix_time((const date_t *) &date);
    return date.unixtime;
}

uint64_t get_posix_time_early()
{
    return date.unixtime;
}

MODULE_INIT(init_rtc);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
