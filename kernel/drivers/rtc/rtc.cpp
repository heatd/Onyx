/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/clock.h>
#include <onyx/cpu.h>
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

static bool update_is_pending(void)
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

const int months[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

uint64_t get_unix_time(const date_t *const udate)
{
    uint64_t utime = 0;
    for (int i = 1970; i < udate->year; i++)
    {
        if (i % 100 == 0)
        {
            utime += 365 * 24 * 60 * 60;
        }
        else if (i % 400 == 0)
        {
            utime += 366 * 24 * 60 * 60;
        }
        else if (i % 4 == 0)
        {
            utime += 366 * 24 * 60 * 60;
        }
        else
        {
            utime += 365 * 24 * 60 * 60;
        }
    }

    // Calculate this year's POSIX time
    int total_day = 0;
    int month = udate->month - 1;
    assert(month < 12);
    for (int m = 0; m < month; m++)
    {
        total_day += months[m];
    }
    total_day += udate->day;
    if (udate->year % 400 == 0)
    {
        total_day++;
    }
    else if (udate->year % 4 == 0)
    {
        total_day++;
    }

    utime += total_day * 86400;
    utime += udate->hours * 60 * 60;
    utime += udate->minutes * 60;
    utime += udate->seconds;

    return utime;
}

static date_t date;
void early_boot_rtc(void)
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

time_t get_posix_time(void);

struct wallclock_source rtc_clock = {.clock_source = "x86 rtc", .get_posix_time = get_posix_time};

#define RTC_IRQ 8

void rtc_eoi(void)
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
        struct clock_time clk;
        clk.epoch = get_posix_time();
        clk.source = get_main_clock();
        clk.tick = clk.source->get_ticks();
        time_set(CLOCK_REALTIME, &clk);
    }

    rtc_eoi();

    return IRQ_HANDLED;
}

#define RTC_PNP_STRING "PNP0B00"

struct acpi_dev_id rtc_dev_table[] = {{RTC_PNP_STRING}, {NULL}};

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

    assert(install_irq(RTC_IRQ, rtc_irq, device, IRQ_FLAG_REGULAR, NULL) == 0);
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

    struct clock_time clk;
    clk.epoch = get_posix_time();
    clk.source = get_main_clock();
    clk.tick = clk.source->get_ticks();
    time_set(CLOCK_REALTIME, &clk);

    register_wallclock_source(&rtc_clock);

    return 0;
}

struct driver rtc_driver = {
    .name = "rtc", .devids = &rtc_dev_table, .probe = rtc_probe, .bus_type_node = {&rtc_driver}};

int init_rtc(void)
{
    acpi_bus_register_driver(&rtc_driver);
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
    date.unixtime = get_unix_time((const date_t *)&date);
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
