/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdbool.h>
#include <stdio.h>

#include <kernel/portio.h>
#include <kernel/irq.h>
#include <kernel/pic.h>
#include <kernel/log.h>

#include <drivers/nmi.h>
#include <drivers/rtc.h>

void nmi_enable()
{
	outb(0x70, inb(0x70) & 0x7F);
}
void nmi_disable()
{
	outb(0x70, inb(0x70) | 0x80);
}
_Bool enabled24_hour = false, binary_mode_enabled = false;
int rtc_get_date_reg(uint8_t reg)
{
	nmi_disable();
	asm volatile("cli");
	outb(0x70, reg);
	uint8_t datereg = inb(0x71);
	asm volatile("sti");
	nmi_enable();
	int ret = datereg;
	if(!binary_mode_enabled)
	{
		ret = ((datereg / 16) * 10) + (datereg & 0xf);
		return ret;
	}
	else
		return ret;
}
int rtc_get_date_reg_early(uint8_t reg)
{
	nmi_disable();
	outb(0x70, reg);
	uint8_t datereg = inb(0x71);
	nmi_enable();
	int ret = datereg;
	if(!binary_mode_enabled)
	{
		ret = ((datereg / 16) * 10) + (datereg & 0xf);
		return ret;
	}
	else
		return ret;
}
const int months[] = 
{
	31,
	28, 
	31,
	30,
	31,
	30,
	31,
	31,
	30,
	31,
	30,
	31
};
uint64_t get_unix_time(const date_t const *udate)
{
	uint64_t utime = 0;
	for(int i = 1970; i < udate->year; i++)
	{
		if(i % 100 == 0)
		{
			utime += 365 * 24 * 60 * 60;
		}
		else if (i % 400 == 0)
		{
			utime += 366 * 24 * 60 * 60; 
		}
		else if(i % 4 == 0)
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
	for(int m = 0; m < udate->month-1; m++)
	{
		total_day += months[m];
	}
	total_day += udate->day;
	if (udate->year % 400 == 0)
	{
		total_day++; 
	}
	else if(udate->year % 4 == 0)
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
static uintptr_t rtc_handler(registers_t *regs)
{
	date.seconds = rtc_get_date_reg(RTC_REG_SECONDS);
	date.minutes = rtc_get_date_reg(RTC_REG_MINUTES);
	date.hours = rtc_get_date_reg(RTC_REG_HOURS);
	date.day = rtc_get_date_reg(RTC_REG_MONTH_DAY);
	date.month = rtc_get_date_reg(RTC_REG_MONTH);
	date.year = rtc_get_date_reg(RTC_REG_CENTURY) * 100 + rtc_get_date_reg(RTC_REG_YEAR);
	date.unixtime = get_unix_time((const date_t *const) &date);
	// Needed for the RTC to fire again
	outb(0x70, RTC_STATUS_REG_C);
	asm volatile("":::"memory");
	inb(0x71);
	return 0;
}
void early_boot_rtc()
{
	date.seconds = rtc_get_date_reg_early(RTC_REG_SECONDS);
	date.minutes = rtc_get_date_reg_early(RTC_REG_MINUTES);
	date.hours = rtc_get_date_reg_early(RTC_REG_HOURS);
	date.day = rtc_get_date_reg_early(RTC_REG_MONTH_DAY);
	date.month = rtc_get_date_reg_early(RTC_REG_MONTH);
	date.year = rtc_get_date_reg_early(RTC_REG_CENTURY) * 100 + rtc_get_date_reg_early(RTC_REG_YEAR);
	date.unixtime = get_unix_time(&date);
}
void init_rtc()
{
	INFO("rtc", "initializing\n");
	// Disable NMI's so we can access the CMOS without any risk of corruption
	nmi_disable();
	asm volatile("cli");
	outb(0x70, RTC_STATUS_REG_B);
	uint8_t b = inb(0x71);
	asm volatile("sti");
	nmi_enable();
	if(b & 2)
		enabled24_hour = true;
	if(b & 4)
		binary_mode_enabled = true;
	if(enabled24_hour)
		INFO("rtc", "24 hour mode set\n");
	if(binary_mode_enabled)
		INFO("rtc", "binary mode enabled\n");
	date.seconds = rtc_get_date_reg(RTC_REG_SECONDS);
	date.minutes = rtc_get_date_reg(RTC_REG_MINUTES);
	date.hours = rtc_get_date_reg(RTC_REG_HOURS);
	date.day = rtc_get_date_reg(RTC_REG_MONTH_DAY);
	date.month = rtc_get_date_reg(RTC_REG_MONTH);
	date.year = rtc_get_date_reg(RTC_REG_CENTURY) * 100 + rtc_get_date_reg(RTC_REG_YEAR);
	date.unixtime = get_unix_time(&date);
	// Enable IRQ8
	irq_install_handler(8, rtc_handler);
	nmi_disable();
	asm volatile("cli");
	outb(0x70, RTC_STATUS_REG_B);
	b = inb(0x71);
	outb(0x70, RTC_STATUS_REG_B | 0x80);
	outb(0x71, b | 0x40);
	nmi_enable();
	asm volatile("sti");
}
uint64_t get_posix_time()
{
	return date.unixtime;
}
