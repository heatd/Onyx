/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _RTC_DRIVERS_H
#define _RTC_DRIVERS_H

#include <stdint.h>

#define RTC_REG_SECONDS 0
#define RTC_REG_MINUTES 0x2
#define RTC_REG_HOURS 0x4
#define RTC_REG_WEEKDAY 0x6
#define RTC_REG_MONTH_DAY 0x7
#define RTC_REG_MONTH 0x8
#define RTC_REG_YEAR 0x9
#define RTC_REG_CENTURY 0x32
#define RTC_STATUS_REG_A 0xA
#define RTC_STATUS_REG_B 0xB
#define RTC_STATUS_REG_C 0xC
typedef struct date
{
	int seconds;
	int minutes;
	int hours;
	int day;
	int month;
	int year;
	uint64_t unixtime;
} date_t;

void init_rtc(void);
void early_boot_rtc(void);
uint64_t get_posix_time(void);
uint64_t get_posix_time_early(void);
#endif
