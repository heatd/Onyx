/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _RTC_DRIVERS_H
#define _RTC_DRIVERS_H

#include <stdint.h>
#include <time.h>

#define RTC_REG_SECONDS   0
#define RTC_REG_MINUTES   0x2
#define RTC_REG_HOURS     0x4
#define RTC_REG_WEEKDAY   0x6
#define RTC_REG_MONTH_DAY 0x7
#define RTC_REG_MONTH     0x8
#define RTC_REG_YEAR      0x9
#define RTC_REG_CENTURY   0x32
#define RTC_STATUS_REG_A  0xA
#define RTC_STATUS_REG_B  0xB
#define RTC_STATUS_REG_C  0xC

void early_boot_rtc(void);
time_t get_posix_time(void);
uint64_t get_posix_time_early(void);

#endif
