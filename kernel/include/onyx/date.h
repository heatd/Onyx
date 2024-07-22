/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_DATE_H
#define _ONYX_DATE_H

#include <onyx/types.h>

#include <uapi/time.h>

typedef struct date
{
    int seconds;
    int minutes;
    int hours;
    int day;
    int month;
    int year;
    time_t unixtime;
} date_t;

u64 get_unix_time(const date_t *udate);

#endif
