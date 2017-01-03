/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_LOG_H
#define _KERNEL_LOG_H

#include <stdio.h>

#include <kernel/tty.h>
#define INFO(x, ...) printf("["ANSI_COLOR_GREEN"INFO"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define WARN(x, ...) printf("["ANSI_COLOR_RED"WARNING"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define ERROR(x, ...) printf("["ANSI_COLOR_RED"ERROR"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define FATAL(x, ...) printf("["ANSI_COLOR_RED"FATAL"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)

#define LOG INFO
#define SUBMIT_BUG_REPORT(x) printf("If you want this bug/feature to be fixed, open an issue at the repo's issue tracker(https://github.com/heatd/Spartix/issues) with a title along the lines of \"%s: Fix x bug\". Thanks!\n", x);
#endif
