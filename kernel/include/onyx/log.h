/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_LOG_H
#define _KERNEL_LOG_H

#include <stdio.h>

#include <onyx/tty.h>
#define INFO(x, ...) printf("["ANSI_COLOR_GREEN"INFO"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define WARN(x, ...) printf("["ANSI_COLOR_YELLOW"WARNING"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define ERROR(x, ...) printf("["ANSI_COLOR_RED"ERROR"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)
#define FATAL(x, ...) printf("["ANSI_COLOR_RED"FATAL"ANSI_COLOR_RESET"] "x": "__VA_ARGS__)

#define LOG INFO
#define SUBMIT_BUG_REPORT(x) printf("If you want this bug/feature to be fixed, open an issue at the repo's issue tracker(https://github.com/heatd/Onyx/issues) with a title along the lines of \"%s: Fix x bug\". Thanks!\n", x);

#define LOG_BUF_SHIFT 	18
#define LOG_BUF_SIZE	(1 << LOG_BUF_SHIFT)

void kernlog_print(const char *msg);
#endif
