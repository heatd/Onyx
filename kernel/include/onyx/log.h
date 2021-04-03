/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_LOG_H
#define _KERNEL_LOG_H

#include <stdio.h>

#define INFO(x, ...) printf("[""INFO""] " x ": " __VA_ARGS__)
#define WARN(x, ...) printf("[""WARNING""] " x ": " __VA_ARGS__)
#define ERROR(x, ...) printf("[""ERROR""] " x ": " __VA_ARGS__)
#define FATAL(x, ...) printf("[""FATAL""] " x ": " __VA_ARGS__)

#define LOG INFO
#define SUBMIT_BUG_REPORT(x) printf("If you want this bug/feature to be fixed, open an issue at the repo's issue tracker(https://github.com/heatd/Onyx/issues) with a title along the lines of \"%s: Fix x bug\". Thanks!\n", x);

#ifdef CONFIG_LOG_BUF_MINIMAL
#define LOG_BUF_SHIFT   12
#else
#define LOG_BUF_SHIFT 	16
#endif
#define LOG_BUF_SIZE	(1 << LOG_BUF_SHIFT)


#define LOG_LEVEL_VERBOSE (1 << 0)
#define LOG_LEVEL_WARNING (1 << 1)
#define LOG_LEVEL_ERROR	  (1 << 2)
#define LOG_LEVEL_FATAL   (1 << 3)

void kernlog_set_log_level(unsigned int level);
void kernlog_send(unsigned int level, const char *msg, ...);
void kernlog_print(const char *msg);

#endif
