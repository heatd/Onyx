/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _INIT_H
#define _INIT_H

#include <stdbool.h>
#include <unistd.h>

#define DEFAULT_TARGETS_PATH		"/etc/init.d/targets"
#define MODULE_PREFIX "/usr/lib/modules/"
#define MODULE_EXT    ".ko"
#define PROPERTY_SERVICE "Service"
#define PROPERTY_DEPENDENCIES "Dependencies"
#define SUBPROP_WANTS "Wants"
#define SUBPROP_BIN "Bin"
#define SUBPROP_TYPE "Type"

struct subproperty
{
	char *name;
	char *value;
	struct subproperty *next; 
};

struct property
{
	char *prop_name;
	struct subproperty *props;
	struct property *next;
};

typedef struct target
{
	struct property *properties;
	struct property *current_property;
} target_t;

struct daemon
{
	pid_t pid;
	const char *name;
	struct daemon *next;
};

int exec_target(int fd);
int exec_daemons(void);

/**
 * @brief Retrieves daemon information of a given pid.
 * 
 * @param pid Process ID to check
 * @return Pointer to the daemon's information, or NULL if its not
 *         a registered daemon.
 */
struct daemon* get_daemon_from_pid(pid_t pid);

#endif
