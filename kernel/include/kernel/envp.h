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
#ifndef _ENVP_H
#define _ENVP_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

char **copy_env_vars(char **envp);
char **copy_argv(char **argv, const char *path, int *argc);

#endif