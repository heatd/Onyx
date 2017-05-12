/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ENVP_H
#define _ENVP_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

char **copy_env_vars(char **envp);
char **copy_argv(char **argv, const char *path, int *argc);

#endif