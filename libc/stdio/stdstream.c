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
#include "stdio_impl.h"
#include <stdio.h>
#include <unistd.h>
FILE stdout_obj = {.fd = STDOUT_FILENO};
FILE stdin_obj = {.fd = STDIN_FILENO};
FILE stderr_obj = {.fd = STDERR_FILENO};
FILE *stdout = &stdout_obj;
FILE *stdin = &stdin_obj;
FILE *stderr = &stderr_obj;