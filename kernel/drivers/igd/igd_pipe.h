/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _IGD_PIPE_H
#define _IGD_PIPE_H

#include "igpu_drv.h"

int igd_setup_pipes(struct igpu_device *dev);
void igd_update_pipe_mode(struct igd_pipe *pipe, struct igpu_device *dev);

#endif