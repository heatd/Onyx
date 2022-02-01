/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_DEVICE_TREE_H
#define _ONYX_DEVICE_TREE_H

#include <libfdt.h>

namespace device_tree
{

/**
 * @brief Initialise the device tree subsystem of the kernel
 * 
 * @param fdt Pointer to the flattened device tree
 */
void init(void *fdt);

}

#endif
