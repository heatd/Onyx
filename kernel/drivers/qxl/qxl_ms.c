/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/framebuffer.h>

#include <pci/pci.h>

#include "qxl.h"
#include "qxl_dev.h"

#define MPRINTF(...) printk("qxl: " __VA_ARGS__)

void do_print_mode(struct qxl_mode *mode)
{
    MPRINTF("Resolution %ux%ux%u\n", mode->x_res, mode->y_res, mode->bits);
}

void qxl_modeset(struct qxl_device *device, uint32_t mode)
{
    MPRINTF("Setting mode %u\n", mode);
    outl(device->iorange_bar.address + QXL_IO_SET_MODE, mode);
}

int qxl_list_modes(struct qxl_device *device)
{
    return 0;
}