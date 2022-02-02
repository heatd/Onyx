/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include "include/bga.h"

#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/module.h>
#include <onyx/mutex.h>
#include <onyx/video.h>

#define MPRINTF(...) printf("bga: "__VA_ARGS__)

static DECLARE_MUTEX(mtx);

void bga_set_index(uint16_t index)
{
    outw(VBE_DISPI_IOPORT_INDEX, index);
}

void bga_write_data(uint16_t value)
{
    outw(VBE_DISPI_IOPORT_DATA, value);
}

void bga_write(uint16_t index, uint32_t value)
{
    /* We need mutexes to protect a race condition
    (i.e: writing to the index port while someone is reading from the value port) */
    mutex_lock(&mtx);
    bga_set_index(index);
    bga_write_data(value);
    mutex_unlock(&mtx);
}

uint16_t bga_read(uint16_t index)
{
    mutex_lock(&mtx);
    bga_set_index(index);
    uint16_t ret = inw(VBE_DISPI_IOPORT_DATA);
    mutex_unlock(&mtx);
    return ret;
}

int bga_modeset(unsigned int width, unsigned int height, unsigned int bpp)
{
    /* Save the old resolutions in case shit goes south */
    uint16_t old_width = bga_read(VBE_DISPI_INDEX_XRES);
    uint16_t old_height = bga_read(VBE_DISPI_INDEX_YRES);
    uint16_t old_bpp = bga_read(VBE_DISPI_INDEX_BPP);

    bga_write(VBE_DISPI_INDEX_ENABLE, 0);
    bga_write(VBE_DISPI_INDEX_XRES, width);
    bga_write(VBE_DISPI_INDEX_YRES, height);
    bga_write(VBE_DISPI_INDEX_BPP, bpp);

    /* Check if the resolution was set*/
    if (bga_read(VBE_DISPI_INDEX_XRES) != width || bga_read(VBE_DISPI_INDEX_YRES) != height ||
        bga_read(VBE_DISPI_INDEX_BPP) != bpp)
    {
        bga_write(VBE_DISPI_INDEX_XRES, old_width);
        bga_write(VBE_DISPI_INDEX_YRES, old_height);
        bga_write(VBE_DISPI_INDEX_BPP, old_bpp);
        bga_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_LFB_ENABLED | 1);
        return -1;
    }

    bga_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_LFB_ENABLED | 1);
    return 0;
}

static struct pci::pci_id pci_bga_devids[] = {
    {PCI_ID_DEVICE(BOCHSVGA_PCI_VENDORID, BOCHSVGA_PCI_DEVICEID, NULL)}, {0}};

int bga_probe(struct device *dev)
{
    pci::pci_device *device = (pci::pci_device *)dev;

    if (device->enable_device() < 0)
        return -1;

    return 0;
}
static struct driver bga_driver = {
    .name = "bga", .devids = &pci_bga_devids, .probe = bga_probe, .bus_type_node = {&bga_driver}};

static int bga_init(void)
{
    pci::register_driver(&bga_driver);
    return 0;
}

int bga_fini(void)
{
    return 0;
}

MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");

MODULE_INIT(bga_init);
MODULE_FINI(bga_fini);
