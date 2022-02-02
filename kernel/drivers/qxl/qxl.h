/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _QXL_QXL_H
#define _QXL_QXL_H

#include <pci/pci.h>

#include "qxl_dev.h"

struct qxl_device
{
    unsigned long irq_count;
    struct pci_bar vram_bar;
    struct pci_bar surface_bar;
    struct pci_bar rom_bar;
    struct pci_bar iorange_bar;
    void *vram_mapping;
    pci::pci_device *device;
    void *surface_mapping;
    struct qxl_rom *rom;
    struct qxl_ram_header *ram_header;
};

#define QXL_INTERRUPT_MASK                                                 \
    (QXL_INTERRUPT_DISPLAY | QXL_INTERRUPT_CURSOR | QXL_INTERRUPT_IO_CMD | \
     QXL_INTERRUPT_CLIENT_MONITORS_CONFIG)

int qxl_list_modes(struct qxl_device *device);

#endif
