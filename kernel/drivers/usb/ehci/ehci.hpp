/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#pragma once

#include <stdint.h>

#include <pci/pci.h>

#include "ehciregs.hpp"

struct usb_periodic_frame
{
    uint32_t dword0;
};

#define PERIODIC_FRAME_END_BIT                           (1 << 0)
#define PERIODIC_FRAME_TYPE_ISOCHRONOUS_TRANSFER_DESC    (0 << 1)
#define PERIODIC_FRAME_TYPE_QUEUE_HEAD                   (1 << 1)
#define PERIODIC_FRAME_TYPE_SPLIT_TRANSCT_ISO_TRSNF_DESC (2 << 1)
#define PERIODIC_FRAME_TYPE_FRAME_SPAN_TRAVERSAL_NODE    (3 << 1)

class ehci_controller
{
private:
    pci::pci_device *pcidev;
    mmio_range host_controller_space;
    mmio_range operational_reg_space;
    struct page *periodic_list_page;
    struct usb_periodic_frame *periodic_list;

public:
    constexpr ehci_controller(pci::pci_device *d, volatile void *base)
        : pcidev(d), host_controller_space{base}, operational_reg_space{}, periodic_list_page{},
          periodic_list{}
    {
    }
    ~ehci_controller();

    bool init();
    void reset();
    void stop_commands();
};
