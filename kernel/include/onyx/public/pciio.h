/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PUBLIC_PCIIO_H
#define _ONYX_PUBLIC_PCIIO_H

/* Implementation of pciio.h as specified in FreeBSD pci(4) */
#undef ONYX_UAPI_HEADER
#define ONYX_UAPI_HEADER

#include <onyx/types.h>

#define PCI_MAXNAMELEN 64

#define PCIOCGETCONF 0x8000

struct pcisel
{
    __u16 pc_domain;
    __u8 pc_bus;
    __u8 pc_dev;
    __u8 pc_func;
};

#define PCI_GETCONF_NO_MATCH     0x0000
#define PCI_GETCONF_MATCH_DOMAIN 0x0001
#define PCI_GETCONF_MATCH_BUS    0x0002
#define PCI_GETCONF_MATCH_DEV    0x0004
#define PCI_GETCONF_MATCH_FUNC   0x0008
#define PCI_GETCONF_MATCH_NAME   0x0010
#define PCI_GETCONF_MATCH_UNIT   0x0020
#define PCI_GETCONF_MATCH_VENDOR 0x0040
#define PCI_GETCONF_MATCH_DEVICE 0x0080
#define PCI_GETCONF_MATCH_CLASS  0x0100

struct pci_match_conf
{
    struct pcisel pc_sel;
    char pd_name[PCI_MAXNAMELEN];
    __u32 pd_unit;
    __u16 pc_vendor;
    __u16 pc_device;
    __u8 pc_class;
    __u32 flags;
};

struct pci_conf
{
    struct pcisel pc_sel;
    __u8 pc_hdr;
    __u16 pc_subvendor;
    __u16 pc_subdevice;
    __u16 pc_vendor;
    __u16 pc_device;
    __u8 pc_class;
    __u8 pc_subclass;
    __u8 pc_progif;
    __u8 pc_revid;
    char pd_name[PCI_MAXNAMELEN];
    __u32 pd_unit;
};

enum pci_conf_status
{
    PCI_GETCONF_LAST_DEVICE = 1,
    PCI_GETCONF_LIST_CHANGED,
    PCI_GETCONF_MORE_DEVS,
    PCI_GETCONF_ERROR
};

struct pci_conf_io
{
    __u32 pat_buf_len;
    __u32 num_patterns;
    struct pci_match_conf *patterns;
    __u32 match_buf_len;
    __u32 num_matches;
    struct pci_conf *matches;
    __u32 offset;
    __u32 generation;
    enum pci_conf_status status;
};

#define PCIOCREAD 0x8001

struct pci_io
{
    struct pcisel pi_sel;
    __u16 pi_reg;
    __u16 pi_width;
    __u32 pi_data;
};

#define PCIOCWRITE 0x8002

#define PCIOCGETBAR 0x8003

struct pci_bar_io
{
    struct pcisel pbi_sel;
    __u32 pbi_reg;
    __s32 pbi_enabled;
    __u64 pbi_base;
    __u64 pbi_length;
};

struct pci_bar_ioreq
{
    struct pcisel pbi_sel;
    __s32 pbi_op;
    __u32 pbi_bar;
    __u32 pbi_offset;
    __u32 pbi_width;
    __u32 pbi_value;
};

#endif
