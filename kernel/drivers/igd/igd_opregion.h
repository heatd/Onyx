/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _IGD_OPREGION_H
#define _IGD_OPREGION_H

#include <assert.h>

/* ASLS - Scratch register(does not affect hw operation) that is initialized
 * by firmware to store a 32-bit pointer to the OpRegion
 */
#define ASLS 0xfc

#define OPREGION_NON_EXISTENT 0

/* According to the docs, the OpRegion's size is defined to be 1KB
 * (size of header + mailboxes 1-3) + VBT mailbox, which is 7KB long
 * Therefore, the mapping's size is 8KiB long
 */

#define OPREGION_SIZE 0x2000

#define OPREGION_SIGNATURE     "IntelGraphicsMem"
#define OPREGION_SIGNATURE_LEN 16

#define OPREGION_MAILBOX_SUPPORTED(nr) (1 << (nr - 1))

#define OPREGION_PCON_CONNECTED_STANDBY_SUPPORTED (1 << 0)
#define OPREGION_PCON_CONNECTED_STANDBY_CAP_SUPP  (1 << 1)
#define OPREGION_PCON_AUDIO_TYPE_NO_AUDIO         (0)
#define OPREGION_PCON_AUDIO_TYPE_HIGHDEF_AUDIO    (1 << 2)
#define OPREGION_PCON_AUDIO_TYPE_LOWPOWER_AUDIO   (2 << 2)
#define OPREGION_PCON_ISCT_CAPABLE                (1 << 4)
#define OPREGION_PCON_ISCT_CAPABILITY_FIELD_SUPP  (1 << 5)
#define OPREGION_PCON_EXTERNAL_GFX_ADAPTER        (1 << 6)
#define OPREGION_PCON_EXTERNAL_GFX_FIELD_VALID    (1 << 7)

struct igd_opregion_header
{
    char signature[OPREGION_SIGNATURE_LEN];
    uint32_t size;
    uint32_t version;
    char system_bios_version[32];
    char vbios_version[16];
    char graphics_drv_build_ver[16];
    uint32_t supported_mailboxes;
    uint32_t driver_model;
    uint32_t pcon;
    char gop_version[32];
    unsigned char mbz[124];
} __attribute__((packed));

struct igd_opregion_public_acpi_methods
{
    uint32_t drdy;
    uint32_t csts;
    uint32_t cevt;
    unsigned char mbz[20];
    uint32_t didl[8]; /* _DOD */
    uint32_t cpdl[8];
    uint32_t cadl[8]; /* _DCS */
    uint32_t nadl[8]; /* _DGS use */
    uint32_t asl_sleep_timeout;
    uint32_t tidx;
    uint32_t chpd;
    uint32_t clid;
    uint32_t cdck;
    uint32_t sxsw;
    uint32_t evts;
    uint32_t cnot;
    uint32_t nrdy;
    uint32_t didl2[7]; /* Extended supported device ids */
    uint32_t cpd2[7];  /* Extended attached device ids */
    uint32_t mbz1;
} __attribute__((packed));

struct igd_software_sci_xface
{
    uint32_t scic;
    uint32_t param;
    uint32_t dslp;
    unsigned char mbz[244];
} __attribute__((packed));

struct igd_bios_to_driver_notification
{
    uint32_t ardy;
    uint32_t aslc;
    uint32_t tche;
    uint32_t alsi;
    uint32_t bclp;
    uint32_t pfit;
    uint32_t cblv;
    unsigned char bclm[40];
    uint32_t cpfm;
    uint32_t epfm;
    unsigned char plut_header;
    unsigned char panel_lut_ident[10];
    unsigned char plut_table[63];
    uint32_t pfmb;
    uint32_t ccdv;
    uint32_t pcft;
    uint32_t srot;
    uint32_t iuer;
    uint64_t fdss;
    uint32_t fdsp;
    uint32_t stat;
    uint64_t rvda;
    uint32_t rvde;
    unsigned char mbz[58];
} __attribute__((packed));

struct igd_opregion_bios_to_driver_notif
{
    uint32_t phed;
    unsigned char bddc[256];
    unsigned char mbz[764];
} __attribute__((packed));

#define OPREGION_VBT_SIZE 6144

struct igd_opregion
{
    struct igd_opregion_header header;
    struct igd_opregion_public_acpi_methods mailbox1;
    struct igd_software_sci_xface mailbox2;
    struct igd_bios_to_driver_notification mailbox3;
    unsigned char mailbox4[OPREGION_VBT_SIZE];
    struct igd_opregion_bios_to_driver_notif mailbox5;
} __attribute__((packed));

static_assert(sizeof(struct igd_opregion) == OPREGION_SIZE, "Invalid struct igd_opregion");

int igd_opregion_init(struct igpu_device *dev);

#endif