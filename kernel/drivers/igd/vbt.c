/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include "vbt.h"

#include <stdio.h>

#include <onyx/panic.h>

#include "igpu_drv.h"

int igd_is_valid_vbt(struct igpu_device *dev, struct vbt_header *header)
{

    if (memcmp(&header->signature, VBT_SIGNATURE_START, VBT_SIGNATURE_START_LEN))
    {
        printk("igd: vbt bad signature\n");
        return -1;
    }

    if (header->header_size < sizeof(struct vbt_header))
    {
        printk("igd: vbt bad header size\n");
        return -1;
    }

    if (header->bdb_off > header->vbt_size)
    {
        printk("igd: vbt bad bdb off\n");
        return -1;
    }

    struct bdb_header *bdb = (void *) ((char *) header + header->bdb_off);

    if (bdb->header_size < sizeof(struct bdb_header))
    {
        printk("igd: vbt bad bdb header size\n");
        return -1;
    }

    if (memcmp(&bdb->signature, BDB_SIGNATURE, BDB_SIGNATURE_LEN))
    {
        printk("igd: vbt bad bdb signature %.16s.\n", bdb->signature);
        return -1;
    }

    printk("igd: Found valid VBT with signature %.16s\n", header->signature);

    dev->igd_vbt = header;
    dev->igd_vbt_bdb = bdb;

    return 0;
}

uint32_t get_blk_size(struct bdb_block_header *blk)
{
    if (blk->block_id == BDB_MIPI_SEQUENCE)
    {
        /* Check the revision for 3+ */
        unsigned char revision = blk->data[0];
        if (revision >= 3)
        {
            uint32_t *ptr = (uint32_t *) &blk->data[1];
            return *ptr;
        }
    }

    return blk->block_size;
}

struct bdb_block_header *igd_find_bdb_block(struct bdb_header *bdb, unsigned char id)
{
    uint16_t size = bdb->bdb_size;
    uint32_t pointer = bdb->header_size;

    while (pointer + sizeof(struct bdb_block_header) < size)
    {
        struct bdb_block_header *blk = (void *) ((uint8_t *) bdb + pointer);

        if (blk->block_id == id)
            return blk;

        pointer += get_blk_size(blk) + sizeof(struct bdb_block_header);
    }

    return NULL;
}

void dump_lvds_lfp_data_entry(struct bdb_lvds_lfp_data_entry *entry)
{
    printk("entry->fp_timing.x_res: %u\n", entry->fp_timing.x_res);
    printk("entry->fp_timing.y_res: %u\n", entry->fp_timing.y_res);
}

int igd_get_integrated_panel_settings(struct igpu_device *dev)
{
    struct bdb_block_header *block = igd_find_bdb_block(dev->igd_vbt_bdb, BDB_LVDS_OPTIONS);

    if (!block)
        return 0;

    struct bdb_lvds_options *opt = (struct bdb_lvds_options *) &block->data;

    uint8_t panel_type = opt->panel_type;

    if (panel_type == 0xff)
        return 0;

    block = igd_find_bdb_block(dev->igd_vbt_bdb, BDB_LVDS_LFP_DATA);
    if (!block)
        return 0;

    struct bdb_block_header *blk = igd_find_bdb_block(dev->igd_vbt_bdb, BDB_LVDS_LFP_DATA_PTRS);

    assert(blk != NULL);

    struct bdb_lvds_lfp_data_ptrs *ptrs = (void *) &blk->data;

    uint32_t lfp_data_size = ptrs->ptr[1].fp_timing_offset - ptrs->ptr[0].fp_timing_offset;

    struct bdb_lvds_lfp_data *data = (struct bdb_lvds_lfp_data *) &block->data;

    struct bdb_lvds_lfp_data_entry *entry =
        (void *) ((uint8_t *) data->data + lfp_data_size * panel_type);
    dev->lfp_data = entry;

    return 0;
}

int igd_parse_vbt(struct igpu_device *dev)
{
    struct bdb_block_header *block = igd_find_bdb_block(dev->igd_vbt_bdb, BDB_GENERAL_DEFINITIONS);
    if (!block)
        return 0;

    struct bdb_general_definitions *defs = (void *) &block->data;
    (void) defs;

    return igd_get_integrated_panel_settings(dev);
}

enum DDI dvo_port_to_ddi(uint8_t dvo_port)
{
    if (dvo_port < DVO_PORT_LVDS)
    {
        /* This is HDMIA-D and maps transparently to DDI */
        return (enum DDI) dvo_port;
    }
    else if (dvo_port >= DVO_PORT_DPB && dvo_port <= DVO_PORT_DPD)
    {
        /* Also maps transparently (just subtract DVO_PORT_DPB - 1) */
        return (enum DDI)(dvo_port - (DVO_PORT_DPB - 1));
    }
    else if (dvo_port == DVO_PORT_DPA)
        return DDI_A;
    else if (dvo_port == DVO_PORT_HDMIE || dvo_port == DVO_PORT_DPE)
        return DDI_E;
    else
        panic("unimplemented port");
}

int igd_get_ddi_info(struct igpu_device *dev)
{
    struct bdb_block_header *block = igd_find_bdb_block(dev->igd_vbt_bdb, BDB_GENERAL_DEFINITIONS);
    if (!block)
        return 0;
    struct bdb_general_definitions *defs = (void *) &block->data;

    uint16_t num_configs =
        (block->block_size - sizeof(struct bdb_general_definitions)) / defs->child_dev_size;

    for (uint16_t i = 0; i < num_configs; i++)
    {
        struct child_device_config *cfg =
            (void *) (((uint8_t *) &defs->devices) + i * defs->child_dev_size);

        enum DDI port = dvo_port_to_ddi(cfg->dvo_port);

#if 0
		char letter[] = "ABCDE";
		printk("Device type: %x\nPin DDI%c\n", cfg->device_type, letter[port]);
#endif

        bool is_dp = cfg->device_type & DEVICE_TYPE_DISPLAYPORT_OUTPUT;
        bool is_dvi = cfg->device_type & DEVICE_TYPE_TMDS_DVI_SIGNALING;
        bool is_edp = is_dp && cfg->device_type & DEVICE_TYPE_INTERNAL_CONNECTOR;
        bool is_hdmi = is_dvi && !(cfg->device_type & DEVICE_TYPE_NOT_HDMI_OUTPUT);
        dev->ddi_info[port].is_dp = is_dp;
        dev->ddi_info[port].is_dvi = is_dvi;
        dev->ddi_info[port].is_edp = is_edp;
        dev->ddi_info[port].is_hdmi = is_hdmi;
    }

    return 0;
}