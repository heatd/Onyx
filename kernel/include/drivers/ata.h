/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_ATA_H
#define _ONYX_ATA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>

#include <pci/pci.h>

/* ATA status bits */
#define ATA_SR_BSY  0x80 // Busy
#define ATA_SR_DRDY 0x40 // Drive ready
#define ATA_SR_DF   0x20 // Drive write fault
#define ATA_SR_DSC  0x10 // Drive seek complete
#define ATA_SR_DRQ  0x08 // Data request ready
#define ATA_SR_CORR 0x04 // Corrected data
#define ATA_SR_IDX  0x02 // Index
#define ATA_SR_ERR  0x01 // Error

/* ATA error bits */
#define ATA_ER_BBK   0x80 // Bad sector
#define ATA_ER_UNC   0x40 // Uncorrectable data
#define ATA_ER_MC    0x20 // No media
#define ATA_ER_IDNF  0x10 // ID mark not found
#define ATA_ER_MCR   0x08 // No media
#define ATA_ER_ABRT  0x04 // Command aborted
#define ATA_ER_TK0NF 0x02 // Track 0 not found
#define ATA_ER_AMNF  0x01 // No address mark

/* ATA commands */

#define ATA_CMD_READ_PIO        0x20
#define ATA_CMD_READ_PIO_EXT    0x24
#define ATA_CMD_READ_DMA        0xC8
#define ATA_CMD_READ_DMA_EXT    0x25
#define ATA_CMD_WRITE_PIO       0x30
#define ATA_CMD_WRITE_PIO_EXT   0x34
#define ATA_CMD_WRITE_DMA       0xCA
#define ATA_CMD_WRITE_DMA_EXT   0x35
#define ATA_CMD_CACHE_FLUSH     0xE7
#define ATA_CMD_CACHE_FLUSH_EXT 0xEA
#define ATA_CMD_PACKET          0xA0
#define ATA_CMD_IDENTIFY_PACKET 0xA1
#define ATA_CMD_IDENTIFY        0xEC
#define ATA_CMD_IDLE            0xE3
#define ATAPI_CMD_READ          0xA8
#define ATAPI_CMD_EJECT         0x1B
#define ATA_CMD_EXEC_DRIVE_DIAG 0x90

#define ATA_TYPE_ATA   1
#define ATA_TYPE_ATAPI 2

// Stolen from Fuchsia, MIT licensed
#define ATA_DEVINFO_SERIAL_LEN   20
#define ATA_DEVINFO_FW_REV_LEN   8
#define ATA_DEVINFO_MODEL_ID_LEN 40

struct ata_identify_response
{                             // 16-bit word offset
    uint16_t general_config;  // 0
    uint16_t _obsolete_1;     // 1
    uint16_t specific_config; // 2
    uint16_t _obsolete_3;     // 3
    uint16_t _retired_4[2];   // 4-5
    uint16_t _obsolete_6;     // 6
    uint16_t cfa_reserved[2]; // 7-8
    uint16_t _retired_9;      // 9
    union {
        uint16_t word[ATA_DEVINFO_SERIAL_LEN / 2]; // 10-19
        char string[ATA_DEVINFO_SERIAL_LEN];
    } serial;
    uint16_t _retired_20[2]; // 20-21
    uint16_t _obsolete_22;   // 22
    union {
        uint16_t word[ATA_DEVINFO_FW_REV_LEN / 2]; // 23-26
        char string[ATA_DEVINFO_FW_REV_LEN];
    } firmware_rev;
    union {
        uint16_t word[ATA_DEVINFO_MODEL_ID_LEN / 2]; // 27-46
        char string[ATA_DEVINFO_MODEL_ID_LEN];
    } model_id;
    uint16_t _obsolete_47;              // 47
    uint16_t trusted_computing_options; // 48
    uint16_t capabilities_1;            // 49
    uint16_t capabilities_2;            // 50
    uint16_t _obsolete_51[2];           // 51-52
    uint16_t unnamed_53;                // 53
    uint16_t _obsolete_54[5];           // 54-58
    uint16_t unnamed_59;                // 59
    uint32_t lba_capacity;              // 60-61
    uint16_t _obsolete_62;              // 62
    uint16_t unnamed_63;                // 63
    uint16_t pio_modes;                 // 64
    uint16_t min_dma_cycle_time;        // 65
    uint16_t rec_dma_cycle_time;        // 66
    uint16_t min_pio_cycle_time;        // 67
    uint16_t min_pio_iordy_cycle_time;  // 68
    uint16_t additional_supported;      // 69
    uint16_t _reserved_70;              // 70
    uint16_t _reserved_71[4];           // 71-74
    uint16_t queue_depth;               // 75
    uint16_t sata_capabilities;         // 76
    uint16_t sata_capabilities2;        // 77
    uint16_t sata_features_supported;   // 78
    uint16_t sata_features_enabled;     // 79
    uint16_t major_version;             // 80
    uint16_t minor_version;             // 81
    uint16_t command_set1_0;            // 82
    uint16_t command_set1_1;            // 83
    uint16_t command_set1_2;            // 84 -- see 119
    uint16_t command_set2_0;            // 85
    uint16_t command_set2_1;            // 86
    uint16_t command_set2_2;            // 87 -- see 120
    uint16_t udma_modes;                // 88
    uint16_t timing_info[2];            // 89-90
    uint16_t apm_level;                 // 91
    uint16_t master_password;           // 92
    uint16_t reset_results;             // 93
    uint16_t _obsolete_94;              // 94
    uint16_t stream_min_size;           // 95
    uint16_t dma_stream_xfer_time;      // 96
    uint16_t stream_access_latency;     // 97
    uint32_t stream_perf_granularity;   // 98-99
    uint64_t lba_capacity2;             // 100-103
    uint16_t pio_stream_xfer_time;      // 104
    uint16_t data_set_max;              // 105
    uint16_t sector_size;               // 106
    uint16_t inter_seek_delay;          // 107
    uint64_t world_wide_name;           // 108-111
    uint16_t _reserved_112[4];          // 112-115
    uint16_t _obsolete_116;             // 116
    uint32_t logical_sector_size;       // 117-118
    uint16_t command_set1_3;            // 119
    uint16_t command_set2_3;            // 120
    uint16_t _reserved_121[6];          // 121-126
    uint16_t _obsolete_127;             // 127
    uint16_t security_status;           // 128
    uint16_t vendor_specific[31];       // 129-159
    uint16_t cfa_reserved2[8];          // 160-167
    uint16_t form_factor;               // 168
    uint16_t data_management_support;   // 169
    uint16_t additional_product_id[4];  // 170-173
    uint16_t _reserved_174[2];          // 174-175
    uint16_t media_serial_number[30];   // 176-205
    uint16_t sct_command_transport;     // 206
    uint16_t reserved_207[2];           // 207-208
    uint16_t sector_alignment;          // 209
    uint32_t wrv_mode3_count;           // 210-211
    uint32_t wrv_mode2_count;           // 212-213
    uint16_t _obsolete_214[3];          // 214-216
    uint16_t rotation_rate;             // 217
    uint16_t _reserved_218;             // 218
    uint16_t _obsolete_219;             // 219
    uint16_t wrv_mode;                  // 220
    uint16_t _reserved_221;             // 221
    uint16_t transport_major_version;   // 222
    uint16_t transport_minor_version;   // 223
    uint16_t _reserved_224[6];          // 224-229
    uint64_t ext_sector_count;          // 230-233
    uint16_t min_microcode_blocks;      // 234
    uint16_t max_microcode_blocks;      // 235
    uint16_t _reserved_236[19];         // 236-254
    uint16_t checksum;                  // 255
} __attribute__((packed));

// Strings are byte-flipped in pairs.
static inline void string_fix(uint16_t *buf, size_t size)
{
    for (size_t i = 0; i < (size / 2); i++)
    {
        buf[i] = bswap16(buf[i]);
    }
}

#endif
