/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VBT_H
#define _VBT_H

#include "igpu_drv.h"

#include <stdint.h>

#define VBT_SIGNATURE_START		"$VBT"
#define VBT_SIGNATURE_START_LEN		4

struct vbt_header
{
	char signature[20];
	uint16_t version;
	uint16_t header_size;
	uint16_t vbt_size;
	uint8_t vbt_checksum;
	uint8_t resv0;
	uint32_t bdb_off;
	uint32_t aim_off[4];
} __attribute__((packed));

/*
 * Copyright © 2006-2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *
 */


/* taken from linux 4.7, drivers/gpu/drm/i915/intel_vbt_defs.h,
 * above license applies
*/

/* Note that every struct is adapted to work with stdint types and use 
 * __attribute__((packed)) directly
*/

struct edp_power_seq
{
	uint16_t t1_t3;
	uint16_t t8;
	uint16_t t9;
	uint16_t t10;
	uint16_t t11_t12;
} __attribute__((packed));

struct edp_link_params
{
	uint8_t rate:4;
	uint8_t lanes:4;
	uint8_t preemphasis:4;
	uint8_t vswing:4;
} __attribute__((packed));

struct bdb_edp
{
	struct edp_power_seq power_seqs[16];
	uint32_t color_depth;
	struct edp_link_params link_params[16];
	uint32_t sdrrs_msa_timing_delay;

	/* ith bit indicates enabled/disabled for (i+1)th panel */
	uint16_t edp_s3d_feature;
	uint16_t edp_t3_optimization;
	uint64_t edp_vswing_preemph;		/* v173 */
} __attribute__((packed));

#define BDB_SIGNATURE	"BIOS_DATA_BLOCK"
#define BDB_SIGNATURE_LEN	15

struct bdb_header
{
	char signature[16];
	uint16_t version;
	uint16_t header_size;
	uint16_t bdb_size;
} __attribute__((packed));


#define BDB_EDP			 27
#define BDB_MIPI_SEQUENCE	 53

/* Raw bdb block header */
struct bdb_block_header
{
	unsigned char block_id;
	uint16_t block_size;
	unsigned char data[0];
} __attribute__((packed));

int igd_is_valid_vbt(struct igpu_device *dev, struct vbt_header *header);

#endif