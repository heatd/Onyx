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

#define BDB_GENERAL_FEATURES	  1
#define BDB_GENERAL_DEFINITIONS	  2
#define BDB_OLD_TOGGLE_LIST	  3
#define BDB_MODE_SUPPORT_LIST	  4
#define BDB_GENERIC_MODE_TABLE	  5
#define BDB_EXT_MMIO_REGS	  6
#define BDB_SWF_IO		  7
#define BDB_SWF_MMIO		  8
#define BDB_PSR			  9
#define BDB_MODE_REMOVAL_TABLE	 10
#define BDB_CHILD_DEVICE_TABLE	 11
#define BDB_DRIVER_FEATURES	 12
#define BDB_DRIVER_PERSISTENCE	 13
#define BDB_EXT_TABLE_PTRS	 14
#define BDB_DOT_CLOCK_OVERRIDE	 15
#define BDB_DISPLAY_SELECT	 16
/* 17 rsvd */
#define BDB_DRIVER_ROTATION	 18
#define BDB_DISPLAY_REMOVE	 19
#define BDB_OEM_CUSTOM		 20
#define BDB_EFP_LIST		 21 /* workarounds for VGA hsync/vsync */
#define BDB_SDVO_LVDS_OPTIONS	 22
#define BDB_SDVO_PANEL_DTDS	 23
#define BDB_SDVO_LVDS_PNP_IDS	 24
#define BDB_SDVO_LVDS_POWER_SEQ	 25
#define BDB_TV_OPTIONS		 26
#define BDB_EDP			 27
#define BDB_LVDS_OPTIONS	 40
#define BDB_LVDS_LFP_DATA_PTRS	 41
#define BDB_LVDS_LFP_DATA	 42
#define BDB_LVDS_BACKLIGHT	 43
#define BDB_LVDS_POWER		 44
#define BDB_MIPI_CONFIG		 52
#define BDB_MIPI_SEQUENCE	 53
#define BDB_SKIP		254 /* VBIOS private block, ignore */

struct bdb_general_features {
        /* bits 1 */
	uint8_t panel_fitting:2;
	uint8_t flexaim:1;
	uint8_t msg_enable:1;
	uint8_t clear_screen:3;
	uint8_t color_flip:1;

        /* bits 2 */
	uint8_t download_ext_vbt:1;
	uint8_t enable_ssc:1;
	uint8_t ssc_freq:1;
	uint8_t enable_lfp_on_override:1;
	uint8_t disable_ssc_ddt:1;
	uint8_t underscan_vga_timings:1;
	uint8_t display_clock_mode:1;
	uint8_t vbios_hotplug_support:1;

        /* bits 3 */
	uint8_t disable_smooth_vision:1;
	uint8_t single_dvi:1;
	uint8_t rotate_180:1;					/* 181 */
	uint8_t fdi_rx_polarity_inverted:1;
	uint8_t vbios_extended_mode:1;				/* 160 */
	uint8_t copy_ilfp_dtd_to_sdvo_lvds_dtd:1;			/* 160 */
	uint8_t panel_best_fit_timing:1;				/* 160 */
	uint8_t ignore_strap_state:1;				/* 160 */

        /* bits 4 */
	uint8_t legacy_monitor_detect;

        /* bits 5 */
	uint8_t int_crt_support:1;
	uint8_t int_tv_support:1;
	uint8_t int_efp_support:1;
	uint8_t dp_ssc_enable:1;	/* PCH attached eDP supports SSC */
	uint8_t dp_ssc_freq:1;	/* SSC freq for PCH attached eDP */
	uint8_t dp_ssc_dongle_supported:1;
	uint8_t rsvd11:2; /* finish byte */
} __attribute__((packed));

#define DEVICE_TYPE_CRT_DPMS		0x6001
#define DEVICE_TYPE_CRT_DPMS_HOTPLUG	0x4001
#define DEVICE_TYPE_TV_COMPOSITE	0x0209
#define DEVICE_TYPE_TV_MACROVISION	0x0289
#define DEVICE_TYPE_TV_RF_COMPOSITE	0x020c
#define DEVICE_TYPE_TV_SVIDEO_COMPOSITE	0x0609
#define DEVICE_TYPE_TV_SCART		0x0209
#define DEVICE_TYPE_TV_CODEC_HOTPLUG_PWR 0x6009
#define DEVICE_TYPE_EFP_HOTPLUG_PWR	0x6012
#define DEVICE_TYPE_EFP_DVI_HOTPLUG_PWR	0x6052
#define DEVICE_TYPE_EFP_DVI_I		0x6053
#define DEVICE_TYPE_EFP_DVI_D_DUAL	0x6152
#define DEVICE_TYPE_EFP_DVI_D_HDCP	0x60d2
#define DEVICE_TYPE_OPENLDI_HOTPLUG_PWR	0x6062
#define DEVICE_TYPE_OPENLDI_DUALPIX	0x6162
#define DEVICE_TYPE_LFP_PANELLINK	0x5012
#define DEVICE_TYPE_LFP_CMOS_PWR	0x5042
#define DEVICE_TYPE_LFP_LVDS_PWR	0x5062
#define DEVICE_TYPE_LFP_LVDS_DUAL	0x5162
#define DEVICE_TYPE_LFP_LVDS_DUAL_HDCP	0x51e2

/* Add the device class for LFP, TV, HDMI */
#define DEVICE_TYPE_INT_LFP		0x1022
#define DEVICE_TYPE_INT_TV		0x1009
#define DEVICE_TYPE_HDMI		0x60D2
#define DEVICE_TYPE_DP			0x68C6
#define DEVICE_TYPE_DP_DUAL_MODE	0x60D6
#define DEVICE_TYPE_eDP			0x78C6

#define DEVICE_TYPE_CLASS_EXTENSION	(1 << 15)
#define DEVICE_TYPE_POWER_MANAGEMENT	(1 << 14)
#define DEVICE_TYPE_HOTPLUG_SIGNALING	(1 << 13)
#define DEVICE_TYPE_INTERNAL_CONNECTOR	(1 << 12)
#define DEVICE_TYPE_NOT_HDMI_OUTPUT	(1 << 11)
#define DEVICE_TYPE_MIPI_OUTPUT		(1 << 10)
#define DEVICE_TYPE_COMPOSITE_OUTPUT	(1 << 9)
#define DEVICE_TYPE_DUAL_CHANNEL	(1 << 8)
#define DEVICE_TYPE_HIGH_SPEED_LINK	(1 << 6)
#define DEVICE_TYPE_LVDS_SIGNALING	(1 << 5)
#define DEVICE_TYPE_TMDS_DVI_SIGNALING	(1 << 4)
#define DEVICE_TYPE_VIDEO_SIGNALING	(1 << 3)
#define DEVICE_TYPE_DISPLAYPORT_OUTPUT	(1 << 2)
#define DEVICE_TYPE_DIGITAL_OUTPUT	(1 << 1)
#define DEVICE_TYPE_ANALOG_OUTPUT	(1 << 0)

/* dvo_port BDB 155+ */
#define DVO_PORT_HDMIA		0
#define DVO_PORT_HDMIB		1
#define DVO_PORT_HDMIC		2
#define DVO_PORT_HDMID		3
#define DVO_PORT_LVDS		4
#define DVO_PORT_TV		5
#define DVO_PORT_CRT		6
#define DVO_PORT_DPB		7
#define DVO_PORT_DPC		8
#define DVO_PORT_DPD		9
#define DVO_PORT_DPA		10
#define DVO_PORT_DPE		11				/* 193 */
#define DVO_PORT_HDMIE		12				/* 193 */

struct child_device_config {
	uint16_t handle;
	uint16_t device_type; /* See DEVICE_TYPE_* above */

	union {
		uint8_t  device_id[10]; /* ascii string */
		struct {
			uint8_t i2c_speed;
			uint8_t dp_onboard_redriver;			/* 158 */
			uint8_t dp_ondock_redriver;			/* 158 */
			uint8_t hdmi_level_shifter_value:5;		/* 169 */
			uint8_t hdmi_max_data_rate:3;		/* 204 */
			uint16_t dtd_buf_ptr;			/* 161 */
			uint8_t edidless_efp:1;			/* 161 */
			uint8_t compression_enable:1;		/* 198 */
			uint8_t compression_method:1;		/* 198 */
			uint8_t ganged_edp:1;			/* 202 */
			uint8_t reserved0:4;
			uint8_t compression_structure_index:4;	/* 198 */
			uint8_t reserved1:4;
			uint8_t slave_port;				/* 202 */
			uint8_t reserved2;
		} __attribute__((packed));
	} __attribute__((packed));

	uint16_t addin_offset;
	uint8_t dvo_port; /* See DEVICE_PORT_* and DVO_PORT_* above */
	uint8_t i2c_pin;
	uint8_t slave_addr;
	uint8_t ddc_pin;
	uint16_t edid_ptr;
	uint8_t dvo_cfg; /* See DEVICE_CFG_* above */

	union {
		struct {
			uint8_t dvo2_port;
			uint8_t i2c2_pin;
			uint8_t slave2_addr;
			uint8_t ddc2_pin;
		} __attribute__((packed));
		struct {
			uint8_t efp_routed:1;			/* 158 */
			uint8_t lane_reversal:1;			/* 184 */
			uint8_t lspcon:1;				/* 192 */
			uint8_t iboost:1;				/* 196 */
			uint8_t hpd_invert:1;			/* 196 */
			uint8_t flag_reserved:3;
			uint8_t hdmi_support:1;			/* 158 */
			uint8_t dp_support:1;			/* 158 */
			uint8_t tmds_support:1;			/* 158 */
			uint8_t support_reserved:5;
			uint8_t aux_channel;
			uint8_t dongle_detect;
		} __attribute__((packed));
	} __attribute__((packed));

	uint8_t pipe_cap:2;
	uint8_t sdvo_stall:1;					/* 158 */
	uint8_t hpd_status:2;
	uint8_t integrated_encoder:1;
	uint8_t capabilities_reserved:2;
	uint8_t dvo_wiring; /* See DEVICE_WIRE_* above */

	union {
		uint8_t dvo2_wiring;
		uint8_t mipi_bridge_type;				/* 171 */
	} __attribute__((packed));

	uint16_t extended_type;
	uint8_t dvo_function;
	uint8_t dp_usb_type_c:1;					/* 195 */
	uint8_t tbt:1;						/* 209 */
	uint8_t flags2_reserved:2;					/* 195 */
	uint8_t dp_port_trace_length:4;				/* 209 */
	uint8_t dp_gpio_index;					/* 195 */
	uint16_t dp_gpio_pin_num;					/* 195 */
	uint8_t dp_iboost_level:4;					/* 196 */
	uint8_t hdmi_iboost_level:4;					/* 196 */
	uint8_t dp_max_link_rate:2;					/* 216 CNL+ */
	uint8_t dp_max_link_rate_reserved:6;				/* 216 */
} __attribute__((packed));

struct bdb_general_definitions {
	/* DDC GPIO */
	uint8_t crt_ddc_gmbus_pin;

	/* DPMS bits */
	uint8_t dpms_acpi:1;
	uint8_t skip_boot_crt_detect:1;
	uint8_t dpms_aim:1;
	uint8_t rsvd1:5; /* finish byte */

	/* boot device bits */
	uint8_t boot_display[2];
	uint8_t child_dev_size;

	/*
	 * Device info:
	 * If TV is present, it'll be at devices[0].
	 * LVDS will be next, either devices[0] or [1], if present.
	 * On some platforms the number of device is 6. But could be as few as
	 * 4 if both TV and LVDS are missing.
	 * And the device num is related with the size of general definition
	 * block. It is obtained by using the following formula:
	 * number = (block_size - sizeof(bdb_general_definitions))/
	 *	     defs->child_dev_size;
	 */
	uint8_t devices[0];
} __attribute__((packed));

/* Mask for DRRS / Panel Channel / SSC / BLT control bits extraction */
#define MODE_MASK		0x3

struct bdb_lvds_options {
	uint8_t panel_type;
	uint8_t rsvd1;
	/* LVDS capabilities, stored in a dword */
	uint8_t pfit_mode:2;
	uint8_t pfit_text_mode_enhanced:1;
	uint8_t pfit_gfx_mode_enhanced:1;
	uint8_t pfit_ratio_auto:1;
	uint8_t pixel_dither:1;
	uint8_t lvds_edid:1;
	uint8_t rsvd2:1;
	uint8_t rsvd4;
	/* LVDS Panel channel bits stored here */
	uint32_t lvds_panel_channel_bits;
	/* LVDS SSC (Spread Spectrum Clock) bits stored here. */
	uint16_t ssc_bits;
	uint16_t ssc_freq;
	uint16_t ssc_ddt;
	/* Panel color depth defined here */
	uint16_t panel_color_depth;
	/* LVDS panel type bits stored here */
	uint32_t dps_panel_type_bits;
	/* LVDS backlight control type bits stored here */
	uint32_t blt_control_type_bits;
} __attribute__((packed));

/* LFP pointer table contains entries to the struct below */
struct bdb_lvds_lfp_data_ptr {
	uint16_t fp_timing_offset; /* offsets are from start of bdb */
	uint8_t fp_table_size;
	uint16_t dvo_timing_offset;
	uint8_t dvo_table_size;
	uint16_t panel_pnp_id_offset;
	uint8_t pnp_table_size;
} __attribute__((packed));

struct bdb_lvds_lfp_data_ptrs {
	uint8_t lvds_entries; /* followed by one or more lvds_data_ptr structs */
	struct bdb_lvds_lfp_data_ptr ptr[16];
} __attribute__((packed));

/* LFP data has 3 blocks per entry */
struct lvds_fp_timing {
	uint16_t x_res;
	uint16_t y_res;
	uint32_t lvds_reg;
	uint32_t lvds_reg_val;
	uint32_t pp_on_reg;
	uint32_t pp_on_reg_val;
	uint32_t pp_off_reg;
	uint32_t pp_off_reg_val;
	uint32_t pp_cycle_reg;
	uint32_t pp_cycle_reg_val;
	uint32_t pfit_reg;
	uint32_t pfit_reg_val;
	uint16_t terminator;
} __attribute__((packed));

struct lvds_dvo_timing {
	uint16_t clock;		/**< In 10khz */
	uint8_t hactive_lo;
	uint8_t hblank_lo;
	uint8_t hblank_hi:4;
	uint8_t hactive_hi:4;
	uint8_t vactive_lo;
	uint8_t vblank_lo;
	uint8_t vblank_hi:4;
	uint8_t vactive_hi:4;
	uint8_t hsync_off_lo;
	uint8_t hsync_pulse_width_lo;
	uint8_t vsync_pulse_width_lo:4;
	uint8_t vsync_off_lo:4;
	uint8_t vsync_pulse_width_hi:2;
	uint8_t vsync_off_hi:2;
	uint8_t hsync_pulse_width_hi:2;
	uint8_t hsync_off_hi:2;
	uint8_t himage_lo;
	uint8_t vimage_lo;
	uint8_t vimage_hi:4;
	uint8_t himage_hi:4;
	uint8_t h_border;
	uint8_t v_border;
	uint8_t rsvd1:3;
	uint8_t digital:2;
	uint8_t vsync_positive:1;
	uint8_t hsync_positive:1;
	uint8_t non_interlaced:1;
} __attribute__((packed));

struct lvds_pnp_id {
	uint16_t mfg_name;
	uint16_t product_code;
	uint32_t serial;
	uint8_t mfg_week;
	uint8_t mfg_year;
} __attribute__((packed));

struct bdb_lvds_lfp_data_entry {
	struct lvds_fp_timing fp_timing;
	struct lvds_dvo_timing dvo_timing;
	struct lvds_pnp_id pnp_id;
} __attribute__((packed));

struct bdb_lvds_lfp_data {
	struct bdb_lvds_lfp_data_entry data[16];
} __attribute__((packed));

/* Raw bdb block header */
struct bdb_block_header
{
	unsigned char block_id;
	uint16_t block_size;
	unsigned char data[0];
} __attribute__((packed));

int igd_is_valid_vbt(struct igpu_device *dev, struct vbt_header *header);

#endif