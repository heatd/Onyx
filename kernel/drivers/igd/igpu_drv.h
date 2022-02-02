/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _IGPU_DRV_H
#define _IGPU_DRV_H

#include <stdbool.h>
#include <stdio.h>

#include <onyx/clock.h>
#include <onyx/i2c.h>

#include <pci/pci.h>

#define MPRINTF(...) printk("ihdgpu: " __VA_ARGS__)

struct igpu_device;

#define INTEL_ARCH_HASWELL 0
#define INTEL_ARCH_SKYLAKE 1

#define INTEL_FLAG_ULT (1 << 0)

struct igpu_driver_data
{
    /* Turns out, we need to know this, because gmch uses the normal
     * gpio regs while PCH has an offset.
     * Pretty sure everything we support is PCH only, but lets keep this
     * around for older hardware support
     * Note that we can only detect if we have a GMCH vs PCH with PCI ids
     */
    bool has_gmch_display;
    int (*enable_power)(struct igpu_device *dev);
    int (*enable_display_engine)(struct igpu_device *dev);
    unsigned int architecture;
    unsigned int extra_flags;
};

struct igpu_gmbus
{
    uint32_t gmbus0;
    uint32_t gmbus1;
    uint32_t gmbus2;
    uint32_t gmbus3;
    uint32_t gmbus4;
    uint32_t gmbus5;
};

struct video_timings
{
    uint32_t hactive;
    uint32_t vactive;
    uint32_t hsync_start;
    uint32_t hsync_end;
    uint32_t htotal;
    uint32_t vsync_start;
    uint32_t vsync_end;
    uint32_t vtotal;
};

enum DDI
{
    DDI_A = 0,
    DDI_B,
    DDI_C,
    DDI_D,
    DDI_E,
    DDI_MAX
};

enum PIPE_NAME
{
    PIPE_A = 0,
    PIPE_B,
    PIPE_C
};

enum TRANSCODER_NAME
{
    TRANS_A = 0,
    TRANS_B,
    TRANS_C,
    TRANS_EDP
};

/* Now, for a Fun and Confusing Fact(tm), between Gen7.5(HSW) and Gen9(KBL)
 * Intel changed the HTOTAL/VTOTAL/HSYNC/VSYNC/etc registers from PIPE_*_A/B/C/EDP
 * to TRANS_*_A/B/C/EDP. Because of this, we should technically keep the
 * register addresses in igd_transcoder for Gen > HSW and igd_pipe for <= HSW.
 * But since that would be complicated and completely stupid to do, we'll just
 * keep them igd_transcoder and pretend they're part of the transcoder,
 * since the reg layout is the same. Because of this, keep in mind that how
 * things are layed out in the driver structures doesn't completely represent
 * how things are layed out on hardware.
 */

struct igd_transcoder
{
    enum TRANSCODER_NAME name;
    uint32_t htotal_reg;
    uint32_t vtotal_reg;
    uint32_t hsync_reg;
    uint32_t vsync_reg;
    uint32_t vblank_reg;
    uint32_t hblank_reg;
};

enum PRI_PLANE_NAME
{
    PLANE_A = 0,
    PLANE_B = 1,
    PLANE_C = 2
};

struct igd_primary_plane
{
    enum PRI_PLANE_NAME name;
    uint32_t pri_ctl_reg;
    uint32_t pri_stride_reg;
    uint32_t pri_surf_reg;
    uint32_t pri_offset_reg;
};

struct igd_pipe
{
    enum PIPE_NAME name;
    struct video_timings current_mode;
    struct igd_transcoder *transcoder;
    uint32_t srcsz_reg;
    struct igd_primary_plane *plane;
};

#define IGPU_NR_GMBUS    6
#define NR_DISPLAY_PORTS 4
#define NR_TRANSCODERS   4
#define NR_PIPES         4
#define NR_PRI_PLANES    3

struct igd_opregion;
struct vbt_header;
struct bdb_header;
struct bdb_lvds_lfp_data_entry;

struct igd_displayport;

struct igd_vbt_ddi_info
{
    bool is_hdmi;
    bool is_dp;
    bool is_edp;
    bool is_dvi;
};

struct igpu_device
{
    volatile void *mmio_regs;
    volatile void *gpu_memory;
    pci::pci_device *device;
    struct igpu_gmbus gmbus;
    uint32_t gpio_regs_off;
    struct i2c_adapter i2c_adapter;
    volatile struct igd_opregion *opregion;
    struct vbt_header *igd_vbt;
    struct bdb_header *igd_vbt_bdb;
    struct igd_displayport *dports[NR_DISPLAY_PORTS];
    struct bdb_lvds_lfp_data_entry *lfp_data;
    struct igd_pipe *pipes[NR_PIPES];
    struct igd_transcoder *transcoders[NR_TRANSCODERS];
    struct igd_primary_plane *planes[NR_PRI_PLANES];
    struct igd_vbt_ddi_info ddi_info[DDI_MAX];
};

struct igd_displayport
{
    const char *name;
    struct igpu_device *device;
    struct i2c_adapter ddaux;
    unsigned int index;
    uint32_t ctl_reg;
    uint32_t data_base_reg;
    struct igd_pipe *pipe;
};

typedef uint32_t igd_gtt_entry_t;

#define igd_get_arch(dev) (((struct igpu_driver_data *)dev->device->driver_data)->architecture)
#define HAS_GMCH_DISPLAY(dev) \
    (((struct igpu_driver_data *)dev->device->driver_data)->has_gmch_display)

uint32_t igpu_mmio_read(struct igpu_device *dev, uint32_t offset);
void igpu_mmio_write(struct igpu_device *dev, uint32_t offset, uint32_t data);

int igpu_i2c_init(struct igpu_device *dev);

int igpu_wait_bit(struct igpu_device *dev, uint32_t reg, uint32_t mask, hrtime_t timeout,
                  bool clear);

int igd_init_displayport(struct igpu_device *dev);
int igd_enable_power_skylake(struct igpu_device *dev);
int igd_enable_power_haswell(struct igpu_device *dev);

int igd_enable_power(struct igpu_device *dev);

int igd_init_pipes(struct igpu_device *device);
int igd_init_transcoders(struct igpu_device *device);
int igd_init_primary_planes(struct igpu_device *device);
int igd_enable_display_engine(struct igpu_device *dev);
int igd_query_displays(struct igpu_device *dev);
int igd_get_ddi_info(struct igpu_device *dev);
int igd_init_gtt(struct igpu_device *dev);

#include "igd_pipe.h"

#endif
