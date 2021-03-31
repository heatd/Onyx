/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdlib.h>

#include <onyx/framebuffer.h>

#include "intel_regs.h"
#include "igpu_drv.h"

int igd_init_pipes(struct igpu_device *device)
{
	for(unsigned int i = 0; i < NR_PIPES; i++)
	{
		struct igd_pipe *pipe = (igd_pipe *) zalloc(sizeof(*pipe));

		if(!pipe)
			return -1;

		pipe->name = (enum PIPE_NAME) i;
		pipe->srcsz_reg = PIPE_SRCSZ + PIPE_OFFSET_PER_PIPE * i;
		device->pipes[i] = pipe;
	}

	return 0;
}

void igd_print_pipe_mode(struct video_timings *mode)
{
	printk("video mode: %u, %u, %u, %u, %u, %u, %u, %u\n",
		mode->hactive, mode->htotal, mode->vactive, mode->vtotal,
		mode->hsync_start, mode->hsync_end, mode->vsync_start, mode->vsync_end);
}

void igd_update_pipe_mode(struct igd_pipe *pipe, struct igpu_device *dev)
{
	uint32_t htotal_reg;
	uint32_t vtotal_reg;
	uint32_t hsync_reg;
	uint32_t vsync_reg;
	uint32_t vblank_reg;
	uint32_t hblank_reg;

	(void) hblank_reg;
	(void) vblank_reg;

	htotal_reg = igpu_mmio_read(dev, pipe->transcoder->htotal_reg);
	vtotal_reg = igpu_mmio_read(dev, pipe->transcoder->vtotal_reg);
	hsync_reg = igpu_mmio_read(dev, pipe->transcoder->hsync_reg);
	vsync_reg = igpu_mmio_read(dev, pipe->transcoder->vsync_reg);

	struct video_timings *mode = &pipe->current_mode;
	mode->hactive = htotal_reg & PIPE_HTOTAL_HACTIVE_MASK;
	mode->htotal = htotal_reg >> PIPE_HTOTAL_HTOTAL_SHIFT;
	mode->vactive = vtotal_reg & PIPE_VTOTAL_VACTIVE_MASK;
	mode->vtotal = vtotal_reg >> PIPE_VTOTAL_VTOTAL_SHIFT;
	mode->hsync_start = hsync_reg & PIPE_HSYNC_START_MASK;
	mode->hsync_end = hsync_reg >> PIPE_HSYNC_END_SHIFT;
	mode->vsync_start = vsync_reg & PIPE_VSYNC_START_MASK;
	mode->vsync_end = vsync_reg >> PIPE_VSYNC_END_SHIFT;

	igd_print_pipe_mode(mode);

	
	uint32_t srcsz = igpu_mmio_read(dev, pipe->srcsz_reg);

	/*srcsz = 1365 << PIPE_SRCSZ_HORIZ_SHIFT | 767;
	igpu_mmio_write(dev, pipe->srcsz_reg, srcsz);
	uint16_t stride = 1366 * 32/8;
	if(stride & (64 - 1))
	{
		stride = (stride & ~(64 - 1)) + 64;
	}

	igpu_mmio_write(dev, pipe->plane->pri_stride_reg, stride);
	igpu_mmio_write(dev, 0x00068080, 0);
	igpu_mmio_write(dev, 0x68074, 0);
	igpu_mmio_write(dev, 0x68070, 0);*/
	printk("PIPE_CONF: %x\n", igpu_mmio_read(dev, 0x7f008));
	printk("VERT: %u\nHORIZONTAL: %u\n", srcsz & PIPE_SRCSZ_VERT_MASK,
					    srcsz >> PIPE_SRCSZ_HORIZ_SHIFT);
}
 