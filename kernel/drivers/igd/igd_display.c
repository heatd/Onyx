/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdlib.h>

#include <onyx/panic.h>

#include "intel_regs.h"
#include "igpu_drv.h"

int igd_enable_displayport(struct igd_displayport *port, struct igpu_device *dev)
{
	/* NOTE: The Display manual for HSW GPUs says we
	 * need to configure DDIA Lane capability control and DDI_BUF_TRANS.
	 * However, we assume they have been properly configured.
	 * Refer to page 171 of the display chapter
	*/
	/*
	 * Another huge ass note: We don't configure the panel or do anything
	 * whatsoever with DisplayPort. This may be bad if the BIOS didn't
	 * configure it properly, but it's kind of safe to assume it was. */

	return 0;
}

int igd_do_modeset_hsw(struct igd_displayport *port,
		       struct video_timings *mode, struct igpu_device *dev)
{
	/* We're doing this in a quick-and-dirty fashion */
	/*struct igd_pipe *pipe = port->pipe;
	struct igd_primary_plane *plane = port->pipe->plane;
	igd_change_pipe_config(port->pipe, mode, dev);*/

	return 0;
}

int igd_change_cdclk_magic_sequence(struct igpu_device *dev)
{
	/* Process described on page 151 of the KBL display chapter */
	/* TODO: Is this the same for Haswell? What about other architectures? */
	while(true)
	{
		igpu_mmio_write(dev, GT_DRIVER_MAILBOX_DATA0, GT_DRIVER_MAILBOX_DATA0_MAGIC_VALUE);
		igpu_mmio_write(dev, GT_DRIVER_MAILBOX_DATA1, GT_DRIVER_MAILBOX_DATA1_MAGIC_VALUE);
		igpu_mmio_write(dev, GT_DRIVER_MAILBOX_INTERFACE, GT_DRIVER_MAILBOX_INTERFACE_MAGIC_VALUE);


		/* Should wait only 150us */
		if(igpu_wait_bit(dev, GT_DRIVER_MAILBOX_INTERFACE, GT_DRIVER_MAILBOX_INTERFACE_RUN_BIT,
			150 * NS_PER_US, true) < 0)
			return -ETIMEDOUT;
		
		/* TODO: The manual suggests we timeout out of the whole process */
		if(igpu_mmio_read(dev, GT_DRIVER_MAILBOX_DATA0) & 0x1)
			break;
	}

	return 0;
}

void igd_finish_cdclk_freq_change_kbl(struct igpu_device *dev, unsigned int freq)
{
	uint32_t data0;

	switch(freq)
	{
		case CDCLK_CTL_FREQ_SELECT_337_5MHZ:
			data0 = 0;
			break;
		case CDCLK_CTL_FREQ_SELECT_450MHZ:
			data0 = 1;
			break;
		case CDCLK_CTL_FREQ_SELECT_540MHZ:
			data0 = 2;
			break;
		case CDCLK_CTL_FREQ_SELECT_675MHZ:
			data0 = 3;
			break;
		default:
			panic("bad freq");
	}

	igpu_mmio_write(dev, GT_DRIVER_MAILBOX_DATA0, data0);
	igpu_mmio_write(dev, GT_DRIVER_MAILBOX_DATA1, GT_DRIVER_MAILBOX_DATA1_MAGIC_VALUE);
	igpu_mmio_write(dev, GT_DRIVER_MAILBOX_INTERFACE, GT_DRIVER_MAILBOX_INTERFACE_MAGIC_VALUE);
}

int igd_enable_display_engine_skl(struct igpu_device *dev)
{
	/* Check page 126 of the KBL display chapter for more info */

	uint32_t rstwrn = igpu_mmio_read(dev, NDE_RSTWRN_OPT);
	rstwrn |= NDE_RST_PCH_HANDSHAKE_ENABLE;
	igpu_mmio_write(dev, NDE_RSTWRN_OPT, rstwrn);

	/* PG1 was previously enabled */

	/* Program CDCLK_CTL to the minimum (and default) frequency */
	uint32_t cdclk_ctl = (CDCLK_CTL_FREQ_SELECT_337_5MHZ << CDCLK_CTL_FREQ_SELECT_SHIFT) |
			      CDCLK_CTL_FREQ_DECIMAL_337_5MHZ;
	igpu_mmio_write(dev, CDCLK_CTL, cdclk_ctl);


	/* Set the link rate to 810 MHz (1.62 GHz) */
	uint32_t dpll_ctrl1 = igpu_mmio_read(dev, DPLL_CTRL1);

	/* Note that we need to mask it out because it might not be zero */
	dpll_ctrl1 &= ~DPLL_CTRL1_DPLL_LINK_RATE_MASK(0);
	dpll_ctrl1 |= DPLL_CTRL1_DPLL_LINK_RATE(0, DPLL_CTRL1_DPLL_LINK_RATE_810MHZ);
	dpll_ctrl1 |= DPLL_CTRL1_DPLL_OVERRIDE(0);
	
	igpu_mmio_write(dev, DPLL_CTRL1, dpll_ctrl1);

	uint32_t lcpll1_ctl = igpu_mmio_read(dev, LCPLL1_CTL);

	lcpll1_ctl |= LCPLL1_CTL_PLL_ENABLE;

	igpu_mmio_write(dev, LCPLL1_CTL, lcpll1_ctl);

	if(igpu_wait_bit(dev, LCPLL1_CTL, LCPLL1_CTL_PLL_LOCK, NS_PER_MS * 5, false) < 0)
	{
		printk("%s: Timed out waiting for PLL Lock(DPLL 0)\n", __func__);
		return -ETIMEDOUT;
	}

	int st = igd_change_cdclk_magic_sequence(dev);

	if(st < 0)
		return st;

	igpu_mmio_write(dev, CDCLK_CTL, cdclk_ctl);

	igd_finish_cdclk_freq_change_kbl(dev, CDCLK_CTL_FREQ_SELECT_337_5MHZ);

	igpu_mmio_write(dev, DBUF_CTL, DBUF_CTL_POWER_REQUEST);

	if(igpu_wait_bit(dev, DBUF_CTL, DBUF_CTL_POWER_STATE, NS_PER_MS * 1, false) < 0)
		return -ETIMEDOUT;

	return 0;
}

int igd_enable_display_engine_hsw(struct igpu_device *dev)
{
	/*uint32_t cdclk_ctl = (CDCLK_CTL_FREQ_SELECT_450MHZ << CDCLK_CTL_FREQ_SELECT_SHIFT) |
			      CDCLK_CTL_FREQ_DECIMAL_337_5MHZ;
	igpu_mmio_write(dev, CDCLK_CTL, cdclk_ctl);*/

	return 0;
}

int igd_query_displays(struct igpu_device *dev)
{
	igd_get_ddi_info(dev);
	for(unsigned int ddi = 0; ddi < DDI_MAX; ddi++)
	{

	}

	return 0;
}
