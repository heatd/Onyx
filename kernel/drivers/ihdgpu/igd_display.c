/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdlib.h>

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
	bool is_edp = port->index == DDI_A;

	return 0;
	//igd_change_pipe_config(port->pipe, mode, dev);
}