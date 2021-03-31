/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>

#include "intel_regs.h"
#include "igpu_drv.h"

int igd_init_primary_planes(struct igpu_device *device)
{
	for(unsigned int i = 0; i < NR_PRI_PLANES; i++)
	{
		struct igd_primary_plane *plane = (igd_primary_plane *) zalloc(sizeof(struct igd_primary_plane));
		if(!plane)
			return -1;
		plane->name = (enum PRI_PLANE_NAME) i;
		plane->pri_ctl_reg = PRI_CTL_BASE + (PRI_OFF_PER_PLANE * i);
		plane->pri_stride_reg = PRI_STRIDE_BASE + (PRI_OFF_PER_PLANE * i);
		plane->pri_surf_reg = PRI_SURF_BASE + (PRI_OFF_PER_PLANE * i);
		plane->pri_offset_reg = PRI_OFFSET_BASE + (PRI_OFF_PER_PLANE * i);

		device->planes[i] = plane;
		device->pipes[i]->plane = plane;
	}

	return 0;
}
