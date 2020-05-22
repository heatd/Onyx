/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>

#include "../virtio.hpp"
#include "gpu.hpp"

namespace virtio
{

bool gpu_vdev::perform_subsystem_initialization()
{
	if(raw_has_feature(gpu_features::virgl_supported))
		signal_feature(gpu_features::virgl_supported);
	
	if(raw_has_feature(gpu_features::edid_supported))
		signal_feature(gpu_features::edid_supported);

	if(!finish_feature_negotiation())
	{
		set_failure();
		return false;
	}

	if(!create_virtqueue(controlq_nr, get_max_virtq_size(controlq_nr) ||
	   !create_virtqueue(cursorq_nr, get_max_virtq_size(cursorq_nr))))
	{
		set_failure();
		return false;
	}

	return true;
}

unique_ptr<vdev> create_gpu_device(pci_device *dev)
{
	return make_unique<gpu_vdev>(dev);
}

}
