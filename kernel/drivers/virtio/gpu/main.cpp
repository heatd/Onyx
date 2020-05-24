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

void gpu_vdev::handle_used_buffer(const virtq_used_elem &elem, const virtq *vq)
{
	if(vq->get_nr() == controlq_nr)
	{
		controlq_msgs.handle_used_buf(elem);
	}
}

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

	if(!create_virtqueue(controlq_nr, get_max_virtq_size(controlq_nr)) ||
	   !create_virtqueue(cursorq_nr, get_max_virtq_size(cursorq_nr)))
	{
		set_failure();
		return false;
	}

	virtio_gpu_ctrl_hdr h = {};
	h.type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;
	virtio_gpu_resp_display_info displ_info{};

	cul::slice<virtio_gpu_ctrl_hdr> out{&h, 1};
	cul::slice<uint8_t> in{reinterpret_cast<uint8_t *>(&displ_info), sizeof(displ_info)};

	virtio_gpu_control_msg msg{out, in, controlq_msgs};

	if(!msg.send())
	{
		set_failure();
		return false;
	}

	msg.wait_for_response();

	return true;
}

unique_ptr<vdev> create_gpu_device(pci_device *dev)
{
	return make_unique<gpu_vdev>(dev);
}

}
