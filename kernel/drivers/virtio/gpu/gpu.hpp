/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _VIRTIO_GPU_HPP
#define _VIRTIO_GPU_HPP

#include <stdint.h>

#include <onyx/net/network.h>

#include "../virtio.hpp"
#include "../virtio_utils.hpp"
#include <onyx/memory.hpp>
#include <onyx/slice.hpp>

namespace virtio
{

enum virtio_gpu_ctrl_type
{
    /* 2D commands */
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    VIRTIO_GPU_CMD_RESOURCE_UNREF,
    VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_GET_CAPSET_INFO,
    VIRTIO_GPU_CMD_GET_CAPSET,
    VIRTIO_GPU_CMD_GET_EDID,

    /* cursor commands */
    VIRTIO_GPU_CMD_UPDATE_CURSOR = 0x0300,
    VIRTIO_GPU_CMD_MOVE_CURSOR,

    /* success responses */
    VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
    VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET,
    VIRTIO_GPU_RESP_OK_EDID,

    /* error responses */
    VIRTIO_GPU_RESP_ERR_UNSPEC = 0x1200,
    VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
};

#define VIRTIO_GPU_FLAG_FENCE (1 << 0)

struct virtio_gpu_ctrl_hdr
{
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
};

#define VIRTIO_GPU_MAX_SCANOUTS 16

struct virtio_gpu_rect
{
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

struct virtio_gpu_resp_display_info : virtio_gpu_ctrl_hdr
{
    struct virtio_gpu_display_one
    {
        struct virtio_gpu_rect r;
        uint32_t enabled;
        uint32_t flags;
    } pmodes[VIRTIO_GPU_MAX_SCANOUTS];
};

class gpu_vdev : public vdev
{
private:
    static constexpr unsigned int controlq_nr = 0;
    static constexpr unsigned int cursorq_nr = 1;

    using virtio_gpu_control_msg = virtio_control_msg<virtio_gpu_ctrl_hdr, uint8_t>;
    virtio_control_msg_queue<virtio_gpu_ctrl_hdr, uint8_t> controlq_msgs;

public:
    gpu_vdev(pci::pci_device *d) : vdev(d), controlq_msgs{this, controlq_nr}
    {
    }
    ~gpu_vdev()
    {
    }

    bool perform_subsystem_initialization() override;
    void handle_used_buffer(const virtq_used_elem &elem, virtq *vq) override;
};

namespace gpu_regs
{

static constexpr unsigned int event_display = (1 << 0);

enum reg
{
    events_read = 0,
    events_clear = 4,
    num_scanouts = 8,
    res = 12
};

}; // namespace gpu_regs

namespace gpu_features
{

enum feats
{
    virgl_supported = (1 << 0),
    edid_supported = (1 << 1)
};

} // namespace gpu_features

} // namespace virtio

#endif
