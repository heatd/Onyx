/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _VIRTIO_BLK_HPP
#define _VIRTIO_BLK_HPP

#include <stdint.h>

#include <onyx/block.h>

#include "../virtio.hpp"
#include <onyx/memory.hpp>
#include <onyx/slice.hpp>

namespace virtio
{

enum class blk_registers
{
    capacity = 0,
    size_max = 8,
    seg_max = 12,
    cylinders = 16,
    heads = 18,
    sectors = 19,
    blk_size = 20,
    topo_physical_block_exp = 24,
    topo_alignment_offset = 25,
    topo_min_io_size = 27,
    topo_opt_io_size = 28,
    writeback = 32,
    unused0 = 33,
    max_discard_sectors = 36,
    max_discard_seg = 40,
    discard_sector_alignment = 44,
    max_write_zeroes_sectors = 48,
    max_write_zeroes_seg = 52,
    write_zeroes_may_unmap = 56,
    unused1 = 57
};

enum class blk_features
{
    size_max = 1,
    seg_max = 2,
    geometry = 4,
    ro = 5,
    blk_size = 6,
    flush = 9,
    topology = 10,
    wce = 11,
    discard = 12,
    write_zeroes = 14
};

class blk_vdev : public vdev
{
private:
    size_t block_size;
    size_t disk_size;
    size_t size_max, seg_max;

public:
    blk_vdev(pci::pci_device *d) : vdev(d), block_size{512}, disk_size{}, size_max{0}, seg_max{0}
    {
    }
    ~blk_vdev();

    bool perform_subsystem_initialization() override;

    void handle_used_buffer(const virtq_used_elem &elem, virtq *vq) override;
    int submit_request(struct bio_req *req);
};

struct virtio_blk_request
{
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
};

struct virtio_blk_tail
{
    uint8_t status;
};

#define VIRTIO_BLK_T_IN           0
#define VIRTIO_BLK_T_OUT          1
#define VIRTIO_BLK_T_FLUSH        4
#define VIRTIO_BLK_T_DISCARD      11
#define VIRTIO_BLK_T_WRITE_ZEROES 13

#define VIRTIO_BLK_S_OK     0
#define VIRTIO_BLK_S_IOERR  1
#define VIRTIO_BLK_S_UNSUPP 2

} // namespace virtio

#endif
