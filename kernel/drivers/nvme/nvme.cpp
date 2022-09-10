/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "include/nvme.h"

#include <string.h>

#include <onyx/block.h>
#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/driver.h>

#include <pci/pci.h>

#include <onyx/atomic.hpp>
#include <onyx/slice.hpp>

pci::pci_id nvme_pci_ids[] = {
    {PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 8, 2, nullptr)},
    {0},
};

static atomic<unsigned int> next_nvme_id = 0;

static void nvme_print_caps(uint64_t caps)
{
}

/**
 * @brief Read the CSTS register
 *
 * @return the CSTS register
 */
uint8_t nvme_device::read_status() const
{
    return regs_.read32(NVME_REG_CSTS);
}

/**
 * @brief Send an NVME identify command
 *
 * @return 0 on success, negative error codes
 */
int nvme_device::identify()
{
    identify_page_ = alloc_page(PAGE_ALLOC_NO_ZERO);
    if (!identify_page_)
        return -ENOMEM;

    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_IDENTIFY) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = 0;
    cmd.cmd.dptr.prp[0] = (prp_entry_t) page_to_phys(identify_page_);
    cmd.cmd.dptr.prp[1] = 0;
    cmd.cmd.cdw10 = NVME_IDENTIFY_CNS_IDENTIFY_CONTROLLER;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);
    return 0;
}

/**
 * @brief Allocates a CID
 *
 * @return 0 on success, negative error codes
 */
int nvme_device::nvme_queue::allocate_cid()
{
    unsigned long bit;
    if (!queued_bitmap_.find_free_bit(&bit))
        return -EAGAIN;
    return (int) bit;
}

/**
 * @brief Submit a raw NVMe command to the queue
 *
 * @param cmd Pointer to the nvmecmd
 * @return 0 on success, negative error codes
 */
int nvme_device::nvme_queue::submit_command(nvmecmd *cmd)
{
    scoped_lock<spinlock, true> g{lock_};

    int cid = allocate_cid();

    if (cid < 0)
        return -EAGAIN;

    auto next_entry = sq_tail_;

    if ((sq_tail_ + 1) % sq_size_ == sq_head_)
        return -EAGAIN;

    sq_tail_ = (sq_tail_ + 1) % sq_size_;
    cmd->cmd.cdw0.cid = cid;
    queued_commands_[cmd->cmd.cdw0.cid] = cmd;
    memcpy(&sq_[next_entry], &cmd->cmd, sizeof(nvmesqe));
    *sq_tail_doorbell_ = sq_tail_;
    return 0;
}

/**
 * @brief Read the controller's capabilities
 *
 * @return Caps
 */
uint64_t nvme_device::read_caps() const
{
    return regs_.read64(NVME_REG_CAP);
}

/**
 * @brief Probe the device and try to initialise it
 *
 * @return 0 on success, negative error codes
 */
int nvme_device::probe()
{
    if (int st = dev_->enable_device(); st < 0)
        return st;

    dev_->enable_busmastering();
    dev_->enable_irq();

    void *mapped = dev_->map_bar(0, VM_NOCACHE);
    if (!mapped)
        return -ENOMEM;

    device_index_ = next_nvme_id++;

    regs_ = mmio_range{(volatile void *) mapped};

    const auto caps = regs_.read64(NVME_REG_CAP);

    if (1U << (12 + NVME_CAP_MPSMIN(caps)) > PAGE_SIZE)
    {
        printf("nvme: error: NVMe controller doesn't support the host page size\n");
        return -EINVAL;
    }

    nvme_print_caps(caps);

    printf("nvme version %04x\n", regs_.read32(NVME_REG_VS));

    const hrtime_t timeout = NVME_CAP_TO(caps) * 500 * NS_PER_MS;

    // If we're ready, disable the controller and wait for it to reset

    if (read_status() & NVME_CSTS_RDY)
    {
        regs_.write32(NVME_REG_CC, regs_.read32(NVME_REG_CC) & ~NVME_CC_EN);
    }

    if (int st = do_with_timeout(
            [&]() -> expected<int, int> { return read_status() & NVME_CSTS_RDY; }, timeout);
        st < 0)
    {
        printf("NVMe controller reset failed with %d\n", st);
        return st;
    }

    if (!init_admin_queue())
    {
        printf("nvme: Failed to allocate memory\n");
        return -ENOMEM;
    }

    uint32_t cc = 0;
    cc |= NVME_CC_EN;
    cc |= NVME_CC_IOSQES(ilog2(sizeof(nvmesqe)));
    cc |= NVME_CC_IOCQES(ilog2(sizeof(nvmecqe)));
    cc |= (PAGE_SHIFT - 12) << NVME_CC_MPS_SHIFT;
    regs_.write32(NVME_REG_CC, cc);

    // Wait for RDY after enabling the controller

    if (int st = do_with_timeout(
            [&]() -> expected<int, int> { return !(read_status() & NVME_CSTS_RDY); }, timeout);
        st < 0)
    {
        printf("NVMe controller reset failed with %d\n", st);
        return st;
    }

    printf("Doorbell stride: %u\n", NVME_CAP_DSTRD(caps));

    const auto handler = [](irq_context *ctx, void *cookie) -> irqstatus_t {
        return ((nvme_device *) cookie)->handle_irq(ctx);
    };

    if (dev_->enable_msi(handler, this) < 0)
    {
        int st = install_irq(dev_->get_intn(), handler, dev_, IRQ_FLAG_REGULAR, this);
        if (st < 0)
        {
            printf("nvme: Failed to enable IRQs, status %d\n", st);
            return st;
        }
    }

    if (int st = identify(); st < 0)
        return st;

    if (int st = init_io_queues(); st < 0)
        return st;

    if (int st = identify_namespaces(); st < 0)
        return st;

    return 0;
}

/**
 * @brief Create an NVME-like(nvme{ID}n{NamespaceId}) block device
 *
 * @param device_index NVMe device index
 * @param namespace_index NVMe namespace index (-1 if it doesn't have a namespace)
 * @return Pointer to blockdev or NULL with errno set
 */
unique_ptr<blockdev> blkdev_create_nvme(unsigned int device_index, unsigned int namespace_index)
{
    unique_ptr<blockdev> dev = make_unique<blockdev>();

    if (!dev)
        return nullptr;

    char buf[sizeof("nvmen") + 1 + 16 * 2];

    if (namespace_index == -1U)
    {
        snprintf(buf, sizeof(buf), "nvme%u", device_index);
    }
    else
    {
        snprintf(buf, sizeof(buf), "nvme%un%u", device_index, namespace_index);
    }

    dev->name = cul::string{buf};
    dev->partition_prefix = "p";

    return cul::move(dev);
}

/**
 * @brief Initialise a new "drive" (namespace)
 *
 * @param nsid Namespace ID
 * @param identify_namespace_data Identify namespace data
 * @return 0 on success, negative error codes
 */
int nvme_device::init_drive(uint32_t nsid, unique_page identify_namespace_data)
{
    unique_ptr<nvme_namespace> nspace = make_unique<nvme_namespace>(this);
    if (!nspace)
        return -ENOMEM;
    const nvme_identify_namespace *nspace_identify =
        (const nvme_identify_namespace *) PAGE_TO_VIRT(identify_namespace_data);

    // Lets get the LBA of the namespace
    const uint64_t lbaf_index =
        (nspace_identify->flbas & (0b1111)) | (nspace_identify->flbas & (1 << 6 | 1 << 5));
    const uint64_t lba = 1 << NVME_LBA_LBASIZE(nspace_identify->lba_formats[lbaf_index]);

    auto d = blkdev_create_nvme(device_index_, nsid);

    if (!d)
        return -ENOMEM;

    nspace->dev_ = d.get();
    nspace->ident_namespace_data_ = cul::move(identify_namespace_data);
    nspace->nsid_ = nsid;
    d->sector_size = lba;
    d->nr_sectors = nspace_identify->nsze * lba;
    d->device_info = nspace.get();
    d->submit_request = [](struct blockdev *dev, struct bio_req *req) -> int {
        nvme_namespace *n = (nvme_namespace *) dev->device_info;
        // TODO: Hack! The disk driver should never get a request for a partition
        // and the block subsystem should handle that
        req->sector_number += dev->offset / n->dev_->sector_size;
        return n->nvme_dev_->submit_request(n, req);
    };

    if (int st = blkdev_init(d.get()); st < 0)
    {
        printf("blkdev_init: error %d\n", st);
        return st;
    }

    d.release();

    if (!namespaces.push_back(cul::move(nspace)))
    {
        return -ENOMEM;
    }

    return 0;
}

/**
 * @brief Setup a PRP for a bio request
 *
 * @param req Request
 * @param ns NVMe namespace
 * @return Expected object containing a prp_setup, or a negative error code
 */
auto nvme_device::setup_prp(bio_req *req, nvme_namespace *ns) -> expected<prp_setup, int>
{
    size_t xfer_size = 0;

    for (size_t i = 0; i < req->nr_vecs; i++)
    {
        xfer_size += req->vec[i].length;

        if (req->vec[i].page_off != 0 && i != 0)
        {
            // If the PRP entry is not the first PRP entry and not a PRP list pointer
            // we can't have an offset here.
            return unexpected{-EINVAL};
        }

        if (req->vec[i].page_off + req->vec[i].length != PAGE_SIZE && i != 0)
        {
            // Same as above. We're basically forced to guarantee all these page_iov are actual full
            // pages
            return unexpected{-EINVAL};
        }
    }

    prp_setup s{};

    s.xfer_blocks = xfer_size / ns->dev_->sector_size;

    // An empty transfer is invalid, and so is a request with a xfer_size % sector_size
    if (s.xfer_blocks == 0 || xfer_size % ns->dev_->sector_size)
        return unexpected{-EIO};

    // Check if we can transfer this number of sectors
    // This is limited by the command dword 12 (Number of logical blocks)
    if (s.xfer_blocks - 1 > 0xffff)
        return unexpected{-EIO};

    s.nr_entries = req->nr_vecs;
    s.first = (prp_entry_t) page_to_phys(req->vec[0].page) + req->vec[0].page_off;

    if (s.nr_entries == 1) [[likely]]
    {
        // Fast path. Get out
        return s;
    }

    size_t nr_entries = req->nr_vecs - 1;

    page *current_list_page = nullptr;
    prp_entry_t *current_list = nullptr;
    size_t list_index = 0;
    const page_iov *v = &req->vec[1];
    constexpr auto prp_entries = PAGE_SIZE / sizeof(prp_entry_t);

    // Logic: Go through all the entries, and progressively allocate memory for them
    while (nr_entries)
    {
        bool has_next = nr_entries > 1;
        // If we don't have a page yet or if we're at the end of the list and have more entries,
        // allocate another page
        if (!current_list_page || (list_index == prp_entries - 1 && has_next))
        {
            current_list_page = alloc_page(PAGE_ALLOC_NO_ZERO);
            if (!current_list_page)
                return unexpected{-ENOMEM};

            if (!s.indirect_list.push_back(current_list_page))
                return free_page(current_list_page), unexpected{-ENOMEM};

            if (current_list)
            {
                // We had a previous list, so link it with this one
                current_list[prp_entries - 1] = (prp_entry_t) page_to_phys(current_list_page);
            }

            current_list = (prp_entry_t *) PAGE_TO_VIRT(current_list_page);
            list_index = 0;
        }

        // Fill the entry
        // Note: None of these entries can have page offsets, and we've checked that before
        current_list[list_index++] = (prp_entry_t) page_to_phys(v->page);
        nr_entries--;
        v++;
    }

    return s;
}

/**
 * @brief Pick an IO queue for this request
 *
 * @param r BIO request
 * @return IO queue index
 */
uint16_t nvme_device::pick_io_queue(bio_req *r)
{
    // Primitive algo: Use the cpu nr as an index
    return (get_cpu_nr() % (queues_.size() - 1)) + 1;
}

/**
 * @brief Submit an IO request
 *
 * @param namespace NVMe namespace to submit an IO request to
 * @param req BIO req to serve
 * @return 0 on success, negative error codes
 */
int nvme_device::submit_request(nvme_namespace *ns, struct bio_req *req)
{
    uint16_t command;

    switch (req->flags & BIO_REQ_OP_MASK)
    {
        case BIO_REQ_READ_OP:
            command = NVME_NVM_CMD_READ;
            break;
        case BIO_REQ_WRITE_OP:
            command = NVME_NVM_CMD_WRITE;
            break;
        default:
            req->flags |= BIO_REQ_EIO;
            return -EOPNOTSUPP;
    }

    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 = NVME_CMD_OPCODE(command) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = ns->nsid_;
    cmd.cmd.cdw12 = 0;

    auto ex = setup_prp(req, ns);

    if (ex.has_error())
    {
        printf("Error setting up PRPs\n");
        req->flags |= BIO_REQ_EIO;
        return ex.error();
    }

    const auto &prp = ex.value();

    cmd.cmd.dptr.prp[0] = prp.first;

    if (prp.nr_entries > 1)
        cmd.cmd.dptr.prp[1] = (prp_entry_t) page_to_phys(prp.indirect_list[0]);

    // Set up the starting LBA and number of sectors
    cmd.cmd.cdw10 = (uint32_t) req->sector_number;
    cmd.cmd.cdw11 = (uint32_t) (req->sector_number >> 32);
    cmd.cmd.cdw12 = (uint16_t) prp.xfer_blocks - 1; // TODO: FUA
    cmd.cmd.cdw13 = 0;
    cmd.cmd.cdw14 = 0;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    auto &queue = queues_[pick_io_queue(req)];
    queue.submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    if (auto status = NVME_CQE_STATUS_CODE(cmd.response.dw3); status != 0)
    {
        printf("nvme%un%u: NVME_NVM_CMD_READ/WRITE: Status error %x\n", device_index_, ns->nsid_,
               status);
        req->flags |= BIO_REQ_EIO;
        return -EIO;
    }

    req->flags |= BIO_REQ_DONE;

    return 0;
}

#define NVME_DEFAULT_SQ_SIZE 128UL
#define NVME_DEFAULT_CQ_SIZE PAGE_SIZE / 16

/**
 * @brief Do a CREATE_IO_SUBMISSION_QUEUE command
 *
 * @param queue Queue number
 * @param queue_address Queue's address
 * @param queue_size Queue size
 * @param completion_queue Completion queue to use for the submitted commands
 * @return 0 on success, negative error codes
 */
int nvme_device::cmd_create_io_submission_queue(uint16_t queue, uint64_t queue_address,
                                                uint16_t queue_size, uint16_t completion_queue)
{
    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_CREATE_IOSQ) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = 0;
    cmd.cmd.dptr.prp[0] = queue_address;
    cmd.cmd.cdw10 = (queue_size - 1U) << 16 | queue;
    cmd.cmd.cdw11 = (unsigned int) completion_queue << 16 |
                    NVME_CREATE_IOSQ_PHYS_CONTIG; // Set bit0 (physically contiguous)
    cmd.cmd.cdw12 = 0;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    if (auto status = NVME_CQE_STATUS_CODE(cmd.response.dw3); status != 0)
    {
        printf("nvme: NVME_ADMIN_OPC_CREATE_IOSQ: Status error %u\n", status);
        return -EIO;
    }

    return 0;
}

/**
 * @brief Do a CREATE_IO_COMPLETION_QUEUE command
 *
 * @param queue Queue number
 * @param queue_address Queue's address
 * @param queue_size Queue size
 * @param interrupt_vector Interrupt vector to use for the queue
 * @return 0 on success, negative error codes
 */
int nvme_device::cmd_create_io_completion_queue(uint16_t queue, uint64_t queue_address,
                                                uint16_t queue_size, uint16_t interrupt_vector)
{
    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_CREATE_IOCQ) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = 0;
    cmd.cmd.dptr.prp[0] = queue_address;
    cmd.cmd.cdw10 = (queue_size - 1U) << 16 | queue;
    cmd.cmd.cdw11 = (unsigned int) interrupt_vector << 16 | NVME_CREATE_IOCQ_IEN |
                    NVME_CREATE_IOCQ_PHYS_CONTIG; // Set bit0 (physically contiguous)
    cmd.cmd.cdw12 = 0;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    if (auto status = NVME_CQE_STATUS_CODE(cmd.response.dw3); status != 0)
    {
        printf("nvme: NVME_ADMIN_OPC_CREATE_IOCQ: Status error %u\n", status);
        return -EIO;
    }

    return 0;
}

/**
 * @brief Create an IO queue
 *
 * @param queue_index The queue's index (ignoring the admin queue)
 * @return 0 on success, negative error codes
 */
int nvme_device::create_io_queue(uint16_t queue_index)
{
    const auto caps = read_caps();
    bool needs_contiguous = caps & NVME_CAP_CQR;
    const uint16_t sq_size = cul::clamp(NVME_CAP_MQES(caps), NVME_DEFAULT_SQ_SIZE);
    const uint16_t cq_size = cul::clamp(NVME_CAP_MQES(caps), NVME_DEFAULT_CQ_SIZE);
    nvme_queue q{this, (uint16_t) (queue_index + 1), sq_size, cq_size};

    if (!q.init(needs_contiguous))
        return -ENOMEM;

    // TODO: Proper MSI and MSI-X multi-vector support
    const uint16_t interrupt_vector = 0;
    if (int st = cmd_create_io_completion_queue(queue_index + 1,
                                                (uint64_t) page_to_phys(q.get_cq_pages()),
                                                q.get_cq_queue_size(), interrupt_vector);
        st < 0)
    {
        printf("nvme%u: create io completion queue: error %d\n", device_index_, st);
        return st;
    }

    if (int st = cmd_create_io_submission_queue(queue_index + 1,
                                                (uint64_t) page_to_phys(q.get_sq_pages()),
                                                q.get_sq_queue_size(), queue_index + 1);
        st < 0)
    {
        printf("nvme%u: create io submission queue: error %d\n", device_index_, st);
        return st;
    }

    if (!queues_.push_back(cul::move(q)))
        return -ENOMEM;

    return 0;
}

/**
 * @brief Initialise the IO queues
 *
 * @return 0 on success, negative error codes
 */
int nvme_device::init_io_queues()
{
    // Note: We clamp the number of queues to the max NVME queues (UINT16_MAX)
    const uint16_t desired_nr_queues = cul::clamp(get_nr_cpus(), (unsigned int) NVME_MAX_QUEUES);

    // Do set features to see if we can get the desired number of IO queues
    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_SET_FEATURE) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = 0;
    cmd.cmd.cdw10 = NVME_SET_FEATURES_NUMBER_QUEUES;
    cmd.cmd.cdw11 = (desired_nr_queues << 16) | desired_nr_queues;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    if (auto status = NVME_CQE_STATUS_CODE(cmd.response.dw3); status != 0)
    {
        printf("nvme%u: namespace set features (number of queues): Status error %u\n",
               device_index_, status);
        return -EIO;
    }

    const uint16_t allocated_cq = cmd.response.dw0 >> 16;
    const uint16_t allocated_sq = (uint16_t) cmd.response.dw0;

    // Note: Due to the current design, we require sq = cq
    // Maybe we should change this
    const uint16_t allocated_queues =
        cul::min(desired_nr_queues, cul::min(allocated_cq, allocated_sq));

    printf("nvme%u: Allocated %u queues\n", device_index_, allocated_queues);

    for (uint16_t i = 0; i < allocated_queues; i++)
    {
        if (int st = create_io_queue(i); st < 0)
        {
            printf("nvme%u: create_io_queue: error %d\n", device_index_, st);
            return st;
        }
    }

    return 0;
}

/**
 * @brief Identify a namespace
 *
 * @param nsid Namespace ID
 * @return 0 on success, negative error codes
 */
int nvme_device::identify_namespace(uint32_t nsid)
{
    auto nsid_page = make_unique_page(PAGE_ALLOC_NO_ZERO);
    if (!nsid_page)
        return -ENOMEM;

    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_IDENTIFY) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = nsid;
    cmd.cmd.dptr.prp[0] = (prp_entry_t) page_to_phys(nsid_page);
    cmd.cmd.dptr.prp[1] = 0;
    cmd.cmd.cdw10 = NVME_IDENTIFY_CNS_IDENTIFY_NAMESPACE;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    if (auto status = NVME_CQE_STATUS_CODE(cmd.response.dw3); status != 0)
    {
        printf("nvme: namespace identify: Status error %u\n", status);
        return -EIO;
    }

    if (int st = init_drive(nsid, cul::move(nsid_page)); st < 0)
        return st;

    return 0;
}

/**
 * @brief Identify and list namespaces
 *
 * @return 0 on success, negative error codes
 */
int nvme_device::identify_namespaces()
{
    auto namespace_identify_page = alloc_page(PAGE_ALLOC_NO_ZERO);
    if (!namespace_identify_page)
        return -ENOMEM;

    nvmecmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd.cdw0.cdw0 =
        NVME_CMD_OPCODE(NVME_ADMIN_OPC_IDENTIFY) | NVME_CMD_FUSE_NORMAL | NVME_CMD_PSDT_PRP;
    cmd.cmd.nsid = 0;
    cmd.cmd.dptr.prp[0] = (prp_entry_t) page_to_phys(namespace_identify_page);
    cmd.cmd.dptr.prp[1] = 0;
    cmd.cmd.cdw10 = NVME_IDENTIFY_CNS_ACTIVE_NSPACE;

    wait_queue wq;
    init_wait_queue_head(&wq);
    cmd.wq = &wq;

    queues_[0].submit_command(&cmd);

    wait_for_event(&wq, cmd.has_response);

    uint32_t *nspaces = (uint32_t *) PAGE_TO_VIRT(namespace_identify_page);

    for (unsigned int i = 0; i < PAGE_SIZE / sizeof(uint32_t); i++)
    {
        if (nspaces[i] == 0)
            break;

        if (int st = identify_namespace(nspaces[i]); st < 0)
            return st;
    }

    free_page(namespace_identify_page);
    return 0;
}
/**
 * @brief Construct a new nvme queue
 *
 * @param dev Device of the queue
 * @param index Index of the queue
 * @param sq_size Size of the submission queue
 * @param cq_size Size of the completion queue
 */
nvme_device::nvme_queue::nvme_queue(nvme_device *dev, uint16_t index, unsigned int sq_size,
                                    unsigned int cq_size)
    : dev_{dev}, sq_size_{sq_size}, cq_size_{cq_size}, index_{index}
{
    spinlock_init(&lock_);
    const auto caps = dev->read_caps();
    sq_tail_doorbell_ = (volatile uint32_t *) (dev_->regs_.as_ptr() +
                                               NVME_REG_SQnTDBL(index_, NVME_CAP_DSTRD(caps)));
    cq_head_doorbell_ = (volatile uint32_t *) (dev_->regs_.as_ptr() +
                                               NVME_REG_CQnHDBL(index_, NVME_CAP_DSTRD(caps)));
}

/**
 * @brief Initialise the nvme queue
 *
 * @param needs_contiguous If true, allocate the SQ and CQ queues contiguously
 * @return True on success, false on failure
 */
bool nvme_device::nvme_queue::init(bool needs_contiguous)
{
    sq_pages_ = alloc_pages(vm_size_to_pages(sq_size_ * sizeof(nvmesqe)), PAGE_ALLOC_CONTIGUOUS);
    if (!sq_pages_)
        return false;
    cq_pages_ = alloc_pages(vm_size_to_pages(cq_size_ * sizeof(nvmecqe)), PAGE_ALLOC_CONTIGUOUS);
    if (!cq_pages_)
        return false;

    sq_ = (nvmesqe *) PAGE_TO_VIRT(sq_pages_);
    cq_ = (nvmecqe *) PAGE_TO_VIRT(cq_pages_);

    if (!queued_commands_.resize(sq_size_))
        return false;

    queued_bitmap_.set_size(sq_size_);
    return queued_bitmap_.allocate_bitmap();
}

/**
 * @brief (Try to) handle a completion IRQ
 *
 * @return True if we got an IRQ, else false
 */
bool nvme_device::nvme_queue::handle_cq()
{
    scoped_lock<spinlock, true> g{lock_};
    bool handled = false;

    while (true)
    {
        auto cqe = cq_ + cq_head_;
        if (bool(NVME_CQE_STATUS_PHASE(cqe->dw3)) == phase)
        {
            handled = true;
            auto cid = NVME_CQE_STATUS_CID(cqe->dw3);
            auto command = queued_commands_[cid];
            if (!command)
                panic("nvme: bad cid %u doesn't exist", cid);

            memcpy(&command->response, cqe, sizeof(nvmecqe));
            command->has_response = true;

            if (command->wq)
                wait_queue_wake_all(command->wq);
            queued_commands_[cid] = nullptr;
            queued_bitmap_.free_bit(cid);
            sq_head_ = NVME_CQE_SQHD(cqe->dw2);
        }
        else
            break;

        cq_head_ = (cq_head_ + 1) % cq_size_;

        if (cq_head_ == 0)
        {
            // Flip the phase
            phase = !phase;
        }
    }

    if (handled)
        *cq_head_doorbell_ = cq_head_;

    return handled;
}

/**
 * @brief Handle an IRQ
 *
 * @param ctx IRQ context (to figure out which MSI vector got triggered)
 * @return Valid irqstatus_t
 */
irqstatus_t nvme_device::handle_irq(const irq_context *ctx)
{
    bool handled = false;
    for (auto &q : queues_)
    {
        handled = handled || q.handle_cq();
    }

    return handled ? IRQ_HANDLED : IRQ_UNHANDLED;
}

/**
 * @brief Initialise the admin queue of the controller
 *
 * @return True on success, else false
 */
bool nvme_device::init_admin_queue()
{
    bool success = queues_.push_back(nvme_queue{this, 0, NVME_DEFAULT_ADMIN_SUBMISSION_QUEUE_SIZE,
                                                NVME_DEFAULT_ADMIN_COMPLETION_QUEUE_SIZE}) &&
                   queues_[0].init(false);
    if (!success)
        return false;
    regs_.write64(NVME_REG_ASQ, (uint64_t) page_to_phys(queues_[0].get_sq_pages()));
    regs_.write64(NVME_REG_ACQ, (uint64_t) page_to_phys(queues_[0].get_cq_pages()));
    // The queue size values are 0's based, so subtract one
    regs_.write32(NVME_REG_AQA, ((queues_[0].get_cq_queue_size() - 1) << 16) |
                                    (queues_[0].get_sq_queue_size() - 1));
    return true;
}

nvme_device::~nvme_device()
{
    // Unmap the BAR
    auto ex = dev_->get_bar(0);
    assert(ex.has_value());

    vm_munmap(&kernel_address_space, (void *) regs_.as_ptr(), ex.value().size);
}

int nvme_probe(struct device *_dev)
{
    pci::pci_device *dev = (pci::pci_device *) _dev;
    printf("Found NVMe device at %04x:%02x:%02x.%d\n", dev->addr().segment, dev->addr().bus,
           dev->addr().device, dev->addr().function);
    unique_ptr<nvme_device> nvmedev = make_unique<nvme_device>(dev);

    if (!nvmedev)
        return -ENOMEM;

    if (int st = nvmedev->probe(); st < 0)
        return st;

    nvmedev.release();

    return 0;
}

driver nvme_driver = {
    .name = "nvme", .devids = &nvme_pci_ids, .probe = nvme_probe, .bus_type_node = {&nvme_driver}};

static int nvme_init()
{
    pci::register_driver(&nvme_driver);
    return 0;
}

DRIVER_INIT(nvme_init);
