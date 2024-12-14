/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _NVME_H
#define _NVME_H

#include <stdint.h>

#include <onyx/bitmap.h>
#include <onyx/block.h>
#include <onyx/block/io-queue.h>
#include <onyx/vector.h>
#include <onyx/wait.h>
#include <onyx/wait_queue.h>

#include <pci/pci.h>

#include <onyx/atomic.hpp>
#include <onyx/hwregister.hpp>

#define NVME_DEFAULT_ADMIN_SUBMISSION_QUEUE_SIZE (PAGE_SIZE / 64)
#define NVME_DEFAULT_ADMIN_COMPLETION_QUEUE_SIZE (PAGE_SIZE / 16)

struct nvmesqe;
struct nvmecmd;
struct nvmecqe;
/**
 * @brief Represents an NVMe device on the PCIe bus
 *
 */
class nvme_device
{
private:
    pci::pci_device *dev_;
    unsigned int device_index_;
    mmio_range regs_{};
    class nvme_queue : public io_queue
    {
    private:
        nvme_device *dev_;
        unsigned int sq_size_;
        unsigned int cq_size_;
        struct page *sq_pages_{nullptr};
        struct page *cq_pages_{nullptr};
        nvmesqe *sq_;
        nvmecqe *cq_;
        volatile uint32_t *sq_tail_doorbell_;
        volatile uint32_t *cq_head_doorbell_;
        uint32_t cq_head_{0};
        uint32_t sq_tail_{0};
        uint32_t sq_head_{0};
        uint16_t index_;
        bool phase{true};
        cul::vector<nvmecmd *> queued_commands_{};
        Bitmap<0> queued_bitmap_;

    public:
        /**
         * @brief Construct a new nvme queue
         *
         * @param dev Device of the queue
         * @param index Index of the queue
         * @param sq_size Size of the submission queue
         * @param cq_size Size of the completion queue
         */
        nvme_queue(nvme_device *dev, uint16_t index, unsigned int sq_size, unsigned int cq_size);

        nvme_queue() : io_queue(0)
        {
        }

        virtual ~nvme_queue()
        {
            if (sq_pages_)
                free_pages(sq_pages_);
            if (cq_pages_)
                free_pages(cq_pages_);
        }

        nvme_queue &operator=(nvme_queue &&q)
        {
            if (&q == this)
                return *this;
            dev_ = q.dev_;
            sq_size_ = q.sq_size_;
            cq_size_ = q.cq_size_;
            sq_pages_ = q.sq_pages_;
            q.sq_pages_ = nullptr;
            cq_pages_ = q.cq_pages_;
            q.cq_pages_ = nullptr;
            sq_ = q.sq_;
            cq_ = q.cq_;
            sq_tail_doorbell_ = q.sq_tail_doorbell_;
            cq_head_doorbell_ = q.cq_head_doorbell_;
            cq_head_ = q.cq_head_;
            sq_tail_ = q.sq_tail_;
            index_ = q.index_;
            phase = q.phase;
            queued_commands_ = cul::move(q.queued_commands_);
            queued_bitmap_ = cul::move(q.queued_bitmap_);
            return *this;
        }

        nvme_queue(nvme_queue &&q) : io_queue{q.sq_size_}
        {
            if (&q == this)
                return;
            dev_ = q.dev_;
            sq_size_ = q.sq_size_;
            cq_size_ = q.cq_size_;
            sq_pages_ = q.sq_pages_;
            q.sq_pages_ = nullptr;
            cq_pages_ = q.cq_pages_;
            q.cq_pages_ = nullptr;
            sq_ = q.sq_;
            cq_ = q.cq_;
            sq_tail_doorbell_ = q.sq_tail_doorbell_;
            cq_head_doorbell_ = q.cq_head_doorbell_;
            cq_head_ = q.cq_head_;
            sq_tail_ = q.sq_tail_;
            index_ = q.index_;
            phase = q.phase;
            queued_commands_ = cul::move(q.queued_commands_);
            queued_bitmap_ = cul::move(q.queued_bitmap_);
        }

        CLASS_DISALLOW_COPY(nvme_queue);

        /**
         * @brief Initialise the nvme queue
         *
         * @param needs_contiguous If true, allocated the SQ and CQ queues contiguously
         * @return True on success, false on failure
         */
        bool init(bool needs_contiguous);

        /**
         * @brief Submit a raw NVMe command to the queue
         *
         * @param cmd Pointer to the nvmecmd
         * @return 0 on success, negative error codes
         */
        int submit_command(nvmecmd *cmd);

        /**
         * @brief (Try to) handle a completion IRQ
         *
         * @return True if we got an IRQ, else false
         */
        bool handle_cq();

        /**
         * @brief Allocates a CID
         *
         * @return 0 on success, negative error codes
         */
        int allocate_cid();

        /**
         * @brief Get the queue's SQ pages
         *
         */
        page *get_sq_pages()
        {
            return sq_pages_;
        }

        /**
         * @brief Get the queue's CQ pages
         *
         */
        page *get_cq_pages()
        {
            return cq_pages_;
        }

        /**
         * @brief Get the SQ queue size
         *
         * @return SQ queue size
         */
        uint16_t get_sq_queue_size()
        {
            return sq_size_;
        }

        /**
         * @brief Get the CQ queue size
         *
         * @return CQ queue size
         */
        uint16_t get_cq_queue_size()
        {
            return cq_size_;
        }

        /**
         * @brief Submits IO to a device
         *
         * @param req bio_req to submit
         * @return 0 on sucess, negative error codes
         */
        int device_io_submit(struct request *req) override;

        /**
         * @brief Complete a block request
         * Called from softirq context. We need to override this function
         * to free nvmecmd.
         *
         * @param req Request to comlete
         */
        void do_complete(struct request *req) override;

        /**
         * @brief Restart the submission queue by "pulling"
         *
         * @return Error code
         */
        int pull_sq() override;
    };
    page *identify_page_;

    cul::vector<unique_ptr<nvme_queue>> queues_;

    /**
     * @brief Identify and list namespaces
     *
     * @return 0 on success, negative error codes
     */
    int identify_namespaces();

    /**
     * @brief Identify a namespace
     *
     * @param nsid Namespace ID
     * @return 0 on success, negative error codes
     */
    int identify_namespace(uint32_t nsid);

    struct nvme_namespace
    {
        unique_page ident_namespace_data_;
        blockdev *dev_;
        uint32_t nsid_;
        nvme_device *nvme_dev_;

        constexpr nvme_namespace(nvme_device *ndev) : nvme_dev_{ndev}
        {
        }
    };

    cul::vector<unique_ptr<nvme_namespace>> namespaces;
    /**
     * @brief Initialise a new "drive" (namespace)
     *
     * @param nsid Namespace ID
     * @param identify_namespace_data Identify namespace data
     * @return 0 on success, negative error codes
     */
    int init_drive(uint32_t nsid, unique_page identify_namespace_data);

    /**
     * @brief Initialise the IO queues
     *
     * @return 0 on success, negative error codes
     */
    int init_io_queues();

    /**
     * @brief Create an IO queue
     *
     * @param queue_index The queue's index (ignoring the admin queue)
     * @return 0 on success, negative error codes
     */
    int create_io_queue(uint16_t queue_index);

    /**
     * @brief Do a CREATE_IO_SUBMISSION_QUEUE command
     *
     * @param queue Queue number
     * @param queue_address Queue's address
     * @param queue_size Queue size
     * @param completion_queue Completion queue to use for the submitted commands
     * @return 0 on success, negative error codes
     */
    int cmd_create_io_submission_queue(uint16_t queue, uint64_t queue_address, uint16_t queue_size,
                                       uint16_t completion_queue);

    /**
     * @brief Do a CREATE_IO_COMPLETION_QUEUE command
     *
     * @param queue Queue number
     * @param queue_address Queue's address
     * @param queue_size Queue size
     * @param interrupt_vector Interrupt vector to use for the queue
     * @return 0 on success, negative error codes
     */
    int cmd_create_io_completion_queue(uint16_t queue, uint64_t queue_address, uint16_t queue_size,
                                       uint16_t interrupt_vector);

    /**
     * @brief Setup a PRP for a bio request
     *
     * @param req Request
     * @param ns NVMe namespace
     * @return 0, or negative error code
     */
    static int setup_prp(struct request *breq, nvme_namespace *ns);

    static int prepare_nvme_request(u8 bio_command, nvmecmd *cmd, struct request *breq,
                                    nvme_namespace *ns);

    void set_queue_properties(blockdev *bdev);

public:
    nvme_device(pci::pci_device *dev) : dev_{dev}
    {
    }

    ~nvme_device();

    /**
     * @brief Probe the device and try to initialise it
     *
     * @return 0 on success, negative error codes
     */
    int probe();

    /**
     * @brief Read the CSTS register
     *
     * @return the CSTS register
     */
    uint8_t read_status() const;

    /**
     * @brief Initialise the admin queue of the controller
     *
     * @return True on success, else false
     */
    bool init_admin_queue();

    /**
     * @brief Send an NVME identify command
     *
     * @return 0 on success, negative error codes
     */
    int identify();

    /**
     * @brief Read the controller's capabilities
     *
     * @return Caps
     */
    uint64_t read_caps() const;

    /**
     * @brief Pick an IO queue for a request
     *
     * @param bdev Block device
     * @return IO queue
     */
    static struct io_queue *pick_queue(blockdev *bdev);

    static irqstatus_t nvme_irq(struct irq_context *ctx, void *cookie);
};

// List of NVMe registers

// NVMe Capabilities
#define NVME_REG_CAP   0x00
// Version
#define NVME_REG_VS    0x08
// Interrupt mask set
#define NVME_REG_INTMS 0x0c
// Interrupt mask clear
#define NVME_REG_INTMC 0x0f
// Controller configuration
#define NVME_REG_CC    0x14
// Controller status
#define NVME_REG_CSTS  0x1c
// NVM subsystem reset - optional
#define NVME_REG_NSSR  0x20
// Admin queue attributes
#define NVME_REG_AQA   0x24
// Admin subsmission queue base
#define NVME_REG_ASQ   0x28
// Admin completion queue base
#define NVME_REG_ACQ   0x30

// Submission queue N tail doorbell
#define NVME_REG_SQnTDBL(N, stride) (0x1000 + (2 * N) * stride)
#define NVME_REG_CQnHDBL(N, stride) (0x1000 + (2 * N + 1) * stride)

// NVMe capabilities list
#define NVME_CAP_CRWMS                 (1ULL << 60)
#define NVME_CAP_CRIMS                 (1ULL << 59)
// NVM subsystem shutdown supported
#define NVME_CAP_NSSS                  (1ULL << 58)
#define NVME_CAP_CMBS                  (1ULL << 57)
#define NVME_CAP_PMRS                  (1ULL << 56)
#define NVME_CAP_MPSMAX(caps)          ((caps >> 52) & 0b11111)
#define NVME_CAP_MPSMIN(caps)          ((caps >> 48) & 0b11111)
#define NVME_CAP_CSS_NVM_COMMAND_SET   (1ULL << 37)
#define NVME_CAP_CSS_IO_COMMAND_SETS   (1ULL << 43)
#define NVME_CAP_CSS_NO_IO_COMMAND_SET (1ULL << 44)
#define NVME_CAP_NSSRS                 (1ULL << 36)
#define NVME_CAP_DSTRD(caps)           (4U << ((caps >> 32) & 0xf))
// Worst case timeout, in 500-ms units
#define NVME_CAP_TO(caps)              ((caps >> 24) & 0xff)
#define NVME_CAP_CQR                   (1ULL << 16)
#define NVME_CAP_MQES(caps)            (caps & 0xffff)

using prp_entry_t = uint64_t;

// NVMe controller status
#define NVME_CSTS_ST    (1 << 6)
#define NVME_CSTS_PP    (1 << 5)
#define NVME_CSTS_NSSRO (1 << 4)
#define NVME_CSTS_CFS   (1 << 1)
#define NVME_CSTS_RDY   (1 << 0)

// NVMe controller configuration register
#define NVME_CC_EN                  (1 << 0)
#define NVME_CC_MPS_SHIFT           7
#define NVME_CC_CSS_NVM_COMMAND_SET 0
#define NVME_CC_AMS_RR              (0 << 11)
#define NVME_CC_AMS_WRR             (1 << 11)
#define NVME_CC_IOSQES(n)           (n << 16)
#define NVME_CC_IOCQES(n)           (n << 20)

struct sgl_descriptor
{
    unsigned char type_specific[15];
    uint8_t sgl_identifier;
};

static_assert(sizeof(sgl_descriptor) == 16);
static_assert(sizeof(prp_entry_t) == 8);

#define NVME_CMD_PSDT_PRP            0
#define NVME_CMD_PSDT_SGL_CONTIGUOUS (0b01 << 14)
#define NVME_CMD_PSDT_SGL            (0b10 << 14)
#define NVME_CMD_FUSE_NORMAL         0
#define NVME_CMD_FUSE_1ST_CMD        (1 << 8)
#define NVME_CMD_FUSE_2ND_CMD        (2 << 8)
#define NVME_CMD_CMD_IDENTIFIER(id)  (((uint32_t) id) << 16)
#define NVME_CMD_OPCODE(opcode)      (opcode)

#define NVME_ADMIN_OPC_DELETE_IOSQ 0x00
#define NVME_ADMIN_OPC_CREATE_IOSQ 0x01
#define NVME_ADMIN_OPC_DELETE_IOCQ 0x04
#define NVME_ADMIN_OPC_CREATE_IOCQ 0x05
#define NVME_ADMIN_OPC_IDENTIFY    0x06
#define NVME_ADMIN_OPC_ABORT       0x08
#define NVME_ADMIN_OPC_SET_FEATURE 0x09
#define NVME_ADMIN_OPC_GET_FEATURE 0x0a
#define NVME_ADMIN_OPC_ASYNC_EVENT 0x0c

/**
 * @brief NVMe submission queue entry
 *
 */
struct nvmesqe
{
    union {
        uint32_t cdw0;
        struct
        {
            uint8_t opcode;
            uint8_t fuse : 2;
            uint8_t resv0 : 4;
            uint8_t psdt : 2;
            uint16_t cid;
        };
    } cdw0;

    uint32_t nsid;
    uint32_t cdw2;
    uint32_t cdw3;
    uint64_t mptr;
    union {
        // If psdt == 00b, so PRP
        prp_entry_t prp[2];
        sgl_descriptor desc;
    } dptr;

    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
};

static_assert(sizeof(struct nvmesqe) == 64);

/**
 * @brief NVMe completion queue entry
 *
 */
struct nvmecqe
{
    uint32_t dw0;
    uint32_t dw1;
    uint32_t dw2;
    uint32_t dw3;
};

#define NVME_CQE_STATUS_PHASE(dw3) ((dw3) & (1 << 16))
#define NVME_CQE_STATUS_CODE(dw3)  ((dw3 >> 17) & 0xff)
#define NVME_CQE_STATUS_SCT(dw3)   ((dw3 >> 25) & 0x7)
#define NVME_CQE_STATUS_CRD(dw3)   ((dw3 >> 28) & 3)
#define NVME_CQE_STATUS_MORE(dw3)  (dw3 & (1 << 30))
#define NVME_CQE_STATUS_DNR(dw3)   (dw3 & (1U << 31))
#define NVME_CQE_STATUS_CID(dw3)   ((uint16_t) dw3)
#define NVME_CQE_SQHD(dw2)         ((uint16_t) dw2)

static_assert(sizeof(nvmecqe) == 16);

/**
 * @brief Internal NVMe command.
 *
 */
struct nvmecmd
{
    wait_queue *wq;
    nvmesqe cmd;
    nvmecqe response;
    bool has_response;
    struct request *req;
};

struct prp_setup
{
    uint64_t first;
    u64 prp2;
    u32 nr_indirects;

    ~prp_setup();
};

struct request_pdu
{
    nvmecmd cmd;
    prp_setup setup;
};

#define NVME_IDENTIFY_CNS_IDENTIFY_NAMESPACE  0
#define NVME_IDENTIFY_CNS_IDENTIFY_CONTROLLER 1
#define NVME_IDENTIFY_CNS_ACTIVE_NSPACE       2

// Identify data taken from Fuchsia
// (https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/src/devices/block/drivers/nvme/nvme-hw.h)
// MIT license applies
// Copyright 2017 The Fuchsia Authors. All rights reserved.
typedef struct
{
    uint32_t w[8];
} nvme_psd_t;

typedef struct
{
    //--------------------- // Controller Capabilities and Features
    uint16_t VID;      // PCI Vendor ID
    uint16_t SSVID;    // PCI Subsystem Vendor ID
    uint8_t SN[20];    // Serial Number
    uint8_t MN[40];    // Model Number
    uint8_t FR[8];     // Firmware Revision
    uint8_t RAB;       // Recommended Arbitrartion Burst
    uint8_t IEEE[3];   // IEEE OUI Identifier
    uint8_t CMIC;      // Controller Multi-Path IO and Namespace Sharing Caps
    uint8_t MDTS;      // Maximum Data Transfer Size
    uint16_t CNTLID;   // Controller ID
    uint32_t VER;      // Version
    uint32_t RTD3R;    // RTD3 Resume Latency (uS)
    uint32_t RTD3E;    // RTD3 ENtry Latency (uS)
    uint32_t OAES;     // Optional Asynch Events Supported;
    uint32_t CTRATT;   // Controller Attributes
    uint8_t zz0[12];   // Reserved
    uint8_t FGUID[16]; // Field Replaceable Unit GUID
    uint8_t zz1[112];  // Reserved
    uint8_t zz2[16];   // Refer to NVMe MI Spec

    // -------------------- // Admin Command Set Attributes and Capabilities
    uint16_t OACS;       // Optional Admin Command Support
    uint8_t ACL;         // Abort Command Limit
    uint8_t AERL;        // Async Event Request Limit
    uint8_t FRMW;        // Firmware Updates
    uint8_t LPA;         // Log Page Attributes;
    uint8_t ELPE;        // Error Log Page Entries
    uint8_t NPSS;        // Number of Power States Supported
    uint8_t AVSCC;       // Admin Vendor Specific Command Config
    uint8_t APSTA;       // Autonomous Power State Transition Attrs
    uint16_t WCTEMP;     // Warning Composite Temp Threshold
    uint16_t CCTEMP;     // Critical Composite Temp Threshold
    uint16_t MTFA;       // Max Time for Firmware Activation (x 100mS, 0 = undef)
    uint32_t HMPRE;      // Host Memory Buffer Preferred Size (4K pages)
    uint32_t HMMIN;      // Host Memory Buffer Minimum Size (4K pages)
    uint64_t TNVMCAP_LO; // Total NVM Capacity (bytes)
    uint64_t TNVMCAP_HI;
    uint64_t UNVMCAP_LO; // Unallocated NVM Capacity (bytes)
    uint64_t UNVMCAP_HI;
    uint32_t RPMBS;   // Replay Protected Memory Block Support
    uint16_t EDSTT;   // Extended Device SelfTest Time
    uint8_t DSTO;     // Devcie SelfTest Options
    uint8_t FWUG;     // Firmware Upgreade Granularity
    uint16_t KAS;     // Keep Alive Support
    uint16_t HCTMA;   // Host Controlled Thermal Management Attrs
    uint16_t MNTMT;   // Minimum Thermal Management Temp
    uint16_t MXTMT;   // Maximum Thermal Management Temp
    uint32_t SANICAP; // Sanitize Capabilities
    uint8_t zz3[180]; // Reserved

    // -------------------- // NVM Command Set Attributes
    uint8_t SQES;        // Submission Queue Entry Size
    uint8_t CQES;        // Completion Queue Entry Size
    uint16_t MAXCMD;     // Max Outstanding Commands
    uint32_t NN;         // Number of Namespaces
    uint16_t ONCS;       // Optional NVM Command Support
    uint16_t FUSES;      // Fused Operation Support
    uint8_t FNA;         // Format NVM Attributes
    uint8_t VWC;         // Volatile Write Cache
    uint16_t AWUN;       // Atomic Write Unit Normal
    uint16_t AWUPF;      // Atomic Write Unit Power Fail
    uint8_t NVSCC;       // NVM Vendor Specific Command Config
    uint8_t zz4;         // Reserved
    uint16_t ACWU;       // Atomic Compare and Write Unit
    uint16_t zz5;        // Reserved
    uint32_t SGLS;       // Scatter Gather List Support
    uint8_t zz6[228];    // Reserved
    uint8_t SUBNQN[256]; // NVM Subsystem NVMe Qualified Name
    uint8_t zz7[768];    // Reserved
    uint8_t zz8[256];    // Refer to NVME over Fabrics Spec

    // -------------------- // Power State Descriptors
    nvme_psd_t PSD[32];

    // -------------------- // Vendor Specific
    uint8_t vendor[1024];
} nvme_identify_t;

// Fuchsia code ends here.

static_assert(sizeof(nvme_identify_t) == 4096);

struct nvme_identify_namespace
{
    uint64_t nsze;
    uint64_t ncap;
    uint64_t nuse;
    uint8_t nsfeat;
    uint8_t nlbaf;
    uint8_t flbas;
    uint8_t mc;
    uint8_t dpc;
    uint8_t dps;
    uint8_t nmic;
    uint8_t rescap;
    uint8_t fpi;
    uint8_t dlfeat;
    uint16_t nawun;
    uint16_t nawupf;
    uint16_t nacwu;
    uint16_t nabsn;
    uint16_t nabo;
    uint16_t nabspf;
    uint16_t noiob;
    uint64_t nvmcap;
    uint16_t npwg;
    uint16_t npwa;
    uint16_t npdg;
    uint16_t npda;
    uint16_t nows;
    uint16_t mssrl;
    uint32_t mcl;
    uint8_t rsv0[10];
    uint32_t anagrpid;
    uint16_t rsv1;
    uint8_t nsattr;
    uint16_t nvmsetid;
    uint16_t endgid;
    uint8_t nguid[16];
    uint8_t eui64[16];
    uint32_t lba_formats[64];
    uint8_t vendor[3711];
};

static_assert(sizeof(nvme_identify_namespace) == 4096);

#define NVME_LBA_LBASIZE(n) (((n) >> 16) & 0xff)

#define NVME_SET_FEATURES_NUMBER_QUEUES 7

#define NVME_MAX_QUEUES UINT16_MAX

#define NVME_CREATE_IOSQ_PHYS_CONTIG (1 << 0)

#define NVME_CREATE_IOCQ_PHYS_CONTIG (1 << 0)
#define NVME_CREATE_IOCQ_IEN         (1 << 1)

#define NVME_NVM_CMD_WRITE 1
#define NVME_NVM_CMD_READ  2

#endif
