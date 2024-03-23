/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/block.h>
#include <onyx/block/io-queue.h>
#include <onyx/block/multiqueue.h>
#include <onyx/clock.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/id.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/port_io.h>
#include <onyx/scoped_lock.h>
#include <onyx/timer.h>
#include <onyx/types.h>
#include <onyx/vm.h>
#include <onyx/wait.h>
#include <onyx/wait_queue.h>

#include <drivers/ata.h>

#include "ide.h"

#include <onyx/memory.hpp>

#define ATA_TIMEOUT          NS_PER_SEC
#define ATA_IDENTIFY_TIMEOUT 100 * NS_PER_MS

static constexpr size_t prdt_nr_pages = 1;

irqstatus_t ide_irq(struct irq_context *ctx, void *cookie);

// The IDE ATA bus is a single queue, 1-depth device
// Every driver on it shares this single queue, annoyingly.
class ide_ata_bus : public io_queue
{
public:
    uint16_t control_reg;
    uint16_t data_reg;
    uint16_t busmaster_reg;
    struct request *req{nullptr};
    prdt_entry_t *prdt{nullptr};
    page *prdt_page{nullptr};

    ide_ata_bus() : io_queue{1}, control_reg{}, data_reg{}, busmaster_reg{}
    {
    }

    int init()
    {
        // TODO: order-N page allocation
        prdt_page = alloc_page_list(prdt_nr_pages, PAGE_ALLOC_4GB_LIMIT);
        if (!prdt_page)
            return -ENOMEM;

        /* Allocate PRDT base */
        prdt = (prdt_entry_t *) mmiomap(page_to_phys(prdt_page), prdt_nr_pages << PAGE_SHIFT,
                                        VM_READ | VM_WRITE);
        if (!prdt)
        {
            ERROR("ata", "Could not allocate a PRDT\n");
            return -ENOMEM;
        }

        return 0;
    }

    ~ide_ata_bus()
    {
        mmiounmap(prdt, prdt_nr_pages << PAGE_SHIFT);
        free_page_list(prdt_page);
    }

    void reset()
    {
        outb(control_reg + IDE_REG_DEVCTL, IDE_DEVCTL_SRST);
    }

    void enable_irqs()
    {
        outb(control_reg + IDE_REG_DEVCTL, 0);
    }

    uint8_t delay_400ns(void)
    {
        for (int i = 0; i < 4; i++) /* Waste 400 ns reading ports*/
            inb(control_reg);

        return inb(control_reg);
    }

    void select_drive(unsigned int drive)
    {
        outb(data_reg + ATA_REG_HDDEVSEL, 0x40 | (drive << 4));
        delay_400ns();
    }

    void send_command(uint8_t command);

    void start_dma(bool write);
    void stop_dma();
    void prepare_dma(struct page *prdt_page, bool write);

    void fill_prdt_from_request(struct request *req);

    /**
     * @brief Submits IO to a device
     *
     * @param req request to submit
     * @return 0 on sucess, negative error codes
     */
    int device_io_submit(struct request *req) override;

    irqstatus_t handle_irq();
};

class ide_dev;
struct ide_drive
{
    bool exists;
    uint32_t lba28;
    uint64_t lba48;
    int type; /* Can be ATA_TYPE_ATA or ATA_TYPE_ATAPI */
    ide_ata_bus &bus;
    int drive;
    ide_dev *dev;
    ata_identify_response identify_buf;

    ide_drive(ide_ata_bus &bus)
        : exists{false}, lba28{}, lba48{}, type{}, bus{bus}, drive{}, identify_buf{}
    {
    }

    int probe();

    /**
     * @brief Waits for DRQ and BSY to be clear
     *
     * @return 0 on success, -EIO on device error and -ETIMEDOUT on timeout
     */
    int wait_for_drq_bsy_clear();

    /**
     * @brief Reads alt status
     *
     * @return Alt status
     */
    uint8_t read_alt_status() const
    {
        return inb(bus.control_reg + ATA_REG_ALTSTATUS);
    }

    /**
     * @brief Wait for BSY to be clear
     *
     * @return 0 on success, -ETIMEDOUT on timeout
     */
    int wait_for_bsy_clear();

    /**
     * @brief Do identify
     *
     * @return 0 on success, negative error codes
     */
    int do_identify();
};

class ide_dev
{
    ide_ata_bus ata_buses[2];

    ide_drive ide_drives[4];
    pci::pci_device *dev;
    uint16_t busmaster_reg{0};

public:
    explicit ide_dev(pci::pci_device *dev)
        : ata_buses{}, ide_drives{ata_buses[0], ata_buses[0], ata_buses[1], ata_buses[1]}, dev{dev}

    {
        for (auto &drv : ide_drives)
            drv.dev = this;
    }

    int probe();
    void enable_pci();

    void reset_controller()
    {
        ata_buses[0].reset();
        ata_buses[1].reset();
        io_wait();
    }

    void enable_irqs()
    {
        ata_buses[0].enable_irqs();
        ata_buses[1].enable_irqs();
    }

    ide_ata_bus &get_bus(int idx)
    {
        return ata_buses[idx];
    }

    void fill_prdt_from_hwvec(const page_iov *vec, size_t nr_vecs);
};

void ide_dev::enable_pci()
{
    /* Enable PCI Busmastering and PCI IDE mode */
    dev->enable_device();
    dev->enable_busmastering();
    dev->write(14, PCI_REGISTER_INTN, sizeof(uint16_t));

#if 0 
	// TODO: Is this needed?
	dev->set_bar(dev->bus, dev->device, dev->function, 0, IDE_DATA1, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 1, IDE_CONTROL1, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 2, IDE_DATA2, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 3, IDE_CONTROL2, 1, 0);
#endif

    ata_buses[0].control_reg = IDE_CONTROL1;
    ata_buses[1].control_reg = IDE_CONTROL2;
    ata_buses[0].data_reg = IDE_DATA1;
    ata_buses[1].data_reg = IDE_DATA2;

    auto st = dev->get_bar(4);
    assert(st.has_error() == false);

    auto bar = st.value();

    busmaster_reg = bar.address;

    ata_buses[0].busmaster_reg = busmaster_reg;
    /* The secondary bus' busmaster reg is offset by 0x8 bytes */
    ata_buses[1].busmaster_reg = busmaster_reg + 0x8;

    assert(install_irq(14, ide_irq, (struct device *) dev, IRQ_FLAG_REGULAR, this) == 0);
    assert(install_irq(15, ide_irq, (struct device *) dev, IRQ_FLAG_REGULAR, this) == 0);
}

int ide_dev::probe()
{
    for (auto &bus : ata_buses)
    {
        if (int st = bus.init(); st < 0)
            return st;
    }

    /* Enable PCI IDE mode, and PCI busmastering DMA*/
    enable_pci();

    /* Reset the controller */
    reset_controller();

    /* Enable interrupts */
    enable_irqs();

    unsigned int i = 0;

    for (auto &drive : ide_drives)
    {
        drive.drive = i++;
        auto st = drive.probe();

        if (st < 0 && st != -ENOENT)
        {
            ERROR("ata", "Error probing drive: %d\n", st);
            continue;
        }
        else if (st == 0)
            INFO("ata", "Found ATA drive at %d:%d\n", drive.drive % 2, drive.drive / 2);
    }

    return 0;
}

void ide_ata_bus::send_command(uint8_t command)
{
    outb(data_reg + ATA_REG_COMMAND, command);
}

irqstatus_t ide_ata_bus::handle_irq()
{
    scoped_lock<spinlock, true> g{lock_};

    auto status = inb(busmaster_reg + IDE_BMR_REG_STATUS);

    if (!(status & IDE_BMR_ST_IRQ_GEN) || !req)
        return IRQ_UNHANDLED;

    bool had_error = status & IDE_BMR_ST_DMA_ERR;
    inb(data_reg + ATA_REG_STATUS);

    outb(busmaster_reg + IDE_BMR_REG_STATUS, status);
    stop_dma();

    req->r_flags |= had_error ? BIO_REQ_EIO : 0;
    req->r_flags |= BIO_REQ_DONE;
    complete_request(req);
    req = nullptr;

    return IRQ_HANDLED;
}

irqstatus_t ide_irq(struct irq_context *ctx, void *cookie)
{
    auto device = (ide_dev *) cookie;

    int bus_idx = 0;

    /* IDE triggers IRQ14 for primary bus irqs, and IRQ15 for secondary bus irqs */
    if (ctx->irq_nr == ATA_IRQ)
        bus_idx = 0;
    else
        bus_idx = 1;

    auto &bus = device->get_bus(bus_idx);

    return bus.handle_irq();
}

ide_drive *ide_drive_from_blockdev(blockdev *dev)
{
    return (ide_drive *) dev->device_info;
}

// bio_req details:
// device_specific[0] layout: top 32 bits = len, bottom 32 is flags
// only 1 flag is defined: bit 0: bounce buffer valid

#define BIO_REQ_HAS_BOUNCE_BUF (1U << 0)

int ide_ata_bus::device_io_submit(struct request *req)
{
    auto drive = ide_drive_from_blockdev(req->r_bdev);
    bool write = (req->r_flags & BIO_REQ_OP_MASK) == BIO_REQ_WRITE_OP;
    u8 command = write ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;
    bool prdt_write = !write;

    fill_prdt_from_request(req);

    prepare_dma(prdt_page, prdt_write);

    int st = drive->wait_for_bsy_clear();
    if (st < 0)
    {
        printf("ata: wait_for_bsy_clear failed: %d\n", st);
        return st;
    }

    select_drive(drive->drive);

    st = drive->wait_for_bsy_clear();

    if (st < 0)
    {
        printf("ata: wait_for_bsy_clear failed: %d\n", st);
        return st;
    }

    const auto sect = req->r_sector;
    const uint16_t num_secs = req->r_nsectors;
    outb(data_reg + ATA_REG_SECCOUNT0, num_secs >> 8);
    outb(data_reg + ATA_REG_LBA0, sect >> 24);
    outb(data_reg + ATA_REG_LBA1, sect >> 32);
    outb(data_reg + ATA_REG_LBA2, sect >> 40);
    outb(data_reg + ATA_REG_SECCOUNT0, num_secs);
    outb(data_reg + ATA_REG_LBA0, sect);
    outb(data_reg + ATA_REG_LBA1, sect >> 8);
    outb(data_reg + ATA_REG_LBA2, sect >> 16);

    outb(data_reg + ATA_REG_COMMAND, command);

    start_dma(prdt_write);

    this->req = req;

    return 0;
}

int ata_flush(struct blockdev *blkd)
{
    auto drv = ide_drive_from_blockdev(blkd);

    drv->bus.send_command(ATA_CMD_CACHE_FLUSH_EXT);
    return 0;
}

int ata_pm(int op, struct blockdev *blkd)
{
    /* Flush all data before entering any power mode */
    ata_flush(blkd);
    auto drv = ide_drive_from_blockdev(blkd);

    if (op == BLKDEV_PM_SLEEP)
    {
        drv->bus.send_command(ATA_CMD_IDLE);
        return 0;
    }
    else
        return errno = EINVAL, -1;
}

/**
 * @brief Waits for DRQ and BSY to be clear
 *
 * @return 0 on success, -EIO on device error and -ETIMEDOUT on timeout
 */
int ide_drive::wait_for_drq_bsy_clear()
{
    return do_with_timeout(
        [&]() -> expected<int, int> {
            auto altstatus = read_alt_status();
            if (altstatus & ATA_SR_BSY)
                return 1;

            if (altstatus & ATA_SR_DRQ)
                return unexpected<int>{-EIO};

            return 0;
        },
        10 * NS_PER_MS);
}

/**
 * @brief Waits for BSY to be clear
 *
 * @return 0 on success, -ETIMEDOUT on timeout
 */
int ide_drive::wait_for_bsy_clear()
{
    return do_with_timeout(
        [&]() -> expected<int, int> {
            auto altstatus = read_alt_status();
            if (altstatus & ATA_SR_BSY)
                return 1;

            return 0;
        },
        10 * NS_PER_MS);
}

int ide_drive::do_identify()
{
    int st = wait_for_bsy_clear();

    if (st < 0)
    {
        printf("Wait for BSY clear error: %d\n", st);
        return 1;
    }

    outb(bus.data_reg + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    bus.delay_400ns();

    st = wait_for_bsy_clear();

    if (st < 0)
    {
        printf("ide: Wait for BSY clear error: %d\n", st);
        return st;
    }

    auto status = read_alt_status();

    if (status & ATA_SR_ERR)
    {
        printf("ata: Error in ATA IDENTIFY\n");
    }

    for (int i = 0; i < 256; i++)
    {
        uint16_t data = inw(bus.data_reg);
        memcpy(((uint16_t *) &identify_buf) + i, &data, sizeof(uint16_t));
    }

    string_fix(identify_buf.serial.word, sizeof(identify_buf.serial.word));
    string_fix(identify_buf.model_id.word, sizeof(identify_buf.model_id.word));
    string_fix(identify_buf.firmware_rev.word, sizeof(identify_buf.firmware_rev.word));

    return 0;
}

static struct io_queue *ide_pick_queue(struct blockdev *dev)
{
    ide_drive *drive = ide_drive_from_blockdev(dev);
    return &drive->bus;
}

static const struct blk_mq_ops ide_mq_ops = {.pick_queue = ide_pick_queue};

#define ATA_MAX_SECTORS UINT16_MAX

static void ide_set_queue_properties(struct queue_properties *qp)
{
    qp->max_sgl_desc_length = UINT16_MAX;
    qp->max_sgls_per_request = (prdt_nr_pages << PAGE_SHIFT) / sizeof(prdt_entry_t);
    qp->bounce_highmem = true;
    qp->max_sectors_per_request = ATA_MAX_SECTORS;
    qp->dma_boundary = 0xffff;
}

int ide_drive::probe()
{
    // Inspired by EDK2's MdeModulePkg/Bus/Ata/AtaAtapiPassThru/IdeMode.c
    // The probing process looks pretty undocumented so this is the best
    // reference I got.
    bus.select_drive(drive);

    outb(bus.data_reg + ATA_REG_COMMAND, ATA_CMD_EXEC_DRIVE_DIAG);

    if (wait_for_bsy_clear() < 0)
    {
        return -ETIMEDOUT;
    }

    bus.select_drive(drive);

    const auto sector_count = inb(bus.data_reg + ATA_REG_SECCOUNT0);
    const auto lba_low = inb(bus.data_reg + ATA_REG_LBA0);
    const auto lba_mid = inb(bus.data_reg + ATA_REG_LBA1);
    const auto lba_hi = inb(bus.data_reg + ATA_REG_LBA2);

    if (sector_count == 1 && lba_low == 1 && lba_mid == 0 && lba_hi == 0)
    {
        type = ATA_TYPE_ATA;
    }
    else if (lba_mid == 0x14 && lba_hi == 0xeb)
    {
        type = ATA_TYPE_ATAPI;
        printf("ide: Found ATAPI device: not yet implemented\n");
        return 0;
    }
    else
        return -ENOENT;

    if (int st = do_identify(); st < 0)
    {
        printk("ide: ATA_CMD_IDENTIFY failed\n");
        return st;
    }

    /* Add to the block device layer */
    auto dev = blkdev_create_scsi_like_dev();

    if (!dev)
    {
        FATAL("ata", "could not create a block device\n");
        return -ENODEV;
    }

    dev->device_info = this;
    dev->flush = ata_flush;
    dev->power = ata_pm;
    dev->submit_request = blk_mq_submit_request;
    dev->sector_size = 512;
    dev->mq_ops = &ide_mq_ops;
    ide_set_queue_properties(&dev->bdev_queue_properties);

    dev->nr_sectors =
        identify_buf.lba_capacity2 != 0 ? identify_buf.lba_capacity2 : identify_buf.lba_capacity;

    if (blkdev_init(dev.get()) < 0)
        return -ENOMEM;

    dev.release();

    return 0;
}

struct pci::pci_id ata_devs[] = {{PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 1, PCI_ANY_ID, NULL)},
                                 {PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 6, PCI_ANY_ID, NULL)},
                                 {0}};

int ata_probe(struct device *d)
{
    pci::pci_device *device = (pci::pci_device *) d;

    // If this is a SATA controller with a valid BAR5 (AHCI HBA BAR), skip this
    // and defer to AHCI.
    if (device->sub_class() == 6 && device->get_bar(5).has_value())
        return -1;

    unique_ptr<ide_dev> dev = make_unique<ide_dev>(device);
    if (!dev)
        return -ENOMEM;

    auto st = dev->probe();

    if (st == 0)
        dev.release();

    return st;
}

struct driver ata_driver = {
    .name = "ata", .devids = &ata_devs, .probe = ata_probe, .bus_type_node = {&ata_driver}};

int ata_init(void)
{
    pci::register_driver(&ata_driver);

    return 0;
}

void ide_ata_bus::fill_prdt_from_request(struct request *req)
{
    auto prd = prdt;
    bool is_first = true;

    for_every_bio(req, [&](struct bio_req *bio) {
        for_every_page_iov_in_bio(bio, [&](page_iov *iov) -> bool {
            prd->address = ((unsigned long) page_to_phys(iov->page)) + iov->page_off;
            prd->flags = PRD_FLAG_END;
            prd->size = (uint16_t) iov->length;

            if (!is_first)
            {
                /* Go to the last PRD and unset the end, because it's clearly not the end descriptor
                 */
                (prd - 1)->flags &= ~PRD_FLAG_END;
            }

            is_first = false;
            ++prd;
            return true;
        });
    });
}

void ide_ata_bus::start_dma(bool write)
{
    outb(busmaster_reg + IDE_BMR_REG_COMMAND, IDE_BMR_CMD_START | (write ? IDE_BMR_CMD_WRITE : 0));
}

void ide_ata_bus::prepare_dma(struct page *prdt_page, bool write)
{
    uint32_t prdt_phys = (uint32_t) (unsigned long) page_to_phys(prdt_page);
    outl(busmaster_reg + IDE_BMR_REG_PRDT_ADDR, prdt_phys);
    outb(busmaster_reg + IDE_BMR_REG_COMMAND, (write ? IDE_BMR_CMD_WRITE : 0));
    outb(busmaster_reg + IDE_BMR_REG_STATUS, IDE_BMR_ST_IRQ_GEN | IDE_BMR_ST_DMA_ERR);
}

void ide_ata_bus::stop_dma()
{
    outb(busmaster_reg + IDE_BMR_REG_COMMAND, 0);
    outl(busmaster_reg + IDE_BMR_REG_PRDT_ADDR, 0);
}

MODULE_INIT(ata_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
