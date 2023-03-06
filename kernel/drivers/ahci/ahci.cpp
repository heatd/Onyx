/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include "include/ahci.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/block.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/dma.h>
#include <onyx/dpc.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/module.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/wait.h>

#include <drivers/ata.h>
#include <pci/pci.h>

#define NUM_PRDT_PER_TABLE 56

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("ahci: " __VA_ARGS__)

#ifndef CONFIG_AHCI_DEBUG
#define VERBOSE_MPRINTF(...)
#else
#define VERBOSE_MPRINTF(...)          \
    do                                \
    {                                 \
        printk("ahci: " __VA_ARGS__); \
    } while (0);
#endif

void ahci_io_queue::do_irq(u16 slot, u32 irq_status)
{
    scoped_lock<spinlock, true> g{lock_};

    auto list = &cmdslots[slot];
    list->received_interrupt = true;
    list->last_interrupt_status = irq_status;
    list->status = port->port->status;
    list->tfd = port->port->tfd;

    // TODO: Understand why this fires and fix it
    // assert(list->breq != nullptr);
    if (!list->breq)
        return;

    if (list->last_interrupt_status & AHCI_INTST_ERROR)
    {
        list->breq->flags |= BIO_REQ_EIO;
    }
    else if (list->last_interrupt_status & AHCI_PORT_INTERRUPT_DHRE)
    {
        list->breq->flags |= BIO_REQ_DONE;
    }

    auto breq = list->breq;

    wake_address(breq);

    auto next = complete_request(breq);

    free_slot(slot);

    port->issued &= ~(1UL << slot);

    if (next)
        device_io_submit(next);
}

void ahci_do_port_irqs(struct ahci_port *port, u32 irq_status)
{
    uint32_t cmd_done = port->issued ^ port->port->command_issue;

    for (unsigned int j = 0; j < 32; j++)
    {
        if (cmd_done & (1U << j))
        {
            port->io_queue->do_irq(j, irq_status);
        }
    }
}

irqstatus_t ahci_irq(struct irq_context *ctx, void *cookie)
{
    UNUSED(ctx);
    struct ahci_device *dev = (ahci_device *) cookie;

    uint32_t ports = dev->hba->interrupt_status;

    /* TODO: Figure this out - AHCI is sending an extra interrupt and the
     * IRQ code is flagging it as SPURIOUS, which isn't actually true.
     */
    if (!ports)
        return IRQ_UNHANDLED;

    for (unsigned int i = 0; i < 32; i++)
    {
        struct ahci_port *port = &dev->ports[i];
        unsigned long cpu_flags = spin_lock_irqsave(&port->port_lock);

        if (ports & (1U << i))
        {
            if (!port->port)
            {
                panic("what? panic at the disco #%u", i);
                return IRQ_UNHANDLED;
            }

            uint32_t port_is = port->port->interrupt_status;
            port->port->interrupt_status = port_is;
            dev->hba->interrupt_status = (1U << i);
            ahci_do_port_irqs(port, port_is);
        }

        spin_unlock_irqrestore(&port->port_lock, cpu_flags);
    }

    return IRQ_HANDLED;
}

#define ATA_CMD_ERR_BAD_REQ 0xff
static uint8_t bio_req_to_ata_command(struct bio_req *req)
{
    uint8_t op = (req->flags & BIO_REQ_OP_MASK);

    switch (op)
    {
        case BIO_REQ_READ_OP:
            return ATA_CMD_READ_DMA_EXT;
        case BIO_REQ_WRITE_OP:
            return ATA_CMD_WRITE_DMA_EXT;
        case BIO_REQ_DEVICE_SPECIFIC:
            return req->device_specific[0];
        default:
            return ATA_CMD_ERR_BAD_REQ;
    }
}

long ahci_setup_prdt_bio(prdt_t *prdt, struct bio_req *r, size_t *size);
void ahci_set_lba(uint64_t lba, cfis_t *cfis);

/**
 * @brief Allocate a command list slow
 *
 * @return Pair with pointer to command_list_t, index
 */
cul::pair<command_list_t *, u16> ahci_io_queue::allocate_clist()
{
    assert(list_bitmap != UINT32_MAX);
    u16 pos = __builtin_ctz(~list_bitmap);

    __atomic_or_fetch(&list_bitmap, 1U << pos, __ATOMIC_RELAXED);

    return {clist + pos, pos};
}

void ahci_io_queue::free_slot(u16 slot)
{
    command_list_t *list = clist + slot;
    list->prdbc = 0;

    cmdslots[slot].req = nullptr;

    list->prdtl = 0;

    list_bitmap &= ~(1 << slot);
}

/**
 * @brief Submits IO to a device
 *
 * @param req bio_req to submit
 * @return 0 on sucess, negative error codes
 */
int ahci_io_queue::device_io_submit(bio_req *req)
{
    auto bdev = req->bdev;
    req->sector_number += (bdev->offset / 512);

    const uint16_t fis_len = 5;
    (void) fis_len;

    auto [list, list_index] = allocate_clist();

    list->desc_info =
        fis_len | ((req->flags & BIO_REQ_OP_MASK) == BIO_REQ_READ_OP ? AHCI_COMMAND_LIST_WRITE : 0);
    list->prdbc = 0;
    command_table_t *table = (command_table_t *) PHYS_TO_VIRT(ctables[list_index]);

    memset(table, 0, sizeof(command_table_t));

    prdt_t *prdt = (prdt_t *) (table + 1);

    long nr_prdt = 0;
    size_t size;

    if ((nr_prdt = ahci_setup_prdt_bio(prdt, req, &size)) < 0)
    {
        req->flags |= BIO_REQ_EIO;
        free_slot(list_index);
        return -EIO;
    }

    list->prdtl = nr_prdt;

    table->cfis.fis_type = FIS_TYPE_REG_H2D;

    table->cfis.port_mult = 0;
    table->cfis.c = 1;
    table->cfis.feature_low = 1;

    /* Load the LBA */
    uint64_t lba = req->sector_number;
    // printk("Lba: %lu\n", lba);
    ahci_set_lba(lba, &table->cfis);

    /* We need to set bit 6 to enable the LBA mode */
    auto op = req->flags & BIO_REQ_OP_MASK;
    bool read_or_write = op == BIO_REQ_READ_OP || op == BIO_REQ_WRITE_OP;
    if (read_or_write)
        table->cfis.device = (1 << 6);
    else
        table->cfis.device = 0;

    size_t num_sectors = size / 512;
    table->cfis.count = (uint16_t) num_sectors;
    table->cfis.command = bio_req_to_ata_command(req);

    struct command_list *l = &cmdslots[list_index];

    l->breq = req;

    COMPILER_BARRIER();

    port->port->command_issue = (1U << list_index);
    port->issued |= (1U << list_index);

    return 0;
}

int ahci_submit_request_new(struct blockdev *dev, struct bio_req *req)
{
    struct ahci_port *port = (ahci_port *) dev->device_info;
    if (port->port->sig != SATA_SIG_ATA)
        return -ENXIO;
    req->bdev = dev;

    int st = port->io_queue->submit_request(req);

    if (st < 0)
        return st;
    st = wait_for(
        req,
        [](void *_req) -> bool {
            struct bio_req *r = (struct bio_req *) _req;
            return r->flags & (BIO_REQ_DONE | BIO_REQ_EIO);
        },
        WAIT_FOR_FOREVER, 0);
    assert(st == 0);

    return 0;
}

bool ahci_command_error(struct ahci_port *port, unsigned int cmdslot)
{
    return (port->cmdslots[cmdslot].last_interrupt_status & AHCI_INTST_ERROR) != 0;
}

void ahci_issue_command(struct ahci_port *port, size_t slot)
{
    port->port->command_issue = (1U << slot);
}

size_t ahci_setup_prdt(prdt_t *table, struct phys_ranges *ranges)
{
    assert(ranges->nr_ranges <= NUM_PRDT_PER_TABLE);

    for (size_t i = 0; i < ranges->nr_ranges; i++)
    {
        struct phys_range *r = ranges->ranges[i];
        table[i].address = r->addr;

        /* TODO: Let's keep these around until the dma_get_ranges code
         * is fully mature, shall we?
         */
        assert(r->size <= PRDT_MAX_SIZE);
        table[i].dw3 = r->size - 1;
        table[i].res0 = 0;
    }

    assert(ranges->nr_ranges != 0);
    return ranges->nr_ranges;
}

void ahci_set_lba(uint64_t lba, cfis_t *cfis)
{
    cfis->lba0 = lba & 0xFF;
    cfis->lba1 = (lba >> 8) & 0xFF;
    cfis->lba2 = (lba >> 16) & 0xFF;
    cfis->lba3 = (lba >> 24) & 0xFF;
    cfis->lba4 = (lba >> 32) & 0xFF;
    cfis->lba5 = (lba >> 40) & 0xFF;
}

void ahci_free_list(struct ahci_port *port, size_t idx);

long ahci_setup_prdt_bio(prdt_t *prdt, struct bio_req *r, size_t *size)
{
    if (!r->vec)
    {
        *size = 0;
        return 0;
    }

    struct page_iov *v = r->vec + r->curr_vec_index;
    size_t left = r->nr_vecs - r->curr_vec_index;

    unsigned int i = 0;
    size_t req_size = 0;

    for (; i < left; i++)
    {
        if (i == NUM_PRDT_PER_TABLE)
            break;
        prdt_t *prd = prdt + i;
        unsigned long paddr = (unsigned long) page_to_phys(v->page) + v->page_off;

        /* Addresses need to be word-aligned :/ */
        if (paddr & (2 - 1))
            return -EINVAL;

        assert(v->length <= PAGE_SIZE);

        /* TODO: Merge contiguous prdt entries? */
        prd->address = paddr;
        prd->dw3 = v->length - 1;
        req_size += v->length;
        prd->res0 = 0;
        v++;
    }

    r->curr_vec_index += i;

    *size = req_size;

    return i;
}

bool ahci_do_command(struct ahci_port *ahci_port, struct ahci_command_ata *buf)
{
    struct bio_req r;
    r.bdev = ahci_port->bdev.get();
    r.curr_vec_index = 0;
    r.flags = BIO_REQ_DEVICE_SPECIFIC;
    r.device_specific[0] = buf->cmd;
    r.sector_number = 0;
    r.nr_vecs = buf->nr_iov;
    r.vec = buf->iovec;

    if (ahci_port->io_queue->submit_request(&r) < 0)
        return false;

    int st = wait_for(
        &r,
        [](void *_req) -> bool {
            struct bio_req *r = (struct bio_req *) _req;
            return r->flags & (BIO_REQ_DONE | BIO_REQ_EIO);
        },
        WAIT_FOR_FOREVER, 0);

    return st == 0 && !(r.flags & BIO_REQ_EIO);
}

unsigned int ahci_check_drive_type(ahci_port_t *port)
{
    uint32_t status = port->status;

    uint8_t ipm = (status >> 8) & 0x0F;
    uint8_t det = status & 0x0F;

    if (!det)
        return -1;
    if (!ipm)
        return -1;

    if (!port->sig)
        return -1;
    return port->sig;
}

void ahci_probe_ports(int n_ports, ahci_hba_memory_regs_t *hba)
{
    uint32_t ports_impl = hba->ports_implemented;
    for (int i = 0; i < 32; i++)
    {
        if (ports_impl & 1)
        {
            unsigned int type = 0;
            if ((type = ahci_check_drive_type(&hba->ports[i])))
            {
                switch (type)
                {
                    case SATA_SIG_ATA:
                        MPRINTF("Found a SATA drive on port %u\n", i);
                        break;
                    case SATA_SIG_ATAPI:
                        MPRINTF("Found a SATAPI drive on port %u\n", i);
                        break;
                }
            }
        }

        ports_impl >>= 1;
    }
}

const char *ahci_get_if_speed(ahci_hba_memory_regs_t *hba)
{
    unsigned int interface_speed = AHCI_CAP_INTERFACE_SPEED(hba->host_cap);
    switch (interface_speed)
    {
        case 0:
            return "<invalid>";
        case 1:
            return "Gen 1(1.5 Gbps)";
        case 2:
            return "Gen 2(3 Gbps)";
        case 3:
            return "Gen 3(6 Gbps)";
        default:
            return "<invalid>";
    }
}

int ahci_check_caps(ahci_hba_memory_regs_t *hba, pci::pci_device *ahci_dev)
{
    MPRINTF("supported features: ");
    if (hba->host_cap & AHCI_CAP_SXS)
        printf("sxs ");
    if (hba->host_cap & AHCI_CAP_EMS)
        printf("ems ");
    if (hba->host_cap & AHCI_CAP_CCCS)
        printf("cccs ");
    if (hba->host_cap & AHCI_CAP_PSC)
        printf("psc ");
    if (hba->host_cap & AHCI_CAP_SSC)
        printf("ssc ");
    if (hba->host_cap & AHCI_CAP_PMD)
        printf("pmd ");
    if (hba->host_cap & AHCI_CAP_FBSS)
        printf("fbss ");
    if (hba->host_cap & AHCI_CAP_SPM)
        printf("spm ");
    if (hba->host_cap & AHCI_CAP_AHCI_ONLY)
        printf("ahci-only ");
    if (hba->host_cap & AHCI_CAP_SCLO)
        printf("sclo ");
    if (hba->host_cap & AHCI_CAP_ACTIVITY_LED)
        printf("activity_led ");
    if (hba->host_cap & AHCI_CAP_SALP)
        printf("salp ");
    if (hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
        printf("staggered_spinup ");
    if (hba->host_cap & AHCI_CAP_SPMS)
        printf("spms ");
    if (hba->host_cap & AHCI_CAP_SSNTF)
        printf("ssntf ");
    if (hba->host_cap & AHCI_CAP_SNCQ)
        printf("sncq ");
    if (hba->host_cap & AHCI_CAP_ADDR64)
        printf("64-bit addressing ");
    printf("\n");

    auto addr = ahci_dev->addr();

    MPRINTF("version %s device at %x:%x:%x:%x running at speed %s\n",
            ahci_stringify_version(ahci_get_version(hba)), addr.segment, addr.bus, addr.device,
            addr.function, ahci_get_if_speed(hba));
    return 0;
}

uint32_t ahci_get_version(ahci_hba_memory_regs_t *hba)
{
    return hba->version;
}

const char *ahci_stringify_version(uint32_t version)
{
    switch (version)
    {
        case 0x00000905:
            return "0.95";
        case 0x00010000:
            return "1.0";
        case 0x00010100:
            return "1.1";
        case 0x00010200:
            return "1.2";
        case 0x00010300:
            return "1.3";
        case 0x00010301:
            return "1.3.1";
        default:
            return "unknown";
    }
}

bool ahci_port_is_idle(ahci_port_t *port)
{
    if (port->pxcmd & AHCI_PORT_CMD_START)
        return false;
    if (port->pxcmd & AHCI_PORT_CMD_CR)
        return false;
    if (port->pxcmd & AHCI_PORT_CMD_FRE)
        return false;
    if (port->pxcmd & AHCI_PORT_CMD_FR)
        return false;
    return true;
}

int ahci_wait_bit(volatile uint32_t *reg, uint32_t mask, unsigned long timeout, bool clear)
{
    uint64_t last = clocksource_get_time();
    while (true)
    {
        /* If the time is up, return a timeout */
        if (clocksource_get_time() - last >= (timeout * NS_PER_MS))
            return errno = ETIMEDOUT, -1;

        if (clear)
        {
            if (!(*reg & mask))
                return 0;
        }
        else
        {
            if (*reg & mask)
                return 0;
        }

        sched_yield();
    }
}

int ahci_port_set_idle(ahci_port_t *port)
{
    /* To set the AHCI port to idle, clear the start bit */
    port->pxcmd = port->pxcmd & ~AHCI_PORT_CMD_START;
    /* Wait for the bit to clear */
    if (ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_CR, 500, true) < 0)
    {
        MPRINTF("error: Timeout waiting for AHCI_PORT_CMD_CR\n");
        return -ETIMEDOUT;
    }

    if (port->pxcmd & AHCI_PORT_CMD_FRE)
    {
        /* Clear the FRE bit */
        port->pxcmd = port->pxcmd & ~AHCI_PORT_CMD_FRE;
        if (ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_FR, 500, true) < 0)
        {
            MPRINTF("error: Timeout waiting for AHCI_PORT_CMD_FR\n");
            return -ETIMEDOUT;
        }
    }

    return 0;
}

bool ahci_port_has_device(ahci_port_t *port)
{
    uint32_t status = port->status;

    uint32_t det = AHCI_PORT_STATUS_DET(status);

    return det != 0;
}

void ahci_enable_interrupts_for_port(ahci_port_t *port)
{
    port->pxie = AHCI_PORT_ENABLED_INTERRUPTS;
}

int ahci_do_identify(struct ahci_port *port)
{
    switch (port->port->sig)
    {
        case SATA_SIG_ATA: {
            struct ahci_command_ata command = {};
            command.size = 512;
            command.write = false;
            command.lba = 0;
            command.cmd = ATA_CMD_IDENTIFY;
            page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
            if (!p)
                return -ENOMEM;

            struct page_iov v;
            v.page = p;
            v.length = sizeof(port->identify);
            v.page_off = 0;

            command.iovec = &v;
            command.nr_iov = 1;

            if (!ahci_do_command(port, &command))
            {
                printf("ATA_CMD_IDENTIFY failed!\n");
                perror("error");
                free_page(p);
                return -1;
            }

            memcpy(&port->identify, PAGE_TO_VIRT(p), sizeof(port->identify));

            free_page(p);

            string_fix(port->identify.serial.word, sizeof(port->identify.serial.word));
            string_fix(port->identify.model_id.word, sizeof(port->identify.model_id.word));
            string_fix(port->identify.firmware_rev.word, sizeof(port->identify.firmware_rev.word));

            port->bdev->nr_sectors = port->identify.lba_capacity2 != 0
                                         ? port->identify.lba_capacity2
                                         : port->identify.lba_capacity;

            break;
        }
        default:
            return -1;
    }
    return 0;
}

int ahci_io_queue::configure_port_dma()
{
    /* Allocate the pointer table */
    if (!ctables.resize(nr_entries_))
        return false;

    /* Allocate ncs command tables and their respective PRDTs */

    /* The allocations are required to fit in a single page
     * The defaults are already very space efficient since you can fit
     * 4 in a single page, without any waste
     */
    const size_t allocation_size = sizeof(command_table_t) + NUM_PRDT_PER_TABLE * sizeof(prdt_t);

    struct page *current_buf_page = nullptr;
    uint8_t *buf = nullptr;
    size_t nr_tables_per_page = PAGE_SIZE / allocation_size;
    /* Curr is the nr of allocations in the page
     * It starts at nr_tables_per_page so it allocates a new one
     */
    size_t curr = nr_tables_per_page;

    for (size_t i = 0; i < nr_entries_; i++)
    {
        if (curr == nr_tables_per_page)
        {
            current_buf_page = alloc_page(0);
            if (!current_buf_page)
                return false;

            buf = (uint8_t *) page_to_phys(current_buf_page);
            curr = 0;
        }

        ctables[i] = (command_table_t *) buf;
        clist[i].base_address_lo = (uint32_t) (uintptr_t) buf;
        clist[i].base_address_hi = ((uintptr_t) buf) >> 32;
        buf += allocation_size;
        curr++;
    }

    return true;
}

/**
 * @brief Initialize the AHCI port's io queue
 *
 * @param hba HBA regs
 * @param port AHCI port
 * @parma _port AHCI port regs
 * @return True if success, else false
 */
bool ahci_io_queue::init(ahci_hba_memory_regs_t *hba, ahci_port_t *port, ahci_port *_port)
{
    bool addr64_supported = hba->host_cap & AHCI_CAP_ADDR64;
    /* Allocates the command list and the FIS buffer for a port */
    void *fisb = nullptr;
    void *command_list = nullptr;
    void *virtual_fisb = nullptr;
    unsigned long alloc_page_flags = addr64_supported ? PAGE_ALLOC_4GB_LIMIT : 0;
    /* The command list is 4k in size, with 4k in alignment */
    struct page *command_list_page = alloc_page(alloc_page_flags);

    if (!command_list_page)
        goto error;

    command_list = page_to_phys(command_list_page);
    if (!command_list)
        goto error;

    /* The fisb is 1024 bytes in size, with 1024 alignment */
    virtual_fisb = vmalloc(1, VM_TYPE_REGULAR, VM_WRITE | VM_READ);

    if (!virtual_fisb)
        goto error;

    /* We keep the virtual fisb in order to free it in case anything goes wrong */
    fisb = virtual2phys(virtual_fisb);

    if ((uintptr_t) fisb > UINT32_MAX && !addr64_supported)
        goto error;

    clist = (command_list_t *) mmiomap(command_list, PAGE_SIZE, VM_READ | VM_WRITE);
    if (!clist)
        goto error;

    /* Set FB and CB */
    port->command_list_base_low = (uintptr_t) command_list & 0xFFFFFFFF;
    if (addr64_supported)
        port->command_list_base_hi = ((unsigned long) command_list) >> 32;
    port->fis_list_base_low = (uintptr_t) fisb & 0xFFFFFFFF;
    if (addr64_supported)
        port->fis_list_base_hi = ((unsigned long) fisb) >> 32;

    return true;
error:
    if (command_list_page)
        free_page(command_list_page);
    if (fisb)
        free(virtual_fisb);
    return false;
}

void ahci_init_port(struct ahci_port *ahci_port)
{
    ahci_port_t *port = ahci_port->port;
    struct ahci_device *device = ahci_port->dev;
    ahci_hba_memory_regs_t *hba = device->hba;

    // ACK old interrupts that might've gotten stuck
    uint32_t port_is = port->interrupt_status;
    port->interrupt_status = port_is;
    /* Enable interrupts */
    ahci_enable_interrupts_for_port(port);

    /* Power on and spin up the device (if needed) */
    if (port->pxcmd & AHCI_PORT_CMD_CPD)
        port->pxcmd = port->pxcmd | AHCI_PORT_CMD_POWER_ON_DEV;
    if (device->hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
        port->pxcmd = port->pxcmd | AHCI_PORT_CMD_SPIN_UP_DEV;

    port->pxcmd = (port->pxcmd & ~0xF0000000) | (1 << 28);
    port->interrupt_status = UINT32_MAX;
    port->error = UINT32_MAX;

    unsigned int ncs = AHCI_CAP_NCS(device->hba->host_cap);
    MPRINTF("AHCI controller supports %u command list slots\n", ncs);

    ahci_port->io_queue = make_unique<ahci_io_queue>(ahci_port, ncs);
    if (!ahci_port->io_queue)
        panic("OOM configuring AHCI");

    if (!ahci_port->io_queue->init(hba, port, ahci_port) ||
        !ahci_port->io_queue->configure_port_dma())
        panic("OOM configuring AHCI port");

    if (port->pxcmd & AHCI_PORT_CMD_CR)
    {
        VERBOSE_MPRINTF("Waiting for PXCMD_CR to clear\n");
        if (ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_CR, 500, true) < 0)
        {
            MPRINTF("error: timeout waiting for PXCMD_CR to clear");
        }
    }

    /* Enable FIS receive */
    port->pxcmd = port->pxcmd | AHCI_PORT_CMD_FRE;

    port->pxcmd = port->pxcmd | AHCI_PORT_CMD_START;

    VERBOSE_MPRINTF("ahci_init_port done\n");
}

int ahci_initialize(struct ahci_device *device)
{
    ahci_hba_memory_regs_t *hba = device->hba;

    /* Firstly, set the AE bit on the GHC register to indicate we're AHCI aware */
    hba->ghc = hba->ghc | AHCI_GHC_AHCI_ENABLE;

    int nr_ports = AHCI_CAP_NR_PORTS(hba->host_cap);
    if (nr_ports == 0)
        nr_ports = 1;

    VERBOSE_MPRINTF("Number of ports: %d\n", nr_ports);
    VERBOSE_MPRINTF("Ports implemented: %08x\n", hba->ports_implemented);
    for (int i = 0; i < nr_ports; i++)
    {
        if (hba->ports_implemented & (1 << i))
        {
            VERBOSE_MPRINTF("Looking at port %d...\n", i);
            /* Do not create a device until we've checked the port has some device behind it */
            if (!ahci_port_has_device(&hba->ports[i]))
                continue;
            VERBOSE_MPRINTF("Port %d has device, continuing...\n", i);

            /* If this port is implemented, check if it's idle. */
            if (!ahci_port_is_idle(&hba->ports[i]))
            {
                /* If not, put it in idle mode */
                int st = ahci_port_set_idle(&hba->ports[i]);

                if (st < 0)
                {
                    ERROR("ahci", "failed to set port to idle\n");
                    return st;
                }
            }

            VERBOSE_MPRINTF("Port is idle\n");

            auto dev = blkdev_create_scsi_like_dev();
            if (!dev)
            {
                ERROR("ahci", "blkdev_create_scsi_like_dev failed");
                return -errno;
            }

            dev->device_info = &device->ports[i];
            dev->submit_request = ahci_submit_request_new;
            dev->sector_size = 512;

            MPRINTF("Created %s for port %d\n", dev->name.c_str(), i);
            device->ports[i].port_nr = i;
            device->ports[i].port = &hba->ports[i];
            device->ports[i].dev = device;
            device->ports[i].bdev = cul::move(dev);

            ahci_init_port(&device->ports[i]);
        }
    }

    hba->interrupt_status = hba->interrupt_status;
    /* Now, enable interrupts in the HBA */
    hba->ghc = hba->ghc | AHCI_GHC_INTERRUPTS_ENABLE;

    return 0;
}

struct pci::pci_id pci_ahci_devids[] = {
    {PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 6, PCI_ANY_ID, nullptr)}, {0}};

int ahci_probe(struct device *dev)
{
    int status = 0;
    int irq = -1;
    int nr_ports;
    pci::pci_device *ahci_dev = (pci::pci_device *) dev;

    if (ahci_dev->enable_device() < 0)
        return -1;

    /* Map BAR5 of the device BARs */

    ahci_hba_memory_regs_t *hba = (ahci_hba_memory_regs_t *) ahci_dev->map_bar(5, VM_NOCACHE);

    assert(hba != nullptr);

    /* Allocate a struct ahci_device and fill it */
    struct ahci_device *device = (ahci_device *) zalloc(sizeof(struct ahci_device));
    if (!device)
        return -1;

    device->pci_dev = ahci_dev;
    device->hba = hba;

    /* Enable PCI busmastering */
    ahci_dev->enable_busmastering();

    if (ahci_check_caps(hba, ahci_dev) < 0)
    {
        status = -1;
        goto ret;
    }

    /* Initialize AHCI */
    if (ahci_initialize(device) < 0)
    {
        MPRINTF("Failed to initialize the AHCI controller\n");
        status = -1;
        goto ret;
    }

    if (ahci_dev->enable_msi(ahci_irq, device))
    {
        /* If we couldn't enable MSI, use normal I/O APIC pins */

        /* Get the interrupt number */
        irq = ahci_dev->get_intn();
        /* and install a handler */
        assert(install_irq(irq, ahci_irq, (struct device *) ahci_dev, IRQ_FLAG_REGULAR, device) ==
               0);
    }

    nr_ports = AHCI_CAP_NR_PORTS(hba->host_cap);
    if (nr_ports == 0)
        nr_ports = 1;

    // For every port in the controller, see if we have initialised it. If so, do identify and
    // blkdev_init
    for (int i = 0; i < nr_ports; i++)
    {
        if (!device->ports[i].bdev)
            continue;

        VERBOSE_MPRINTF("Identify on %s\n", device->ports[i].bdev->name.c_str());

        ahci_do_identify(&device->ports[i]);

        VERBOSE_MPRINTF("Identify done on %s\n", device->ports[i].bdev->name.c_str());
        blkdev_init(device->ports[i].bdev.get());

        VERBOSE_MPRINTF("blkdev_init done on %s\n", device->ports[i].bdev->name.c_str());
    }

    ahci_probe_ports(count_bits<uint32_t>(hba->ports_implemented), hba);
ret:
    if (status != 0)
    {
        free(device);
        free_irq(irq, (struct device *) ahci_dev);
        device = nullptr;
    }

    return -1;
}
struct driver ahci_driver = {.name = "ahci",
                             .devids = &pci_ahci_devids,
                             .probe = ahci_probe,
                             .bus_type_node = {&ahci_driver}};

static int ahci_init()
{
    MPRINTF("initializing!\n");

    pci::register_driver(&ahci_driver);

    return 0;
}

int ahci_fini()
{
    MPRINTF("de-initializing!\n");
    return 0;
}

MODULE_INIT(ahci_init);
MODULE_FINI(ahci_fini);
