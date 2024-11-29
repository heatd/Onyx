/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include "e1000.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/net/network.h>
#include <onyx/panic.h>
#include <onyx/scoped_lock.h>
#include <onyx/vm.h>

#include <drivers/mmio.h>
#include <pci/pci.h>

static constexpr size_t number_rx_desc = ((PAGE_SIZE * 2) / sizeof(e1000_tx_desc));

/* There's a -1 here to account for the tail descriptor that's 16 bytes in size (aka the size of a
 * desc) */
static constexpr size_t number_tx_desc = ((PAGE_SIZE * 2) / sizeof(e1000_tx_desc));

struct e1000_device;

void e1000_write(uint16_t addr, uint32_t val, e1000_device *dev);
uint32_t e1000_read(uint16_t addr, const e1000_device *dev);

struct e1000_device
{
    char *mmio_space{};
    bool eeprom_exists{false};

    unsigned int rx_cur{0};

    unsigned int tx_cur{0};
    unsigned int tx_used{0};
    mutable spinlock tx_lock{};
    mutable wait_queue tx_queue{};

    e1000_rx_desc *rx_descs;
    unsigned char *tx_descs;

    static constexpr unsigned int tx_desc_size = 16;

    page *rx_pages;
    page *tx_pages;
    page *rx_buf_pages;
    pci::pci_device *nicdev;
    netif *nic_netif;
    unsigned char e1000_internal_mac_address[6];
    unsigned int irq_nr;

    template <typename Type>
    Type &tx_descriptor(unsigned int idx)
    {
        return *(Type *) (tx_descs + idx * tx_desc_size);
    }

    e1000_device()
    {
        spinlock_init(&tx_lock);
        init_wait_queue_head(&tx_queue);
    }

    unsigned int nr_tx_descs_available() const
    {
        return number_tx_desc - tx_used;
    }

    bool has_nr_tx_descs_available(unsigned int descs) const
    {
        return nr_tx_descs_available() >= descs;
    }

    void wait_for_tx_descs(unsigned int descs) const
    {
        spin_lock(&tx_lock);

        wait_for_event_locked(&tx_queue, has_nr_tx_descs_available(descs), &tx_lock);
    }

    int send_packet_legacy_tx(packetbuf *buf);

    int send_packet_extended_tx(packetbuf *buf);

    unsigned int prepare_legacy_descs(packetbuf *buf);

    unsigned int prepare_extended_descs(packetbuf *buf);

    void prepare_context_desc(packetbuf *buf);

    void free_descs(unsigned int to_free)
    {
        scoped_lock g{tx_lock};

        tx_used -= to_free;

        /* 2 descs should be useful for ~1 caller */
        if (tx_used < 3)
            wait_queue_wake(&tx_queue);
        else
            wait_queue_wake_all(&tx_queue);
    }

    void increment_tx_cur()
    {
        tx_cur = (tx_cur + 1) % number_tx_desc;
    }
};

static void e1000_init_busmastering(struct e1000_device *dev)
{
    dev->nicdev->enable_busmastering();
}

int e1000_process_packet(netif *nif, e1000_rx_desc &desc)
{
    if (desc.errors != 0)
        return -EIO;

    auto pckt = make_refc<packetbuf>();
    if (!pckt)
        return -ENOMEM;

    if (!pckt->allocate_space(desc.length))
        return -ENOMEM;

    if (desc.status & (RSTA_IXSM))
    {
        pckt->needs_csum = 1;
    }

    void *p = pckt->put(desc.length);

    memcpy(p, PHYS_TO_VIRT(desc.addr), desc.length);

    return netif_process_pbuf(nif, pckt.get());
}

int e1000_pollrx(netif *nif)
{
    e1000_device *dev = (e1000_device *) nif->priv;

    bool found_one = false;
    uint16_t old_cur = 0;
    while ((dev->rx_descs[dev->rx_cur].status & RSTA_DD))
    {
        auto &rxd = dev->rx_descs[dev->rx_cur];
        e1000_process_packet(nif, rxd);
        dev->rx_descs[dev->rx_cur].status = 0;
        old_cur = dev->rx_cur;
        dev->rx_cur = (dev->rx_cur + 1) % number_rx_desc;
        found_one = true;
    }

    if (found_one)
        e1000_write(REG_RXDESCTAIL, old_cur, dev);
    return 0;
}

void e1000_rxend(netif *nif)
{
    e1000_device *dev = (e1000_device *) nif->priv;

    e1000_write(REG_IMS, IMS_TXDW | IMS_TXQE | IMS_RXT0, dev);
}

unsigned int e1000_irqs = 0;

irqstatus_t e1000_irq(struct irq_context *ctx, void *cookie)
{
    auto device = (e1000_device *) cookie;

    volatile uint32_t status = e1000_read(REG_ICR, device);
    if (status & ICR_RXT0)
    {
        netif_signal_rx(device->nic_netif);
        e1000_write(REG_IMS, IMS_TXDW | IMS_TXQE, device);
        e1000_irqs++;
    }

    return IRQ_HANDLED;
}

void e1000_write(uint16_t addr, uint32_t val, e1000_device *dev)
{
    mmio_writel((uintptr_t) (dev->mmio_space + addr), val);
}

uint32_t e1000_read(uint16_t addr, const e1000_device *dev)
{
    return mmio_readl((uintptr_t) (dev->mmio_space + addr));
}

void e1000_detect_eeprom(struct e1000_device *dev)
{
    e1000_write(REG_EEPROM, 0x1, dev);
    for (int i = 0; i < 1000000; i++)
    {
        uint32_t test = e1000_read(REG_EEPROM, dev);
        if (test & 0x10)
        {
            INFO("e1000", "confirmed eeprom exists at spin %d\n", i);
            dev->eeprom_exists = true;
            break;
        }
    }
}

uint32_t e1000_eeprom_read(uint8_t addr, struct e1000_device *dev)
{
    uint16_t data = 0;
    uint32_t tmp = 0;
    if (dev->eeprom_exists)
    {
        e1000_write(REG_EEPROM, (1) | ((uint32_t) (addr) << 8), dev);
        while (!((tmp = e1000_read(REG_EEPROM, dev)) & (1 << 4)))
            ;
    }
    else
    {
        e1000_write(REG_EEPROM, (1) | ((uint32_t) (addr) << 2), dev);
        while (!((tmp = e1000_read(REG_EEPROM, dev)) & (1 << 1)))
            ;
    }

    data = (uint16_t) ((tmp >> 16) & 0xFFFF);
    return data;
}

int e1000_read_mac_address(struct e1000_device *dev)
{
    if (dev->eeprom_exists)
    {
        uint32_t temp;
        temp = e1000_eeprom_read(0, dev);
        dev->e1000_internal_mac_address[0] = temp & 0xff;
        dev->e1000_internal_mac_address[1] = temp >> 8;
        temp = e1000_eeprom_read(1, dev);
        dev->e1000_internal_mac_address[2] = temp & 0xff;
        dev->e1000_internal_mac_address[3] = temp >> 8;
        temp = e1000_eeprom_read(2, dev);
        dev->e1000_internal_mac_address[4] = temp & 0xff;
        dev->e1000_internal_mac_address[5] = temp >> 8;
        return 0;
    }
    else
    {
        uint8_t *mem_base_mac_8 = (uint8_t *) (dev->mmio_space + 0x5400);
        uint32_t *mem_base_mac_32 = (uint32_t *) (dev->mmio_space + 0x5400);
        if (mem_base_mac_32[0] != 0)
        {
            for (int i = 0; i < 6; i++)
            {
                dev->e1000_internal_mac_address[i] = mem_base_mac_8[i];
            }
            return 0;
        }
    }

    return 1;
}

struct page_frag_alloc_info
{
    struct page *page_list;
    struct page *curr;
    size_t off;
};

struct page_frag_res
{
    struct page *page;
    size_t off;
};

/* TODO: Put this in an actual header */

extern "C" struct page_frag_res page_frag_alloc(struct page_frag_alloc_info *inf, size_t size)
{
    assert(size <= PAGE_SIZE);

    struct page_frag_res r;
    r.page = NULL;
    r.off = 0;

    if (inf->off + size > PAGE_SIZE)
    {
        struct page *next = inf->curr->next_un.next_allocation;
        if (!next)
            return r;
        inf->curr = next;
        inf->off = 0;
    }

    r.page = inf->curr;
    r.off = inf->off;

    inf->off += size;

    return r;
}

const size_t rx_buffer_size = 2048;

int e1000_init_rx(struct e1000_device *dev)
{
    int st = 0;
    size_t needed_pages = vm_size_to_pages(sizeof(struct e1000_rx_desc) * number_rx_desc);
    struct page *rx_pages = alloc_pages(pages2order(needed_pages), PAGE_ALLOC_CONTIGUOUS);

    struct page_frag_alloc_info alloc_info;
    unsigned long rxd_base = 0;
    struct e1000_rx_desc *rxdescs;

    if (!rx_pages)
        return -ENOMEM;

    struct page *rx_buf_pages =
        alloc_page_list(vm_size_to_pages(number_rx_desc * rx_buffer_size), PAGE_ALLOC_NO_ZERO);
    if (!rx_buf_pages)
    {
        st = -ENOMEM;
        goto error0;
    }
    alloc_info.curr = alloc_info.page_list = rx_buf_pages;
    alloc_info.off = 0;

    // FIXME: Stuff like this forces alloc_pages to chain the individual pages in higher order
    // allocations
    rxdescs = (e1000_rx_desc *) mmiomap(page_to_phys(rx_pages), needed_pages << PAGE_SHIFT,
                                        VM_READ | VM_WRITE);
    if (!rxdescs)
    {
        st = -ENOMEM;
        goto error1;
    }

    for (unsigned int i = 0; i < number_rx_desc; i++)
    {
        struct page_frag_res res = page_frag_alloc(&alloc_info, rx_buffer_size);
        /* How can this even happen? Keep this here though, as a sanity check */
        if (!res.page)
            panic("OOM allocating rx buffers");

        rxdescs[i].addr = (uint64_t) page_to_phys(res.page) + res.off;

        rxdescs[i].status = 0;
    }

    rxd_base = (unsigned long) page_to_phys(rx_pages);

    e1000_write(REG_RXDESCLO, (uint32_t) rxd_base, dev);
    e1000_write(REG_RXDESCHI, (uint32_t) (rxd_base >> 32), dev);

    e1000_write(REG_RXDESCLEN, number_rx_desc * 16, dev);

    e1000_write(REG_RXDESCHEAD, 0, dev);
    e1000_write(REG_RXDESCTAIL, number_rx_desc - 1, dev);

    dev->rx_buf_pages = rx_buf_pages;
    dev->rx_pages = rx_pages;
    dev->rx_cur = 0;
    dev->rx_descs = rxdescs;

    e1000_write(REG_RCTL,
                RCTL_EN | RCTL_SBP | RCTL_UPE | RCTL_MPE | RCTL_LBM_NONE | RTCL_RDMTS_HALF |
                    RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2048,
                dev);

    return 0;

error1:
    free_page_list(rx_buf_pages);
error0:
    free_pages(rx_pages);
    return st;
}

#define E1000_DEFAULT_COLLISION_THRESH 15
#define E1000_DEFAULT_COLD             0x3f
#define E1000_RECOMMENDED_TIPG         0x00702008

int e1000_init_tx(struct e1000_device *dev)
{
    struct e1000_tx_desc *txdescs = NULL;
    int st = 0;
    size_t needed_pages = vm_size_to_pages(sizeof(struct e1000_tx_desc) * number_tx_desc);
    auto order = pages2order(needed_pages);
    struct page *tx_pages = alloc_pages(order, PAGE_ALLOC_CONTIGUOUS);
    unsigned long txd_base = 0;

    if (!tx_pages)
        return -ENOMEM;

    txdescs = (e1000_tx_desc *) mmiomap(page_to_phys(tx_pages), needed_pages << PAGE_SHIFT,
                                        VM_READ | VM_WRITE);
    if (!txdescs)
    {
        st = -ENOMEM;
        goto error0;
    }

    txd_base = (unsigned long) page_to_phys(tx_pages);
    e1000_write(REG_TXDESCLO, (uint32_t) txd_base, dev);
    e1000_write(REG_TXDESCHI, (uint32_t) (txd_base >> 32), dev);

    e1000_write(REG_TXDESCLEN, number_tx_desc * 16, dev);

    e1000_write(REG_TXDESCHEAD, 0, dev);
    e1000_write(REG_TXDESCTAIL, 0, dev);

    /* Note: TCTL_RRTHRESH(1) is the default and means 4 lines of 16 bytes */
    e1000_write(REG_TCTL,
                TCTL_EN | TCTL_PSP | (E1000_DEFAULT_COLLISION_THRESH << TCTL_CT_SHIFT) |
                    (E1000_DEFAULT_COLD << TCTL_COLD_SHIFT) | TCTL_RRTHRESH(1),
                dev);
    e1000_write(REG_TIPG, E1000_RECOMMENDED_TIPG, dev);

    dev->tx_cur = 0;
    dev->tx_pages = tx_pages;
    dev->tx_descs = (unsigned char *) txdescs;

    return 0;
error0:
    free_pages(tx_pages);
    return st;
}

int e1000_init_descs(struct e1000_device *dev)
{
    int st;
    if ((st = e1000_init_rx(dev)) < 0)
        return st;
    if ((st = e1000_init_tx(dev)) < 0)
        return st;
    return 0;
}

void e1000_enable_interrupts(struct e1000_device *dev)
{
    dev->irq_nr = dev->nicdev->get_intn();

    // Get the IRQ number and install its handler
    INFO("e1000", "using IRQ number %u\n", dev->irq_nr);

    assert(install_irq(dev->irq_nr, e1000_irq, (struct device *) dev->nicdev, IRQ_FLAG_REGULAR,
                       dev) == 0);

    e1000_write(REG_IMS, IMS_TXDW | IMS_TXQE | IMS_RXT0, dev);
    e1000_read(REG_ICR, dev);
}

static unsigned int calc_packetbuf_descs(packetbuf *buf)
{
    unsigned int descs = 0;
    for (const auto &v : buf->page_vec)
    {
        if (!v.page)
            return descs;
        descs++;
    }

    __builtin_unreachable();
}

unsigned int e1000_device::prepare_legacy_descs(packetbuf *buf)
{
    unsigned int last_tx = 0;
    unsigned int xmited = 0;

    for (const auto &vec : buf->page_vec)
    {
        if (!vec.page)
            break;

        unsigned long buffer_start_off = 0;
        auto length = vec.length;

        /* Account header overhead that might exist here */
        if (!xmited)
        {
            buffer_start_off = buf->start_page_off();
            length -= buffer_start_off;
        }

        buffer_start_off += vec.page_off;

        auto &desc = tx_descriptor<e1000_tx_desc>(tx_cur);

        desc.addr = ((uint64_t) page_to_phys(vec.page)) + buffer_start_off;
        desc.length = length;
        desc.cmd = CMD_IFCS | CMD_RS | CMD_RPS | (buf->needs_csum ? CMD_IC : 0);
        desc.status = 0;

        if (buf->needs_csum)
        {
            auto offset = (unsigned char *) buf->csum_offset - buf->data;
            desc.cso = (uint8_t) offset;
            desc.css = (uint8_t) (buf->csum_start - buf->data);
        }
        else
        {
            desc.cso = 0;
            desc.css = 0;
        }

        last_tx = tx_cur;

        increment_tx_cur();

        xmited++;
    }

    /* The last tx descriptor requires EOP set */
    auto &last = tx_descriptor<e1000_tx_desc>(last_tx);
    last.cmd = last.cmd | CMD_EOP;

    return last_tx;
}

#define SEND_PACKET_PERF_TEST 0

int e1000_device::send_packet_legacy_tx(packetbuf *buf)
{
    unsigned int needed_descs = calc_packetbuf_descs(buf);

    wait_for_tx_descs(needed_descs);

    auto old_cur = prepare_legacy_descs(buf);

    e1000_write(REG_TXDESCTAIL, tx_cur, this);

#if SEND_PACKET_PERF_TEST
    auto t0 = clocksource_get_time();
#endif

    spin_unlock(&tx_lock);

    while (!(tx_descriptor<e1000_tx_desc>(old_cur).status & 0xff))
        cpu_relax();

#if SEND_PACKET_PERF_TEST
    auto t1 = clocksource_get_time();

    printk("send packet busy wait took %lu\n", t1 - t0);
#endif

    free_descs(needed_descs);

    return 0;
}

void e1000_device::prepare_context_desc(packetbuf *buf)
{
    auto &desc = tx_descriptor<e1000_tx_tcpip_context_desc>(tx_cur);

    memset(&desc, 0, sizeof(desc));

    desc.tucss = buf->transport_header_off();
    desc.ipcss = buf->net_header_off();

    if (buf->needs_csum)
    {
        desc.tucso = buf->csum_offset_bytes();
        desc.tucse = 0;
    }

    desc.dtype = E1000_TX_CONTEXT_DESC;
    desc.tucmd = CMD_DEXT | CMD_RS;

    increment_tx_cur();
}

unsigned int e1000_device::prepare_extended_descs(packetbuf *buf)
{
    unsigned int last_tx = 0;
    unsigned int xmited = 0;

    unsigned int last_desc_cmd = CMD_EOP | CMD_IFCS;

    for (const auto &vec : buf->page_vec)
    {
        if (!vec.page)
            break;

        unsigned long buffer_start_off = 0;
        auto length = vec.length;
        auto &desc = tx_descriptor<e1000_tx_tcpip_data_desc>(tx_cur);
        memset(&desc, 0, sizeof(desc));

        /* Account header overhead that might exist here */
        if (!xmited)
        {
            buffer_start_off = (buf->data - (unsigned char *) buf->buffer_start);
            length = buf->tail - buf->data;
            desc.popts = (buf->needs_csum ? POPTS_TXSM : 0);
        }

        buffer_start_off += vec.page_off;

        desc.address = ((uint64_t) page_to_phys(vec.page)) + buffer_start_off;
        desc.datalen = length;
        desc.dtype = E1000_TX_TCPIP_DATA_DESC;
        desc.dcmd = CMD_RS | CMD_DEXT;
        desc.status = 0;
        desc.special = 0;

        last_tx = tx_cur;

        increment_tx_cur();

        xmited++;
    }

    tx_descriptor<e1000_tx_tcpip_data_desc>(last_tx).dcmd |= last_desc_cmd;

    return last_tx;
}

int e1000_device::send_packet_extended_tx(packetbuf *buf)
{
    /* We need a context descriptor, so we're adding 1 to the descriptors
     * required by the packetbuf's data itself
     */

    unsigned int needed_descs = calc_packetbuf_descs(buf) + 1;

    wait_for_tx_descs(needed_descs);

    prepare_context_desc(buf);

    auto old_cur = prepare_extended_descs(buf);

    e1000_write(REG_TXDESCTAIL, tx_cur, this);

#if SEND_PACKET_PERF_TEST
    auto t0 = clocksource_get_time();
#endif

    spin_unlock(&tx_lock);

    while (!(tx_descriptor<e1000_tx_tcpip_data_desc>(old_cur).status & 0xff))
        ;

#if SEND_PACKET_PERF_TEST
    auto t1 = clocksource_get_time();

    printk("send packet busy wait took %lu\n", t1 - t0);
#endif

    free_descs(needed_descs);

    return 0;
}

int e1000_send_packet(packetbuf *buf, netif *nif)
{
    auto dev = (e1000_device *) nif->priv;
    return dev->send_packet_extended_tx(buf);
}

void e1000_disable_rxtx(struct e1000_device *dev)
{
    e1000_write(REG_RCTL, 0, dev);
    e1000_write(REG_TCTL, 0, dev);
}

void e1000_setup_flow_control(struct e1000_device *dev)
{
    /* Setup the standard flow control addresses */
    e1000_write(REG_FCAL, 0x00c28001, dev);
    e1000_write(REG_FCAH, 0x0100, dev);
    e1000_write(REG_FCT, 0x8808, dev);
    e1000_write(REG_FCTTV, 0, dev);
}

void e1000_clear_stats(struct e1000_device *dev)
{
    for (uint32_t x = 0; x < 256; x += 4)
        e1000_read(REG_CRCERRS + x, dev);
}

void e1000_reset_device(struct e1000_device *dev)
{
    /* Disable busmastering and interrupts before resetting the NIC */
    dev->nicdev->disable_busmastering();
    dev->nicdev->disable_irq();

    /* Also disable rx/tx */
    e1000_disable_rxtx(dev);

    /* And disable interrupts in the NIC itself */
    e1000_write(REG_IMC, UINT32_MAX, dev);

    /* Reset the NIC by setting the correct bit */
    uint32_t ctrl = e1000_read(REG_CTRL, dev);
    e1000_write(REG_CTRL, ctrl | CTRL_RST, dev);

    for (;;)
    {
        /*
         * Sortix does it, maybe we should too.
         * On some hardware, this loop would hang without this.
         * Read all the statisics registers (which we do later anyway).
         */
        e1000_clear_stats(dev);
        ctrl = e1000_read(REG_CTRL, dev);
        if (!(ctrl & CTRL_PHY_RST))
            break;
    }

    /* Disable interrupts again */
    e1000_write(REG_IMC, UINT32_MAX, dev);

    e1000_init_busmastering(dev);

    ctrl = e1000_read(REG_CTRL, dev);

    ctrl |= CTRL_SLU;
    /* TODO: The docs say that ASDE should be set to 0 on 82574's */
    ctrl |= CTRL_ASDE;
    ctrl &= ~CTRL_FORCE_SPEED;
    ctrl &= ~CTRL_FRCDPLX;

    e1000_write(REG_CTRL, ctrl, dev);

    /* Setup flow control */
    e1000_setup_flow_control(dev);

    /* Clear statistical registers */
    e1000_clear_stats(dev);

    dev->nicdev->enable_irq();
}

struct pci::pci_id e1000_pci_ids[] = {{PCI_ID_DEVICE(INTEL_VENDOR, E1000_DEV, NULL)},
                                      {PCI_ID_DEVICE(INTEL_VENDOR, E1000_I217, NULL)},
                                      {PCI_ID_DEVICE(INTEL_VENDOR, E1000_82577LM, NULL)},
                                      {0}};

int e1000_probe(struct device *__dev)
{
    pci::pci_device *dev = (pci::pci_device *) __dev;

    auto addr = dev->addr();

    INFO("e1000",
         "Found suitable e1000 device at %04x:%02x:%02x:%02x\n"
         "ID %04x:%04x\n",
         addr.segment, addr.bus, addr.device, addr.function, dev->vid(), dev->did());

    char *mem_space = (char *) dev->map_bar(0, VM_NOCACHE);
    if (!mem_space)
    {
        ERROR("e1000",
              "Sorry! This driver only supports e1000 register access through MMIO, "
              "and sadly your card needs the legacy I/O port method of accessing registers\n");
        return -1;
    }

    struct e1000_device *nicdev = new e1000_device;
    if (!nicdev)
    {
        /* TODO: Unmap mem_space */
        return -1;
    }

    nicdev->mmio_space = mem_space;
    nicdev->nicdev = dev;

    INFO("e1000", "mmio mode\n");

    e1000_reset_device(nicdev);

    e1000_detect_eeprom(nicdev);

    if (e1000_read_mac_address(nicdev))
        return -1;

    if (e1000_init_descs(nicdev))
    {
        ERROR("e1000", "failed to initialize!\n");
        return -1;
    }

    e1000_enable_interrupts(nicdev);

    netif *n = new netif;
    if (!n)
        return -1;

    /* TODO: Allocate device names */
    n->name = "eth0";
    n->flags |= NETIF_LINKUP;
    n->sendpacket = e1000_send_packet;
    n->priv = nicdev;
    n->mtu = 1500;
    n->poll_rx = e1000_pollrx;
    n->rx_end = e1000_rxend;
    nicdev->nic_netif = n;
    n->dll_ops = &eth_ops;
    memcpy(n->mac_address, nicdev->e1000_internal_mac_address, 6);
    netif_register_if(n);

    return 0;
}

struct driver e1000_driver = {.name = "e1000",
                              .devids = &e1000_pci_ids,
                              .probe = e1000_probe,
                              .bus_type_node = {&e1000_driver}};

int e1000_init(void)
{
    pci::register_driver(&e1000_driver);
    return 0;
}

MODULE_INIT(e1000_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
