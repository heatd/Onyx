/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "rtl8168.h"

#include <assert.h>
#include <stdio.h>

#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/net/netif.h>
#include <onyx/wait_queue.h>

#include <pci/pci.h>

#include <onyx/hwregister.hpp>

#define RTL_VENDORID 0x10EC

constexpr size_t number_tx_desc = 256;
constexpr size_t tx_buffer_size = 2048;

class rtl8168_device
{
private:
    pci::pci_device *dev_;
    mmio_range regs_;
    unsigned char mac_[6];
    rtl8168_rx_desc *rxdescs_;
    rtl8168_rx_desc *txdescs_;
    netif *netif_;

    unsigned int rx_cur{0};

    unsigned int tx_cur{0};
    unsigned int tx_used{0};
    spinlock tx_lock{};
    wait_queue tx_queue{};

public:
    rtl8168_device(pci::pci_device *dev)
        : dev_{dev}, regs_{}, mac_{}, rxdescs_{}, txdescs_{}, netif_{}
    {
    }

    /**
     * @brief Initialises the rtl8111/rtl8168 device
     *
     * @return 0 on success, else error code
     */
    int init();

    /**
     * @brief Reset the device
     *
     * @return 0 on success, else -ETIMEDOUT
     */
    int reset();

    /**
     * @brief Configure RX
     *
     * @return 0 on success, else negative error codes.
     */
    int configure_rx();

    /**
     * @brief Unlock the registers by writing to the 9436CR
     *
     */
    void unlock_registers()
    {
        auto val = regs_.read8(RTL8168_9436CR) & RTL8168_9436CR_EEM_MASK;
        val |= RTL8168_9436CR_EEM_UNLOCK;
        regs_.write8(RTL8168_9436CR, val);
    }

    /**
     * @brief Lock the registers by writing to the 9436CR
     *
     */
    void lock_registers()
    {
        auto val = regs_.read8(RTL8168_9436CR) & RTL8168_9436CR_EEM_MASK;
        val &= RTL8168_9436CR_EEM_LOCK;
        regs_.write8(RTL8168_9436CR, val);
    }

    /**
     * @brief Configure TX
     *
     * @return 0 on success, else negative error codes
     */
    int configure_tx();

    /**
     * @brief Clears interrupts
     *
     */
    void clear_ints()
    {
        regs_.write16(RTL8168_ISR, 0xffff);
    }

    /**
     * @brief Sets up interrupts on the NIC
     *
     */
    void setup_irqs();

    /**
     * @brief Handles IRQs
     *
     * @return Valid irqstatus_t
     */
    irqstatus_t handle_irq();

    /**
     * @brief Sends a packet
     *
     * @param buf Pointer to a filled packetbuf
     * @return 0 on success, else negative error code
     */
    int send_packet(packetbuf *buf);

    /**
     * @brief Does an RX poll
     *
     * @return 0 on success, else error code
     */
    int poll_rx();

    /**
     * @brief Ends the rx poll
     *
     */
    void rx_end();

    unsigned int nr_tx_descs_available() const
    {
        return number_tx_desc - tx_used;
    }

    bool has_nr_tx_descs_available(unsigned int descs) const
    {
        return nr_tx_descs_available() >= descs;
    }

    void wait_for_tx_descs(unsigned int descs)
    {
        spin_lock(&tx_lock);

        wait_for_event_locked(&tx_queue, has_nr_tx_descs_available(descs), &tx_lock);
    }

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

    unsigned int prepare_send(packetbuf *buf);
};

/**
 * @brief Handles IRQs
 *
 * @return Valid irqstatus_t
 */
irqstatus_t rtl8168_device::handle_irq()
{
    const auto status = regs_.read16(RTL8168_ISR);

    if (status == 0)
        return IRQ_UNHANDLED;

    if (status & RTL8168_INT_ROK)
    {
        netif_signal_rx(netif_);
        regs_.write16(RTL8168_IMR, RTL8168_INT_LINKCHG);
    }

    return IRQ_HANDLED;
}

/**
 * @brief Reset the device
 *
 * @return 0 on success, else -ETIMEDOUT
 */
int rtl8168_device::reset()
{
    regs_.write8(RTL8168_CR, RTL8168_CR_RST);

    auto start = clocksource_get_time();

    while (regs_.read8(RTL8168_CR) & RTL8168_CR_RST)
    {
        auto now = clocksource_get_time();

        if (now - start > 1 * NS_PER_SEC)
            return -ETIMEDOUT;
    }

    return 0;
}

constexpr size_t number_rx_desc = 256;
constexpr size_t rx_buffer_size = 2048;

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

extern "C" struct page_frag_res page_frag_alloc(struct page_frag_alloc_info *inf, size_t size);

#include <onyx/byteswap.h>
/**
 * @brief Configure RX
 *
 * @return 0 on success, else negative error codes.
 */
int rtl8168_device::configure_rx()
{
    regs_.write32(RTL8168_RCR, RTL8168_RXCFG_APM | RTL8168_RXCFG_AB | RTL8168_RXCFG_AM |
                                   RTL8168_RXCFG_MXDMA_UNLIMITED | RTL8168_RXCFG_NO_RX_THRESHOLD);

    regs_.write16(RTL8168_RMS, rx_buffer_size);

    auto desc_pages = vm_size_to_pages(number_rx_desc * sizeof(rtl8168_rx_desc));
    printk("Pages: %lu\n", desc_pages);
    // FIXME: Fix and test
    struct page *p = alloc_pages(desc_pages, PAGE_ALLOC_CONTIGUOUS);
    if (!p)
    {
        return -ENOMEM;
    }

    struct page_frag_alloc_info alloc_info;
    auto buf_pages = vm_size_to_pages(number_rx_desc * rx_buffer_size);
    struct page *rx_buf_pages = alloc_pages(buf_pages, PAGE_ALLOC_NO_ZERO);
    if (!rx_buf_pages)
    {
        free_pages(p);
        return -ENOMEM;
    }

    alloc_info.curr = alloc_info.page_list = rx_buf_pages;
    alloc_info.off = 0;

    rxdescs_ = (rtl8168_rx_desc *) map_page_list(p, desc_pages << PAGE_SHIFT, VM_READ | VM_WRITE);
    if (!rxdescs_)
    {
        free_pages(rx_buf_pages);
        free_pages(p);
        return -ENOMEM;
    }

    for (unsigned int i = 0; i < number_rx_desc; i++)
    {
        struct page_frag_res res = page_frag_alloc(&alloc_info, rx_buffer_size);
        /* How can this even happen? Keep this here though, as a sanity check */
        assert(res.page != nullptr);
        auto phys_addr = (uint64_t) page_to_phys(res.page) + res.off;
        rxdescs_[i].buffer_addr_low = (uint32_t) phys_addr;
        rxdescs_[i].buffer_addr_high = (uint32_t) (phys_addr >> 32);
        rxdescs_[i].status = RTL8168_RX_DESC_FLAG_OWN | (uint32_t) rx_buffer_size;

        if (i == number_rx_desc - 1)
        {
            // set the EOR
            rxdescs_[i].status |= RTL8168_RX_DESC_FLAG_EOR;
        }
    }

    unsigned long rxd_base = (unsigned long) page_to_phys(p);

    regs_.write32(RTL8168_RDSAR_LOW, (uint32_t) rxd_base);
    regs_.write32(RTL8168_RDSAR_HIGH, (uint32_t) (rxd_base >> 32));

    // Enable RX on the CR
    regs_.write8(RTL8168_CR, regs_.read8(RTL8168_CR) | RTL8168_CR_RX_ENABLE);

    return 0;
}

/**
 * @brief Configure TX
 *
 * @return 0 on success, else negative error codes
 */
int rtl8168_device::configure_tx()
{
    const auto desc_pages = vm_size_to_pages(number_rx_desc * sizeof(rtl8168_rx_desc));
    struct page *p = alloc_pages(desc_pages, PAGE_ALLOC_CONTIGUOUS);
    if (!p)
    {
        return -ENOMEM;
    }

    txdescs_ = (rtl8168_rx_desc *) map_page_list(p, desc_pages << PAGE_SHIFT, VM_READ | VM_WRITE);
    if (!rxdescs_)
    {
        free_pages(p);
        return -ENOMEM;
    }

    // Enable TX on the CR. The RTL8168 spec says we need to enable it before touching the txcfg
    // register
    regs_.write8(RTL8168_CR, regs_.read8(RTL8168_CR) | RTL8168_CR_TX_ENABLE);

    regs_.write32(RTL8168_TCR,
                  RTL8168_TXCFG_IFG96 | RTL8168_TXCFG_MXDMA_UNLIMITED | RTL8168_TXCFG_NOCRC);
    regs_.write32(RTL8168_MTPS, tx_buffer_size / 128);

    for (unsigned int i = 0; i < number_tx_desc; i++)
    {
        txdescs_[i].status = 0;

        if (i == number_tx_desc - 1)
        {
            txdescs_[i].status = RTL8168_TX_DESC_FLAG_EOR;
        }
    }

    const auto txd_base = (unsigned long) page_to_phys(p);
    regs_.write32(RTL8168_TNPDS_LOW, (uint32_t) txd_base);
    regs_.write32(RTL8168_TNPDS_HIGH, (uint32_t) (txd_base >> 32));

    return 0;
}

int rtl8168_send_packet(packetbuf *buf, netif *nif)
{
    return ((rtl8168_device *) nif->priv)->send_packet(buf);
}

int rtl8168_poll_rx(netif *nif)
{
    return ((rtl8168_device *) nif->priv)->poll_rx();
}

void rtl8168_rx_end(netif *nif)
{
    ((rtl8168_device *) nif->priv)->rx_end();
}

unsigned int rtl8168_device::prepare_send(packetbuf *buf)
{
    unsigned int last_tx = 0;
    unsigned int xmited = 0;

    for (const auto &vec : buf->page_vec)
    {
        if (!vec.page)
            break;

        unsigned long buffer_start_off = 0;
        auto length = vec.length;
        auto &desc = txdescs_[tx_cur];
        memset(&desc, 0, sizeof(desc));

        /* Account header overhead that might exist here */
        if (!xmited)
        {
            buffer_start_off = (buf->data - (unsigned char *) buf->buffer_start);
            length -= buffer_start_off;
        }

        buffer_start_off += vec.page_off;
        const auto addr = ((uint64_t) page_to_phys(vec.page)) + buffer_start_off;
        desc.buffer_addr_low = (uint32_t) addr;
        desc.buffer_addr_high = (uint32_t) (addr >> 32);

        desc.status = length | RTL8168_TX_DESC_FLAG_OWN;

        if (!xmited)
            desc.status |= RTL8168_TX_DESC_FLAG_FS;

        last_tx = tx_cur;

        increment_tx_cur();

        xmited++;
    }

    txdescs_[last_tx].status |= RTL8168_TX_DESC_FLAG_LS;

    return last_tx;
}

/**
 * @brief Sends a packet
 *
 * @param buf Pointer to a filled packetbuf
 * @return 0 on success, else negative error code
 */
int rtl8168_device::send_packet(packetbuf *buf)
{
    auto tx = prepare_send(buf);
    regs_.write8(RTL8168_TPPOLL, RTL8168_TPPOLL_NPQ);

    while (txdescs_[tx].status & RTL8168_TX_DESC_FLAG_OWN)
    {
    }

    return 0;
}

static int process_packet(netif *nif, rtl8168_rx_desc &desc)
{
    auto pckt = make_refc<packetbuf>();
    if (!pckt)
        return -ENOMEM;

    unsigned int len = desc.status & RTL8168_RX_LENGTH_MASK;
    auto addr = ((uint64_t) desc.buffer_addr_high << 32) | desc.buffer_addr_low;

    eth_header *eth = (eth_header *) (PHYS_TO_VIRT(addr));

    printk("Eth: %04x\n", ntohs(eth->ethertype));
    printk("Packet length %u\n", len);

    if (!pckt->allocate_space(len))
        return -ENOMEM;

    pckt->needs_csum = 1;

    void *p = pckt->put(len);

    memcpy(p, PHYS_TO_VIRT(addr), len);

    return netif_process_pbuf(nif, pckt.get());
}

/**
 * @brief Does an RX poll
 *
 * @return 0 on success, else error code
 */
int rtl8168_device::poll_rx()
{
    while (!(rxdescs_[rx_cur].status & RTL8168_RX_DESC_FLAG_OWN))
    {
        auto &rx_desc = rxdescs_[rx_cur];
        process_packet(netif_, rx_desc);
        rx_cur = (rx_cur + 1) % number_rx_desc;
    }

    return 0;
}

/**
 * @brief Ends the rx poll
 *
 */
void rtl8168_device::rx_end()
{
    regs_.write16(RTL8168_IMR, RTL8168_INT_LINKCHG | RTL8168_INT_ROK);
}

/**
 * @brief Initialises the rtl8111/rtl8168 device
 *
 * @return 0 on success, else error code
 */
int rtl8168_device::init()
{
    if (int st = dev_->enable_device(); st < 0)
        return st;

    dev_->enable_busmastering();
    regs_ = dev_->map_bar(2, VM_NOCACHE);

    if (!regs_.as_ptr())
        return -ENOMEM;

    // Driver programming note says to configure the C+ and command registers first, in this
    // order
    regs_.write16(RTL8168_CPLUS, RTL8168_CPLUS_RXCHKSUM | RTL8168_CPLUS_VLAN_DETAGGING);

    // Reset the NIC
    reset();

    unlock_registers();

    for (int i = 0; i < 6; i++)
    {
        mac_[i] = regs_.read8(RTL8168_IDRx(i));
    }

    if (int st = configure_rx(); st < 0)
    {
        return st;
    }

    if (int st = configure_tx(); st < 0)
    {
        return st;
    }

    setup_irqs();

    lock_registers();

    bool online = regs_.read8(RTL8168_PHYSTATUS) & RTL8168_PHYSTATUS_LINKSTS;
    printk("Online? %s\n", online ? "yes" : "no");

    netif *n = new netif;
    if (!n)
        return -1;

    /* TODO: Allocate device names */
    n->name = "eth0";
    n->flags |= NETIF_LINKUP;
    n->sendpacket = rtl8168_send_packet;
    n->priv = this;
    n->mtu = 1500;
    n->poll_rx = rtl8168_poll_rx;
    n->rx_end = rtl8168_rx_end;
    netif_ = n;
    n->dll_ops = &eth_ops;
    memcpy(n->mac_address, mac_, 6);
    netif_register_if(n);

    return 0;
}

/**
 * @brief Sets up interrupts on the NIC
 *
 */
void rtl8168_device::setup_irqs()
{
    regs_.write16(RTL8168_IMR, RTL8168_INT_LINKCHG | RTL8168_INT_ROK);
    clear_ints();

    const auto irq_lambda = [](irq_context *ctx, void *cookie) -> irqstatus_t {
        return ((rtl8168_device *) cookie)->handle_irq();
    };

    if (dev_->enable_msi(irq_lambda, this) < 0)
    {
        int st = install_irq(dev_->get_intn(), irq_lambda, dev_, IRQ_FLAG_REGULAR, this);

        assert(st == 0);
    }
}

int rtl8168_probe(device *dev_)
{
    auto dev = (pci::pci_device *) dev_;

    auto addr = dev->addr();

    printk("Found suitable rtl8111/rtl8168 device at %04x:%02x:%02x:%02x\n"
           "ID %04x:%04x\n",
           addr.segment, addr.bus, addr.device, addr.function, dev->vid(), dev->did());

    unique_ptr<rtl8168_device> rtldev = make_unique<rtl8168_device>(dev);

    if (!rtldev)
        return -ENOMEM;

    if (int st = rtldev->init(); st < 0)
    {
        printk("St: %d\n", st);
        return st;
    }

    rtldev.release();

    return 0;
}

struct pci::pci_id rtl8168_pci_ids[] = {
    {PCI_ID_DEVICE(RTL_VENDORID, 0x8168, NULL)}, {PCI_ID_DEVICE(RTL_VENDORID, 0x8111, NULL)}, {0}};

struct driver rtl8168_driver = {.name = "rtl8168",
                                .devids = &rtl8168_pci_ids,
                                .probe = rtl8168_probe,
                                .bus_type_node = {&rtl8168_driver}};

int rtl8168_init(void)
{
    pci::register_driver(&rtl8168_driver);
    return 0;
}

MODULE_INIT(rtl8168_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
