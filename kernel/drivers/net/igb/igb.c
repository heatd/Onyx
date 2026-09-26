/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/mm/slab.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/net/network.h>
#include <onyx/panic.h>
#include <onyx/vm.h>

#include <drivers/mmio.h>

#include "e1000.h"
#include "mii.h"

void igb_write(u32 addr, u32 val, struct igb_dev *dev)
{
    mmio_writel((u64) (dev->regs + addr), val);
}

u32 igb_read(u32 addr, const struct igb_dev *dev)
{
    return mmio_readl((u64) (dev->regs + addr));
}

static bool igb_block_phy_reset(struct igb_dev *dev)
{
    /* The management chip might require a stable link. In that case, skip the reset. */
    return igb_read(REG_MANC, dev) & MANC_BLK_PHY_RST_ON_IDE;
}

static void igb_lock_swsm(struct igb_dev *dev)
{
    u32 swsm;

    do
    {
        swsm = igb_read(REG_SWSM, dev);
        igb_write(REG_SWSM, swsm | SWSM_SWESMBI, dev);
    } while (!(igb_read(REG_SWSM, dev) & SWSM_SWESMBI));
}

static void igb_unlock_swsm(struct igb_dev *dev)
{
    igb_write(REG_SWSM, igb_read(REG_SWSM, dev) & ~SWSM_SWESMBI, dev);
}

static int igb_lock_shared(struct igb_dev *dev, enum FW_SYNC resource)
{
    u32 sfsync;
    int err;

    /* The whole process is detailed in 4.6 Access to Shared Resources */
    igb_lock_swsm(dev);

    /* SW_FW_SYNC is now locked, only we can touch it */
    sfsync = igb_read(REG_SW_FW_SYNC, dev);

    err = -EBUSY;
    /* If both the software and firmware bits are clear (_or_ there is no firmware bit), we can take
     * it. Set the bit. */
    if (!(sfsync & SW_FW_SYNC_SOFT(resource)) &&
        (resource > SYNC_FW_MAX || !(sfsync & SW_FW_SYNC_FW(resource))))
    {
        igb_write(REG_SW_FW_SYNC, sfsync | SW_FW_SYNC_SOFT(resource), dev);
        err = 0;
    }

    igb_unlock_swsm(dev);
    return err;
}

static void igb_unlock_shared(struct igb_dev *dev, enum FW_SYNC resource)
{
    u32 sfsync;

    igb_lock_swsm(dev);
    sfsync = igb_read(REG_SW_FW_SYNC, dev);
    sfsync &= ~SW_FW_SYNC_SOFT(resource);
    igb_write(REG_SW_FW_SYNC, sfsync, dev);
    igb_unlock_swsm(dev);
}

static int igb_read_phy_reg(struct igb_dev *dev, unsigned int reg, u16 *val)
{
    u32 mdic;

    WARN_ON(reg & ~MDIC_REGADD_MASK);
    igb_write(REG_MDIC, MDIC_REGADD(reg) | MDIC_OP_READ | (1 << 21), dev);

    /* Now that the command was issued, wait for ready */
    while (!((mdic = igb_read(REG_MDIC, dev)) & MDIC_READY))
        sched_sleep_ms(1);

    if (mdic & MDIC_MDI_ERR)
    {
        dev_err(dev->dev, "PHY register read for %x failed.\n", reg);
        return -EIO;
    }
    *val = mdic & MDIC_DATA_MASK;
    return 0;
}

static int igb_write_phy_reg(struct igb_dev *dev, unsigned int reg, u16 val)
{
    u32 mdic;

    WARN_ON(reg & ~MDIC_REGADD_MASK);
    igb_write(REG_MDIC, MDIC_REGADD(reg) | MDIC_OP_WRITE | val | (1 << 21), dev);

    /* Now that the command was issued, wait for ready */
    while (!((mdic = igb_read(REG_MDIC, dev)) & MDIC_READY))
        sched_sleep_ms(1);

    if (mdic & MDIC_MDI_ERR)
    {
        dev_err(dev->dev, "PHY register write for %x failed.\n", reg);
        return -EIO;
    }
    return 0;
}

static int igb_configure_autoneg(struct igb_dev *dev)
{
    u16 adv_reg, gb_ctrl;
    int err;

    /* The driver (and/or the user) populated a list of desired link speeds. Limit them to the
     * supported ones, and tell the PHY what we're looking for. */
    dev->autoneg_advertise &= dev->autoneg_mask;

    err = igb_read_phy_reg(dev, MII_ADVERTISE, &adv_reg);
    if (err)
        return err;
    err = igb_read_phy_reg(dev, MII_1000BASE_T_CTRL, &gb_ctrl);
    if (err)
        return err;

    /* Clear relevant bits from the registers */
    adv_reg &= ~(ADV_10BASE_HALF | ADV_10BASE_FULL | ADV_100BASE_HALF | ADV_100BASE_FULL);
    gb_ctrl &= ~(MII_1000T_CTRL_1000_HALF_DUPLEX | MII_1000T_CTRL_1000_FULL_DUPLEX);

    /* And set everything */
    if (dev->autoneg_advertise & IGB_10_HALF)
        adv_reg |= ADV_10BASE_HALF;
    if (dev->autoneg_advertise & IGB_10_FULL)
        adv_reg |= ADV_10BASE_FULL;
    if (dev->autoneg_advertise & IGB_100_HALF)
        adv_reg |= ADV_100BASE_HALF;
    if (dev->autoneg_advertise & IGB_100_FULL)
        adv_reg |= ADV_100BASE_FULL;
    if (dev->autoneg_advertise & IGB_1000_FULL)
        gb_ctrl |= MII_1000T_CTRL_1000_FULL_DUPLEX;

    err = igb_write_phy_reg(dev, MII_ADVERTISE, adv_reg);
    if (err)
        return err;
    return igb_write_phy_reg(dev, MII_1000BASE_T_CTRL, gb_ctrl);
}

#define AUTONEG_TIMEOUT 500

static int igb_wait_autoneg(struct igb_dev *dev)
{
    int err, i;
    u16 bmst;

    for (i = 0; i < AUTONEG_TIMEOUT; i++)
    {
        err = igb_read_phy_reg(dev, MII_BMST, &bmst);
        if (err)
            return err;
        err = igb_read_phy_reg(dev, MII_BMST, &bmst);
        if (err)
            return err;
        if (bmst & MII_BMST_AUTONEG_COMPLETE)
            return 0;
        sched_sleep_ms(10);
    }

    dev_warn(dev->dev, "link auto-negotiation timed out\n");
    return 0;
}

static int igb_configure_link(struct igb_dev *dev)
{
    u16 phy_ctrl;
    int err;

    err = igb_configure_autoneg(dev);
    if (err)
        return err;

    dev_info(dev->dev, "restarting link auto-negotiation\n");
    err = igb_read_phy_reg(dev, MII_BMCR, &phy_ctrl);
    if (err)
        return err;
    phy_ctrl |= (MII_BMCR_AUTONEG_ENABLE | MII_BMCR_RESTART_AUTONEG);
    err = igb_write_phy_reg(dev, MII_BMCR, phy_ctrl);
    if (err)
        return err;
    if (dev->wait_for_autoneg)
    {
        err = igb_wait_autoneg(dev);
        if (err)
            return err;
        dev_info(dev->dev, "auto-negotiation complete\n");
    }
    return 0;
}

static int igb_reset_phy(struct igb_dev *dev)
{
    int err;

    /* See 4.3.1.4 PHY reset for more */
    err = igb_lock_shared(dev, SYNC_PHY_SM);
    if (err)
    {
        dev_warn(dev->dev, "cannot reset PHY: FW is busy: %d\n", err);
        return err;
    }

    /* We hold the semaphore, now drive the PHY reset high */
    igb_write(REG_CTRL, igb_read(REG_CTRL, dev) | CTRL_PHY_RST, dev);
    /* and wait... */
    sched_sleep(100 * NS_PER_US);
    /* and release PHY reset */
    igb_write(REG_CTRL, igb_read(REG_CTRL, dev) & ~CTRL_PHY_RST, dev);
    /* release the semaphore now, as we're waiting for the PHY to auto-load config */
    igb_unlock_shared(dev, SYNC_PHY_SM);

    while (0 && !(igb_read(REG_EEMNGCTL, dev) & EEMNGCTL_CFG_DONE0))
        sched_sleep_ms(1);

    /* Linux igb decides to sleep between reset and link configuration, to avoid timeout issues. */
    sched_sleep_ms(100);

    err = igb_lock_shared(dev, SYNC_PHY_SM);
    if (err)
    {
        dev_warn(dev->dev, "cannot configure PHY: FW is busy: %d\n", err);
        return err;
    }

    err = igb_configure_link(dev);
    igb_unlock_shared(dev, SYNC_PHY_SM);
    return err;
}

static int igb_configure_phy(struct igb_dev *dev)
{
    u32 ctrl, ctrl_ext;

    ctrl_ext = igb_read(REG_CTRL_EXT, dev);
    /* Currently we don't support anything other than copper autonegotiation. Bail if we get
     * something else. */
    if ((ctrl_ext & CTRL_EXT_LINK_MODE_MASK) != CTRL_EXT_LINK_MODE_COPPER)
    {
        dev_err(dev->dev, "unsupported link mode %x\n", ctrl_ext >> 22);
        return -EIO;
    }

    if (!igb_block_phy_reset(dev))
        igb_reset_phy(dev);

    ctrl = igb_read(REG_CTRL, dev);

    /* Set up auto-negotiation for the copper link */
    ctrl |= CTRL_SLU;
    ctrl |= CTRL_ASDE;
    ctrl &= ~CTRL_FORCE_SPEED;
    ctrl &= ~CTRL_FRCDPLX;
    /* ILOS should normally be set to 0 for an internal copper PHY, or when using SGMII, 1000BASE-BX
     * or 1000BASE-KX. */
    ctrl &= ~CTRL_ILOS;

    igb_write(REG_CTRL, ctrl, dev);

    return 0;
}

static void igb_clear_stats(struct igb_dev *dev)
{
    for (u32 x = 0; x < 512; x += 4)
        igb_read(REG_CRCERRS + x, dev);
}

static void igb_detect_eeprom(struct igb_dev *dev)
{
    igb_write(REG_EEPROM, 0x1, dev);
    for (int i = 0; i < 10; i++)
    {
        u32 test = igb_read(REG_EEPROM, dev);
        if (test & 0x10)
        {
            dev_info(dev->dev, "device has eeprom\n");
            dev->eeprom_exists = true;
            break;
        }
    }
}

static u32 igb_eeprom_read(u8 addr, struct igb_dev *dev)
{
    u16 data = 0;
    u32 tmp = 0;
    if (dev->eeprom_exists)
    {
        igb_write(REG_EEPROM, (1) | ((u32) (addr) << 8), dev);
        while (!((tmp = igb_read(REG_EEPROM, dev)) & (1 << 4)))
            ;
    }
    else
    {
        igb_write(REG_EEPROM, (1) | ((u32) (addr) << 2), dev);
        while (!((tmp = igb_read(REG_EEPROM, dev)) & (1 << 1)))
            ;
    }

    data = (u16) ((tmp >> 16) & 0xFFFF);
    return data;
}

static int igb_read_mac_address(struct igb_dev *dev)
{
    u32 low;
    u16 high;

    if (dev->eeprom_exists)
    {
        u32 temp;
        temp = igb_eeprom_read(0, dev);
        dev->internal_mac[0] = temp & 0xff;
        dev->internal_mac[1] = temp >> 8;
        temp = igb_eeprom_read(1, dev);
        dev->internal_mac[2] = temp & 0xff;
        dev->internal_mac[3] = temp >> 8;
        temp = igb_eeprom_read(2, dev);
        dev->internal_mac[4] = temp & 0xff;
        dev->internal_mac[5] = temp >> 8;
        /* TODO: program the MAC in case it's not in RAL/RAH? */
        return 0;
    }

    low = igb_read(REG_RAL, dev);
    high = igb_read(REG_RAH, dev) & 0xffff;

    /* Nothing set? probably not present. */
    if (!low)
        return -EIO;

    memcpy(dev->internal_mac, &low, sizeof(low));
    memcpy(dev->internal_mac + 4, &high, sizeof(high));
    return 0;
}

static int igb_reset_dev(struct igb_dev *dev)
{
    u32 ctrl;
    int err;

    /* Disable interrupts in the NIC itself */
    igb_write(REG_IMC, UINT32_MAX, dev);

    /* Reset the NIC by setting the correct bit */
    ctrl = igb_read(REG_CTRL, dev);
    igb_write(REG_CTRL, ctrl | CTRL_RST, dev);

    /* To ensure that the software reset fully completed, we wait for at least 3ms */
    sched_sleep_ms(3);
    /* And now verify that EEC.Auto_RD and STATUS.PF_RST_DONE are both 1 */
    if (0 && !(igb_read(REG_EEC, dev) & EEC_AUTO_RD))
    {
        dev_err(dev->dev, "flash auto-read not complete after reset. NIC might be stuck.\n");
        return -EIO;
    }

    if (0 && !(igb_read(REG_STATUS, dev) & STATUS_PF_RST_DONE))
    {
        dev_err(dev->dev, "device reset not complete after 3ms. NIC might be stuck.\n");
        return -EIO;
    }

    /* Diasble interrupts again (not like we're listening anyway) */
    igb_write(REG_IMC, UINT32_MAX, dev);

    igb_clear_stats(dev);
    dev_info(dev->dev, "device reset complete.\n");

    err = igb_configure_phy(dev);
    if (err)
        return err;
    return 0;
}

static void igb_clear_mta(struct igb_dev *igb)
{
    /* Multicast address table might have garbage, clear it */
    for (int i = 0; i < NR_MTA; i++)
        igb_write(REG_MTA0 + i, 0, igb);
}

static void igb_map_ivar(struct igb_dev *dev, unsigned int queue, bool tx)
{
    unsigned int idx = (queue * 2) + (int) tx;
    unsigned int ivar_n;
    u32 val;

    /* We have four queues of each (8 in total), so they will land in either IVAR0 or IVAR1. */
    ivar_n = queue > 1 ? 1 : 0;

    /* Calculate the relative index in the register */
    idx -= 4 * ivar_n;
    val = igb_read(REG_IVAR(ivar_n), dev);
    /* Clear what was there already */
    val &= ~(0xffU << (idx * 8));
    val |= (queue << (idx * 8));
    val |= (IVAR_INT_VALID << (idx * 8));
    igb_write(REG_IVAR(ivar_n), val, dev);
}

#define RX_BUFLEN        2048
#define IGB_RX_RING_SIZE 1024
#define IGB_TX_RING_SIZE 4096

static int igb_fill_buffers(struct igb_rx_queue *rxq)
{
    struct page_frag frag;
    int i, err;

    for (i = 0; i < (int) rxq->nr_entries; i++)
    {
        err = page_frag_alloc(&rxq->pfi, RX_BUFLEN, GFP_KERNEL, &frag);
        if (err)
        {
            while (--i >= 0)
                page_unref(rxq->rx_bufs[i].page);
            return err;
        }

        rxq->rx_bufs[i].page = frag.page;
        rxq->rx_bufs[i].offset = frag.offset;
        /* for header-data split */
        rxq->rx_bufs[i].hdr_buf = NULL;
        rxq->rx_base[i].read.hdr_addr = 0;
        rxq->rx_base[i].read.pkt_addr = (u64) (page_to_phys(frag.page) + frag.offset);
    }

    return 0;
}

static int igb_init_rx_queue(struct igb_dev *dev, struct igb_rx_queue *rxq)
{
    struct page *pages;

    rxq->nr_entries = IGB_RX_RING_SIZE;
    rxq->bytes = IGB_RX_RING_SIZE * sizeof(union igb_rx_advdesc);
    rxq->head = 0;
    pfi_init(&rxq->pfi);

    if (WARN_ON(rxq->nr_entries % 8))
        return -EIO;

    rxq->rx_bufs = kcalloc(sizeof(struct igb_rxbuf), rxq->nr_entries, GFP_KERNEL);
    if (!rxq->rx_bufs)
        return -ENOMEM;

    pages = alloc_pages(pages2order(vm_size_to_pages(rxq->bytes)), GFP_KERNEL | __GFP_COMP);
    if (!pages)
        goto enomem_free_bufs;

    rxq->rx_base = PAGE_TO_VIRT(pages);
    if (igb_fill_buffers(rxq) < 0)
        goto enomem_free_pages;

    igb_write(REG_RDBAL(rxq->index), (u32) (u64) page_to_phys(pages), dev);
    igb_write(REG_RDBAH(rxq->index), (u32) ((u64) page_to_phys(pages) >> 32), dev);
    igb_write(REG_RDLEN(rxq->index), rxq->bytes, dev);
    igb_write(REG_SRRCTL(rxq->index), SRRCTL_DESCTYPE_ADV_ONE_BUFFER, dev);
    /* We can take the defaults for now. */
    igb_write(REG_RXDCTL(rxq->index), igb_read(REG_RXDCTL(rxq->index), dev) | RXDCTL_ENABLE, dev);

    /* Now, wait for the queue to actually be enabled. */
    while (!(igb_read(REG_RXDCTL(rxq->index), dev) & RXDCTL_ENABLE))
        ;

    igb_write(REG_RDH(rxq->index), 0, dev);
    igb_write(REG_RDT(rxq->index), rxq->nr_entries - 1, dev);
    igb_map_ivar(dev, rxq->index, false);
    return 0;
enomem_free_pages:
    free_pages(pages);
enomem_free_bufs:
    kfree(rxq->rx_bufs);
    return -ENOMEM;
}

static void igb_destroy_rxq(struct igb_rx_queue *rxq)
{
    unsigned int i;

    for (i = 0; i < rxq->nr_entries; i++)
        page_unref(rxq->rx_bufs[i].page);
    kfree(rxq->rx_bufs);
    free_page(phys_to_page(VIRT_TO_PHYS(rxq->rx_base)));
}

#define IGB_NR_RX_QUEUES 1
#define IGB_NR_TX_QUEUES 4

static int igb_init_rx(struct igb_dev *igb)
{
    struct igb_rx_queue *rxq;
    int err, i;

    igb_clear_mta(igb);
    /* Default RXPBSIZE and TXPBSIZE values are fine, I think. */
    rxq = kcalloc(IGB_NR_RX_QUEUES, sizeof(*rxq), GFP_KERNEL);
    if (!rxq)
        return -ENOMEM;

    igb_write(REG_RCTL,
              RCTL_SBP | RCTL_MPE | RCTL_LBM_NONE | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2048, igb);

    /* Disable queue 0 beforehand */
    igb_write(REG_RXDCTL(0), 0, igb);
    for (i = 0; i < IGB_NR_RX_QUEUES; i++)
    {
        rxq[i].index = i;
        err = igb_init_rx_queue(igb, &rxq[i]);
        if (err)
        {
            while (--i >= 0)
                igb_destroy_rxq(&rxq[i]);
            kfree(rxq);
            return err;
        }
    }

    igb_write(REG_RCTL, igb_read(REG_RCTL, igb) | RCTL_EN, igb);
    dev_info(igb->dev, "link: %s\n", (igb_read(REG_STATUS, igb) & STATUS_LU) ? "up" : "down");
    igb->rxq = rxq;
    return 0;
}

static int igb_init_tx_queue(struct igb_dev *dev, struct igb_tx_queue *txq)
{
    struct page *pages;

    txq->nr_entries = txq->nr_avail = IGB_TX_RING_SIZE;
    txq->bytes = IGB_TX_RING_SIZE * sizeof(union igb_tx_desc);
    txq->tail = txq->old_head = 0;
    spinlock_init(&txq->lock);

    if (WARN_ON(txq->nr_entries % 8))
        return -EIO;

    txq->tx_bufs = kcalloc(sizeof(struct igb_txbuf), txq->nr_entries, GFP_KERNEL);
    if (!txq->tx_bufs)
        return -ENOMEM;

    pages = alloc_pages(pages2order(vm_size_to_pages(txq->bytes)), GFP_KERNEL | __GFP_COMP);
    if (!pages)
        goto enomem_free_bufs;

    txq->tx_base = PAGE_TO_VIRT(pages);

    igb_write(REG_TDBAL(txq->index), (u32) (u64) page_to_phys(pages), dev);
    igb_write(REG_TDBAH(txq->index), (u32) ((u64) page_to_phys(pages) >> 32), dev);
    igb_write(REG_TDLEN(txq->index), txq->bytes, dev);
    igb_write(REG_TDH(txq->index), 0, dev);
    igb_write(REG_TDT(txq->index), 0, dev);
    /* We can take the defaults for now. The i210 docs recommend WTHRESH=1 */
    igb_write(REG_TXDCTL(txq->index), TXDCTL_WTHRESH(1) | TXDCTL_ENABLE, dev);

    /* Note: no one seems to be using TDWBAL/H. */

    /* Now, wait for the queue to actually be enabled. */
    while (!(igb_read(REG_TXDCTL(txq->index), dev) & TXDCTL_ENABLE))
        ;

    igb_map_ivar(dev, txq->index, true);
    return 0;
enomem_free_bufs:
    kfree(txq->tx_bufs);
    return -ENOMEM;
}

static void igb_destroy_txq(struct igb_tx_queue *txq)
{
    free_pages(phys_to_page(VIRT_TO_PHYS(txq->tx_base)));
    kfree(txq->tx_bufs);
}

static int igb_init_tx(struct igb_dev *igb)
{
    struct igb_tx_queue *txq;
    int err, i;

    /* Disable TXQ 0 */
    igb_write(REG_TXDCTL(0), 0, igb);

    txq = kcalloc(IGB_NR_TX_QUEUES, sizeof(*txq), GFP_KERNEL);
    if (!txq)
        return -ENOMEM;

    for (i = 0; i < IGB_NR_TX_QUEUES; i++)
    {
        txq[i].index = i;
        err = igb_init_tx_queue(igb, &txq[i]);
        if (err)
        {
            while (--i >= 0)
                igb_destroy_txq(&txq[i]);
            kfree(txq);
            return err;
        }
    }

    igb_write(REG_TCTL, TCTL_EN | TCTL_PSP | (0xf << TCTL_CT_SHIFT) | (0x40 << TCTL_BST_SHIFT),
              igb);
    igb->txq = txq;
    return 0;
}

static inline unsigned int pbf_count_iovs(struct packetbuf *pbf)
{
    const struct page_iov *iov = pbf->page_vec;
    unsigned int i;

    for (i = 0; i < PBF_PAGE_IOVS; i++, iov++)
    {
        if (!iov->page)
            break;
    }

    return i;
}

#define TCP_HDR_CSUM_OFF 16
#define UDP_HDR_CSUM_OFF 6

struct mini_iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#else
    unsigned int version : 4;
    unsigned int ihl : 4;
#endif
};

static void igb_tx_prepare_ctx(struct igb_tx_queue *tx, struct packetbuf *pbf, bool *is_v4)
{
    u8 offset = (u8 *) pbf->csum_offset - pbf->transport_header, l4_type;
    union igb_tx_desc *desc = tx->tx_base + tx->tail;
    u32 vlan_maclen_iplen = 0;
    struct mini_iphdr *header;

    *is_v4 = false;
    /* Anything that needs a csum needs to have a net_header and transport_header. Sorry, company
     * policy. */
    if (!pbf->needs_csum || WARN_ON_ONCE(!pbf->net_header || !pbf->transport_header))
        return;
    header = (struct mini_iphdr *) pbf->net_header;
    *is_v4 = (header->version == 4);

    switch (offset)
    {
        case TCP_HDR_CSUM_OFF:
            l4_type = IGB_L4_PACKET_TYPE_TCP;
            break;
        case UDP_HDR_CSUM_OFF:
            l4_type = IGB_L4_PACKET_TYPE_UDP;
            break;
        default:
            WARN_ON_ONCE(1);
            pr_warn_once("bad csum offset %u\n", offset);
            return;
    }

    vlan_maclen_iplen = (pbf->transport_header - pbf->net_header) | (MACLEN << MACLEN_SHIFT);
    desc->raw.word[0] = vlan_maclen_iplen;
    desc->raw.word[1] =
        (*is_v4 ? TUCMD_IPV4 : 0) | (l4_type << TUCMD_L4T_SHIFT) | DTYP_TXCTX_DESC | DEXT_BIT;
}

static void igb_tx_layout_pbf(struct igb_tx_queue *tx, struct packetbuf *pbf)
{
    unsigned int start_off = pbf->data - (unsigned char *) pbf->buffer_start;
    union igb_tx_desc *desc, *prev = NULL;
    const u32 pbf_len = pbf_length(pbf);
    const struct page_iov *iov;
    unsigned int xmitted = 0;
    bool is_v4;

    igb_tx_prepare_ctx(tx, pbf, &is_v4);
    desc = tx->tx_base + tx->tail;
    for (iov = pbf->page_vec; iov->page; iov++, tx->tail = (tx->tail + 1) & (tx->nr_entries - 1),
        desc = tx->tx_base + tx->tail, xmitted++)
    {
        prev = desc;
        desc->raw.word[0] = desc->raw.word[1] = 0;
        desc->adv_data.address = (u64) page_to_phys(iov->page) + iov->page_off;
        desc->adv_data.datalen = iov->length;
        desc->adv_data.mac = 0;
        desc->adv_data.dtyp = DTYP_TDESD;
        desc->adv_data.dcmd = CMD_IFCS | CMD_RS | CMD_DEXT;
        desc->adv_data.sta = 0;
        desc->adv_data.idx = 0;
        desc->adv_data.popts = 0;
        if (pbf->needs_csum)
        {
            desc->adv_data.popts = POPTS_TXSM;
            if (is_v4)
                desc->adv_data.popts |= POPTS_IXSM;
        }

        desc->adv_data.paylen = pbf_len;
        if (!xmitted)
        {
            desc->adv_data.address += start_off;
            desc->adv_data.datalen = pbf->tail - pbf->data;
        }

        tx->nr_avail--;
    }

    prev->adv_data.dcmd |= CMD_EOP;
    tx->tx_bufs[prev - tx->tx_base].pbf = pbf;
    pbf_get(pbf);
}

static int igb_send_packet(struct packetbuf *pbf, struct netif *nif)
{
    struct igb_dev *dev = nif->priv;
    struct igb_tx_queue *tx;
    unsigned int nr_descs;
    int err;

    nr_descs = pbf_count_iovs(pbf) + 1;
    tx = &dev->txq[0];

    spin_lock(&tx->lock);
    err = 0;

    // pr_warn("available tx desc (%u)\n", tx->nr_avail);
    if (unlikely(tx->nr_avail <= nr_descs))
    {
        pr_warn("unavailable tx desc (%u)\n", nr_descs);
        goto out;
    }
    igb_tx_layout_pbf(tx, pbf);
    /* ring the doorbell */
    igb_write(REG_TDT(tx->index), tx->tail, dev);
    err = 0;
out:
    spin_unlock(&tx->lock);
    return err;
}

irqstatus_t igb_irq(struct irq_context *context, void *cookie)
{
    struct igb_dev *dev = cookie;
    u32 icr;

    /* TODO: extended registers */
    icr = igb_read(REG_ICR, dev);
    /* An ICR read auto-clears IAM from the mask */

    if (icr & ICR_LSC)
    {
        if (igb_read(REG_STATUS, dev) & STATUS_LU)
            atomic_or_relaxed(dev->netif->flags, NETIF_LINKUP);
        else
            atomic_and_relaxed(dev->netif->flags, ~NETIF_LINKUP);
        schedule_work(&dev->netif->link_status_work);
    }

    if (icr & ICR_TXDW)
        dev->tx_work_pending = 1;
    if (icr & ICR_RXT0)
        dev->rx_work_pending = 1;
    netif_signal_rx(dev->netif);
    return IRQ_HANDLED;
}

static void igb_clean_tx(struct igb_tx_queue *txq)
{
    unsigned int i = txq->old_head;
    union igb_tx_desc *desc;

    spin_lock(&txq->lock);
    while (i != txq->tail)
    {
        desc = txq->tx_base + i;
        if (!(desc->legacy.status & TSTA_DD))
            break;

        if (desc->legacy.cmd & CMD_EOP)
        {
            WARN_ON(!txq->tx_bufs[i].pbf);
            pbf_put_ref(txq->tx_bufs[i].pbf);
            txq->tx_bufs[i].pbf = NULL;
        }
        else
        {
            WARN_ON(txq->tx_bufs[i].pbf);
        }

        txq->nr_avail++;
        i = (i + 1) & (txq->nr_entries - 1);
    }

    /* We'll resume from here on the next run. */
    txq->old_head = i;
    spin_unlock(&txq->lock);
}

static void igb_refill_rx(struct igb_dev *dev, struct igb_rx_queue *rxq, u32 old_head)
{
    union igb_rx_advdesc *desc;
    struct igb_rxbuf *rxb;
    struct page_frag frag;
    int err;

    while (old_head != rxq->head)
    {
        err = netdev_alloc_frag_rx(GFP_ATOMIC, RX_BUFLEN, &frag);
        /* TODO: Gracefully handle this. */
        if (WARN_ON(err))
            break;
        desc = rxq->rx_base + old_head;
        rxb = rxq->rx_bufs + old_head;
        rxb->page = frag.page;
        rxb->offset = frag.offset;
        rxb->hdr_buf = NULL;
        desc->read.hdr_addr = 0;
        desc->read.pkt_addr = ((u64) page_to_phys(frag.page)) + frag.offset;
        old_head = (old_head + 1) & (rxq->nr_entries - 1);
    }

    igb_write(REG_RDT(rxq->index), (old_head - 1) & (rxq->nr_entries - 1), dev);
}

static int igb_do_rx(struct igb_dev *dev, struct igb_rx_queue *rx)
{
    u32 processed = 0, old_head = rx->head;
    union igb_rx_advdesc *desc;
    struct packetbuf *pbf;
    struct igb_rxbuf *rxb;

    while ((rx->rx_base[rx->head].wb.extended_status & RSTA_DD))
    {
        desc = &rx->rx_base[rx->head];
        rxb = &rx->rx_bufs[rx->head];

        pbf = pbf_alloc_rx_nocopy(GFP_ATOMIC, rxb->page, rxb->offset, desc->wb.pkt_len);
        if (!pbf)
            break;
        netif_process_pbuf(dev->netif, pbf);
        pbf_put_ref(pbf);
        rxb->page = NULL;
        rxb->offset = 0;
        rxb->hdr_buf = NULL;
        rx->head = (rx->head + 1) & (rx->nr_entries - 1);
        processed++;
    }

    if (processed > 0)
        igb_refill_rx(dev, rx, old_head);
    return 0;
}

static int igb_poll_rx(struct netif *nif)
{
    struct igb_dev *dev = nif->priv;

    igb_clean_tx(&dev->txq[0]);
    igb_do_rx(dev, &dev->rxq[0]);
    return 0;
}

static void igb_rx_end(struct netif *nif)
{
    struct igb_dev *dev = nif->priv;

    dev->tx_work_pending = dev->rx_work_pending = 0;
    igb_write(REG_IAM, IMS_TXDW | IMS_RXT0, dev);
    igb_write(REG_IMS, IMS_TXDW | IMS_RXT0, dev);
}

int igb_probe(struct igb_dev *igb)
{
    struct netif *netif;
    int err;

    igb->autoneg_advertise = igb->autoneg_mask = IGB_SUPPORTED_LINK_SPEEDS;
    /* Waiting for autoneg is too slow for probing. We'll get the link-up event in a delayed
     * fashion. */
    igb->wait_for_autoneg = false;
    err = igb_reset_dev(igb);
    if (err)
        return err;

    igb_detect_eeprom(igb);
    err = igb_read_mac_address(igb);
    /* TODO: there's probably no need to bail if we can't read a MAC. software can set it anyway. */
    if (err)
        return err;

    dev_info(igb->dev, "mac address: %*ph\n", 6, igb->internal_mac);
    err = igb_init_rx(igb);
    if (err)
        return err;

    err = igb_init_tx(igb);
    if (err)
        return err;
    netif = alloc_ether_netif(IGB_NR_RX_QUEUES, IGB_NR_TX_QUEUES);
    if (!netif)
        return err;

    igb->tx_work_pending = igb->rx_work_pending = 0;

    memcpy(netif->mac_address, igb->internal_mac, 6);
    netif->priv = igb;
    netif->tx_queue_len = igb->txq[0].nr_entries;
    netif->sendpacket = igb_send_packet;
    netif->rx_end = igb_rx_end;
    netif->poll_rx = igb_poll_rx;
    netif->flags |= NETIF_SUPPORTS_CSUM_OFFLOAD;
    igb->netif = netif;
    if (igb_read(REG_STATUS, igb) & STATUS_LU)
        netif->flags |= NETIF_LINKUP;
    igb_enable_interrupts(igb);
    netif_register_if(netif);

    return 0;
}
