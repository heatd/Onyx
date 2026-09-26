/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _DRIVERS_E1000_H
#define _DRIVERS_E1000_H

#include <stdint.h>

#include <onyx/compiler.h>
#include <onyx/dev_printk.h>
#include <onyx/irq.h>
#include <onyx/packetbuf.h>
#include <onyx/page_frag.h>
#include <onyx/types.h>

#define INTEL_VENDOR  0x8086
#define E1000_DEV     0x100E
#define E1000_I217    0x153A
#define E1000E_DEV    0x10D3
#define E1000_82577LM 0x10EA
#define E1000_I210    0x1533

/* Register values look up in linux/drivers/net/ethernet/intel/e1000e/regs.h */
#define REG_CTRL       0x0000
#define REG_STATUS     0x0008
#define REG_EECD       0x0010
#define REG_EEPROM     0x0014
#define REG_CTRL_EXT   0x0018
#define REG_FLA        0x001c
#define REG_MDIC       0x0020
#define REG_SCTL       0x0024
#define REG_FCAL       0x0028
#define REG_FCAH       0x002c
#define REG_FEXT       0x002c
#define REG_FCT        0x0030
#define REG_ICR        0x00c0
#define REG_IMS        0x00d0
#define REG_IMC        0x00d8
#define REG_IVAR(n)    (0x1700 + (4 * (n)))
#define REG_RCTL       0x0100
#define REG_IAM        0x1510
#define REG_FCTTV      0x0170
#define REG_RXDESCLO   0x2800
#define REG_RXDESCHI   0x2804
#define REG_RXDESCLEN  0x2808
#define REG_RXDESCHEAD 0x2810
#define REG_RXDESCTAIL 0x2818
#define REG_CRCERRS    0x4000
#define REG_TCTL       0x0400
#define REG_TXDESCLO   0x3800
#define REG_TXDESCHI   0x3804
#define REG_TXDESCLEN  0x3808
#define REG_TXDESCHEAD 0x3810
#define REG_TXDESCTAIL 0x3818

#define RXQ_STRIDE      0x40
#define TXQ_STRIDE      RXQ_STRIDE
#define REG_RXQ(off, n) ((0xc000 + (off)) + (RXQ_STRIDE * (n)))
#define REG_RDBAL(n)    (REG_RXQ(0, n))
#define REG_RDBAH(n)    (REG_RXQ(4, n))
#define REG_RDLEN(n)    (REG_RXQ(8, n))
#define REG_SRRCTL(n)   (REG_RXQ(0xc, n))
#define REG_RDH(n)      (REG_RXQ(0x10, n))
#define REG_RDT(n)      (REG_RXQ(0x18, n))
#define REG_RXDCTL(n)   (REG_RXQ(0x28, n))
#define REG_RQDPC(n)    (REG_RXQ(0x30, n))

#define REG_TXQ(off, n) ((0xe000 + (off)) + (TXQ_STRIDE * (n)))
#define REG_TDBAL(n)    (REG_TXQ(0, n))
#define REG_TDBAH(n)    (REG_TXQ(4, n))
#define REG_TDLEN(n)    (REG_TXQ(8, n))
#define REG_TDH(n)      (REG_TXQ(0x10, n))
#define REG_TDT(n)      (REG_TXQ(0x18, n))
#define REG_TXDCTL(n)   (REG_TXQ(0x28, n))
#define REG_TDWBAL(n)   (REG_TXQ(0x38, n))
#define REG_TDWBAH(n)   (REG_TXQ(0x3c, n))

#define REG_RDTR  0x2820 // RX Delay Timer Register
#define REG_RADV  0x282C // RX Int. Absolute Delay Timer
#define REG_RSRPD 0x2C00 // RX Small Packet Detect Interrupt

#define REG_TIPG 0x0410 /* Transmit Inter Packet Gap */

#define REG_RAL 0x05400
#define REG_RAH 0x05404

#define RAH_ADDRESS_VALID (1U << 31)

#define REG_EEC 0x12010

/* EEC register bits */
#define EEC_AUTO_RD (1U << 9)

/* STATUS register bits */
#define STATUS_LU          (1U << 1)
#define STATUS_PF_RST_DONE (1U << 21)

#define RCTL_EN            (1 << 1)  // Receiver Enable
#define RCTL_SBP           (1 << 2)  // Store Bad Packets
#define RCTL_UPE           (1 << 3)  // Unicast Promiscuous Enabled
#define RCTL_MPE           (1 << 4)  // Multicast Promiscuous Enabled
#define RCTL_LPE           (1 << 5)  // Long Packet Reception Enable
#define RCTL_LBM_NONE      (0 << 6)  // No Loopback
#define RCTL_LBM_PHY       (3 << 6)  // PHY or external SerDesc loopback
#define RTCL_RDMTS_HALF    (0 << 8)  // Free Buffer Threshold is 1/2 of RDLEN
#define RTCL_RDMTS_QUARTER (1 << 8)  // Free Buffer Threshold is 1/4 of RDLEN
#define RTCL_RDMTS_EIGHTH  (2 << 8)  // Free Buffer Threshold is 1/8 of RDLEN
#define RCTL_MO_36         (0 << 12) // Multicast Offset - bits 47:36
#define RCTL_MO_35         (1 << 12) // Multicast Offset - bits 46:35
#define RCTL_MO_34         (2 << 12) // Multicast Offset - bits 45:34
#define RCTL_MO_32         (3 << 12) // Multicast Offset - bits 43:32
#define RCTL_BAM           (1 << 15) // Broadcast Accept Mode
#define RCTL_VFE           (1 << 18) // VLAN Filter Enable
#define RCTL_CFIEN         (1 << 19) // Canonical Form Indicator Enable
#define RCTL_CFI           (1 << 20) // Canonical Form Indicator Bit Value
#define RCTL_DPF           (1 << 22) // Discard Pause Frames
#define RCTL_PMCF          (1 << 23) // Pass MAC Control Frames
#define RCTL_SECRC         (1 << 26) // Strip Ethernet CRC

#define RCTL_BSIZE_256   (3 << 16)
#define RCTL_BSIZE_512   (2 << 16)
#define RCTL_BSIZE_1024  (1 << 16)
#define RCTL_BSIZE_2048  (0 << 16)
#define RCTL_BSIZE_4096  ((3 << 16) | (1 << 25))
#define RCTL_BSIZE_8192  ((2 << 16) | (1 << 25))
#define RCTL_BSIZE_16384 ((1 << 16) | (1 << 25))

/* TCTL Register */

#define TCTL_EN          (1 << 1)  // Transmit Enable
#define TCTL_PSP         (1 << 3)  // Pad Short Packets
#define TCTL_CT_SHIFT    4         // Collision Threshold
#define TCTL_BST_SHIFT   12        // Collision Distance
#define TCTL_SWXOFF      (1 << 22) // Software XOFF Transmission
#define TCTL_RTLC        (1 << 24) // Re-transmit on Late Collision
#define TCTL_RRTHRESH(x) (x << 29)

#define MAX_MTU 1514

/* CTRL Register */
#define CTRL_FD             (1 << 0)
#define CTRL_GIO_MASTER_DIS (1 << 1)
#define CTRL_ASDE           (1 << 5)
#define CTRL_SLU            (1 << 6)
#define CTRL_ILOS           (1 << 7)
#define CTRL_SPEED_10MB     (0)
#define CTRL_SPEED_100MB    (1 << 8)
#define CTRL_SPEED_1000MB   (2 << 8)
#define CTRL_FORCE_SPEED    (1 << 11)
#define CTRL_FRCDPLX        (1 << 12)
#define CTRL_ADVD3WUC       (1 << 20)
#define CTRL_RST            (1 << 26)
#define CTRL_RFCE           (1 << 27)
#define CTRL_TFCE           (1 << 28)
#define CTRL_VME            (1 << 30)
#define CTRL_PHY_RST        (1U << 31)

/* CTRL_EXT register bits */
#define CTRL_EXT_LINK_MODE_MASK (3 << 22)

#define CTRL_EXT_LINK_MODE_COPPER 0

#define ICR_TXDW         (1 << 0)
#define ICR_TXQE         (1 << 1)
#define ICR_LSC          (1 << 2)
#define ICR_RXDMT0       (1 << 4)
#define ICR_DSW          (1 << 5)
#define ICR_RXO          (1 << 6)
#define ICR_RXT0         (1 << 7)
#define ICR_MDAC         (1 << 9)
#define ICR_PHYINT       (1 << 12)
#define ICR_LSECPN       (1 << 14)
#define ICR_TXDLOW       (1 << 15)
#define ICR_SRPD         (1 << 16)
#define ICR_ACK          (1 << 17)
#define ICR_MNG          (1 << 18)
#define ICR_EPRST        (1 << 20)
#define ICR_ECCER        (1 << 22)
#define ICR_INT_ASSERTED (1 << 31)

#define IMS_TXDW (1 << 0)
#define IMS_RXT0 (1 << 7)

#define REG_MTA0 0x5200
#define NR_MTA   128

#define SRRCTL_DESCTYPE_ADV_ONE_BUFFER (1U << 25)

#define RXDCTL_ENABLE (1U << 25)

#define TXDCTL_WTHRESH(val) ((val) << 16)
#define TXDCTL_ENABLE       (1U << 25)

#define IVAR_INT_VALID 0x80U

#define REG_MANC                0x5820
#define MANC_BLK_PHY_RST_ON_IDE (1U << 18)

#define REG_SWSM     0x5B50
#define SWSM_SWESMBI (1U << 1)

#define REG_SW_FW_SYNC 0x5B5C

enum FW_SYNC
{
    SYNC_FLASH_SM = 0,
    SYNC_PHY_SM,
    SYNC_I2C_SM,
    SYNC_MAC_CSR_SM,
    SYNC_RSV0,
    SYNC_RSV1,
    SYNC_RSV2,
    SYNC_SVR_SM,
    SYNC_FW_MAX = SYNC_SVR_SM,
    SYNC_MB_SM,
    SYNC_RSV3,
    SYNC_MNG_SM,
};

#define SW_FW_SYNC_SOFT(bit) (1U << (bit))
#define SW_FW_SYNC_FW(bit)   (1U << ((bit) + 16))

#define REG_EEMNGCTL       0x12030
#define EEMNGCTL_CFG_DONE0 (1U << 18)

#define MDIC_DATA_MASK    0xffff
#define MDIC_REGADD_MASK  0x1f
#define MDIC_REGADD(addr) ((addr) << 16)
#define MDIC_OP_WRITE     (1U << 26)
#define MDIC_OP_READ      (2U << 26)
#define MDIC_READY        (1U << 28)
#define MDIC_MDI_IE       (1U << 29)
#define MDIC_MDI_ERR      (1U << 30)

struct e1000_rx_desc
{
    volatile uint64_t addr;
    volatile uint16_t length;
    volatile uint16_t checksum;
    volatile uint8_t status;
    volatile uint8_t errors;
    volatile uint16_t special;
} __attribute__((packed));

#define RSTA_DD    (1 << 0)
#define RSTA_EOP   (1 << 1)
#define RSTA_IXSM  (1 << 2)
#define RSTA_VP    (1 << 3)
#define RSTA_TCPCS (1 << 5)
#define RSTA_IPCS  (1 << 6)
#define RSTA_PIF   (1 << 7)

#define RERR_CE   (1 << 0)
#define RERR_SE   (1 << 1)
#define RERR_SEQ  (1 << 2)
#define RERR_CXE  (1 << 4)
#define RERR_TCPE (1 << 5)
#define RERR_IPE  (1 << 6)
#define RERR_RXE  (1 << 7)

/* Transmit Command */

#define CMD_EOP  (1 << 0) // End of Packet
#define CMD_IFCS (1 << 1) // Insert FCS
#define CMD_IC   (1 << 2) // Insert Checksum

/* Report status */
#define CMD_RS (1 << 3)

/* Report Packet Sent - Not valid for TCP/IP context descriptors */
#define CMD_RPS (1 << 4)

/* Descriptor extension - Set as 1 for extended (non-legacy) descriptors */
#define CMD_DEXT (1 << 5)

/* VLAN Packet Enable - Not valid for TCP/IP context descriptors */
#define CMD_VLE (1 << 6)

/* Interrupt Delay Enable */
#define CMD_IDE (1 << 7)

/* TCP/IP specific context descriptor CMD's */

/* Set as 1b for TCP, 0b for non-tcp */
#define CMD_TCP (1 << 0)

/* Set as 1b for IPv4, 0b for IPv6 */
#define CMD_IP (1 << 1)

/* TCP Segmentation Enable */
#define CMD_TSE (1 << 2)

#define TSTA_DD (1 << 0) // Descriptor Done
#define TSTA_EC (1 << 1) // Excess Collisions
#define TSTA_LC (1 << 2) // Late Collision
#define LSTA_TU (1 << 3) // Transmit Underrun

#define POPTS_IXSM (1 << 0)
#define POPTS_TXSM (1 << 1)

struct e1000_tx_desc
{
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
};

#define E1000_TX_CONTEXT_DESC    0
#define E1000_TX_TCPIP_DATA_DESC 1

/* All of this is described on page 57 of the 8254x software developer's manual */
struct e1000_tx_tcpip_context_desc
{
    /* IP checksum start */
    uint8_t ipcss;

    /* IP checksum offset */
    uint8_t ipcso;

    /* IP checksum ending - 0 means until the end of the packet */
    uint16_t ipcse;

    /* TCP/UDP checksum start */
    uint8_t tucss;

    /* TCP/UDP checksum offset */
    uint8_t tucso;

    /* TCP/UDP checksum ending - 0 means until the end of the packet */
    uint16_t tucse;

    /* Payload length */
    unsigned int paylen : 20;

    /* Descriptor type */
    unsigned int dtype : 4;

    /* TCP/UDP command field */
    unsigned int tucmd : 8;

    uint8_t status;

    /* Header length */
    uint8_t hdrlen;

    /* Maximum segment size */
    uint16_t mss;

} __attribute__((packed));

struct e1000_tx_tcpip_data_desc
{
    uint64_t address;
    unsigned int datalen : 20;
    unsigned int dtype : 4;
    unsigned int dcmd : 8;

    uint8_t status;
    uint8_t popts;
    uint16_t special;

} __attribute__((packed));

struct device;

union igb_rx_advdesc {
    /* Read-side (from the HW's perspective) */
    struct
    {
        u64 pkt_addr;
        /* lowest bit is DD */
        u64 hdr_addr;
    } read;

    /* Written back by the HW on RX */
    struct
    {
        u64 rss_type : 4;
        u64 packet_type : 13;
        u64 rsv : 2;
        u64 hdr_len11_10 : 2;
        u64 hdr_len9_0 : 10;
        u64 sph : 1;
        u64 rss_hash_val : 32;
        u64 extended_status : 20;
        u64 extended_error : 12;
        u64 pkt_len : 16;
        u64 vlan_tag : 16;
    } wb;
};

struct igb_adv_data_desc
{
    u64 address;
    u16 datalen;
    u32 rsv : 2;
    u32 mac : 2;
    u32 dtyp : 4;
    u32 dcmd : 8;
    u32 sta : 4;
    u32 idx : 3;
    u32 rsv2 : 1;
    u32 popts : 6;
    u32 paylen : 18;
};

union igb_tx_desc {
    struct
    {
        u64 word[2];
    } raw;
    struct e1000_tx_desc legacy;
    struct igb_adv_data_desc adv_data;
};

#define IGB_L4_PACKET_TYPE_UDP 0
#define IGB_L4_PACKET_TYPE_TCP 1

#define TUCMD_IPV4      (1U << 10)
#define TUCMD_L4T_SHIFT (11)
#define DTYP_TDESD      (0b11)
#define DTYP_TXCTX_DESC (0b10 << 20)
#define DEXT_BIT        (1U << 29)

#define MACLEN       14
#define MACLEN_SHIFT 9

struct igb_rxbuf
{
    struct page *page;
    void *hdr_buf;
    u32 offset;
};

struct igb_txbuf
{
    struct packetbuf *pbf;
};

struct igb_rx_queue
{
    unsigned int index;
    unsigned int nr_entries;
    unsigned int bytes;
    unsigned int head;
    union igb_rx_advdesc *rx_base;
    struct page_frag_info pfi;
    struct igb_rxbuf *rx_bufs;
};

struct igb_tx_queue
{
    unsigned int index;
    unsigned int nr_entries;
    unsigned int bytes;
    unsigned int nr_avail;
    unsigned int old_head;
    unsigned int tail;
    struct spinlock lock;
    union igb_tx_desc *tx_base;
    struct igb_txbuf *tx_bufs;
};

/* Supported link speeds for the IGB cards. Note that 1000mbps half duplex is not supported (nor
 * valid). */
#define IGB_10_HALF   (1 << 0)
#define IGB_10_FULL   (1 << 1)
#define IGB_100_HALF  (1 << 2)
#define IGB_100_FULL  (1 << 3)
#define IGB_1000_HALF (1 << 4)
#define IGB_1000_FULL (1 << 5)

#define IGB_SUPPORTED_LINK_SPEEDS \
    (IGB_10_HALF | IGB_10_FULL | IGB_100_HALF | IGB_100_FULL | IGB_1000_FULL)

struct igb_dev
{
    struct device *dev;
    volatile char *regs;
    struct igb_rx_queue *rxq;
    struct igb_tx_queue *txq;
    struct netif *netif;
    bool eeprom_exists;
    bool wait_for_autoneg;
    u8 internal_mac[6];
    unsigned int irq_nr;
    unsigned int autoneg_mask;
    unsigned int autoneg_advertise;
    bool tx_work_pending : 1;
    bool rx_work_pending : 1;
};

__BEGIN_CDECLS

int igb_probe(struct igb_dev *igb);
irqstatus_t igb_irq(struct irq_context *context, void *cookie);
void igb_enable_interrupts(struct igb_dev *dev);
void igb_write(u32 addr, u32 val, struct igb_dev *dev);
u32 igb_read(u32 addr, const struct igb_dev *dev);
__END_CDECLS

#endif
