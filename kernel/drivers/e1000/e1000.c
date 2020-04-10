/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <onyx/vm.h>
#include <onyx/ethernet.h>
#include <onyx/pic.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/network.h>
#include <onyx/driver.h>
#include <onyx/netif.h>
#include <onyx/dev.h>
#include <onyx/panic.h>
#include <onyx/ethernet.h>

#include <drivers/mmio.h>
#include "e1000.h"
#include <pci/pci.h>

#define E1000_NUM_RX_DESC 		32
#define E1000_NUM_TX_DESC		8
 
struct e1000_device
{
	char *mmio_space;
	bool eeprom_exists;
	unsigned long rx_cur;
	unsigned long tx_cur;
	struct spinlock tx_cur_lock;
	struct e1000_rx_desc *rx_descs;
	struct e1000_tx_desc *tx_descs;
	struct page *rx_pages;
	struct page *tx_pages;
	struct page *rx_buf_pages;
	struct pci_device *nicdev;
	struct netif *nic_netif;
	unsigned char e1000_internal_mac_address[6];
	unsigned int irq_nr;
};

void e1000_write(uint16_t addr, uint32_t val, struct e1000_device *dev);
uint32_t e1000_read(uint16_t addr, struct e1000_device *dev);

static void e1000_init_busmastering(struct e1000_device *dev)
{
	pci_enable_busmastering(dev->nicdev);
}

void e1000_handle_recieve(struct e1000_device *dev)
{
	uint16_t old_cur = 0;
	while((dev->rx_descs[dev->rx_cur].status & 0x1))
	{
		uint8_t *buf = (uint8_t *) dev->rx_descs[dev->rx_cur].addr;
		uint16_t len = dev->rx_descs[dev->rx_cur].length;

		network_dispatch_recieve(buf + PHYS_BASE, len, dev->nic_netif);

		dev->rx_descs[dev->rx_cur].status = 0;
		old_cur = dev->rx_cur;

		dev->rx_cur = (dev->rx_cur + 1) % E1000_NUM_RX_DESC;

		e1000_write(REG_RXDESCTAIL, old_cur, dev);
	}
}

irqstatus_t e1000_irq(struct irq_context *ctx, void *cookie)
{
	volatile uint32_t status = e1000_read(REG_ICR, cookie);
	if(status & ICR_RXT0)
	{
		e1000_handle_recieve(cookie);
	}
	
	return IRQ_HANDLED;
}

void e1000_write(uint16_t addr, uint32_t val, struct e1000_device *dev)
{
	mmio_writel((uintptr_t) (dev->mmio_space + addr), val);
}

uint32_t e1000_read(uint16_t addr, struct e1000_device *dev)
{
	return mmio_readl((uintptr_t) (dev->mmio_space + addr));
}

void e1000_detect_eeprom(struct e1000_device *dev)
{
	e1000_write(REG_EEPROM, 0x1, dev);
	for(int i = 0; i < 1000000; i++)
	{
		uint32_t test = e1000_read(REG_EEPROM, dev);
		if(test & 0x10)
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
	if(dev->eeprom_exists)
	{
		e1000_write(REG_EEPROM, (1) | ((uint32_t)(addr) << 8), dev);
		while(!((tmp = e1000_read(REG_EEPROM, dev)) & (1 << 4)));
    }
	else
	{
		e1000_write(REG_EEPROM, (1) | ((uint32_t)(addr) << 2), dev);
		while(!((tmp = e1000_read(REG_EEPROM, dev)) & (1 << 1)));
	}

	data = (uint16_t)((tmp >> 16) & 0xFFFF);
	return data;
}

int e1000_read_mac_address(struct e1000_device *dev)
{
	if(dev->eeprom_exists)
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
		if(mem_base_mac_32[0] != 0)
		{
			for(int i = 0; i < 6; i++)
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

struct page_frag_res page_frag_alloc(struct page_frag_alloc_info *inf, size_t size)
{
	assert(size <= PAGE_SIZE);

	struct page_frag_res r;
	r.page = NULL;
	r.off = 0;

	if(inf->off + size > PAGE_SIZE)
	{
		struct page *next = inf->curr->next_un.next_allocation;
		if(!next)
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
	size_t needed_pages = vm_size_to_pages(sizeof(struct e1000_rx_desc) * E1000_NUM_RX_DESC + 16);
	struct page *rx_pages = alloc_pages(needed_pages, PAGE_ALLOC_CONTIGUOUS);

	if(!rx_pages)
		return -ENOMEM;

	struct page *rx_buf_pages = alloc_pages(vm_size_to_pages(E1000_NUM_RX_DESC * rx_buffer_size),
                                             PAGE_ALLOC_NO_ZERO);
	if(!rx_buf_pages)
	{
		st = -ENOMEM;
		goto error0;
	}

	struct page_frag_alloc_info alloc_info;
	alloc_info.curr = alloc_info.page_list = rx_buf_pages;
	alloc_info.off = 0;

	struct e1000_rx_desc *rxdescs = map_page_list(rx_pages, needed_pages << PAGE_SHIFT,
                                                  VM_WRITE | VM_NOEXEC);
	if(!rxdescs)
	{
		st = -ENOMEM;
		goto error1;
	}

	for(int i = 0; i < E1000_NUM_RX_DESC; i++)
	{
		struct page_frag_res res = page_frag_alloc(&alloc_info, rx_buffer_size);
		/* How can this even happen? Keep this here though, as a sanity check */
		if(!res.page)
			panic("OOM allocating rx buffers");
	
		rxdescs[i].addr = (uint64_t) page_to_phys(res.page) + res.off;
	
		rxdescs[i].status = 0;
	}

	unsigned long rxd_base = (unsigned long) page_to_phys(rx_pages);

	e1000_write(REG_RXDESCLO, (uint32_t) rxd_base, dev);
	e1000_write(REG_RXDESCHI, (uint32_t)(rxd_base >> 32), dev);

	e1000_write(REG_RXDESCLEN, E1000_NUM_RX_DESC * 16, dev);

	e1000_write(REG_RXDESCHEAD, 0, dev);
	e1000_write(REG_RXDESCTAIL, E1000_NUM_RX_DESC-1, dev);

	dev->rx_buf_pages = rx_buf_pages;
	dev->rx_pages = rx_pages;
	dev->rx_cur = 0;
	dev->rx_descs = rxdescs;

	e1000_write(REG_RCTL,
				RCTL_EN | RCTL_SBP| RCTL_UPE | RCTL_MPE | RCTL_LBM_NONE |
				RTCL_RDMTS_HALF | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2048, dev);

	return 0;

error1:
	free_pages(rx_buf_pages);
error0:
	free_pages(rx_pages);
	return st;
}

#define E1000_DEFAULT_COLLISION_THRESH	15
#define E1000_DEFAULT_COLD				0x3f
#define E1000_RECOMMENDED_TIPG				0x00702008

int e1000_init_tx(struct e1000_device *dev)
{
	struct e1000_tx_desc *txdescs = NULL;
	int st = 0;
	size_t needed_pages = vm_size_to_pages(sizeof(struct e1000_rx_desc) * E1000_NUM_RX_DESC + 16);
	struct page *tx_pages = alloc_pages(needed_pages, PAGE_ALLOC_CONTIGUOUS);

	if(!tx_pages)
		return -ENOMEM;

	txdescs = map_page_list(tx_pages, needed_pages << PAGE_SHIFT, VM_WRITE | VM_NOEXEC);
	if(!txdescs)
	{
		st = -ENOMEM;
		goto error0;
	}

	unsigned long txd_base = (unsigned long) page_to_phys(tx_pages);
	e1000_write(REG_TXDESCLO, (uint32_t) txd_base, dev);
	e1000_write(REG_TXDESCHI, (uint32_t)(txd_base >> 32), dev);

	e1000_write(REG_TXDESCLEN, E1000_NUM_TX_DESC * 16, dev);

	e1000_write(REG_TXDESCHEAD, 0, dev);
	e1000_write(REG_TXDESCTAIL, 0, dev);

	/* Note: TCTL_RRTHRESH(1) is the default and means 4 lines of 16 bytes */
	e1000_write(REG_TCTL, TCTL_EN | TCTL_PSP | (E1000_DEFAULT_COLLISION_THRESH << TCTL_CT_SHIFT) |
                (E1000_DEFAULT_COLD << TCTL_COLD_SHIFT) | TCTL_RRTHRESH(1), dev);
	e1000_write(REG_TIPG, E1000_RECOMMENDED_TIPG, dev);

	dev->tx_cur = 0;
	dev->tx_pages = tx_pages;
	dev->tx_descs = txdescs;

	return 0;
error0:
	free_pages(tx_pages);
	return st;
}

int e1000_init_descs(struct e1000_device *dev)
{
	int st;
	if((st = e1000_init_rx(dev)) < 0)
		return st;
	if((st = e1000_init_tx(dev)) < 0)
		return st;
	return 0;
}

void e1000_enable_interrupts(struct e1000_device *dev)
{
	dev->irq_nr = pci_get_intn(dev->nicdev);
	
	// Get the IRQ number and install its handler
	INFO("e1000", "using IRQ number %u\n", dev->irq_nr);

	assert(install_irq(dev->irq_nr, e1000_irq, (struct device *) dev->nicdev,
		IRQ_FLAG_REGULAR, dev) == 0);

	e1000_write(REG_IMS, IMS_TXDW | IMS_TXQE | IMS_RXT0, dev);
	e1000_read(REG_ICR, dev);
}

int e1000_send_packet(const void *data, uint16_t len, struct netif *nif)
{
	struct e1000_device *dev = nif->priv;

	/* TODO: Rework this */
	struct page *buf = alloc_page(PAGE_ALLOC_NO_ZERO);
	if(!buf)
		return -ENOMEM;

	memcpy(PAGE_TO_VIRT(buf), data, len);

	spin_lock(&dev->tx_cur_lock);

	dev->tx_descs[dev->tx_cur].addr = (uint64_t) page_to_phys(buf);
	dev->tx_descs[dev->tx_cur].length = len;
	dev->tx_descs[dev->tx_cur].cmd = CMD_EOP | CMD_IFCS | CMD_RS | CMD_RPS;
	dev->tx_descs[dev->tx_cur].status = 0;
	dev->tx_descs[dev->tx_cur].popts = POPTS_TXSM;
	uint8_t old_cur = dev->tx_cur;
	dev->tx_cur = (dev->tx_cur + 1) % E1000_NUM_TX_DESC;
	e1000_write(REG_TXDESCTAIL, dev->tx_cur, dev);
	spin_unlock(&dev->tx_cur_lock);

	while(!(dev->tx_descs[old_cur].status & 0xff));

	free_page(buf);

	return 0;
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
	e1000_write(REG_FCT,  0x8808, dev);
	e1000_write(REG_FCTTV, 0, dev);
}

void e1000_clear_stats(struct e1000_device *dev)
{
	for(uint32_t x = 0; x < 256; x += 4)
		e1000_read(REG_CRCERRS + x, dev);
}

void e1000_reset_device(struct e1000_device *dev)
{
	/* Disable busmastering and interrupts before resetting the NIC */
	pci_disable_busmastering(dev->nicdev);
	pci_disable_irq(dev->nicdev);

	/* Also disable rx/tx */
	e1000_disable_rxtx(dev);

	/* And disable interrupts in the NIC itself */
	e1000_write(REG_IMC, UINT32_MAX, dev);

	/* Reset the NIC by setting the correct bit */
	uint32_t ctrl = e1000_read(REG_CTRL, dev);
	e1000_write(REG_CTRL, ctrl | CTRL_RST, dev);

	for(;;)
	{
		/*
		 * Sortix does it, maybe we should too.
		 * On some hardware, this loop would hang without this.
		 * Read all the statisics registers (which we do later anyway).
		*/
		e1000_clear_stats(dev);
		ctrl = e1000_read(REG_CTRL, dev);
		if(!(ctrl & CTRL_PHY_RST))
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

	pci_enable_irq(dev->nicdev);
}

struct pci_id e1000_pci_ids[] = 
{
	{ PCI_ID_DEVICE(INTEL_VENDOR, E1000_DEV, NULL) },
	{ PCI_ID_DEVICE(INTEL_VENDOR, E1000_I217, NULL) },
	{ PCI_ID_DEVICE(INTEL_VENDOR, E1000_82577LM, NULL) }
};

struct packetbuf_proto *e1000_get_packetbuf_proto(struct netif *n)
{
	return eth_get_packetbuf_proto();
}

int e1000_probe(struct device *__dev)
{
	struct pci_device *dev = (struct pci_device *) __dev;

	INFO("e1000", "Found suitable e1000 device at %04x:%02x:%02x:%02x\n"
		"ID %04x:%04x\n", dev->segment, dev->bus, dev->device,
		dev->function, dev->vendorID, dev->deviceID);
	
	char *mem_space = pci_map_bar(dev, 0);
	if(!mem_space)
	{
		ERROR("e1000", "Sorry! This driver only supports e1000 register access through MMIO, "
		"and sadly your card needs the legacy I/O port method of accessing registers\n");
		return -1;
	}

	struct e1000_device *nicdev = zalloc(sizeof(*nicdev));
	if(!nicdev)
	{
		/* TODO: Unmap mem_space */
		return -1;
	}

	nicdev->mmio_space = mem_space;
	nicdev->nicdev = dev;
	
	INFO("e1000", "mmio mode\n");
	
	e1000_reset_device(nicdev);

	e1000_detect_eeprom(nicdev);

	if(e1000_read_mac_address(nicdev))
		return -1;
	
	printk("Mac address: ");
	for(int i = 0; i < 6; i++)
		printk("%02x%s", nicdev->e1000_internal_mac_address[i], i != 5 ? ":" : "");
	printk("\n");
	
	if(e1000_init_descs(nicdev))
	{
		ERROR("e1000", "failed to initialize!\n");
		return -1;
	}

	e1000_enable_interrupts(nicdev);

	struct netif *n = zalloc(sizeof(struct netif));
	if(!n)
		return -1;

	/* TODO: Allocate device names */
	n->name = "eth0";
	n->flags |= NETIF_LINKUP;
	n->sendpacket = e1000_send_packet;
	n->priv = nicdev;
	n->get_packetbuf_proto = e1000_get_packetbuf_proto;
	n->mtu = MAX_MTU;
	nicdev->nic_netif = n;
	memcpy(n->mac_address, nicdev->e1000_internal_mac_address, 6);
	netif_register_if(n);

	return 0;
}

struct driver e1000_driver = 
{
	.name = "e1000",
	.devids = &e1000_pci_ids,
	.probe = e1000_probe
};

int e1000_init(void)
{
	pci_bus_register_driver(&e1000_driver);
	return 0;
}

MODULE_INIT(e1000_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
