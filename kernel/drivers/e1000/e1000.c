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

#include <drivers/mmio.h>
#include <drivers/e1000.h>
#include <pci/pci.h>

struct e1000_device
{
	char *mmio_space;
	bool eeprom_exists;
	unsigned long rx_cur;
	unsigned long tx_cur;
	struct spinlock tx_cur_lock;
	struct e1000_rx_desc *rx_descs[E1000_NUM_RX_DESC];
	struct e1000_tx_desc *tx_descs[E1000_NUM_TX_DESC];
	struct pci_device *nicdev;
	struct netif *nic_netif;
	unsigned char e1000_internal_mac_address[6];
	unsigned int irq_nr;
};

void e1000_write_command(uint16_t addr, uint32_t val, struct e1000_device *dev);
uint32_t e1000_read_command(uint16_t addr, struct e1000_device *dev);

static void e1000_init_busmastering(struct e1000_device *dev)
{
	pci_enable_busmastering(dev->nicdev);
}

void e1000_handle_recieve(struct e1000_device *dev)
{
	uint16_t old_cur = 0;
	while((dev->rx_descs[dev->rx_cur]->status & 0x1))
	{
		uint8_t *buf = (uint8_t *) dev->rx_descs[dev->rx_cur]->addr;
		uint16_t len = dev->rx_descs[dev->rx_cur]->length;

		network_dispatch_recieve(buf + PHYS_BASE, len, dev->nic_netif);

		dev->rx_descs[dev->rx_cur]->status = 0;
		old_cur = dev->rx_cur;

		dev->rx_cur = (dev->rx_cur + 1) % E1000_NUM_RX_DESC;

		e1000_write_command(REG_RXDESCTAIL, old_cur, dev);
	}
}

irqstatus_t e1000_irq(struct irq_context *ctx, void *cookie)
{
	volatile uint32_t status = e1000_read_command(REG_ICR, cookie);
	if(status & 0x80)
	{
		e1000_handle_recieve(cookie);
	}
	
	return IRQ_HANDLED;
}

void e1000_write_command(uint16_t addr, uint32_t val, struct e1000_device *dev)
{
	mmio_writel((uintptr_t) (dev->mmio_space + addr), val);
}

uint32_t e1000_read_command(uint16_t addr, struct e1000_device *dev)
{
	return mmio_readl((uintptr_t) (dev->mmio_space + addr));
}

void e1000_detect_eeprom(struct e1000_device *dev)
{
	e1000_write_command(REG_EEPROM, 0x1, dev);
	for(int i = 0; i < 1000000; i++)
	{
		uint32_t test = e1000_read_command(REG_EEPROM, dev);
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
            	e1000_write_command(REG_EEPROM, (1) | ((uint32_t)(addr) << 8), dev);
        	while(!((tmp = e1000_read_command(REG_EEPROM, dev)) & (1 << 4)));
        }
        else
        {
		e1000_write_command(REG_EEPROM, (1) | ((uint32_t)(addr) << 2), dev);
		while(!((tmp = e1000_read_command(REG_EEPROM, dev)) & (1 << 1)));
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
		if (mem_base_mac_32[0] != 0)
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

int e1000_init_descs(struct e1000_device *dev)
{
	return 0;
#if 0
	uint8_t *ptr = NULL;
	struct e1000_rx_desc *rxdescs = NULL;
	size_t needed_pages = vm_align_size_to_pages(sizeof(struct e1000_rx_desc) * E1000_NUM_RX_DESC + 16);
	ptr = vmalloc(needed_pages, VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);

	if(!ptr)
		return 1;

	rxdescs = (struct e1000_rx_desc *) ptr;
	for(int i = 0; i < E1000_NUM_RX_DESC; i++)
	{
		rx_descs[i] = (struct e1000_rx_desc *)((uint8_t *)rxdescs + i*16);
		rx_descs[i]->addr = (uint64_t) malloc(MAX_MTU);
		if(!rx_descs[i]->addr)
		{
			/* Free the past entries */
			for(int j = 0; j < i; j++)
			{
				free(rx_descs[j]);
			}

			vm_unmap_range(ptr, needed_pages);
			return 1;
		}
		rx_descs[i]->addr = (uint64_t) virtual2phys((void*) rx_descs[i]->addr);
		rx_descs[i]->status = 0;
	}

	/* TODO: This shouldn't work because vmalloc returns non-contiguous memory, FIXME */
	ptr = virtual2phys(ptr);
	e1000_write_command(REG_RXDESCLO, (uint32_t)((uint64_t)ptr & 0xFFFFFFFF));
	e1000_write_command(REG_RXDESCHI, (uint32_t)((uint64_t)ptr >> 32));

	e1000_write_command(REG_RXDESCLEN, E1000_NUM_RX_DESC * 16);

	e1000_write_command(REG_RXDESCHEAD, 0);
	e1000_write_command(REG_RXDESCTAIL, E1000_NUM_RX_DESC-1);
	rx_cur = 0;
	e1000_write_command(REG_RCTRL, RCTL_EN| RCTL_SBP| RCTL_UPE | RCTL_MPE | RCTL_LBM_NONE | RTCL_RDMTS_HALF | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2048);
	
	struct e1000_tx_desc *txdescs = NULL;
	
	needed_pages = (sizeof(struct e1000_tx_desc) * E1000_NUM_TX_DESC + 16) / 4096;
	if((sizeof(struct e1000_tx_desc) * E1000_NUM_TX_DESC + 16) % 4096)
		needed_pages++;
	ptr = vmalloc(needed_pages, VM_TYPE_HW, VM_WRITE  | VM_NOEXEC);
	if(!ptr)
		return 1;

	txdescs = (struct e1000_tx_desc *) ptr;

	for(int i = 0; i < E1000_NUM_TX_DESC; i++)
	{
		tx_descs[i] = (struct e1000_tx_desc *)((uint8_t *)txdescs + i*16);
		tx_descs[i]->addr = 0;
		tx_descs[i]->cmd = 0;
		tx_descs[i]->status = TSTA_DD;
	}

	/* FIXME: Same as above */
	ptr = virtual2phys(ptr);
	e1000_write_command(REG_TXDESCLO, (uint32_t)((uint64_t)ptr & 0xFFFFFFFF));
	e1000_write_command(REG_TXDESCHI, (uint32_t)((uint64_t)ptr >> 32));

	e1000_write_command(REG_TXDESCLEN, E1000_NUM_TX_DESC * 16);

	e1000_write_command(REG_TXDESCHEAD, 0);
	e1000_write_command(REG_TXDESCTAIL, 0);
	tx_cur = 0;
	/*e1000_write_command(REG_TCTRL,  TCTL_EN
        | TCTL_PSP
        | (15 << TCTL_CT_SHIFT)
        | (64 << TCTL_COLD_SHIFT)
        | TCTL_RTLC); */
 
	e1000_write_command(REG_TCTRL,  0b0110000000000111111000011111010);
	e1000_write_command(REG_TIPG,  0x0060200A);

	return 0;
#endif
}

void e1000_enable_interrupts(struct e1000_device *dev)
{
	dev->irq_nr = pci_get_intn(dev->nicdev);
	
	// Get the IRQ number and install its handler
	INFO("e1000", "using IRQ number %u\n", dev->irq_nr);

	assert(install_irq(dev->irq_nr, e1000_irq, (struct device *) dev->nicdev,
		IRQ_FLAG_REGULAR, dev) == 0);
	
	e1000_write_command(REG_IMC, 0x1F6DC, dev);
	e1000_write_command(REG_IMC ,0xff & ~4, dev);
	e1000_read_command(REG_ICR, dev);
}

int e1000_send_packet(const void *data, uint16_t len)
{
#if 0
	spin_lock(&dev->tx_cur_lock);
	
	dev->tx_descs[dev->tx_cur]->addr = (uint64_t) virtual2phys((void*) data);
	tx_descs[tx_cur]->length = len;
	tx_descs[tx_cur]->cmd = CMD_EOP | CMD_IFCS | CMD_RS | CMD_RPS | CMD_IC;
	tx_descs[tx_cur]->status = 0;
	uint8_t old_cur = tx_cur;
	tx_cur = (tx_cur + 1) % E1000_NUM_TX_DESC;
	e1000_write_command(REG_TXDESCTAIL, tx_cur);
	spin_unlock(&tx_cur_lock);

	while(!(tx_descs[old_cur]->status & 0xff));
#endif
	panic("implement");
	return 0;
}

void e1000_disable_rxtx(struct e1000_device *dev)
{
	e1000_write_command(REG_RCTL, 0, dev);
	e1000_write_command(REG_TCTRL, 0, dev);
}

void e1000_setup_flow_control(struct e1000_device *dev)
{
	/* Setup the standard flow control addresses */
	e1000_write_command(REG_FCAL, 0x00c28001, dev);
	e1000_write_command(REG_FCAH, 0x0100, dev);
	e1000_write_command(REG_FCT, 0x8808, dev);
	e1000_write_command(REG_FCTTV, 0, dev);
}

void e1000_clear_stats(struct e1000_device *dev)
{
	for(uint32_t x = 0; x < 256; x += 4)
		e1000_read_command(REG_CRCERRS + x, dev);
}

void e1000_reset_device(struct e1000_device *dev)
{
	/* Disable busmastering and interrupts before resetting the NIC */
	pci_disable_busmastering(dev->nicdev);
	pci_disable_irq(dev->nicdev);

	/* Also disable rx/tx */
	e1000_disable_rxtx(dev);

	/* And disable interrupts in the NIC itself */
	e1000_write_command(REG_IMC, UINT32_MAX, dev);

	/* Reset the NIC by setting the correct bit */
	uint32_t ctrl = e1000_read_command(REG_CTRL, dev);
	e1000_write_command(REG_CTRL, ctrl | CTRL_RST, dev);

	for(;;)
	{
		/*
		 * Sortix does it, maybe we should too.
		 * On some hardware, this loop would hang without this.
		 * Read all the statisics registers (which we do later anyway).
		*/
		e1000_clear_stats(dev);
		ctrl = e1000_read_command(REG_CTRL, dev);
		if(!(ctrl & CTRL_PHY_RST))
			break;
	}

	/* Disable interrupts again */
	e1000_write_command(REG_IMC, UINT32_MAX, dev);

	e1000_init_busmastering(dev);

	ctrl = e1000_read_command(REG_CTRL, dev);

	ctrl |= CTRL_SLU;
	/* TODO: The docs say that ASDE should be set to 0 on 82574's */
	ctrl |= CTRL_ASDE;
	ctrl &= ~CTRL_FORCE_SPEED;
	ctrl &= ~CTRL_FRCDPLX;

	e1000_write_command(REG_CTRL, ctrl, dev);

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

DRIVER_INIT(e1000_init);
