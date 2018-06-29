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

#include <onyx/vmm.h>
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

static struct pci_device *nicdev = NULL;
static struct e1000_rx_desc *rx_descs[E1000_NUM_RX_DESC];
static struct e1000_tx_desc *tx_descs[E1000_NUM_TX_DESC];
static spinlock_t tx_cur_lock;
static unsigned long rx_cur = 0, tx_cur = 0;
bool eeprom_exists = false;
static char *mem_space = NULL;
static uint16_t io_space = 0;
struct netif *nic_netif = NULL;
void e1000_write_command(uint16_t addr, uint32_t val);
uint32_t e1000_read_command(uint16_t p_address);

static void initialize_e1000_busmastering()
{
	pci_enable_busmastering(nicdev);
}

void e1000_handle_recieve()
{
	uint16_t old_cur = 0;
	while((rx_descs[rx_cur]->status & 0x1))
	{
		uint8_t *buf = (uint8_t *)rx_descs[rx_cur]->addr;
		uint16_t len = rx_descs[rx_cur]->length;

		network_dispatch_recieve(buf + PHYS_BASE, len, nic_netif);

		rx_descs[rx_cur]->status = 0;
		old_cur = rx_cur;

		rx_cur = (rx_cur + 1) % E1000_NUM_RX_DESC;

		e1000_write_command(REG_RXDESCTAIL, old_cur);
	}
}

irqstatus_t e1000_irq(struct irq_context *ctx, void *cookie)
{
	volatile uint32_t status = e1000_read_command(0xc0);
	if(status & 0x80)
	{
		e1000_handle_recieve();
	}
	
	return IRQ_HANDLED;
}

void e1000_write_command(uint16_t addr, uint32_t val)
{
	mmio_writel((uintptr_t) (mem_space + addr), val);
}

uint32_t e1000_read_command(uint16_t addr)
{
	return mmio_readl((uintptr_t) (mem_space + addr));
}

void e1000_detect_eeprom(void)
{
	e1000_write_command(REG_EEPROM, 0x1);
	for(int i = 0; i < 1000000; i++)
	{
		uint32_t test = e1000_read_command(REG_EEPROM);
		if(test & 0x10)
		{
			INFO("e1000", "confirmed eeprom exists at spin %d\n", i);
			eeprom_exists = true;
			break;
		}
	}
}

uint32_t e1000_eeprom_read(uint8_t addr)
{
	uint16_t data = 0;
	uint32_t tmp = 0;
        if (eeprom_exists)
        {
            	e1000_write_command(REG_EEPROM, (1) | ((uint32_t)(addr) << 8));
        	while(!((tmp = e1000_read_command(REG_EEPROM)) & (1 << 4)));
        }
        else
        {
            e1000_write_command(REG_EEPROM, (1) | ((uint32_t)(addr) << 2));
            while(!((tmp = e1000_read_command(REG_EEPROM)) & (1 << 1)));
        }
	data = (uint16_t)((tmp >> 16) & 0xFFFF);
	return data;
}

static unsigned char e1000_internal_mac_address[6];

int e1000_read_mac_address(void)
{
	if(eeprom_exists)
	{
		uint32_t temp;
		temp = e1000_eeprom_read(0);
		e1000_internal_mac_address[0] = temp & 0xff;
		e1000_internal_mac_address[1] = temp >> 8;
		temp = e1000_eeprom_read(1);
		e1000_internal_mac_address[2] = temp & 0xff;
		e1000_internal_mac_address[3] = temp >> 8;
		temp = e1000_eeprom_read(2);
		e1000_internal_mac_address[4] = temp & 0xff;
		e1000_internal_mac_address[5] = temp >> 8;
		return 0;
	}
	else
	{
		uint8_t *mem_base_mac_8 = (uint8_t *) (mem_space+0x5400);
		uint32_t *mem_base_mac_32 = (uint32_t *) (mem_space+0x5400);
		if (mem_base_mac_32[0] != 0)
		{
			for(int i = 0; i < 6; i++)
			{
				e1000_internal_mac_address[i] = mem_base_mac_8[i];
			}
			return 0;
		}
   	}
	return 1;
}

int e1000_init_descs(void)
{
	uint8_t *ptr = NULL;
	struct e1000_rx_desc *rxdescs = NULL;
	size_t needed_pages = vmm_align_size_to_pages(sizeof(struct e1000_rx_desc) * E1000_NUM_RX_DESC + 16);
	ptr = vmm_allocate_virt_address(VM_KERNEL, needed_pages, VM_TYPE_HW,
		VM_WRITE | VM_GLOBAL | VM_NOEXEC, 0);
	if(!ptr)
		return 1;
	vmm_map_range(ptr, needed_pages, VM_WRITE | VM_GLOBAL | VM_NOEXEC);
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
			vmm_unmap_range(ptr, needed_pages);
			return 1;
		}
		rx_descs[i]->addr = (uint64_t) virtual2phys((void*) rx_descs[i]->addr);
		rx_descs[i]->status = 0;
	}
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
	ptr = vmm_allocate_virt_address(VM_KERNEL, needed_pages, VMM_TYPE_HW, VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC, 0);
	if(!ptr)
		return 1;
	vmm_map_range(ptr, needed_pages, VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC);
	txdescs = (struct e1000_tx_desc *) ptr;

	for(int i = 0; i < E1000_NUM_TX_DESC; i++)
	{
		tx_descs[i] = (struct e1000_tx_desc *)((uint8_t *)txdescs + i*16);
		tx_descs[i]->addr = 0;
		tx_descs[i]->cmd = 0;
		tx_descs[i]->status = TSTA_DD;
	}
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
}

struct driver e1000_driver = 
{
	.name = "e1000"
};

void e1000_enable_interrupts()
{
	uint16_t int_no = pci_get_intn(nicdev);
	
	// Get the IRQ number and install its handler
	INFO("e1000", "using IRQ number %u\n", int_no);

	assert(install_irq(int_no, e1000_irq, (struct device *) nicdev,
		IRQ_FLAG_REGULAR, NULL) == 0);
	
	e1000_write_command(REG_IMASK, 0x1F6DC);
	e1000_write_command(REG_IMASK ,0xff & ~4);
	e1000_read_command(0xC0);
}

int e1000_send_packet(const void *data, uint16_t len)
{
	acquire_spinlock(&tx_cur_lock);
	
	tx_descs[tx_cur]->addr = (uint64_t) virtual2phys((void*) data);
	tx_descs[tx_cur]->length = len;
	tx_descs[tx_cur]->cmd = CMD_EOP | CMD_IFCS | CMD_RS | CMD_RPS | CMD_IC;
	tx_descs[tx_cur]->status = 0;
	uint8_t old_cur = tx_cur;
	tx_cur = (tx_cur + 1) % E1000_NUM_TX_DESC;
	e1000_write_command(REG_TXDESCTAIL, tx_cur);
	release_spinlock(&tx_cur_lock);

	while(!(tx_descs[old_cur]->status & 0xff));
	return 0;
}

void e1000_disable_rxtx(void)
{
	e1000_write_command(REG_RCTRL, 0);
	e1000_write_command(REG_TCTRL, 0);
}

void e1000_setup_flow_control(void)
{
	/* Setup the standard flow control addresses */
	e1000_write_command(REG_FCAL, 0x00c28001);
	e1000_write_command(REG_FCAH, 0x0100);
	e1000_write_command(REG_FCT, 0x8808);
	e1000_write_command(REG_FCTTV, 0);
}

void e1000_clear_stats(void)
{
	for(uint32_t x = 0; x < 256; x += 4)
		e1000_read_command(REG_CRCERRS + x);
}

void e1000_reset_device(void)
{
	/* Disable busmastering and interrupts before resetting the NIC */
	pci_disable_busmastering(nicdev);
	pci_disable_irq(nicdev);

	/* Also disable rx/tx */
	e1000_disable_rxtx();

	/* And disable interrupts in the NIC itself */
	e1000_write_command(REG_IMC, UINT32_MAX);

	/* Reset the NIC by setting the correct bit */
	uint32_t ctrl = e1000_read_command(REG_CTRL);
	e1000_write_command(REG_CTRL, ctrl | CTRL_RST);

	for(;;)
	{
		/*
		 * Sortix does it, maybe we should too.
		 * On some hardware, this loop would hang without this.
		 * Read all the statisics registers (which we do later anyway).
		*/
		e1000_clear_stats();
		ctrl = e1000_read_command(REG_CTRL);
		if(!(ctrl & CTRL_PHY_RST))
			break;
	}

	/* Disable interrupts again */
	e1000_write_command(REG_IMC, UINT32_MAX);

	initialize_e1000_busmastering();

	ctrl = e1000_read_command(REG_CTRL);

	ctrl |= CTRL_SLU;
	/* TODO: The docs say that ASDE should be set to 0 on 82574's */
	ctrl |= CTRL_ASDE;
	ctrl &= ~CTRL_FORCE_SPEED;
	ctrl &= ~CTRL_FRCDPLX;

	e1000_write_command(REG_CTRL, ctrl);

	/* Setup flow control */
	e1000_setup_flow_control();

	/* Clear statistical registers */
	e1000_clear_stats();

	pci_enable_irq(nicdev);
}

bool e1000_filter(struct pci_device *dev)
{
	if(dev->vendorID != INTEL_VENDOR)
		return false;
	switch(dev->deviceID)
	{
		case E1000_DEV:
		case E1000_I217:
		case E1000E_DEV:
		case E1000_82577LM:
			nicdev = dev;
			return true;
		default:
			return false;
	}
}

int e1000_init(void)
{

	pci_find_device(e1000_filter, true);
	
	if(!nicdev)
		return -1;

	driver_register_device(&e1000_driver, (struct device *) nicdev);

	pcibar_t *bar = pci_get_bar(nicdev, 0);
	char *phys_mem_space = NULL;
	if(bar->isIO)
		io_space = (uint16_t)bar->address;
	else
		phys_mem_space = (char *)(uint64_t)bar->address;
	if(phys_mem_space)
		INFO("e1000", "mmio mode\n");
	else
	{
		free(bar);
		ERROR("e1000", "Sorry! This driver only supports e1000 register access through MMIO, "
		"and sadly your card needs the legacy I/O port method of accessing registers\n");
		return -1;
	}

	mem_space = dma_map_range(phys_mem_space, bar->size, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	
	e1000_reset_device();

	e1000_detect_eeprom();

	if(e1000_read_mac_address())
		return -1;
	
	if(e1000_init_descs())
	{
		ERROR("e1000", "failed to initialize!\n");
		return -1;
	}

	e1000_enable_interrupts();
	struct netif *n = zalloc(sizeof(struct netif));
	if(!n)
		return -1;

	n->name = "eth0";
	n->flags |= NETIF_LINKUP;
	n->sendpacket = e1000_send_packet;
	memcpy(n->mac_address, e1000_internal_mac_address, 6);
	netif_register_if(n);

	nic_netif = n;
	free(bar);
	return 0;
}

DRIVER_INIT(e1000_init);
