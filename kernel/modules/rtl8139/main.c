/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <rtl8139.h>

#include <kernel/log.h>
#include <kernel/irq.h>
#include <kernel/portio.h>
#include <kernel/module.h>
#include <kernel/scheduler.h>
#include <kernel/page.h>
#include <kernel/spinlock.h>
#include <kernel/ethernet.h>
#include <kernel/timer.h>
#include <kernel/netif.h>

#include <drivers/mmio.h>
#include <drivers/pci.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

struct tx_buffer tx_buffers[RTL_NR_TX] = {0};
static spinlock_t tx_lock = {0};
static int tx = 0;
static struct pci_device *device = NULL;
static uint16_t io_base = 0;
static volatile uint8_t *memory_base = NULL;
int get_next_tx(void)
{
	acquire_spinlock(&tx_lock);
	int next_tx = tx;
	tx++;
	if(tx == RTL_NR_TX)
		tx = 0;
	release_spinlock(&tx_lock);
	return next_tx;
}
uint8_t rtl_readb(uint8_t reg)
{
	if(io_base)
	{
		return inb(io_base + reg);
	}
	else
	{
		return mmio_readb((uint64_t) memory_base + reg);
	}
}
uint16_t rtl_readw(uint8_t reg)
{
	if(io_base)
	{
		return inw(io_base + reg);
	}
	else
	{
		return mmio_readw((uint64_t) memory_base + reg);
	}
}
uint32_t rtl_readl(uint8_t reg)
{
	if(io_base)
	{
		return inl(io_base + reg);
	}
	else
	{
		return mmio_readl((uint64_t) memory_base + reg);
	}
}
void rtl_writeb(uint8_t reg, uint8_t value)
{
	if(io_base)
	{
		outb(io_base + reg, value);
	}
	else
	{
		mmio_writeb((uint64_t) memory_base + reg, value);
	}
}
void rtl_writew(uint8_t reg, uint16_t value)
{
	if(io_base)
	{
		outw(io_base + reg, value);
	}
	else
	{
		mmio_writew((uint64_t) memory_base + reg, value);
	}
}
void rtl_writel(uint8_t reg, uint32_t value)
{
	if(io_base)
	{
		outl(io_base + reg, value);
	}
	else
	{
		mmio_writel((uint64_t) memory_base + reg, value);
	}
}
uint16_t rtl_clear_interrupt(void)
{
	/* Clear interrupts by writing to the ISR register */
	uint16_t status = rtl_readw(REG_ISR);
	rtl_writew(REG_ISR, status);
	return status;
}
static volatile bool recieved_irq = false;
uintptr_t rtl_irq_handler(registers_t *regs)
{
	uint16_t status = rtl_readw(REG_ISR);
	printk("status: %x\n", status);
	if(status & ISR_ROK)
	{
		printk("Recieved a packet\n");
	}
	else
		recieved_irq = true;
	rtl_clear_interrupt();
	return 0;
}
void rtl_software_reset(void)
{
	INFO("rtl8139", "Doing a software reset of the card...\n");
	rtl_writeb(REG_CMD, CMD_RESET);
	while(rtl_readb(REG_CMD) & CMD_RESET)
		sched_sleep(1);
	INFO("rtl8139", "Reset complete!\n");
}
void rtl_destroy_tx(void)
{
	for(int i = 0; i < RTL_NR_TX; i++)
	{
		if(tx_buffers[i].buffer)	__free_pages(tx_buffers[i].buffer, 0);
		tx_buffers[i].buffer = NULL;
	}
}
void rtl_init_tx(void)
{
	for(int i = 0; i < RTL_NR_TX; i++)
	{
		tx_buffers[i].buffer = __alloc_pages(0);
		if(!tx_buffers[i].buffer)
		{
			ERROR("rtl8139", "Couldn't allocate enough pages for the tx buffers\n");
		}
	}
}
int rtl_init(void)
{
	/* Turn on the RTL8139 */
	rtl_writeb(REG_CONFIG1, 0x00);
	/* Do a software reset */
	rtl_software_reset();

	/* Allocate 2 contiguous pages */
	/* Sadly we'll have to waste 2 pages because the RTL8139 requires 8k/16k/32K/64k + 16 bytes */
	void *ph_rx = __alloc_pages(2);
	if(!ph_rx)
	{
		ERROR("rtl8139", "Couldn't allocate enough contiguous memory for the rx buffer\n");
		return -1;
	}
	rtl_writel(REG_RBSTART, (uint32_t) (uintptr_t) ph_rx);
	rtl_writel(REG_RCR, RCR_AAP | RCR_APM | RCR_AM | RCR_AB); /* Accept every valid packet */
	/* Enable Transmitter OK, Reciever OK and Timeout interrupts */
	rtl_writew(REG_IMR, IMR_TOK | IMR_ROK | IMR_TIMEOUT);
	/* Enable RX and TX */
	rtl_writew(REG_CMD, CMD_RECIEVER_ENABLE | CMD_TRANSMITTER_ENABLE);
	/* Initialize the TX buffers */
	rtl_init_tx();

	return 0;
}
int rtl_wait_for_irq(int timeout, int tx)
{
	uint64_t curr_stamp = get_tick_count();
	while(!recieved_irq)
	{
		if(curr_stamp + timeout <= get_tick_count())
			return -ETIMEDOUT;
		/* TODO: Maybe we shouldn't sleep, or should we? */
		sched_sleep(5);
	}
	recieved_irq = false;
	return 0;
}
int rtl_send_packet(const void *buf, const uint16_t size)
{
	int status;
	int tx = get_next_tx();

	acquire_spinlock(&tx_buffers[tx].lock);
	memcpy((void*)((uintptr_t) tx_buffers[tx].buffer + PHYS_BASE), buf, size);
	/* Setup the tx buffer */
	rtl_writel(REG_TSAD0 + tx * 4, (uint32_t)(uintptr_t) tx_buffers[tx].buffer);
	rtl_writel(REG_TSD0 + tx * 4, size);

	status = rtl_wait_for_irq(10000, tx);
	release_spinlock(&tx_buffers[tx].lock);

	return status;
}
void rtl_fill_mac(struct netif *n)
{
	uint8_t port = REG_MAC;
	for(int i = 0; i < 6; i++)
	{
		/* Read the mac address */
		n->mac_address[i] = rtl_readb(port + i);
	}
}
int module_init()
{
	device = get_pcidev_from_vendor_device(RTL8139_DEVICEID, RTL8139_VENDORID);
	if(!device)
		return -1;
	/* Enable PCI busmastering */
	pci_enable_busmastering(device);
	pcibar_t *bar = pci_get_bar(device, RTL8139_PCI_MMIO_BAR);
	/* If there is no MMIO BAR, use the port I/O BAR*/
	if(!bar || !bar->address)
		bar = pci_get_bar(device, RTL8139_PCI_PIO_BAR);
	if(bar->isIO)
	{
		INFO("rtl8139", "Using Port I/O for hardware access\n");
		io_base = (uint16_t) bar->address;
	}
	else
	{
		INFO("rtl8139", "Using MMIO for hardware access\n");
		memory_base = dma_map_range((void*) (uintptr_t) bar->address, bar->size, 
			VM_WRITE | VM_NOEXEC | VM_GLOBAL);
		if(!memory_base)
		{
			ERROR("rtl8139", "Could not allocate enough memory\n");
			return -1;
		}
	}
	free(bar);
	/* Initialize the actual hardware */
	if(rtl_init() < 0)
		return -1;
	int irq = pci_get_intn(device);
	irq_install_handler(irq, rtl_irq_handler);

	struct netif *n = malloc(sizeof(struct netif));
	if(!n)
		return -1;
	memset(n, 0, sizeof(struct netif));
	n->name = "eth0";
	n->flags |= NETIF_LINKUP;
	n->sendpacket = rtl_send_packet;
	rtl_fill_mac(n);
	netif_register_if(n);
	return 0;
}
int module_fini(void)
{
	rtl_destroy_tx();
	return 0;
}
