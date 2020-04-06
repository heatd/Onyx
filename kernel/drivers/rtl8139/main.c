/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "include/rtl8139.h"

#include <onyx/log.h>
#include <onyx/irq.h>
#include <onyx/portio.h>
#include <onyx/module.h>
#include <onyx/scheduler.h>
#include <onyx/page.h>
#include <onyx/spinlock.h>
#include <onyx/ethernet.h>
#include <onyx/timer.h>
#include <onyx/netif.h>
#include <onyx/dpc.h>
#include <onyx/network.h>

#include <drivers/mmio.h>
#include <pci/pci.h>

void *rx_buffer = NULL;
struct tx_buffer tx_buffers[RTL_NR_TX] = {0};
static struct spinlock tx_lock = {0};
static int tx = 0;
static struct pci_device *device = NULL;
static uint16_t io_base = 0;
static volatile uint8_t *memory_base = NULL;
static size_t rx_buf_seek = 0;
static const size_t rx_buf_size = 4096 * 2;
static struct netif *nic_netif = NULL;

int get_next_tx(void)
{
	spin_lock(&tx_lock);
	int next_tx = tx;
	tx++;
	if(tx == RTL_NR_TX)
		tx = 0;
	spin_unlock(&tx_lock);
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

struct rtl_rx_header
{
	uint16_t status;
	uint16_t len;
};

static size_t dropped_packets = 0;

void rtl_dpc(void *ctx)
{
	while((rtl_readw(REG_CMD) & 1) == 0)
	{
		struct rtl_rx_header *header = rx_buffer + rx_buf_seek;
		uint8_t *packet = (uint8_t*)(header + 1);

		/* Copy the packet */
		uint8_t *new_packet = malloc(header->len - 4);
		if(!new_packet)
		{
			printf("rtl8139: OOM while copying packet, dropping it\n");
			printf("Header len %u\n", header->len);
			dropped_packets++;
			break;
		}

		memcpy(packet, new_packet, header->len - 4);

		/* Send it down the network stack */
		network_handle_packet(new_packet, header->len - 4, nic_netif);

		free(new_packet);
		if(rx_buf_seek + header->len <= rx_buf_size)
			rx_buf_seek = (rx_buf_seek + header->len + 4 + 3) & ~3;
		else rx_buf_seek = 0;
		rtl_writew(REG_CAPR, rx_buf_seek);
	}
	printf("Done my work!\n");

}

static volatile bool recieved_irq = false;
irqstatus_t rtl_irq_handler(struct irq_context *ctx, void *cookie)
{
	uint16_t status = rtl_readw(REG_ISR);

	if(status & ISR_ROK)
	{
		struct dpc_work work;
		work.funcptr = rtl_dpc;
		work.context = NULL;
		work.next = NULL;
		dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
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
		sched_sleep_ms(1);
	INFO("rtl8139", "Reset complete!\n");
}
void rtl_destroy_tx(void)
{
	for(int i = 0; i < RTL_NR_TX; i++)
	{
		if(tx_buffers[i].buffer)	free_page(phys_to_page((uintptr_t) tx_buffers[i].buffer));
		tx_buffers[i].buffer = NULL;
	}
}

void rtl_init_tx(void)
{
	for(int i = 0; i < RTL_NR_TX; i++)
	{
		struct page *p = alloc_page(0);
		if(!p)
		{
			ERROR("rtl8139", "Couldn't allocate enough pages for the tx buffers\n");
			return;
		}

		tx_buffers[i].buffer = page_to_phys(p);

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
	void *ph_rx = page_to_phys(alloc_pages(2, PAGE_ALLOC_CONTIGUOUS));
	if(!ph_rx)
	{
		ERROR("rtl8139", "Couldn't allocate enough contiguous memory for the rx buffer\n");
		return -1;
	}
	rtl_writel(REG_RBSTART, (uint32_t) (uintptr_t) ph_rx);
	rtl_writel(REG_RCR, RCR_WRAP | RCR_AAP | RCR_APM | RCR_AM | RCR_AB); /* Accept every valid packet */
	/* Enable Transmitter OK, Reciever OK and Timeout interrupts */
	rtl_writew(REG_IMR, IMR_TOK | IMR_ROK | IMR_TIMEOUT);
	/* Enable RX and TX */
	rtl_writew(REG_CMD, CMD_RECIEVER_ENABLE | CMD_TRANSMITTER_ENABLE);
	/* Initialize the TX buffers */
	rtl_init_tx();

	rx_buffer = (void*)((uintptr_t) ph_rx + PHYS_BASE);
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
		sched_sleep_ms(5);
	}
	recieved_irq = false;
	return 0;
}

int rtl_send_packet(const void *buf, const uint16_t size, struct netif *nif)
{
	(void) nif;
	int status;
	int tx = get_next_tx();

	spin_lock(&tx_buffers[tx].lock);
	memcpy((void*)((uintptr_t) tx_buffers[tx].buffer + PHYS_BASE), buf, size);
	/* Setup the tx buffer */
	rtl_writel(REG_TSAD0 + tx * 4, (uint32_t)(uintptr_t) tx_buffers[tx].buffer);
	rtl_writel(REG_TSD0 + tx * 4, size);

	status = rtl_wait_for_irq(10000, tx);
	spin_unlock(&tx_buffers[tx].lock);

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

static struct pci_id pci_rtl_devids[] = 
{
	{ PCI_ID_DEVICE(RTL8139_VENDORID, RTL8139_DEVICEID, NULL) },
	{ 0 }
};

/* FIXME: Fix this driver, that's even full of globals */

int rtl_probe(struct device *dev)
{
	device = (struct pci_device *) dev;

	/* Enable PCI busmastering */
	pci_enable_busmastering(device);
	struct pci_bar bar;
	if(pci_get_bar(device, RTL8139_PCI_MMIO_BAR, &bar) < 0)
	{
		if(pci_get_bar(device, RTL8139_PCI_PIO_BAR, &bar) < 0)
			return -1;
	}

	if(bar.is_iorange)
	{
		INFO("rtl8139", "Using Port I/O for hardware access\n");
		io_base = (uint16_t) bar.address;
	}
	else
	{
		INFO("rtl8139", "Using MMIO for hardware access\n");
		memory_base = mmiomap((void*) bar.address, bar.size, 
			VM_WRITE | VM_NOEXEC | VM_NOCACHE);
		if(!memory_base)
		{
			ERROR("rtl8139", "Could not allocate enough memory\n");
			return -1;
		}
	}

	/* Initialize the actual hardware */
	if(rtl_init() < 0)
		return -1;
	int irq = pci_get_intn(device);
	assert(install_irq(irq, rtl_irq_handler, (struct device *) device,
		IRQ_FLAG_REGULAR, NULL) == 0);

	struct netif *n = malloc(sizeof(struct netif));
	if(!n)
		return -1;
	memset(n, 0, sizeof(struct netif));
	n->name = "eth0";
	n->flags |= NETIF_LINKUP;
	n->sendpacket = rtl_send_packet;
	rtl_fill_mac(n);
	netif_register_if(n);

	nic_netif = n;
	return 0;
}

static struct driver rtl_driver = 
{
	.name = "rtl",
	.devids = &pci_rtl_devids,
	.probe = rtl_probe
};

static int rtl8139_init()
{
	pci_bus_register_driver(&rtl_driver);
	return 0;
}

int rtl8139_fini(void)
{
	rtl_destroy_tx();
	return 0;
}

MODULE_INIT(rtl8139_init);
MODULE_FINI(rtl8139_fini);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
