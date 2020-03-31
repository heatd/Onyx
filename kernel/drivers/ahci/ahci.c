/*
* Copyright (c) 2016, 2017, 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "include/ahci.h"
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <onyx/timer.h>
#include <onyx/page.h>
#include <onyx/log.h>
#include <onyx/compiler.h>
#include <onyx/module.h>
#include <onyx/vm.h>
#include <onyx/task_switching.h>
#include <onyx/irq.h>
#include <onyx/block.h>
#include <onyx/vfs.h>
#include <onyx/dev.h>
#include <onyx/dma.h>
#include <onyx/panic.h>
#include <onyx/async_io.h>
#include <onyx/dpc.h>
#include <onyx/cpu.h>

#include <pci/pci.h>
#include <drivers/ata.h>

#define NUM_PRDT_PER_TABLE	56

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

void ahci_destroy_aio(struct ahci_port *port, struct aio_req *req);

#define MPRINTF(...) printf("ahci: "__VA_ARGS__)

void ahci_wake_io(void *ctx)
{
	struct aio_req *req = ctx;
	wait_queue_wake_all(&req->wake_sem);
	req->signaled = true;
}

void ahci_deal_aio(struct command_list *list)
{
	assert(list->req != NULL);
	
	struct aio_req *req = list->req;

	if(list->last_interrupt_status & AHCI_INTST_ERROR)
	{
		req->status = AIO_STATUS_EIO;
	}
	else if(list->last_interrupt_status & AHCI_PORT_INTERRUPT_DHRE)
	{
		req->status = AIO_STATUS_OK;
	}

	req->req_end = get_main_clock()->get_ns();
	ahci_wake_io(req);
}

void ahci_do_clist_irq(struct ahci_port *port, int j)
{
	port->cmdslots[j].recieved_interrupt = true;
	port->cmdslots[j].last_interrupt_status = port->port->interrupt_status;
	port->cmdslots[j].status = port->port->status;
	port->cmdslots[j].tfd = port->port->tfd;
	ahci_deal_aio(&port->cmdslots[j]);
}

void ahci_do_port_irqs(struct ahci_port *port)
{
	uint32_t cmd_done = port->issued ^ port->port->command_issue;

	for(unsigned int j = 0; j < 32; j++)
	{
		if(cmd_done & (1U << j))
		{
			ahci_do_clist_irq(port, j);
			port->issued &= ~(1UL << j);
		}
	}
}

irqstatus_t ahci_irq(struct irq_context *ctx, void *cookie)
{
	UNUSED(ctx);
	struct ahci_device *dev = cookie;

	uint32_t ports = dev->hba->interrupt_status;

	/* TODO: Figure this out - AHCI is sending an extra interrupt and the
	 * IRQ code is flagging it as SPURIOUS, which isn't actually true.
	*/
	if(!ports)
		return IRQ_UNHANDLED;

	for(unsigned int i = 0; i < 32; i++)
	{
		struct ahci_port *port = &dev->ports[i];
		spin_lock_irqsave(&port->port_lock);

		if(ports & (1U << i))
		{
			uint32_t port_is = port->port->interrupt_status;
			dev->hba->interrupt_status = (1U << i);
			ahci_do_port_irqs(port);
			port->port->interrupt_status = port_is;
		}

		spin_unlock_irqrestore(&port->port_lock);

	}

	return IRQ_HANDLED;
}

#define AHCI_BYTES_PER_REQ	(NUM_PRDT_PER_TABLE * PRDT_MAX_SIZE)

ssize_t ahci_read(size_t offset, size_t count, void* buffer, struct blockdev* blkd)
{
	struct ahci_port *p = blkd->device_info;
	
	size_t to_read = count;

	uint64_t lba = offset / 512;
	assert(offset % 512 == 0);
	assert(count % 512 == 0);
	uint8_t *buf = buffer;

	while(count != 0)
	{
		size_t c = count > AHCI_BYTES_PER_REQ ?
			   AHCI_BYTES_PER_REQ : count;

		struct ahci_command_ata cmd;
		cmd.buffer = buf;
		cmd.lba = lba;
		cmd.size = c;
		cmd.write = false;
		cmd.cmd = ATA_CMD_READ_DMA_EXT;
	
		if(!ahci_do_command(p, &cmd))
		{
			return -1;
		}

		buf += c;
		count -= c;
		lba += c / 512;
	}

	return to_read;
}

ssize_t ahci_write(size_t offset, size_t count, void* buffer, struct blockdev* blkd)
{
	struct ahci_port *p = blkd->device_info;
	
	size_t to_read = count;

	uint64_t lba = offset / 512;
	uint8_t *buf = buffer;
	assert(offset % 512 == 0);
	assert(count % 512 == 0);

	while(count != 0)
	{
		size_t c = count > AHCI_BYTES_PER_REQ ?
			   AHCI_BYTES_PER_REQ : count;

		struct ahci_command_ata cmd;
		cmd.buffer = buf;
		cmd.lba = lba;
		cmd.size = c;
		cmd.write = true;
		cmd.cmd = ATA_CMD_WRITE_DMA_EXT;
	
		if(!ahci_do_command(p, &cmd))
		{
			return -1;
		}

		buf += c;
		count -= c;
		lba += c / 512;
	}

	return to_read;
}

bool ahci_command_error(struct ahci_port *port, unsigned int cmdslot)
{
	if(port->cmdslots[cmdslot].last_interrupt_status & AHCI_INTST_ERROR)
			return true;
	return false;
}

command_list_t *ahci_find_free_command_list(command_list_t *lists,
	unsigned int ncs, size_t *n)
{
	while(true)
	{
		for(unsigned int i = 0; i < ncs; i++)
		{
			if(lists[i].prdtl == 0)
			{
				/* Set a placeholder */
				lists[i].prdtl = 0xff;
				*n = i;
				return &lists[i];
			}
		}

		sched_yield();
	}
}

void ahci_issue_command(struct ahci_port *port, size_t slot)
{
	port->port->command_issue = (1 << slot);
}

command_list_t *ahci_allocate_command_list(struct ahci_port *ahci_port, size_t *index)
{
	command_list_t *clist = ahci_port->clist;

	spin_lock(&ahci_port->bitmap_spl);

	/* Erm, I give up. For now. wait_queues are broken, and there's nothing I can do.
	 * Maybe I'll do a clean rewrite or something. */
	wait_for_event_locked(&ahci_port->list_wq, ahci_port->list_bitmap != ~0U, &ahci_port->bitmap_spl);

	/*while(ahci_port->list_bitmap == ~0U)
	{
		spin_unlock(&ahci_port->bitmap_spl);
		sched_yield();
		spin_lock(&ahci_port->bitmap_spl);
	}*/
	
	unsigned int pos = __builtin_ctz(~ahci_port->list_bitmap);

	ahci_port->list_bitmap |= (1 << pos);

	spin_unlock(&ahci_port->bitmap_spl);

	clist = clist + pos;

	*index = (size_t) pos;

	return clist;
}

size_t ahci_setup_prdt(prdt_t *table, struct phys_ranges *ranges)
{
	assert(ranges->nr_ranges <= NUM_PRDT_PER_TABLE);

	for(size_t i = 0; i < ranges->nr_ranges; i++)
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

bool ahci_do_command_async(struct ahci_port *ahci_port,
	struct ahci_command_ata *buf,
	struct aio_req *ioreq)
{
	const uint16_t fis_len = 5;
	size_t list_index = 0;

	command_list_t *list = ahci_allocate_command_list(ahci_port, &list_index);

	list->desc_info = fis_len | (buf->write ? AHCI_COMMAND_LIST_WRITE : 0);
	list->prdbc = 0;

	struct phys_ranges ranges;
	
	vm_lock_range(buf->buffer, buf->size, VM_FUTURE_PAGES);

	if(dma_get_ranges(buf->buffer, buf->size, PRDT_MAX_SIZE, &ranges) < 0)
	{
		list->prdtl = 0;
		return false;
	}

	command_table_t *table = PHYS_TO_VIRT(ahci_port->ctables[list_index]);

	memset(table, 0, sizeof(command_table_t));

	prdt_t *prdt = (prdt_t *) (table + 1);

	size_t nr_prdt = ahci_setup_prdt(prdt, &ranges);

	dma_destroy_ranges(&ranges);

	list->prdtl = nr_prdt;

	table->cfis.fis_type = FIS_TYPE_REG_H2D;

	table->cfis.port_mult = 0;
	table->cfis.c = 1;
	table->cfis.feature_low = 1;

	/* Load the LBA */
	uint64_t lba = buf->lba;
	ahci_set_lba(lba, &table->cfis);

	/* We need to set bit 6 to enable the LBA mode */
	table->cfis.device = (1 << 6);

	size_t num_sectors = buf->size / 512;
	table->cfis.count = (uint16_t) num_sectors;
	table->cfis.command = buf->cmd;
	
	struct command_list *l = &ahci_port->cmdslots[list_index];

	l->req = ioreq;
	ioreq->cookie = (void *) list_index;

	spin_lock_irqsave(&ahci_port->port_lock);

	ahci_port->issued |= (1 << list_index);

	ahci_issue_command(ahci_port, list_index);

	spin_unlock_irqrestore(&ahci_port->port_lock);

	return true;
}

void ahci_wake_callback(void *cb, struct wait_queue_token *token)
{
	struct aio_req *req = cb;
	req->signaled = true;
}

bool ahci_do_command(struct ahci_port *ahci_port, struct ahci_command_ata *buf)
{
	struct aio_req req = {0};
	memset(&req, 0, sizeof(req));
	aio_req_init(&req);

	req.req_start = get_main_clock()->get_ns();
	struct wait_queue_token wait_token = {0};
	
	memset(&wait_token, 0, sizeof(wait_token));

	wait_token.thread = get_current_thread();
	wait_token.context = &req;
	wait_token.callback = NULL;

	wait_queue_add(&req.wake_sem, &wait_token);

	set_current_state(THREAD_UNINTERRUPTIBLE);

	if(!ahci_do_command_async(ahci_port, buf, &req))
	{
		return false;
	}


	while(!req.signaled)
	{
		//sched_yield();
		set_current_state(THREAD_UNINTERRUPTIBLE);
	}

	set_current_state(THREAD_RUNNABLE);


	while(!wait_queue_may_delete(&req.wake_sem)) {}

#if 0
	printk("Response time: %luns. Disk time: %luns\n", get_main_clock()->get_ns() - req.req_start,
		req.req_end - req.req_start);
#endif

	vm_unlock_range(buf->buffer, buf->size, VM_FUTURE_PAGES);

	if(req.status == AIO_STATUS_OK)
	{
		ahci_destroy_aio(ahci_port, &req);
		return true;
	}
	else
	{
		ahci_destroy_aio(ahci_port, &req);
		return false;
	}
}

int ahci_check_drive_type(ahci_port_t *port)
{
	uint32_t status = port->status;

	uint8_t ipm = (status >> 8) & 0x0F;
	uint8_t det = status & 0x0F;

	if(!det)
		return -1;
	if(!ipm)
		return -1;
	
	if(!port->sig)
		return -1;
	return port->sig;
}

void ahci_probe_ports(int n_ports, ahci_hba_memory_regs_t *hba)
{
	uint32_t ports_impl = hba->ports_implemented;
	for(int i = 0; i < 32; i++)
	{
		if(ports_impl & 1)
		{
			int type = 0;
			if((type = ahci_check_drive_type(&hba->ports[i])))
			{
				switch(type)
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
	switch(interface_speed)
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

int ahci_check_caps(ahci_hba_memory_regs_t *hba, struct pci_device *ahci_dev)
{
	MPRINTF("supported features: ");
	if(hba->host_cap & AHCI_CAP_SXS)
		printf("sxs ");
	if(hba->host_cap & AHCI_CAP_EMS)
		printf("ems ");
	if(hba->host_cap & AHCI_CAP_CCCS)
		printf("cccs ");
	if(hba->host_cap & AHCI_CAP_PSC)
		printf("psc ");
	if(hba->host_cap & AHCI_CAP_SSC)
		printf("ssc ");
	if(hba->host_cap & AHCI_CAP_PMD)
		printf("pmd ");
	if(hba->host_cap & AHCI_CAP_FBSS)
		printf("fbss ");
	if(hba->host_cap & AHCI_CAP_SPM)
		printf("spm ");
	if(hba->host_cap & AHCI_CAP_AHCI_ONLY)
		printf("ahci-only ");
	if(hba->host_cap & AHCI_CAP_SCLO)
		printf("sclo ");
	if(hba->host_cap & AHCI_CAP_ACTIVITY_LED)
		printf("activity_led ");
	if(hba->host_cap & AHCI_CAP_SALP)
		printf("salp ");
	if(hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
		printf("staggered_spinup ");
	if(hba->host_cap & AHCI_CAP_SPMS)
		printf("spms ");
	if(hba->host_cap & AHCI_CAP_SSNTF)
		printf("ssntf ");
	if(hba->host_cap & AHCI_CAP_SNCQ)
		printf("sncq ");
	if(hba->host_cap & AHCI_CAP_ADDR64)
		printf("64-bit addressing ");
	printf("\n");

	MPRINTF("version %s device at %x:%x:%x running at speed %s\n",
		ahci_stringify_version(ahci_get_version(hba)), ahci_dev->bus, 
		ahci_dev->device, ahci_dev->function, ahci_get_if_speed(hba));
	return 0;
}

uint32_t ahci_get_version(ahci_hba_memory_regs_t *hba)
{
	return hba->version;
}

char *ahci_stringify_version(uint32_t version)
{
	switch(version)
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
	if(port->pxcmd & AHCI_PORT_CMD_START)
		return false;
	if(port->pxcmd & AHCI_PORT_CMD_CR)
		return false;
	if(port->pxcmd & AHCI_PORT_CMD_FRE)
		return false;
	if(port->pxcmd & AHCI_PORT_CMD_FR)
		return false;
	return true;
}

int ahci_wait_bit(volatile uint32_t *reg, uint32_t mask, unsigned long timeout, bool clear)
{
	uint64_t last = get_tick_count();
	while(1)
	{
		/* If the time is up, return a timeout */
		if(last + timeout < get_tick_count())
			return errno = ETIMEDOUT, -1;
		if(clear)
		{
			if(!(*reg & mask))
				return 0;
		}
		else
		{
			if(*reg & mask)
				return 0;
		}

		sched_yield();
	}
	return -1;
}

void ahci_port_set_idle(ahci_port_t *port)
{
	/* To set the AHCI port to idle, clear the start bit */
	port->pxcmd &= ~AHCI_PORT_CMD_START;
	/* Wait for the bit to clear */
	if(ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_CR, 500, true) < 0)
	{
		MPRINTF("error: Timeout waiting for AHCI_PORT_CMD_CR\n");
		/* TODO: Handle this correctly */
		return;
	}

	if(port->pxcmd & AHCI_PORT_CMD_FRE)
	{
		/* Clear the FRE bit */
		port->pxcmd &= ~AHCI_PORT_CMD_FRE;
		if(ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_FR, 500, true) < 0)
		{
			MPRINTF("error: Timeout waiting for AHCI_PORT_CMD_FR\n");
			/* TODO: Handle this correctly */
			return;
		}
	}
}

int ahci_allocate_port_lists(ahci_hba_memory_regs_t *hba, ahci_port_t *port,
	struct ahci_port *_port)
{
	bool addr64_supported = hba->host_cap & AHCI_CAP_ADDR64;
	/* Allocates the command list and the FIS buffer for a port */
	void *fisb = NULL;
	void *virtual_fisb = NULL;
	/* The command list is 4k in size, with 4k in alignment */
	struct page *command_list_page = alloc_page(0);
	if(!command_list_page)
		goto error;
	void *command_list = page_to_phys(command_list_page);
	if(!command_list)
		goto error;

	/* The fisb is 1024 bytes in size, with 1024 alignment */
	if(posix_memalign(&fisb, 1024, 1024) != 0)
		goto error;

	/* We keep the virtual fisb in order to free it in case anything goes wrong */
	virtual_fisb = fisb;
	fisb = virtual2phys(fisb);

	if((uintptr_t) command_list & 0xFFFFFFFF00000000 && addr64_supported == false)
		goto error;

	if((uintptr_t) fisb & 0xFFFFFFFF00000000 && addr64_supported == false)
		goto error;

	_port->clist = mmiomap(command_list, PAGE_SIZE, VM_WRITE | VM_NOEXEC);
	if(!_port->clist)
		goto error;

	_port->fisb = virtual_fisb;

	/* Set FB and CB */
	port->command_list_base_low = (uintptr_t) command_list & 0xFFFFFFFF;
	port->command_list_base_hi = ((unsigned long) command_list) >> 32;
	port->fis_list_base_low = (uintptr_t) fisb & 0xFFFFFFFF;
	port->fis_list_base_hi = ((unsigned long) fisb) >> 32;
	
	return 0;
error:
	if(command_list_page)	free_page(command_list_page);
	if(fisb)		free(virtual_fisb);
	return -1;
}

bool ahci_port_has_device(ahci_port_t *port)
{
	uint32_t status = port->status;

	uint32_t det = AHCI_PORT_STATUS_DET(status);

	if(det != 0)
		return true;
	return false;
}

void ahci_enable_interrupts_for_port(ahci_port_t *port)
{
	port->pxie = AHCI_PORT_INTERRUPT_DHRE | AHCI_PORT_INTERRUPT_PSE |
		     AHCI_PORT_INTERRUPT_DSE;
}

static unsigned int woke = 0;
void ahci_free_list(struct ahci_port *port, size_t idx)
{
	command_list_t *list = port->clist + idx;

	list->prdbc = 0;

	port->cmdslots[idx].req = NULL;

	list->prdtl = 0;

	spin_lock(&port->bitmap_spl);

	bool needs_to_wake_up = port->list_bitmap == ~0U;

	port->list_bitmap &= ~(1 << idx);

	if(needs_to_wake_up)
	{
		wait_queue_wake(&port->list_wq);
		woke++;
	}

	spin_unlock(&port->bitmap_spl);
}

void ahci_destroy_aio(struct ahci_port *port, struct aio_req *req)
{
	ahci_free_list(port, (size_t) req->cookie);
}

int ahci_do_identify(struct ahci_port *port)
{
	switch(port->port->sig)
	{
		case SATA_SIG_ATA:
		{
			struct ahci_command_ata command = {0};
			command.size = 512;
			command.write = false;
			command.lba = 0;
			command.cmd = ATA_CMD_IDENTIFY;
			command.buffer = &port->identify;

			if(!ahci_do_command(port, &command))
			{
				printf("ATA_CMD_IDENTIFY failed!\n");
				perror("error");
				return -1;
			}

			break;
		}
		default:
			return -1;
	}
	return 0;
}

int ahci_configure_port_dma(struct ahci_port *port, unsigned int ncs)
{
	/* Allocate the pointer table */
	port->ctables = calloc(ncs, sizeof(void *));

	if(!port->ctables)
		return -1;

	/* Allocate ncs command tables and their respective PRDTs */

	/* The allocations are required to fit in a single page 
	 * The defaults are already very space efficient since you can fit
	 * 4 in a single page, without any waste
	*/
	const size_t allocation_size = sizeof(command_table_t) +
				       NUM_PRDT_PER_TABLE * sizeof(prdt_t);

	struct page *current_buf_page = NULL;
	uint8_t *buf = NULL;
	size_t nr_tables_per_page = PAGE_SIZE / allocation_size;
	/* Curr is the nr of allocations in the page
	 * It starts at nr_tables_per_page so it allocates a new one
	*/
	size_t curr = nr_tables_per_page;
	
	for(size_t i = 0; i < ncs; i++)
	{
		if(curr == nr_tables_per_page)
		{
			current_buf_page = alloc_page(0);
			if(!current_buf_page)
				return -1;
			
			buf = page_to_phys(current_buf_page);
			curr = 0;
		}

		port->ctables[i] = (command_table_t *) buf;
		port->clist[i].base_address_lo = (uint32_t) (uintptr_t) buf;
		if(port->dev->hba->host_cap & AHCI_CAP_ADDR64)
			port->clist[i].base_address_hi = ((uintptr_t) buf) >> 32;
		buf += allocation_size;
		curr++;
	}

	return 0;
}

void ahci_init_port(struct ahci_port *ahci_port)
{
	ahci_port_t *port = ahci_port->port;
	struct ahci_device *device = ahci_port->dev;
	ahci_hba_memory_regs_t *hba = device->hba;

	/* Enable interrupts */
	ahci_enable_interrupts_for_port(port);
	
	/* Power on and spin up the device (if needed) */
	if(port->pxcmd & AHCI_PORT_CMD_CPD)
		port->pxcmd |= AHCI_PORT_CMD_POWER_ON_DEV;
	if(device->hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
		port->pxcmd |= AHCI_PORT_CMD_SPIN_UP_DEV;

	port->pxcmd = (port->pxcmd & ~0xF0000000) | (1 << 28);
	port->interrupt_status = UINT32_MAX;
	port->error = UINT32_MAX;

	unsigned int ncs = AHCI_CAP_NCS(device->hba->host_cap);
	printf("ahci: AHCI controller supports %u command list slots\n", ncs);
	ahci_port->list_bitmap = -(1 << ncs);
	// wait queue debugging value: ~((1 << 1) - 1); true: -(1 << ncs)
	if(ahci_allocate_port_lists(hba, port, ahci_port) < 0)
	{
		MPRINTF("Failed to allocate the command and FIS lists for port %p\n", port);
		return;
	}

	if(ahci_configure_port_dma(ahci_port, ncs) < 0)
	{
		MPRINTF("Failed to configure command tables\n");
		return;
	}

	if(port->pxcmd & AHCI_PORT_CMD_CR)
	{
		if(ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_CR, 500, true) < 0)
		{
			MPRINTF("error: timeout waiting for PXCMD_CR to clear");
		}
	}

	init_wait_queue_head(&ahci_port->list_wq);

	/* Enable FIS receive */
	port->pxcmd |= AHCI_PORT_CMD_FRE;

	port->pxcmd |= AHCI_PORT_CMD_START;

	ahci_do_identify(ahci_port);
}

int ahci_initialize(struct ahci_device *device)
{
	ahci_hba_memory_regs_t *hba = device->hba;

	/* Firstly, set the AE bit on the GHC register to indicate we're AHCI aware */
	hba->ghc |= AHCI_GHC_AHCI_ENABLE;

	/* Now, enable interrupts in the HBA */
	hba->ghc |= AHCI_GHC_INTERRUPTS_ENABLE;

	int nr_ports = AHCI_CAP_NR_PORTS(hba->host_cap);
	if(nr_ports == 0)	nr_ports = 1;

	char device_letter = 'a';
	MPRINTF("Number of ports: %d\n", nr_ports);
	for(int i = 0; i < nr_ports; i++)
	{
		if(hba->ports_implemented & (1 << i))
		{
			/* If this port is implemented, check if it's idle. */
			if(!ahci_port_is_idle(&hba->ports[i]))
			{
				/* If not, put it in idle mode */
				ahci_port_set_idle(&hba->ports[i]);
				/* TODO: Handle a failure to idle correctly */
			}

			/* Do not create a device until we've checked the port has some device behind it */
			if(ahci_port_has_device(&hba->ports[i]) == false)
				continue;
			/* Create the device */
			char path[255];
			memset(path, 0, 255);
			strcpy(path, "/dev/sd");
			path[strlen(path)] = device_letter;
			char buf[255];
			memset(buf, 0, 255);
			strcpy(buf, "sd");
			buf[strlen(buf)] = device_letter++;

			/* Allocate a major-minor pair for a device */
			struct dev *min = dev_register(0, 0, strdup(buf));
			assert(min != NULL);			

			struct blockdev *dev = zalloc(sizeof(struct blockdev));
			assert(dev != NULL);

			dev->name = strdup(buf);
			assert(dev->name != NULL);

			dev->device_info = &device->ports[i];
			dev->dev = min;
			dev->read = ahci_read;
			dev->write = ahci_write;
			dev->sector_size = 512;

			MPRINTF("Created %s for port %d\n", path, i);
			device->ports[i].port_nr = i; 
			device->ports[i].port = &hba->ports[i];
			device->ports[i].dev = device;

			ahci_init_port(&device->ports[i]);

			blkdev_init(dev);
		}
	}

	return 0;
}

struct pci_id pci_ahci_devids[] = 
{
	{ PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 6, PCI_ANY_ID, NULL) },
	{ 0 }
};


int ahci_probe(struct device *dev)
{
	int status = 0;
	int irq = -1;
	struct pci_device *ahci_dev = (struct pci_device *) dev;

	if(pci_enable_device(ahci_dev) < 0)
		return -1;

	/* Get BAR5 of the device BARs */
	struct pci_bar bar;
	if(pci_get_bar(ahci_dev, 5, &bar) < 0)
		return -1;

	ahci_hba_memory_regs_t *hba = mmiomap((void *) bar.address, bar.size,
										  VM_WRITE | VM_NOCACHE | VM_NOEXEC);

	assert(hba != NULL);

	/* Allocate a struct ahci_device and fill it */
	struct ahci_device *device = zalloc(sizeof(struct ahci_device));
	if(!device)
		return -1;

	device->pci_dev = ahci_dev;
	device->hba = hba;

	pci_enable_device(ahci_dev);

	/* Enable PCI busmastering */
	pci_enable_busmastering(ahci_dev);
	
	if(ahci_check_caps(hba, ahci_dev) < 0)
	{
		status = -1;
		goto ret;
	}
	
	if(pci_enable_msi(ahci_dev, ahci_irq, device))
	{
		/* If we couldn't enable MSI, use normal I/O APIC pins */

		/* Get the interrupt number */
		irq = pci_get_intn(ahci_dev);
		printf("IRQ: %u\n", irq);
		/* and install a handler */
		assert(install_irq(irq, ahci_irq, (struct device *) ahci_dev,
			IRQ_FLAG_REGULAR, device) == 0);
	}
	/* Initialize AHCI */
	if(ahci_initialize(device) < 0)
	{
		MPRINTF("Failed to initialize the AHCI controller\n");
		status = -1;
		goto ret;
	}

	ahci_probe_ports(count_bits32(hba->ports_implemented), hba);
ret:
	if(status != 0)
	{
		free(device);
		free_irq(irq, (struct device *) ahci_dev);
		device = NULL;
	}

	return -1;
}
struct driver ahci_driver =
{
	.name = "ahci",
	.devids = &pci_ahci_devids,
	.probe = ahci_probe
};

static int ahci_init(void)
{
	MPRINTF("initializing!\n");

	pci_bus_register_driver(&ahci_driver);

	return 0;
}

int ahci_fini(void)
{
	MPRINTF("de-initializing!\n");
	return 0;
}

MODULE_INIT(ahci_init);
MODULE_FINI(ahci_fini);
