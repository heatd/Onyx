/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ahci.h>
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

#include <pci/pci.h>
#include <drivers/ata.h>

#define NUM_PRDT_PER_TABLE	64

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("ahci: "__VA_ARGS__)
#define ACCESS_PHYS(x) (PHYS_TO_VIRT((uintptr_t) x))

struct ahci_device *device = NULL;
static struct pci_device *ahci_dev = NULL;
static ahci_hba_memory_regs_t *hba = NULL;

irqstatus_t ahci_irq(struct irq_context *ctx, void *cookie)
{
	UNUSED(ctx);
	UNUSED(cookie);

	uint32_t ports = device->hba->interrupt_status;
	if(!ports)
		return IRQ_UNHANDLED;
	for(int i = 0; i < 32; i++)
	{
		if(ports & (1L << i))
		{
			uint32_t port_is = device->ports[i].port->interrupt_status;
			/* Check if we have any pending interrupts, continue otherwise */
			if(!port_is)
				continue;
			uint32_t current_list = (device->ports[i].port->pxcmd >> 8) & 0xF;
			device->ports[i].port->interrupt_status = UINT32_MAX;
			device->ports[i].cmdslots[current_list].recieved_interrupt = true;
			device->ports[i].cmdslots[current_list].last_interrupt_status = port_is;
		}
	}

	return IRQ_HANDLED;
}

ssize_t ahci_read(size_t offset, size_t count, void* buffer, struct blkdev* blkd)
{
	return -1;
}

ssize_t ahci_write(size_t offset, size_t count, void* buffer, struct blkdev* blkd)
{
	return -1;
}

int ahci_await_interrupt(unsigned long timeout, struct ahci_port *port, unsigned int command_slot)
{
	uint64_t ticks = get_tick_count();
	while(ticks + timeout > get_tick_count())
	{
		if(port->cmdslots[command_slot].recieved_interrupt)
		{
			port->cmdslots[command_slot].recieved_interrupt = false;
			return 0;
		}
		sched_yield();
	}
	return -1;
}
bool ahci_command_error(struct ahci_port *port, unsigned int cmdslot)
{
	printk("Port Status: %x\n", port->cmdslots[cmdslot].last_interrupt_status);
	if(port->cmdslots[cmdslot].last_interrupt_status & AHCI_INTST_ERROR)
			return true;
	return false;
}
command_list_t *ahci_find_free_command_list(command_list_t *lists, unsigned int ncs, size_t *n)
{
	while(1)
	{
		for(unsigned int i = 0; i < ncs; i++)
		{
			if(lists[i].prdtl == 0)
			{
				*n = i;
				return &lists[i];
			}
		}
		sched_yield();
	}
}
bool ahci_command_dma_ata(struct ahci_port *ahci_port, struct ahci_command_ata *buf)
{
	ahci_port_t *port = ahci_port->port;
	uint16_t fis_len = 5;
	command_list_t *clist = ACCESS_PHYS((uintptr_t) ((uintptr_t) port->command_list_base_hi << 32 
				| port->command_list_base_low));

	/* Allocate a command list */
	spin_lock(&ahci_port->port_lock);
	size_t num;
	command_list_t *list = ahci_find_free_command_list(clist, AHCI_CAP_NCS(device->hba->host_cap), &num);
	list->desc_info = fis_len | (buf->write ? AHCI_COMMAND_LIST_WRITE : 0);
	list->prdtl = 1;
	list->prdbc = 0;
	void *phys_buffer = virtual2phys(buf->buffer);

	prdt_t *prdt = ACCESS_PHYS((uintptr_t) ahci_port->prdt);

	prdt[0].address = (uintptr_t) phys_buffer;
	prdt[0].dw3 = (buf->size - 1);

	command_table_t *table = ACCESS_PHYS((uintptr_t) ((uintptr_t) list->base_address_hi << 32 
				| list->base_address_lo));

	table->cfis.fis_type = FIS_TYPE_REG_H2D;
	table->cfis.port_mult = 0;
	table->cfis.c = 1;

	/* Load the LBA */
	uint64_t lba = buf->lba;
	table->cfis.lba0 = lba & 0xFF;
	table->cfis.lba1 = (lba >> 8) & 0xFF;
	table->cfis.lba2 = (lba >> 16) & 0xFF;
	table->cfis.lba3 = (lba >> 24) & 0xFF;
	table->cfis.lba4 = (lba >> 32) & 0xFF;
	table->cfis.lba5 = (lba >> 40) & 0xFF;
	table->cfis.device = 0x40;

	size_t num_sectors = buf->size / 512;
	table->cfis.count = (uint16_t) num_sectors;
	table->cfis.command = buf->cmd;
	
	spin_unlock(&ahci_port->port_lock);

	port->command_issue = (1 << num);
	bool status = true;
	if(ahci_await_interrupt(1000, ahci_port, num) < 0)
	{
		errno = ETIMEDOUT;
		status = false;
		goto ret;
	}
	if(ahci_command_error(ahci_port, num))
	{
		status = false;
		goto ret;
	}
ret:
	prdt[0].address = 0;
	prdt[0].dw3 = 0;
	list->prdtl = 0;
	return status;
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
void ahci_probe_ports(int n_ports)
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
int ahci_check_caps(ahci_hba_memory_regs_t *hba)
{
	MPRINTF("supported features: ");
	if(hba->host_cap & AHCI_CAP_SXS)
		printk("sxs ");
	if(hba->host_cap & AHCI_CAP_EMS)
		printk("ems ");
	if(hba->host_cap & AHCI_CAP_CCCS)
		printk("cccs ");
	if(hba->host_cap & AHCI_CAP_PSC)
		printk("psc ");
	if(hba->host_cap & AHCI_CAP_SSC)
		printk("ssc ");
	if(hba->host_cap & AHCI_CAP_PMD)
		printk("pmd ");
	if(hba->host_cap & AHCI_CAP_FBSS)
		printk("fbss ");
	if(hba->host_cap & AHCI_CAP_SPM)
		printk("spm ");
	if(hba->host_cap & AHCI_CAP_AHCI_ONLY)
		printk("ahci-only ");
	if(hba->host_cap & AHCI_CAP_SCLO)
		printk("sclo ");
	if(hba->host_cap & AHCI_CAP_ACTIVITY_LED)
		printk("activity_led ");
	if(hba->host_cap & AHCI_CAP_SALP)
		printk("salp ");
	if(hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
		printk("staggered_spinup ");
	if(hba->host_cap & AHCI_CAP_SPMS)
		printk("spms ");
	if(hba->host_cap & AHCI_CAP_SSNTF)
		printk("ssntf ");
	if(hba->host_cap & AHCI_CAP_SNCQ)
		printk("sncq ");
	if(hba->host_cap & AHCI_CAP_ADDR64)
		printk("64-bit addressing ");
	printk("\n");

	MPRINTF("version %s device at %x:%x:%x running at speed %s\n", ahci_stringify_version(ahci_get_version(hba)), ahci_dev->bus, 
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
_Bool ahci_port_is_idle(ahci_port_t *port)
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
int ahci_wait_bit(volatile uint32_t *reg, uint32_t mask, unsigned long timeout, _Bool clear)
{
	uint64_t last = get_tick_count();
	while(1)
	{
		/* If the time is up, return a timeout */
		if(last + timeout <= get_tick_count())
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
int ahci_allocate_port_lists(ahci_hba_memory_regs_t *hba, ahci_port_t *port)
{
	_Bool addr64_supported = hba->host_cap & AHCI_CAP_ADDR64;
	/* Allocates the command list and the FIS buffer for a port */
	void *fisb = NULL;
	void *virtual_fisb = NULL;
	/* The command list is 4k in size, with 4k in alignment */
	struct page *command_list_page = alloc_page(0);
	if(!command_list_page)
		goto error;
	void *command_list = command_list_page->paddr;
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
	
	/* Set FB and CB */
	port->command_list_base_low = (uintptr_t) command_list & 0xFFFFFFFF;
	port->command_list_base_hi = (uintptr_t) command_list & 0xFFFFFFFF00000000;
	port->fis_list_base_low = (uintptr_t) fisb & 0xFFFFFFFF;
	port->fis_list_base_hi = (uintptr_t) fisb & 0xFFFFFFFF00000000;
	return 0;
error:
	if(command_list_page)	free_page(command_list_page);
	if(fisb)		free(virtual_fisb);
	return -1;
}
_Bool ahci_port_has_device(ahci_port_t *port)
{
	uint32_t status = port->status;

	uint32_t det = AHCI_PORT_STATUS_DET(status);

	if(det != 0)
		return true;
	return false;
}
void ahci_enable_interrupts_for_port(ahci_port_t *port)
{
	port->pxie = AHCI_PORT_INTERRUPT_DHRE | AHCI_PORT_INTERRUPT_PSE | AHCI_PORT_INTERRUPT_DSE;
}
int ahci_do_identify(struct ahci_port *port)
{
	switch(port->port->sig)
	{
		case SATA_SIG_ATA:
		{
			return 0;
			struct ahci_command_ata command = {0};
			command.size = 512;
			command.write = false;
			command.lba = 0;	
			command.cmd = ATA_CMD_IDENTIFY;
			command.buffer = &port->identify; 
			if(!ahci_command_dma_ata(port, &command))
			{
				printk("ATA_CMD_IDENTIFY failed!\n");
				return -1;
			}
			break;
		}
		default:
			return -1;
	}
	return 0;
}
void ahci_init_port(struct ahci_port *ahci_port)
{
	ahci_port_t *port = ahci_port->port;
	/* Enable interrupts */
	ahci_enable_interrupts_for_port(port);
	
	/* Power on and spin up the device (if needed) */
	if(port->pxcmd & AHCI_PORT_CMD_CPD)
		port->pxcmd |= AHCI_PORT_CMD_POWER_ON_DEV;
	if(device->hba->host_cap & AHCI_CAP_STAGGERED_SPINUP)
		port->pxcmd |= AHCI_PORT_CMD_SPIN_UP_DEV;

	port->pxcmd = (port->pxcmd & ~0xF0000000) | (1 << 28);
	port->interrupt_status = port->interrupt_status;
	port->error = port->error;

	unsigned int ncs = AHCI_CAP_NCS(device->hba->host_cap);
	printk("ahci: AHCI controller supports %u command list slots\n", ncs);
	ahci_port->ctable = zalloc(sizeof(command_list_t) * ncs + NUM_PRDT_PER_TABLE * sizeof(prdt_t));
	assert(ahci_port->ctable != NULL);
	ahci_port->ctable = virtual2phys(ahci_port->ctable);
	ahci_port->prdt = (void*)(ahci_port->ctable + ncs);

	if(ahci_allocate_port_lists(hba, port) < 0)
	{
		MPRINTF("Failed to allocate the command and FIS lists for port %p\n", port);
		return;
	}
	command_list_t *clist = ACCESS_PHYS((uintptr_t) ((uintptr_t) port->command_list_base_hi << 32 
				| port->command_list_base_low));
	for(size_t i = 0; i < ncs; clist++, i++)
	{
		uintptr_t addr = (uintptr_t) (ahci_port->ctable + i);
		clist->base_address_lo = addr & 0xffffffff;
		if(device->hba->host_cap & AHCI_CAP_ADDR64)
			clist->base_address_hi = addr >> 32;
	}
	/* Enable FIS receive */
	port->pxcmd |= AHCI_PORT_CMD_FRE;
	if (port->pxcmd & AHCI_PORT_CMD_CR)
	{
		if (ahci_wait_bit(&port->pxcmd, AHCI_PORT_CMD_CR, 500, true) < 0)
		{
			MPRINTF("error: timeout waiting for PXCMD_CR to clear");
		}
	}
	port->pxcmd |= AHCI_PORT_CMD_START;

	ahci_do_identify(ahci_port);
}
int ahci_initialize(void)
{
	ahci_hba_memory_regs_t *hba = device->hba;

	/* Firstly, set the AE bit on the GHC register to indicate we're AHCI aware */
	hba->ghc |= AHCI_GHC_AHCI_ENABLE;

	/* Now, enable interrupts in the HBA */
	hba->ghc |= AHCI_GHC_INTERRUPTS_ENABLE;

	int nr_ports = AHCI_CAP_NR_PORTS(hba->host_cap);
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
			if(!min)
			{
				/* Again, should we be doing this? */
				continue;
			}
			
			device_show(min, DEVICE_NO_PATH);

			block_device_t *dev = malloc(sizeof(block_device_t));
			if(!dev)
				continue;
			memset(dev, 0, sizeof(block_device_t));
			dev->device_info = &device->ports[i];
			dev->dev = min->majorminor;
			dev->node_path = strdup(buf);
			dev->read = ahci_read;
			dev->write = ahci_write;

			blkdev_add_device(dev);
			MPRINTF("Created %s for port %d\n", path, i);
			device->ports[i].port_nr = i; 
			device->ports[i].port = &hba->ports[i];
			ahci_init_port(&device->ports[i]);
		}
	}
	return 0;
}

struct pci_id pci_ahci_devids[] = 
{
	{ PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 6, PCI_ANY_ID) },
	{ 0 }
};

struct driver ahci_driver =
{
	.name = "ahci",
	.devids = &pci_ahci_devids
};

int module_init()
{
	int status = 0;
	int irq = -1;
	MPRINTF("initializing!\n");

	/* Get the PCI device */
	ahci_dev = get_pcidev_from_classes(CLASS_MASS_STORAGE_CONTROLLER, 6, 0);
	if(!ahci_dev)
		ahci_dev = get_pcidev_from_classes(CLASS_MASS_STORAGE_CONTROLLER, 6, 1);
	if(!ahci_dev)
	{
		MPRINTF("could not find a valid SATA device!\n");
		return 1;
	}

	if(pci_enable_device(ahci_dev) < 0)
		return -1;
	driver_register_device(&ahci_driver, (struct device *) ahci_dev);

	/* Get BAR5 of the device BARs */
	struct pci_bar bar;
	if(pci_get_bar(ahci_dev, 5, &bar) < 0)
		return -1;

	/* TODO: Map the MMIO range instead of using PHYS_BASE */
	hba = (ahci_hba_memory_regs_t*)(bar.address + PHYS_BASE);

	/* Allocate a struct ahci_device and fill it */
	device = malloc(sizeof(struct ahci_device));
	if(!device)
	{
		return -1;
	}
	memset(device, 0, sizeof(struct ahci_device));
	device->pci_dev = ahci_dev;
	device->hba = hba;

	/* Enable PCI busmastering */
	pci_enable_busmastering(ahci_dev);
	
	if(ahci_check_caps(hba) < 0)
	{
		status = -1;
		goto ret;
	}
	
	if(1)
	{
		/* If we couldn't enable MSI, use normal I/O APIC pins */

		/* Get the interrupt number */
		irq = pci_get_intn(ahci_dev);
		printk("IRQ: %u\n", irq);
		/* and install a handler */
		/*assert(install_irq(irq, ahci_irq, (struct device *) ahci_dev,
			IRQ_FLAG_REGULAR, NULL) == 0);*/
	}
	/* Initialize AHCI */
	if(ahci_initialize() < 0)
	{
		MPRINTF("Failed to initialize the AHCI controller\n");
		status = -1;
		goto ret;
	}
	ahci_probe_ports(count_bits32(hba->ports_implemented));
ret:
	if(status != 0)
	{
		free(device);
		free_irq(irq, (struct device *) ahci_dev);
		device = 0;
	}
	return status;
}
int module_fini()
{
	MPRINTF("de-initializing!\n");
	return 0;
}
