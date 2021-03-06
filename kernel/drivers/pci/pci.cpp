/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/log.h>
#include <onyx/acpi.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/init.h>

#include <pci/pci.h>

int pci_shutdown(struct device *__dev);
static struct bus pci_bus = 
{
	.name = "pci",
	.device_list_head = LIST_HEAD_INIT(pci_bus.device_list_head),
	.shutdown = pci_shutdown,
};

void __pci_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size);
uint64_t __pci_read(struct pci_device *dev, uint16_t off, size_t size);
const uint16_t CONFIG_ADDRESS = 0xCF8;
const uint16_t CONFIG_DATA = 0xCFC;
static struct spinlock pci_lock;

__attribute__((no_sanitize_undefined))
uint16_t __pci_config_read_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
        union { uint8_t bytes[4]; uint32_t val;} data;
	data.val = __pci_config_read_dword(bus, slot, func, offset);
	return data.bytes[(offset & 0x3)] | (data.bytes[(offset & 3) + 1] << 8);
}

uint32_t __pci_config_read_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;
	uint32_t tmp = 0;

	address = (uint32_t)((lbus << 16) | (lslot << 11) |
                     (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));
	spin_lock(&pci_lock);
	/* write out the address */
	outl(CONFIG_ADDRESS, address);
	/* read in the data */
	tmp = inl(CONFIG_DATA);
	spin_unlock(&pci_lock);
	return tmp;
}

void __pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t) 0x80000000));
	
	spin_lock(&pci_lock);
	/* write out the address */
	outl(CONFIG_ADDRESS, address);
	/* read in the data */
	outl(CONFIG_DATA, data);
	spin_unlock(&pci_lock);
}

void __pci_write_word_aligned(uint8_t bus, uint8_t slot, uint8_t func,
			      uint8_t offset, uint16_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t) 0x80000000));
	
	spin_lock(&pci_lock);
	/* write out the address */
	outl(CONFIG_ADDRESS, address);
	/* read in the data */
	outw(CONFIG_DATA, data);
	spin_unlock(&pci_lock);
}

void __pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data)
{
	uint8_t aligned_offset = offset & -4;

	if(aligned_offset == offset)
	{
		/* NOTE: Check pcie.c's __pcie_config_write_word
		 * commentary on why this is needed
		*/
		__pci_write_word_aligned(bus, slot, func, offset, data);
		return;
	}

	uint8_t bshift = offset - aligned_offset;
	uint32_t byte_mask = 0xffff << (bshift * 8);
	uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);
	dword = (dword & ~byte_mask) | (data << (bshift * 8));
	__pci_write_dword(bus, slot, func, aligned_offset, dword);
}

int pci_set_power_state(struct pci_device *dev, int power_state)
{
	struct pci_device *element = NULL;
	void *saveptr = NULL; /* Used by extrusive_list_get_element in a strtok_r kind of way */
	/* If we can't perform power management on this device, just return 
	 * success(it wasn't really an error was it?) 
	*/
	if(dev->has_power_management == false)
		return -ENOSYS;
	/* I guess we're already there, so just return */
	if(dev->current_power_state == power_state)
		return 0;
	
	/* TODO: It's unsafe to cut power to the PCI bridge just like that, so we ignore setting it */
	if(dev->type == PCI_TYPE_BRIDGE)
		return 0;
	
	/* Check if the desired power state is supported */
	if(dev->supported_power_states & power_state)
		return -EINVAL;	/* If not, just return */

	/* Set its children's power state as well */
	while((element = (pci_device *) extrusive_list_get_element(&dev->dev.children, &saveptr)))
	{
		pci_set_power_state(element, power_state);
	}
	/* Ok, if we can perform power management, get the PMCSR offset */
	uint16_t pmcsr_off = dev->pm_cap_off + 4;

	uint16_t pmcsr = pci_read(dev, pmcsr_off, sizeof(uint16_t));

	/* Translate the argument into the actual bits */
	int p;
	switch(power_state)
	{
		case PCI_POWER_STATE_D0:
			p = 0;
			break;
		case PCI_POWER_STATE_D1:
			p = 1;
			break;
		case PCI_POWER_STATE_D2:
			p = 2;
			break;
		case PCI_POWER_STATE_D3:
			p = 3;
			break;
		default:
			panic("pci: Invalid target power state\n");
	}
	/* And set them in PMCSR, writing them back */
	pmcsr |= p;
	pci_write(dev, p, pmcsr_off, sizeof(uint16_t));
	return 0;
}

int pci_shutdown(struct device *__dev)
{
	/* Okay, we're shutting down and our purpose here is to cut power to the device.
	 * Hopefully the device driver has already been notified that we're shutting down, so
	 * we're safe to cut power to the device by setting the power state to D3
	*/
	assert(__dev);
	return pci_set_power_state((struct pci_device*) __dev, PCI_POWER_STATE_D3);
}

void pci_find_supported_capabilities(struct pci_device *dev)
{
	size_t pm_off = pci_find_capability(dev, PCI_CAP_ID_POWER_MANAGEMENT_INTERFACE, 0);
	if(pm_off == 0)
	{
		/* We found the PM Register block! Great, now we'll cache the offset and the
		 * fact that the capability exists
		*/
		dev->has_power_management = true;
		dev->pm_cap_off = (uint8_t) pm_off;
		/* Now, grab the PMC and cache the available power states 
		 * The PMC is at pm_off + 2, and is 16 bits in size
		*/
		uint16_t pmc = pci_read(dev, pm_off + 2, sizeof(uint16_t));
		/* D0 and D3 are always supported */
		dev->supported_power_states = PCI_POWER_STATE_D0 | PCI_POWER_STATE_D3;
		if(pmc & PCI_PMC_D1_SUPPORT)
			dev->supported_power_states |= PCI_POWER_STATE_D1;
		if(pmc & PCI_PMC_D2_SUPPORT)
			dev->supported_power_states |= PCI_POWER_STATE_D2;
	}
}

struct pci_device *linked_list = NULL;
struct pci_device* last = NULL;

void pci_enumerate_device(uint16_t bus, uint8_t device, uint8_t function, struct pci_device *parent)
{
	// Get vendor
	uint16_t vendor = (uint16_t)(__pci_config_read_dword(bus, device, function,
					PCI_REGISTER_VENDOR_ID) & 0x0000ffff);

	if(vendor == 0xFFFF) /* Invalid, just skip this device */
		return;

	uint16_t header = (uint16_t) __pci_config_read_word(bus, device, function, PCI_REGISTER_HEADER);

	uint32_t word = __pci_config_read_dword(bus, device, function, 0x08);
	uint8_t progIF = (word >> 8) & 0xFF;
	uint8_t subClass = (word >> 16) & 0xFF;
	uint8_t pciClass = (word >> 24) & 0xFF;

	// Set up some meta-data
	struct pci_device* dev = (pci_device *) zalloc(sizeof(struct pci_device));
	if(!dev)
		panic("pci: early unrecoverable oom\n");

	dev->bus = bus;
	dev->function = function;
	dev->device = device;
	dev->vendorID = vendor;
	dev->deviceID = __pci_config_read_dword(bus, device, function, 0) >> 16;
	dev->pciClass = pciClass;
	dev->subClass = subClass;
	dev->progIF = progIF;
	dev->current_power_state = PCI_POWER_STATE_D0;
	dev->read = __pci_read;
	dev->write = __pci_write;
	dev->type = header & PCI_TYPE_MASK;
	/* Find supported caps and add them to dev */
	pci_find_supported_capabilities(dev);
	/* Set up the pci device's name */
	char name_buf[200] = {};
	snprintf(name_buf, 200, "%02x.%02x.%02x", dev->bus, dev->device, dev->function);
	dev->dev.name = strdup(name_buf);
	assert(dev->dev.name);

	assert(device_init(&dev->dev) == 0);

	bus_add_device(&pci_bus, (struct device*) dev);

	if(likely(last))
		last->next = dev;
	else
		linked_list = dev;
	if(parent)
	{
		dev->dev.parent = (struct device*) parent;
		/* Failing to enumerate PCI devices is pretty much a failure anyway */
		assert(extrusive_list_add(&dev->dev.children, dev) == 0);		
	}

	last = dev;
	/* It's pointless to enumerate subfunctions since functions can't have them */
	/* TODO: Running qemu with -machine q35 returned 0x80 on pci headers with functions != 0
	   Is this a qemu bug or is it our fault?
	*/
	if(function != 0)
		return;
	if(header & 0x80)
	{
		for(int i = 1; i < 8; i++)
		{
			if(__pci_config_read_word(bus, device, i, 0) == 0xFFFF)
				continue;
			pci_enumerate_device(bus, device, i, dev);
		}
	}
}

void pci_enumerate_devices(void)
{
	for(uint16_t slot = 0; slot < 256; slot++)
	{
		for(uint16_t device = 0; device < 32; device++)
		{
			pci_enumerate_device(slot, device, 0, NULL);	
		}
	}
}

#define PCI_MAX_BAR		5
#define PCI_BAR_GET_TYPE(x)	((x >> 1) & 0x3)
#define PCI_BAR_TYPE_32		0
#define PCI_BAR_TYPE_64		0x2

#define PCI_BAR_IO_RANGE	(1 << 0)
#define PCI_BAR_PREFETCHABLE	(1 << 3)

int pci_get_bar(struct pci_device *dev, int index, struct pci_bar *bar)
{
	assert(index <= PCI_MAX_BAR);

	uint16_t offset = PCI_BARx(index);

	uint32_t word = (uint32_t) pci_read(dev, offset, sizeof(word));
	uint32_t upper_half = 0;

	bar->is_iorange = word & PCI_BAR_IO_RANGE;
	bar->may_prefetch = word & PCI_BAR_PREFETCHABLE;
	
	bool is_64 = PCI_BAR_GET_TYPE(word) == PCI_BAR_TYPE_64;

	if(is_64)
	{
		upper_half = pci_read(dev, PCI_BARx((index + 1)), sizeof(uint32_t));
	}

	uint32_t mask = 0xfffffff0;
	if(bar->is_iorange)
	{
		mask = 0xfffffffc;
	}

	bar->address = word & mask;
	bar->address |= ((uint64_t) upper_half << 32);

	/* Get the size */
	pci_write(dev, 0xffffffff, offset, sizeof(uint32_t));

	uint32_t size = (~((pci_read(dev, offset, sizeof(uint32_t)) & 0xfffffff0))) + 1;
	bar->size = size;

	pci_write(dev, word, offset, sizeof(uint32_t));

	return 0;
}

void *pci_map_bar(struct pci_device *device, int index, unsigned int caching)
{
	struct pci_bar bar;

	if(pci_get_bar(device, index, &bar) < 0)
		return NULL;
	
	if(bar.is_iorange)
	{
		printf("pci: warning: trying to map io range\n");
		return NULL;
	}

#if 0
	printf("Mapping bar%d %lx %lx\n", index, bar.address, bar.size);
#endif

	return mmiomap((void *) bar.address, bar.size, VM_WRITE | VM_NOEXEC
		| caching);
}

uint16_t pci_get_intn(struct pci_device *dev)
{
	uint8_t pin = pci_read(dev, 0x3C, sizeof(uint16_t)) >> 8;
	if(pin == 0xff)
		return UINT16_MAX;

	/* Make the pin a 0-based int so it fits nicely with the array */
	pin--;

	uint16_t intn = dev->pin_to_gsi[pin].gsi;
	ioapic_set_pin(dev->pin_to_gsi[pin].active_high,
		       dev->pin_to_gsi[pin].level, intn);

	return intn;
}

struct bus b =
{
	.name = "test",
	.device_list_head = LIST_HEAD_INIT(b.device_list_head)
};

void pci_init(void)
{
	pcie_get_mcfg();
	if(pcie_is_enabled())
	{
		pcie_init();
	}
	else
	{
		assert(bus_init(&pci_bus) == 0);
		bus_init(&b);
		bus_register(&b);
		/* Check every pci device and add it onto the bus */
		pci_enumerate_devices();
		/* Register the PCI bus */
		bus_register(&pci_bus);
		assert(acpi_get_irq_routing_info(&pci_bus) == 0);
	}
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pci_init);

void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index,
	uint32_t address, uint8_t is_io, uint8_t is_prefetch)
{
	uint32_t bar = address | is_io | (is_prefetch << 2);
	__pci_write_dword(slot, device, function, PCI_BARx(index), bar);
}

extern struct bus pcie_bus;

struct pci_device *pci_get_dev(struct pci_device_address *addr)
{
	struct list_head *dev_list = pcie_is_enabled() ? &pcie_bus.device_list_head : &pci_bus.device_list_head;
	list_for_every(dev_list)
	{

		struct device *__pci = container_of(l, struct device, device_list_node);
		struct pci_device *pci = (struct pci_device *) __pci;
		if(pci->segment == addr->segment && pci->bus == addr->bus && pci->device == 
		   addr->device && pci->function == addr->function)
			return pci;
	}

	return NULL;
}

void __pci_write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t data)
{
	uint8_t aligned_offset = offset & -4;
	uint8_t byte_shift = offset - aligned_offset;
	uint32_t byte_mask = 0xff << (byte_shift * 8);
	uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);
	dword = (dword & ~byte_mask) | (data << (byte_shift * 8));
	__pci_write_dword(bus, slot, func, aligned_offset, dword);
}

uint8_t __pci_read_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
	uint8_t aligned_offset = offset & -4;
	uint8_t byte_shift = offset - aligned_offset;
	uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);
	
	return ((dword >> (byte_shift * 8)) & 0xff);
}

void __pci_write_qword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint64_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));
	
	spin_lock(&pci_lock);
	/* write out the address */
	outl(CONFIG_ADDRESS, address);
	/* Write out the lower half of the data */
	outl(CONFIG_DATA, data & 0xFFFFFFFF);
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | ((offset+4) & 0xfc) | ((uint32_t) 0x80000000));

	/* write out the address */
	outl(CONFIG_ADDRESS, address);
	outl(CONFIG_DATA, data & 0xFFFFFFFF00000000);
	spin_unlock(&pci_lock);
}

void __pci_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size)
{
	if(size == sizeof(uint8_t))
		__pci_write_byte(dev->bus, dev->device, dev->function, off, (uint8_t) value);
	if(size == sizeof(uint16_t))
		__pci_write_word(dev->bus, dev->device, dev->function, off, (uint16_t) value);
	if(size == sizeof(uint32_t))
		__pci_write_dword(dev->bus, dev->device, dev->function, off, (uint32_t) value);
	if(size == sizeof(uint64_t))
		__pci_write_qword(dev->bus, dev->device, dev->function, off, value);
}

void pci_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size)
{
	dev->write(dev, value, off, size);
}

uint64_t __pci_read(struct pci_device *dev, uint16_t off, size_t size)
{
	uint64_t val = 0;
	switch(size)
	{
		case sizeof(uint16_t):
			val = __pci_config_read_word(dev->bus, dev->device, dev->function, off);
			break;
		case sizeof(uint32_t):
			val = __pci_config_read_dword(dev->bus, dev->device, dev->function, off);
			break;
		case sizeof(uint64_t):
			val = __pci_config_read_dword(dev->bus, dev->device, dev->function, off);
			break;
		default:
			val = __pci_read_byte(dev->bus, dev->device, dev->function, off);
			break;
	}
	return val;
}

uint64_t pci_read(struct pci_device *dev, uint16_t off, size_t size)
{
	return dev->read(dev, off, size);
}

void pci_enable_busmastering(struct pci_device *dev)
{
	uint32_t command_register = (uint32_t) pci_read(dev, PCI_REGISTER_COMMAND, sizeof(uint32_t));
	pci_write(dev, command_register | PCI_COMMAND_BUS_MASTER, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

uint16_t pci_get_status(struct pci_device *dev)
{
	return (uint16_t) pci_read(dev, PCI_REGISTER_STATUS, sizeof(uint16_t));
}

size_t pci_find_capability(struct pci_device *dev, uint8_t cap, int instance)
{
	uint16_t status = pci_get_status(dev);
	if(!(status & PCI_STATUS_CAP_LIST_SUPPORTED))
		return 0;
	
	uint8_t offset = (uint8_t) pci_read(dev, PCI_REGISTER_CAPABILTIES_POINTER, sizeof(uint8_t)) & ~3;

	while(offset)
	{
		uint16_t _cap = pci_read(dev, offset, sizeof(uint16_t));

		if((_cap & 0xFF) == cap && instance-- == 0)
			return offset;

		offset = ((uint8_t) (_cap >> 8)) & ~3;
	}

	return 0;
}

extern struct bus pcie_bus;

void pci_disable_busmastering(struct pci_device *dev)
{
	uint32_t command_register = (uint32_t) pci_read(dev, PCI_REGISTER_COMMAND, sizeof(uint32_t));
	pci_write(dev, command_register & ~PCI_COMMAND_BUS_MASTER, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

void pci_disable_irq(struct pci_device *dev)
{
	uint32_t command_register = (uint32_t) pci_read(dev, PCI_REGISTER_COMMAND, sizeof(uint32_t));
	pci_write(dev, command_register | PCI_COMMAND_INTR_DISABLE, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

void pci_enable_irq(struct pci_device *dev)
{
	uint32_t command_register = (uint32_t) pci_read(dev, PCI_REGISTER_COMMAND, sizeof(uint32_t));
	pci_write(dev, command_register & ~PCI_COMMAND_INTR_DISABLE, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

struct pci_id *pci_driver_supports_device(struct driver *driver, struct device *device)
{
	struct pci_id *dev_table = (pci_id *) driver->devids;

	struct pci_device *dev = (struct pci_device *) device;

	for(; dev_table->vendor_id != 0; dev_table++)
	{
		if(dev_table->vendor_id != PCI_ANY_ID)
		{
			if(dev_table->vendor_id != dev->vendorID)
				continue;
		}

		if(dev_table->device_id != PCI_ANY_ID)
		{
			if(dev_table->device_id != dev->deviceID)
				continue;
		}

		if(dev_table->pci_class != PCI_ANY_ID)
		{
			if(dev_table->pci_class != dev->pciClass)
				continue;
		}

		if(dev_table->subclass != PCI_ANY_ID)
		{
			if(dev_table->subclass != dev->subClass)
				continue;
		}

		if(dev_table->progif != PCI_ANY_ID)
		{
			if(dev_table->progif != dev->progIF)
				continue;
		}

		return dev_table;
	}

	return NULL;
}

void __pci_bus_register(struct driver *driver, struct bus *bus)
{
	list_for_every(&bus->device_list_head)
	{
		struct device *dev = container_of(l, struct device, device_list_node);
		struct pci_id *id;
		struct pci_device *d = (struct pci_device *) dev;
#if 0
		printk("%04x:%02x:%02x:%02x -> %04x:%04x\n",
			d->segment, d->bus, d->device, d->function,
			d->deviceID, d->vendorID);
#endif

		if((id = pci_driver_supports_device(driver, dev)))
		{
			d->driver_data = id->driver_data;
			driver_register_device(driver, dev);
			if(driver->probe(dev) < 0)
				driver_deregister_device(driver, dev);
		}
	}
}

void pci_bus_register_driver(struct driver *driver)
{
	spin_lock(&pci_bus.bus_lock);

	if(!pci_bus.registered_drivers)
	{
		pci_bus.registered_drivers = driver;
	}
	else
	{
		struct driver *d;
		for(d = pci_bus.registered_drivers; d->next_bus;
			d = d->next_bus);
		d->next_bus = driver;
	}

	driver->next_bus = NULL;

	spin_unlock(&pci_bus.bus_lock);

	__pci_bus_register(driver, &pci_bus);
	__pci_bus_register(driver, &pcie_bus);
}

int pci_enable_device(struct pci_device *device)
{
	int st = pci_set_power_state(device, PCI_POWER_STATE_D0);

	if(st < 0)
	{
		/* Check if the device could actually change power states */
		if(st != -ENOSYS)
			return -1;
		/* if it failed purely because we can't change it, proceed
		 * since the device is already in D0
		*/
	}

	/* Enable the IO and MMIO of the device */
	uint16_t command = (uint16_t) pci_read(device, PCI_REGISTER_COMMAND, sizeof(uint16_t));
	command |= PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_IOSPACE;

	pci_write(device, command, PCI_REGISTER_COMMAND, sizeof(uint16_t));

	return 0;
}

#define PCI_AF_REG_LENGTH		2
#define PCI_AF_REG_AF_CAPS		3
#define PCI_AF_REG_CONTROL		4
#define PCI_AF_REG_STATUS		5

#define PCI_AF_CAP_TP			(1 << 0)
#define PCI_AF_CAP_FLR			(1 << 1)

#define PCI_AF_INTIATE_FLR		(1 << 0)

#define PCI_AF_STATUS_TP		(1 << 0)

int pci_wait_for_tp(struct pci_device *device, off_t cap_start)
{
	while(!(pci_read(device, cap_start + PCI_AF_REG_STATUS, sizeof(uint16_t))
	      & PCI_AF_STATUS_TP));

	return 0;
}

int pci_reset_device(struct pci_device *device)
{
	size_t off = pci_find_capability(device, PCI_CAP_ID_AF, 0);
	if(off == 0)
		return errno = ENOTSUP, -1;
	
	if(pci_read(device, off + PCI_AF_REG_LENGTH, sizeof(uint8_t)) != 6)
	{
		ERROR("pci", "pci device at %04x:%02x:%02x:%02x has an invalid AF\n",
			device->segment, device->bus, device->device,
			device->function);
		return errno = EIO, -1;
	}

	uint8_t caps = pci_read(device, off + PCI_AF_REG_AF_CAPS, sizeof(uint8_t));

	/* Check for TP and FLR */
	if(!(caps & PCI_AF_CAP_TP) || !(caps & PCI_AF_CAP_FLR))
		return errno = EIO, -1;
	
	pci_write(device, PCI_AF_INTIATE_FLR, off + PCI_AF_REG_CONTROL, sizeof(uint8_t));

	return pci_wait_for_tp(device, off);
}

uint16_t pci_get_subsys_id(struct pci_device *dev)
{
	return (uint16_t) pci_read(dev, PCI_REGISTER_SUBSYSTEM_ID, sizeof(uint16_t));
}
