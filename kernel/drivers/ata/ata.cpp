/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <onyx/id.h>
#include <onyx/vm.h>
#include <onyx/port_io.h>
#include <onyx/irq.h>
#include <onyx/panic.h>
#include <onyx/timer.h>
#include <onyx/dev.h>
#include <onyx/block.h>
#include <onyx/log.h>
#include <onyx/compiler.h>
#include <onyx/page.h>
#include <onyx/mutex.h>
#include <onyx/driver.h>
#include <onyx/page.h>
#include <onyx/memory.hpp>
#include <onyx/wait_queue.h>
#include <onyx/clock.h>
#include <onyx/async_io.h>
#include <onyx/scoped_lock.h>

#include <drivers/ata.h>

#include "ide.h"

#define ATA_TIMEOUT 		  NS_PER_SEC
#define ATA_IDENTIFY_TIMEOUT   100 * NS_PER_MS

static struct ids *ata_ids = nullptr;

irqstatus_t ide_irq(struct irq_context *ctx, void *cookie);

class ide_ata_bus
{
public:
	uint16_t control_reg;
	uint16_t data_reg;
	uint16_t busmaster_reg;
	aio_req *req;

	ide_ata_bus() : control_reg{}, data_reg{}, busmaster_reg{}, req{nullptr}
	{
	}

	void reset()
	{
		outb(control_reg + IDE_REG_DEVCTL, IDE_DEVCTL_SRST);
	}

	void enable_irqs()
	{
		outb(control_reg + IDE_REG_DEVCTL, 0);
	}

	uint8_t delay_400ns(void)
	{
		for(int i = 0; i < 4; i++) /* Waste 400 ns reading ports*/
			inb(control_reg);

		return inb(control_reg);
	}

	void select_drive(unsigned int drive)
	{
		outb(data_reg + ATA_REG_HDDEVSEL, 0x40 | (drive << 4));
		delay_400ns();
	}

	void send_command(uint8_t command);

	void start_dma(bool write);
	void stop_dma();
	void prepare_dma(struct page *prdt_page, bool write);
};

class ide_dev;
struct ide_drive
{
	bool exists;
	uint32_t lba28;
	uint64_t lba48;
	int type; /* Can be ATA_TYPE_ATA or ATA_TYPE_ATAPI */
	ide_ata_bus& bus;
	int drive;
	ide_dev *dev;
	unsigned char buffer[512];

	ide_drive(ide_ata_bus& bus) : exists{false},
	                              lba28{}, lba48{}, type{},
								  bus{bus}, drive{}, buffer{} {}
	int probe();
};


class ide_dev
{
	static constexpr size_t prdt_nr_pages = 1;

	ide_ata_bus ata_buses[2];

	ide_drive ide_drives[4];
	prdt_entry_t *prdt;
	page *prdt_page;
	pci::pci_device *dev;
	uint16_t busmaster_reg;
	mutex io_op_lock;

public:
	explicit ide_dev(pci::pci_device *dev) : ata_buses{},
										ide_drives{ata_buses[0], ata_buses[0], ata_buses[1], ata_buses[1]},
										prdt{}, prdt_page{}, dev{dev},
	                                    busmaster_reg{}, io_op_lock{}
	{
		for(auto &drv : ide_drives)
			drv.dev = this;
	}

	~ide_dev()
	{
		vm_munmap(&kernel_address_space, prdt, prdt_nr_pages << PAGE_SHIFT);
		free_pages(prdt_page);
	}

	int probe();
	void enable_pci();

	void reset_controller()
	{
		ata_buses[0].reset();
		ata_buses[1].reset();
		io_wait();
	}
	
	void enable_irqs()
	{
		ata_buses[0].enable_irqs();
		ata_buses[1].enable_irqs();
	}

	ide_ata_bus& get_bus(int idx)
	{
		return ata_buses[idx];
	}

	int submit_request(bio_req *req, ide_drive *drive);

	void fill_prdt_from_hwvec(const page_iov *vec, size_t nr_vecs);
};

void ide_dev::enable_pci()
{
	/* Enable PCI Busmastering and PCI IDE mode */
	dev->enable_device();
	dev->enable_busmastering();
	dev->write(14, PCI_REGISTER_INTN, sizeof(uint16_t));

#if 0 
	// TODO: Is this needed?
	dev->set_bar(dev->bus, dev->device, dev->function, 0, IDE_DATA1, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 1, IDE_CONTROL1, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 2, IDE_DATA2, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 3, IDE_CONTROL2, 1, 0);
#endif

	ata_buses[0].control_reg = IDE_CONTROL1;
	ata_buses[1].control_reg = IDE_CONTROL2;
	ata_buses[0].data_reg = IDE_DATA1;
	ata_buses[1].data_reg = IDE_DATA2;

	auto st = dev->get_bar(4);
	assert(st.has_error() == false);

	auto bar = st.value();

	busmaster_reg = bar.address;

	ata_buses[0].busmaster_reg = busmaster_reg;
	/* The secondary bus' busmaster reg is offset by 0x8 bytes */
	ata_buses[1].busmaster_reg = busmaster_reg + 0x8;
	
	assert(install_irq(14, ide_irq, (struct device *) dev,
		IRQ_FLAG_REGULAR, this) == 0);
	assert(install_irq(15, ide_irq, (struct device *) dev,
		IRQ_FLAG_REGULAR, this) == 0);
}

int ide_dev::probe()
{
	prdt_page = alloc_pages(prdt_nr_pages, PAGE_ALLOC_4GB_LIMIT);
	if(!prdt_page)
		return -ENOMEM;

	/* Allocate PRDT base */
	prdt = (prdt_entry_t *) mmiomap(page_to_phys(prdt_page), prdt_nr_pages << PAGE_SHIFT, VM_WRITE | VM_NOEXEC);
	if(!prdt)
	{
		ERROR("ata", "Could not allocate a PRDT\n");
		return -ENOMEM;
	}

	/* Enable PCI IDE mode, and PCI busmastering DMA*/
	enable_pci();

	/* Reset the controller */
	reset_controller();

	/* Enable interrupts */
	enable_irqs();

#if 0
	struct page *read_buffer_pgs = alloc_pages(2, PAGE_ALLOC_CONTIGUOUS);
	struct page *write_buffer_pgs = alloc_pages(2, PAGE_ALLOC_CONTIGUOUS);

	assert(read_buffer_pgs != NULL);
	assert(write_buffer_pgs != NULL);

	read_buffer = (void *) pfn_to_paddr(page_to_pfn(read_buffer_pgs));
	write_buffer = (void *) pfn_to_paddr(page_to_pfn(write_buffer_pgs));
#endif

	unsigned int i = 0;

	for(auto &drive : ide_drives)
	{
		drive.drive = i++;
		auto st = drive.probe();

		if(st < 0)
		{
			ERROR("ata", "Error probing drive: %d\n", st);
			return -1;
		}
		else if(st == 0)
			INFO("ata", "Found ATA drive at %d:%d\n", drive.drive / 2, drive.drive % 2);
	}

	return 0;
}

void ide_ata_bus::send_command(uint8_t command)
{
	outb(data_reg + ATA_REG_COMMAND, command);
}

unsigned long nr_ide_irq = 0;
unsigned long total_irq_ide = 0;

irqstatus_t ide_irq(struct irq_context *ctx, void *cookie)
{
	auto device = (ide_dev *) cookie;

	int bus_idx = 0;

	/* IDE triggers IRQ14 for primary bus irqs, and IRQ15 for secondary bus irqs */
	if(ctx->irq_nr == ATA_IRQ)
		bus_idx = 0;
	else
		bus_idx = 1;

	auto &bus = device->get_bus(bus_idx);
	total_irq_ide++;

	auto status = inw(bus.busmaster_reg + IDE_BMR_REG_STATUS);

	/*if(!(status & IDE_BMR_ST_IRQ_GEN) || !bus.req)
		return IRQ_UNHANDLED;*/
	
	bool had_error = status & IDE_BMR_ST_DMA_ERR;
	inb(bus.data_reg + ATA_REG_STATUS);

	bus.req->status = had_error ? AIO_STATUS_EIO : AIO_STATUS_OK;
	bus.req->signaled = true;
	wait_queue_wake_all(&bus.req->wake_sem);

	nr_ide_irq++;

	outw(bus.busmaster_reg + IDE_BMR_REG_STATUS, status);

	return IRQ_HANDLED;
}

static int num_drives = 0;
static char devname[] = "sdxx";
static char dev_name[] = "sd";

ide_drive *ide_drive_from_blockdev(blockdev *dev)
{
	return (ide_drive *) dev->device_info;
}

int ata_flush(struct blockdev *blkd)
{
	auto drv = ide_drive_from_blockdev(blkd);

	drv->bus.send_command(ATA_CMD_CACHE_FLUSH_EXT);
	return 0;
}

int ata_pm(int op, struct blockdev *blkd)
{
	/* Flush all data before entering any power mode */
	ata_flush(blkd);
	auto drv = ide_drive_from_blockdev(blkd);

	if(op == BLKDEV_PM_SLEEP)
	{
		drv->bus.send_command(ATA_CMD_IDLE);
		return 0;
	}
	else
		return errno = EINVAL, -1;
}

int ata_submit_request(blockdev *dev, bio_req *req);

int ide_drive::probe()
{
	bus.select_drive(drive);

	auto status = inb(bus.data_reg + ATA_REG_STATUS);
	if(status != 0)
		exists = true;
	else
	{
		return 0;
	}

	struct aio_req r;
	aio_req_init(&r);

	bus.req = &r;

	outb(bus.data_reg + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
	
	bus.delay_400ns();

	if(aio_wait_on_req(&r, ATA_IDENTIFY_TIMEOUT) == -ETIMEDOUT)
	{
		return 0;
	}

	while(!wait_queue_may_delete(&r.wake_sem));

	for(int i = 0; i < 256; i++)
	{
		uint16_t data = inw(bus.data_reg);
		uint16_t *ptr = (uint16_t *) &buffer[i*2];
		*ptr = data;
	}

	char *path = (char *) zalloc(strlen(devname) + 1);
	if(!path)
		return 0;

	strcpy(path, dev_name);
	const char *id = idm_get_device_letter(ata_ids);
	assert(id != NULL);
	strcat(path, id);

	/* Create /dev/sdxx */

	/* Allocate a major-minor pair for a device */
	struct dev *min = dev_register(0, 0, path);
	if(!min)
	{
		free(path);
		FATAL("ata", "could not create a device ID for %s\n", path);
		return 0;
	}

	memset(&min->fops, 0, sizeof(struct file_ops));

	num_drives++;

	if(buffer[0] == 0)
		type = ATA_TYPE_ATAPI;
	else
		type = ATA_TYPE_ATA;

	/* Add to the block device layer */
	blockdev *dev = (blockdev *) malloc(sizeof(struct blockdev));

	if(!dev)
	{
		FATAL("ata", "could not create a block device\n");
		dev_unregister(min->majorminor);
		return 1;	
	}

	memset(dev, 0, sizeof(struct blockdev));

	dev->device_info = this;
	dev->dev = min;
	char *p = (char *) malloc(strlen("/dev/") + strlen(path) + 1);
	if(!p)
	{
		free(dev);
		return errno = ENOMEM;
	}

	memset(p, 0, strlen("/dev/") + strlen(path) + 1);
	strcpy(p, "/dev/");
	strcat(p, path);
	dev->name = p;
	dev->flush = ata_flush;
	dev->power = ata_pm;
	dev->submit_request = ata_submit_request;
	dev->sector_size = 512;
	min->priv = dev;

	blkdev_init(dev);
	
	INFO("ata", "Created %s for drive %u\n", path, num_drives);
	return 1;
}

struct pci::pci_id ata_devs[] =
{
	{PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 1, PCI_ANY_ID, NULL)},
	{PCI_ID_CLASS(CLASS_MASS_STORAGE_CONTROLLER, 6, PCI_ANY_ID, NULL)},
	{0}
};

int ata_probe(struct device *d)
{
	pci::pci_device *device = (pci::pci_device *) d;

	unique_ptr<ide_dev> dev = make_unique<ide_dev>(device);
	if(!dev)
		return -ENOMEM;
	
	auto st = dev->probe();

	if(st == 0)
		dev.release();

	return st; 
}

struct driver ata_driver = 
{
	.name = "ata",
	.devids = &ata_devs,
	.probe = ata_probe,
	.bus_type_node = {&ata_driver}
};

int ata_init(void)
{
	ata_ids = idm_add("sd", 0, UINTMAX_MAX);
	if(!ata_ids)
		return -1;

	pci::register_driver(&ata_driver);

	return 0;
}

/* Looks at the bio req and gathers some important data about it */
static unsigned int look_at_bio_req(const bio_req *req, bool &needs_bounce)
{
	unsigned int count = 0;
	for(unsigned int i = 0; i < req->nr_vecs; i++)
	{
		auto &vec = req->vec[i];

		/* Oh yeah boyy, bounce buffer time.
		 * please shoot me. old hw = garbage
		 */
		if((unsigned long) page_to_phys(vec.page) >= UINT32_MAX)
		{
			needs_bounce = true;
		}

		count += vec.length;
	}

	return count;
}

void fill_bounce_buf_vec(page_iov *hw_vec, size_t nr_pages, page *pages, size_t len)
{
	for(size_t i = 0; i < nr_pages; i++)
	{
		hw_vec[i].page = pages;
		hw_vec[i].length = cul::min(len, (unsigned long) PAGE_SIZE);
		hw_vec[i].page_off = 0;
		pages = pages->next_un.next_allocation;
		len -= hw_vec[i].length;
	}
}

void fill_bounce_buf(page_iov *hw_vec, size_t vec_size, bio_req *req)
{
	auto it = hw_vec->to_iter();
	
	for(size_t i = 0; i < req->nr_vecs; i++)
	{
		const auto &vec = req->vec[i];

		unsigned int copied = 0;

		while(copied != vec.length)
		{
			if(it.length() <= 0)
				++it;

			const auto page_source = (unsigned char *)
			               ((unsigned long) PAGE_TO_VIRT(vec.page) + vec.page_off + copied);
			const auto to_copy = min(vec.length, it.v->length);
			memcpy(it.to_pointer<unsigned char>(), page_source, to_copy);
			it.increment(vec.length);

			copied += to_copy;
		}
	}
}

void ide_dev::fill_prdt_from_hwvec(const page_iov *vec, size_t nr_vecs)
{
	auto prd = prdt;

	while(nr_vecs--)
	{
		/* If it's the last entry, nr_vecs is 0 right now(after being
		 * decremented by the line above)
		 */
		bool is_last_entry = nr_vecs == 0;

		prd->address = (uint32_t) (unsigned long) page_to_phys(vec->page) + vec->page_off;
		prd->flags = is_last_entry ? PRD_FLAG_END : 0;
		prd->size = (uint16_t) vec->length;

		++prd;
		++vec;
	}
}

void ide_ata_bus::start_dma(bool write)
{
	outb(busmaster_reg + IDE_BMR_REG_COMMAND, IDE_BMR_CMD_START | (write ? IDE_BMR_CMD_WRITE : 0));
}

void ide_ata_bus::prepare_dma(struct page *prdt_page, bool write)
{
	uint32_t prdt_phys = (uint32_t) (unsigned long) page_to_phys(prdt_page);
	outl(busmaster_reg + IDE_BMR_REG_PRDT_ADDR, prdt_phys);
	outb(busmaster_reg + IDE_BMR_REG_COMMAND, (write ? IDE_BMR_CMD_WRITE : 0));
	outb(busmaster_reg + IDE_BMR_REG_STATUS, IDE_BMR_ST_IRQ_GEN | IDE_BMR_ST_DMA_ERR);
}

void ide_ata_bus::stop_dma()
{
	outb(busmaster_reg + IDE_BMR_REG_COMMAND, 0);
	outl(busmaster_reg + IDE_BMR_REG_PRDT_ADDR, 0);
}

int ide_dev::submit_request(bio_req *req, ide_drive *drive)
{
	if(req->nr_vecs > ((prdt_nr_pages << PAGE_SHIFT) / sizeof(prdt_entry_t)))
		return -EIO;

	auto req_code = req->flags & BIO_REQ_OP_MASK;
	bool needs_bounce = false;
	struct page *bounce_buffer_pages = nullptr;

	page_iov *hw_vec = req->vec;
	auto iov_size = req->nr_vecs;

	auto len = look_at_bio_req(req, needs_bounce);

	if(needs_bounce)
	{
		size_t nr_pages = vm_size_to_pages(len);

		struct page *pages = alloc_pages(nr_pages, PAGE_ALLOC_4GB_LIMIT);
		if(!pages)
			return -ENOMEM;

		bounce_buffer_pages = pages;
		hw_vec = (page_iov *) calloc(nr_pages, sizeof(page_iov));
		if(!hw_vec)
		{
			free_pages(pages);
			return -ENOMEM;
		}

		iov_size = nr_pages;

		fill_bounce_buf_vec(hw_vec, nr_pages, pages, len);
		if(req_code == BIO_REQ_WRITE_OP) fill_bounce_buf(hw_vec, iov_size, req);
	}

	bool write = req_code == BIO_REQ_WRITE_OP;
	uint8_t command = write ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;

	scoped_mutex g{io_op_lock};

	fill_prdt_from_hwvec(hw_vec, iov_size);

	auto &bus = drive->bus;

	struct aio_req r;
	aio_req_init(&r);

	bus.req = &r;

	/*outl(bus.busmaster_reg + 0x4, (uint32_t)(uint64_t) page_to_phys(prdt_page));
	outb(bus.busmaster_reg + 2, 4);*/
	//printk("ATA status %x\n", inb(bus.control_reg + ATA_REG_ALTSTATUS));

	bus.prepare_dma(prdt_page, write);

	bus.select_drive(drive->drive);

	const auto sect = req->sector_number;
	const uint16_t num_secs = len / 512;
	outb(bus.data_reg + ATA_REG_SECCOUNT0 , num_secs >> 8);
	outb(bus.data_reg + ATA_REG_LBA0, sect >> 24);
	outb(bus.data_reg + ATA_REG_LBA1, sect >> 32);
	outb(bus.data_reg + ATA_REG_LBA2, sect >> 40);
	outb(bus.data_reg + ATA_REG_SECCOUNT0 , num_secs);
	outb(bus.data_reg + ATA_REG_LBA0, sect);
	outb(bus.data_reg + ATA_REG_LBA1, sect >> 8);
	outb(bus.data_reg + ATA_REG_LBA2, sect >> 16);

	outb(bus.data_reg + ATA_REG_COMMAND, command);

	bus.start_dma(write);

	//printk("op %u sector %lu num_sec %u\n", req_code, sect, num_secs);

	auto st = aio_wait_on_req(&r, ATA_TIMEOUT);

	bus.stop_dma();
	//printk("st %d\n", st);
	//printk("ATA status %x\n", inb(bus.control_reg + ATA_REG_ALTSTATUS));

	if(needs_bounce)
	{
		free(hw_vec);
		free_pages(bounce_buffer_pages);
	}

	if(st == -ETIMEDOUT)
	{
		req->flags |= BIO_REQ_TIMEOUT;
		return st;
	}

	if(r.status == AIO_STATUS_EIO)
	{
		req->flags |= BIO_REQ_EIO;
	}
	else
	{
		req->flags |= BIO_REQ_DONE;
	}

	return st;
}

int ata_submit_request(blockdev *dev, bio_req *req)
{
	auto drive = ide_drive_from_blockdev(dev);
	req->sector_number += dev->offset / 512;
	
	return drive->dev->submit_request(req, drive);
}

MODULE_INIT(ata_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
