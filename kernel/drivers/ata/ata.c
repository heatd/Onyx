/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <mbr.h>

#include <kernel/vmm.h>
#include <kernel/portio.h>
#include <kernel/vfs.h>
#include <kernel/pic.h>
#include <kernel/irq.h>
#include <kernel/pit.h>
#include <kernel/panic.h>
#include <kernel/timer.h>
#include <kernel/dev.h>
#include <kernel/block.h>
#include <kernel/log.h>
#include <kernel/fscache.h>
#include <kernel/compiler.h>
#include <kernel/page.h>

#include <drivers/ata.h>

#define ATA_TIMEOUT 10000

prdt_entry_t *PRDT;
void *prdt_base = NULL;
struct pci_device *idedev = NULL;
uint16_t bar4_base = 0;
struct ide_drive
{
	_Bool exists;
	uint32_t lba28;
	uint64_t lba48;
	int type; /* Can be ATA_TYPE_ATA or ATA_TYPE_ATAPI */
	int channel;
	int drive;
	unsigned char buffer[512];
} ide_drives[4];
static volatile int irq = 0;
unsigned int current_drive = (unsigned int)-1;
unsigned int current_channel = (unsigned int)-1;

void ata_send_command(struct ide_drive* drive, uint8_t command)
{
	if(drive->channel > 0)
		outb(ATA_DATA2 + ATA_REG_COMMAND, command);
	else
		outb(ATA_DATA1 + ATA_REG_COMMAND, command);
}
int ata_wait_for_irq(uint64_t timeout)
{
	uint64_t time = get_tick_count();
	while(!irq)
	{
		if(get_tick_count() - time <= timeout)
		{
			irq = 0;
			return 2;
		}
		uint16_t altstatus = inb(current_channel ? ATA_CONTROL1 : ATA_CONTROL2);
		if(altstatus & 1)
		{
			altstatus &= ~1;
			outb((current_channel ? ATA_DATA1 : ATA_DATA2) + ATA_REG_STATUS, altstatus);
			irq = 0;
			return 1;
		}
	}
	irq = 0;
	return 0;
}
static uintptr_t ata_irq(registers_t *regs)
{
	uint8_t status = inb((current_channel ? ATA_DATA2 : ATA_DATA1) + ATA_REG_STATUS);
	UNUSED(status);
	/*if(!(status & 0x4))
	{
		// If this bit isn't set, then the ATA device didn't trigger an IRQ, so just return
		return 0;
	}*/
	irq = 1;
	inb(bar4_base + 2);
	//status &= ~0x4;
	//outb((current_channel ? ATA_DATA2 : ATA_DATA1) + ATA_REG_STATUS, status);
	return 0;
}
uint8_t delay_400ns()
{
	for(int i = 0; i < 4; i++) /* Waste 400 ns reading ports*/
		inb(current_channel ? ATA_CONTROL2 : ATA_CONTROL1);

	return inb(current_channel ? ATA_CONTROL2 : ATA_CONTROL1);
}
void ata_set_drive(unsigned int channel, unsigned int drive)
{
	current_channel = channel;
	current_drive = drive;
	if(channel == 0)
		outb(ATA_DATA1 + ATA_REG_HDDEVSEL, 0x40 | (drive << 4));
	else
		outb(ATA_DATA2 + ATA_REG_HDDEVSEL, 0x40 | (drive << 4));
	delay_400ns();
}
void ata_enable_pci_ide(struct pci_device *dev)
{
	/* Enable PCI Busmastering and PCI IDE mode by setting the bits 2 and 0 on the command register of the PCI
	configuration space */
	pci_enable_busmastering(dev);
	pci_write(dev, 14, PCI_INTN, sizeof(uint16_t));
	pci_set_barx(dev->bus, dev->device, dev->function, 0, 0x1F0, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 1, 0x3F6, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 2, 0x170, 1, 0);
	pci_set_barx(dev->bus, dev->device, dev->function, 3, 0x376, 1, 0);
	pcibar_t *bar4 = pci_get_bar(dev, 4);
	bar4_base = bar4->address;
	irq_install_handler(14, &ata_irq);
	irq_install_handler(15, &ata_irq);
}
static int num_drives = 0;
static char devname[] = "hdx";
int ata_flush(struct blkdev *blkd)
{
	struct ide_drive *drv = blkd->device_info;
	if(!drv)
		return errno = EINVAL, -1;
	ata_send_command(drv, ATA_CMD_CACHE_FLUSH_EXT);
	return 0;
}
int ata_pm(int op, struct blkdev *blkd)
{
	/* Flush all data before entering any power mode */
	ata_flush(blkd);
	struct ide_drive *drv = blkd->device_info;
	if(!drv)
		return errno = EINVAL, -1;

	if(op == BLKDEV_PM_SLEEP)
	{
		ata_send_command(drv, ATA_CMD_IDLE);
		return 0;
	}
	else
		return errno = ENOSYS, -1;
}
ssize_t ata_read(size_t offset, size_t count, void* buffer, struct blkdev* blkd)
{
	struct ide_drive *drv = blkd->device_info;
	if(drv->type == ATA_TYPE_ATAPI)
		return errno = ENODEV, -1;
	if(!drv)
		return errno = EINVAL, -1;
	size_t off = offset;
	void *buf = NULL;
	errno = posix_memalign(&buf, UINT16_MAX+1, count);

	if(!buf)
		return -1;
	if(count < UINT16_MAX) ata_read_sectors(drv->channel, drv->drive, (uint32_t) (uintptr_t)virtual2phys(buf), count, off / 512);
	//fscache_cache_sectors(buffer, blkd, off / 512, count);
	/* If count > count_max, split this into multiple I/O operations */
	if(count > UINT16_MAX)
	{
		panic("Implement, you lazy ass!");
	}
	memcpy(buffer, buf, count);

	free(buf);
	return count;
}
ssize_t ata_write(size_t offset, size_t count, void* buffer, struct blkdev* blkd)
{
	struct ide_drive *drv = blkd->device_info;
	if(!drv)
		return errno = EINVAL, -1;
	size_t off = offset;

	void *buf = NULL;
	errno = posix_memalign(&buf, UINT16_MAX+1, count);

	if(!buf)
		return -1;
	memcpy(buf, buffer, count);

	if(count < UINT16_MAX) ata_write_sectors(drv->channel, drv->drive, (uint32_t) (uintptr_t)virtual2phys(buf), count, off / 512);
	/* If count > count_max, split this into multiple I/O operations */
	if(count > UINT16_MAX)
	{
		panic("Implement, you lazy ass!");
	}

	memcpy(buffer, buf, count);
	return count;
}
int ata_initialize_drive(int channel, int drive)
{
	ata_set_drive(channel, drive);
	int curr = channel + drive;
	uint8_t status;
	if(channel == 0)
		status = inb(ATA_DATA1 + ATA_REG_STATUS);
	else
		status = inb(ATA_DATA2 + ATA_REG_STATUS);
	if (status != 0)
		ide_drives[curr].exists = 1;
	else
	{
		return 0;
	}
	if(channel == 0)
		outb(ATA_DATA1 + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
	else
		outb(ATA_DATA1 + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
	delay_400ns();
	if(ata_wait_for_irq(100))
	{
		ERROR("ata", "IDENTIFY error\n");
		return 0;
	}
	for(int i = 0; i < 256; i++)
	{
		uint16_t data;
		if(channel == 0)
			data = inw(ATA_DATA1);
		else
			data = inw(ATA_DATA2);
		uint16_t *ptr = (uint16_t *)&ide_drives[curr].buffer[i*2];
		*ptr = data;
	}
	ide_drives[curr].drive = drive;
	ide_drives[curr].channel = channel;

	char *path = malloc(strlen(devname) + 1);
	if(!path)
		return 1;
	strcpy(path, devname);
	path[strlen(path) - 1] = 'a' + curr;

	/* Create /dev/hdx */
	vfsnode_t *atadev = creat_vfs(slashdev, path, 0666);
	if(!atadev)
	{
		free(path);
		FATAL("ata", "could not create a device node!\n");
		return 0;
	}
	/* Allocate a major-minor pair for a device */
	struct minor_device *min = dev_register(0, 0);
	if(!min)
	{
		free(path);
		FATAL("ata", "could not create a device ID for %s\n", path);
		return 0;
	}
	
	min->fops = malloc(sizeof(struct file_ops));
	if(!min->fops)
	{
		free(path);
		dev_unregister(min->majorminor);
		FATAL("ata", "could not create a file operation table for %s\n", path);
		return 0;
	}
	memset(min->fops, 0, sizeof(struct file_ops));
	/*min->fops->write = atadevfs_write;
	min->fops->read = atadevfs_read;*/
	atadev->type = VFS_TYPE_CHAR_DEVICE;
	atadev->dev = min->majorminor;
	num_drives++;

	if(ide_drives[curr].buffer[0] == 0)
		ide_drives[curr].type = ATA_TYPE_ATAPI;
	else
		ide_drives[curr].type = ATA_TYPE_ATA;

	/* Add to the block device layer */
	block_device_t *dev = malloc(sizeof(block_device_t));

	if(!dev)
	{
		FATAL("ata", "could not create a block device\n");
		free(min->fops);
		dev_unregister(min->majorminor);
		return 1;	
	}
	memset(dev, 0, sizeof(block_device_t));

	dev->device_info = &ide_drives[curr];
	dev->dev = min->majorminor;
	char *p = malloc(strlen("/dev/") + strlen(path) + 1);
	if(!p)
	{
		free(dev);
		return errno = ENOMEM;
	}
	memset(p, 0, strlen("/dev/") + strlen(path) + 1);
	strcpy(p, "/dev/");
	strcat(p, path);
	dev->node_path = p;
	dev->read = ata_read;
	dev->write = ata_write;
	dev->flush = ata_flush;
	dev->power = ata_pm;
	blkdev_add_device(dev);
	
	INFO("ata", "Created %s for drive %u\n", path, num_drives);
	return 1;
}
void ata_init(struct pci_device *dev)
{
	idedev = dev;

	/* Allocate PRDT base */
	prdt_base = dma_map_range(__alloc_pages(4), UINT16_MAX, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	if(!prdt_base)
	{
		ERROR("ata", "Could not allocate a PRDT\n");
	}
	INFO("ata", "allocated prdt base %p\n", prdt_base);
	/* Enable PCI IDE mode, and PCI busmastering DMA*/
	ata_enable_pci_ide(idedev);
	/* Reset the controller */
	outb(ATA_CONTROL1, 4);
	outb(ATA_CONTROL2, 4);
	io_wait();
	/* Enable interrupts */
	outb(ATA_CONTROL1, 0);
	outb(ATA_CONTROL2, 0);
	
	for(int channel = 0; channel < 2; channel++)
	{
		for(int drive = 0; drive < 2; drive++)
		{
			if(ata_initialize_drive(channel, drive))
				INFO("ata", "Found ATA drive at %d:%d\n", channel, drive);
		}
	}	
}
void ata_read_sectors(unsigned int channel, unsigned int drive, uint32_t buffer, uint16_t bytesoftransfer, uint64_t lba48)
{
	if(bytesoftransfer == 0) bytesoftransfer = UINT16_MAX;
	uint16_t num_secs = bytesoftransfer / 512;
	if(bytesoftransfer % 512)
		num_secs++;
	if(!PRDT)
		PRDT = prdt_base;
	PRDT->data_buffer = buffer;
	PRDT->size = bytesoftransfer;
	PRDT->res = 0x8000;
	uint32_t param = (uint32_t)((uint64_t)virtual2phys(PRDT));
	if(!channel)
	{
		outl(bar4_base + 0x4, param);
		outb(bar4_base + 2, 4);
	}
	else
	{
		outl(bar4_base + 0x8 + 0x4, param);
		outb(bar4_base + 0x8 + 2, 4);
	}
	ata_set_drive(channel, drive);
	outb(0x1F0 + ATA_REG_SECCOUNT0 , num_secs >> 8 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA0, lba48 >> 24 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA1, lba48 >> 32 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA2, lba48 >> 40 & 0xFF);
	outb(0x1F0 + ATA_REG_SECCOUNT0 , num_secs & 0xFF);
	outb(0x1F0 + ATA_REG_LBA0, lba48 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA1, lba48 >> 8 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA2, lba48 >> 16 & 0xFF);
	/* Send the read command */
	outb(bar4_base, 8);
	if(channel == 0)
		outb(ATA_DATA1 + ATA_REG_COMMAND, ATA_CMD_READ_DMA_EXT);
	else
		outb(ATA_DATA2 + ATA_REG_COMMAND, ATA_CMD_READ_DMA_EXT);
	outb(bar4_base, 9);
	ata_wait_for_irq(10000);
	outb(bar4_base, 0);
}
void ata_write_sectors(unsigned int channel, unsigned int drive, uint32_t buffer, uint16_t bytesoftransfer, uint64_t lba48)
{
	if(bytesoftransfer == 0) bytesoftransfer = UINT16_MAX;
	uint16_t num_secs = bytesoftransfer / 512;
	if(bytesoftransfer % 512)
		num_secs++;
	if(!PRDT)
		PRDT = prdt_base;
	PRDT->data_buffer = buffer;
	PRDT->size = bytesoftransfer;
	PRDT->res = 0x8000;
	uint32_t param = (uint32_t)((uint64_t)virtual2phys(PRDT));
	if(!channel)
	{
		outl(bar4_base + 0x4, param);
		outb(bar4_base + 2, 4);
	}
	else
	{
		outl(bar4_base + 0x8 + 0x4, param);
		outb(bar4_base + 0x8 + 2, 4);
	}
	ata_set_drive(channel, drive);
	outb(0x1F0 + ATA_REG_SECCOUNT0 , num_secs >> 8 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA0, lba48 >> 24 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA1, lba48 >> 32 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA2, lba48 >> 40 & 0xFF);
	outb(0x1F0 + ATA_REG_SECCOUNT0 , num_secs & 0xFF);
	outb(0x1F0 + ATA_REG_LBA0, lba48 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA1, lba48 >> 8 & 0xFF);
	outb(0x1F0 + ATA_REG_LBA2, lba48 >> 16 & 0xFF);
	/* Send the write command */
	outb(bar4_base, 0);
	if(channel == 0)
		outb(ATA_DATA1 + ATA_REG_COMMAND, ATA_CMD_WRITE_DMA_EXT);
	else
		outb(ATA_DATA2 + ATA_REG_COMMAND, ATA_CMD_WRITE_DMA_EXT);
	outb(bar4_base, 1);
	ata_wait_for_irq(10000);
	outb(bar4_base, 0);
	if(!channel)
	{
		outl(bar4_base + 0x4, 0);
		outb(bar4_base + 2, 4);
	}
	else
	{
		outl(bar4_base + 0x8 + 0x4, 0);
		outb(bar4_base + 0x8 + 2, 4);
	}
}
