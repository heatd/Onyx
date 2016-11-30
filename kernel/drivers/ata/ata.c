/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
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

#include <drivers/ata.h>

prdt_entry_t *PRDT;
void *prdt_base = NULL;
PCIDevice *idedev = NULL;
uint16_t bar4_base = 0;
struct ide_drive
{
	_Bool exists;
	uint32_t lba28;
	uint64_t lba48;
	int type; /* Can be ATA_TYPE_ATA or ATA_TYPE_ATAPI */
	unsigned char buffer[512];
} ide_drives[4];
unsigned int current_drive = (unsigned int)-1;
unsigned int current_channel = (unsigned int)-1;
static volatile int irq = 0;
#define ATA_TIMEOUT 10000
int ata_wait_for_irq(uint64_t timeout)
{
	uint64_t time = get_tick_count();
	while(!irq)
	{
		if(get_tick_count() - time == timeout)
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
void ata_enable_pci_ide(PCIDevice *dev)
{
	/* Enable PCI Busmastering and PCI IDE mode by setting the bits 2 and 0 on the command register of the PCI
	configuration space */
	uint32_t command_reg = pci_config_read_dword(dev->slot, dev->device, dev->function, PCI_COMMAND);
	pci_write_dword(dev->slot, dev->device, dev->function, PCI_COMMAND, command_reg | 4);
	pci_write_word(dev->slot, dev->device, dev->function, PCI_INTN, 14);
	pci_set_barx(dev->slot, dev->device, dev->function, 0, 0x1F0, 1, 0);
	pci_set_barx(dev->slot, dev->device, dev->function, 1, 0x3F6, 1, 0);
	pci_set_barx(dev->slot, dev->device, dev->function, 2, 0x170, 1, 0);
	pci_set_barx(dev->slot, dev->device, dev->function, 3, 0x376, 1, 0);
	pcibar_t *bar4 = pci_get_bar(dev->slot, dev->device, dev->function, 4);
	bar4_base = bar4->address;
	irq_install_handler(14, &ata_irq);
	irq_install_handler(15, &ata_irq);
}
static int num_drives = 0;
static char devname[] = "/dev/hdx";
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
		printf("ata: IDENTIFY error\n");
		return 0;
	}
	for(int i = 0; i < 256; i++)
	{
		uint16_t data;
		if(channel == 0)
			data = inw(ATA_DATA1);
		else
			data = inw(ATA_DATA2);
		uint16_t *ptr = &ide_drives[curr].buffer[i*2];
		*ptr = data;
	}
	char *path = malloc(strlen(devname) + 1);
	strcpy(path, devname);
	path[strlen(path) - 1] = 'a' + curr;
	vfsnode_t *atadev = creat_vfs(slashdev, path, 0666);
	/*atadev->write = atadevfs_write;
	atadev->read = atadevfs_read;*/
	atadev->type = VFS_TYPE_CHAR_DEVICE;
	num_drives++;
	if(ide_drives[curr].buffer[0] == 0)
		ide_drives[curr].type = ATA_TYPE_ATAPI;
	else
		ide_drives[curr].type = ATA_TYPE_ATA;
	printf("ata: Created %s for drive %u\n", devname, num_drives);
	return 1;
}
void ata_init()
{
	idedev = get_pcidev_from_classes(1,1,0);
	if(idedev)
		printf("ata: found IDE controller\n");
	else
		return;
	/* Allocate PRDT base */
	prdt_base = vmm_allocate_virt_address(VM_KERNEL, 16/*64K*/, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(prdt_base, 16, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	printf("ata: allocated prdt base %x\n",prdt_base);
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
				printf("ata: Found ATA drive at %d:%d\n", channel, drive);
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
	}else
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
	}else
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
	}else
	{
		outl(bar4_base + 0x8 + 0x4, 0);
		outb(bar4_base + 0x8 + 2, 4);
	}
}
