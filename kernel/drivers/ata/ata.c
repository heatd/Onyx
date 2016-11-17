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
	irq = 1;
	inb(bar4_base + 2);
	inb((current_channel ? ATA_DATA2 : ATA_DATA1) + ATA_REG_STATUS);
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
void enable_pci_ide(PCIDevice *dev)
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
	printf("bar4: %x\n", bar4_base);
	irq_install_handler(14, &ata_irq);
	irq_install_handler(15, &ata_irq);
}
void initialize_ata()
{
	idedev = get_pcidev_from_classes(1,1,0);
	if(idedev)
		printf("ata: found IDE controller\n");
	else
		return;
	/*vfsnode_t *node = malloc(sizeof(node));
	node->name = "/dev/ata";
	node->type = VFS_TYPE_DEV;
	//vfs_register_node(node);*/
	/* Allocate PRDT base */
	prdt_base = vmm_allocate_virt_address(VM_KERNEL, 16/*64K*/, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(prdt_base, 16, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	printf("ata: allocated prdt base %x\n",prdt_base);
	/* Enable PCI IDE mode, and PCI busmastering DMA*/
	enable_pci_ide(idedev);
	/* Reset the controller */
	outb(ATA_CONTROL1, 4);
	outb(ATA_CONTROL2, 4);
	io_wait();
	/* Enable interrupts */
	outb(ATA_CONTROL1, 0);
	outb(ATA_CONTROL2, 0);
	printf("Probing the ATA drives\n");
	for(int f = 0; f < 2; f++)
	{
		for(int w = 0; w < 2; w++)
		{
			ata_set_drive(f, w);
			int curr = f + w;
			uint8_t status = inb(ATA_DATA1 + ATA_REG_STATUS);
			if (status != 0)
				ide_drives[curr].exists = 1;
			else
				continue;
			outb(ATA_DATA1 + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
			delay_400ns();
			if(ata_wait_for_irq(100))
			{
				printf("ata: IDENTIFY error\n");
				continue;
			}
			for(int i = 0; i < 256; i++)
			{
				uint64_t data = (uint64_t)inw(ATA_DATA1);
				if(i == 61)
					ide_drives[curr].lba28 |= data;
				else if(i == 60)
					ide_drives[curr].lba28 |= data << 16;
				else if(i == 100)
					ide_drives[curr].lba48 |= data << 48;
				else if(i == 101)
					ide_drives[curr].lba48 |= data << 32;
				else if(i == 102)
					ide_drives[curr].lba48 |= data << 16;
				else if(i == 103)
					ide_drives[curr].lba48 |= data;
			}
		}
	}
	printf("Probing finished\n");
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
